"""Verification loop — independently re-test candidate findings to kill FPs.

Only findings that reproduce under an independent re-test are promoted to
VERIFIED and allowed into the final report. Everything else is REFUTED and
fed back to evolution as negative signal.

The `Verifier` is pluggable: the default `RunnerVerifier` delegates to the
engagement runner`s `verify_finding` (a fresh re-test). The default for SEAL
is the LLMVerifier — an independent LLM that critically re-reviews each finding.
Both are pluggable without touching the loop.
"""
from __future__ import annotations

import abc
import json
import re
from dataclasses import dataclass, field

from ..models import Finding, FindingStatus
from ..engine import EngagementRunner


class Verifier(abc.ABC):
    @abc.abstractmethod
    def verify(self, finding: Finding, target: str, workdir: str) -> tuple[bool, str]:
        ...


class RunnerVerifier(Verifier):
    """Delegate verification to the engagement runner (fresh re-test)."""

    def __init__(self, runner: EngagementRunner):
        self.runner = runner

    def verify(self, finding: Finding, target: str, workdir: str) -> tuple[bool, str]:
        return self.runner.verify_finding(finding, target, workdir)


_JUDGE_SYSTEM = (
    "You are a senior offensive-security reviewer performing INDEPENDENT verification of "
    "vulnerability findings produced by an automated scanner. Automated scanners over-report; "
    "your job is to rule each finding as a TRUE, exploitable vulnerability or a FALSE POSITIVE, "
    "with rigorous, concrete reasoning — the way an experienced human reviewer would.\n"
    "Known false-positive patterns to catch:\n"
    "- Raw user input reflected in a JSON API response is NOT XSS. A JSON body is inert; XSS "
    "requires the payload to reach an HTML execution context, and modern frontends (React/Vue) "
    "escape on render. Refute unless there is proof of actual browser execution.\n"
    "- A header/control reported 'missing' that is actually present or enforced.\n"
    "- Theoretical issues with no demonstrated exploit path or impact.\n"
    "- 'Weak password policy' / 'no rate limiting' claimed without an actual bypass shown.\n"
    "Demand concrete evidence of exploitation. Be skeptical. Reply with STRICT JSON only."
)


class LLMVerifier(Verifier):
    """An INDEPENDENT LLM (a DIFFERENT model than the scanner) critically reviews
    each finding and rules real vs false-positive by reasoning — catching FPs the
    scanner's own validation misses. Its verdict AND its 'what to investigate
    instead' hint steer the loop: refuted findings feed a re-run or a new
    direction into evolution.

    Uses an OpenAI-compatible endpoint (the LiteLLM proxy or OpenRouter) so no
    key leaves the host beyond the normal inference call.
    """

    def __init__(self, *, model: str | None = None, endpoint: str | None = None,
                 api_key: str | None = None, timeout: int = 60):
        self.model = model or _env("SEAL_JUDGE_MODEL", "openrouter/anthropic/claude-sonnet-4-6")
        self.endpoint = (endpoint or _env("SEAL_JUDGE_URL", "http://localhost:4000/v1")).rstrip("/")
        self.api_key = (api_key or _env("SEAL_JUDGE_API_KEY", "")
                        or _env("LITELLM_MASTER_KEY", "") or _env("OPENROUTER_API_KEY", ""))
        self.timeout = timeout
        self.directions: list[str] = []   # steering hints for the evolution loop

    def verify(self, finding: Finding, target: str, workdir: str) -> tuple[bool, str]:
        real, reasoning, direction = self._judge(finding, target)
        if not real and direction:
            self.directions.append(direction)
        return real, reasoning

    def _judge(self, finding: Finding, target: str) -> tuple[bool, str, str]:
        user = (
            f"Target: {target}\n"
            f"Reported finding:\n"
            f"  class: {finding.vuln_class}\n"
            f"  title: {finding.title}\n"
            f"  severity: {finding.severity.name}\n"
            f"  surface: {finding.surface}\n"
            f"  evidence: {finding.evidence}\n"
            f"  proof-of-concept:\n{finding.poc}\n\n"
            'Reply with STRICT JSON: {"real": true|false, "reasoning": "<=60 words", '
            '"suggested_direction": "if false/uncertain, what the next scan round should '
            'investigate instead (else empty)"}'
        )
        try:
            content = self._chat(user)
            data = _extract_json(content)
            return (bool(data.get("real")), str(data.get("reasoning", ""))[:400],
                    str(data.get("suggested_direction", ""))[:200])
        except Exception as e:  # noqa: BLE001 — never let the judge crash the loop
            # Fail-CLOSED: if the judge is unreachable, do NOT auto-pass a finding.
            return False, f"independent judge unavailable ({type(e).__name__}); left unverified", ""

    def _chat(self, user: str) -> str:
        import urllib.request  # noqa: PLC0415
        body = json.dumps({
            "model": self.model, "temperature": 0,
            "messages": [{"role": "system", "content": _JUDGE_SYSTEM},
                         {"role": "user", "content": user}],
        }).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint + "/chat/completions", data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.api_key}"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            d = json.loads(r.read().decode("utf-8", "ignore"))
        return d["choices"][0]["message"]["content"]


def _env(name: str, default: str) -> str:
    import os  # noqa: PLC0415
    return os.environ.get(name, "").strip() or default


def _extract_json(text: str) -> dict:
    """Pull the first JSON object out of an LLM reply (handles ```json fences)."""
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("no JSON object in judge reply")
    return json.loads(m.group(0))


@dataclass
class VerificationReport:
    verified: list[Finding] = field(default_factory=list)
    refuted: list[Finding] = field(default_factory=list)

    @property
    def fp_rate(self) -> float:
        total = len(self.verified) + len(self.refuted)
        return (len(self.refuted) / total) if total else 0.0


class VerificationLoop:
    """Re-test each unique candidate finding; classify verified vs refuted.

    Emits live judge events through `on_event(event, payload)` so a front-end
    (the CLI live view) can show each real/false-positive verdict — and the
    judge's reasoning — the moment it's decided, instead of only in the report.
    """

    def __init__(self, verifier: Verifier, *, dedup: bool = True, on_event=None):
        self.verifier = verifier
        self.dedup = dedup
        self.on_event = on_event or (lambda _e, _p: None)

    def run(self, candidates: list[Finding], target: str, workdir: str,
            *, already_seen: set[str] | None = None) -> VerificationReport:
        seen = set(already_seen or set())
        pending: list[Finding] = []
        for f in candidates:
            if self.dedup and f.id in seen:
                continue
            seen.add(f.id)
            pending.append(f)

        self.on_event("judge_start", {"count": len(pending)})
        report = VerificationReport()
        for f in pending:
            ok, notes = self.verifier.verify(f, target, workdir)
            f.verify_notes = notes
            # The LLM judge stores a "what to investigate instead" hint per
            # refuted finding; surface it live next to the FP verdict.
            hint = ""
            dirs = getattr(self.verifier, "directions", None)
            if not ok and dirs:
                hint = dirs[-1]
            if ok:
                f.status = FindingStatus.VERIFIED
                report.verified.append(f)
            else:
                f.status = FindingStatus.REFUTED
                report.refuted.append(f)
            self.on_event("judge_finding", {
                "title": f.title, "class": f.vuln_class,
                "real": ok, "notes": notes, "hint": hint,
            })
        return report
