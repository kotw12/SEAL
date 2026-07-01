"""ScanRunner — drive SEAL's external scan engine.

SEAL runs an autonomous scan engine as a subprocess: it discovers endpoints,
fingerprints the stack, and runs class-by-class exploit attempts with an
internal validation pass — fast and cheap.

The engine's own validation still ships false positives (e.g. it flags
"Stored XSS" when the API merely returns raw input in a JSON body — not an
execution context; a React frontend escapes it on render). So SEAL layers its
own independent-judge verification loop ON TOP of the engine, and the evolution
loop builds only on SEAL-verified findings.

The scan engine is the open-source scanner credited in NOTICE. SEAL invokes it
as `<engine> -t <target> --instruction <text> -n -m <mode>` and reads findings
from its run directory (vulnerabilities/vuln-*.md).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from .config import SealConfig
from .engine import EngagementRunner
from .models import Finding, FindingStatus, RoundResult, Severity, Strategy


def _resolve_engine() -> str:
    """Resolve the scan-engine command: SEAL_ENGINE_BIN, else the engine on
    PATH, else its standalone binary location. (Engine credited in NOTICE.)"""
    override = os.environ.get("SEAL_ENGINE_BIN")
    if override:
        return os.path.expanduser(override)
    return shutil.which("strix") or os.path.expanduser("~/.strix/bin/strix")

# (class, needle-patterns). Ordered most-specific first. Short acronyms use \b
# word boundaries so "rce" never matches "resource" and "xss" never matches a
# mention inside another finding's description.
_CLASS_HINTS = [
    ("idor", (r"\bidor\b", "insecure direct object", "cwe-639")),
    ("ssrf", (r"\bssrf\b", "server-side request forgery", "cwe-918")),
    ("sqli", (r"\bsql injection\b", r"\bsqli\b")),
    ("xss", (r"\bxss\b", "cross-site scripting")),
    ("ratelimit", ("rate limit", "rate-limit", "brute")),
    ("auth", ("refresh token", "broken access", "authentication", "authorization",
              r"\bjwt\b", "session", "enumeration")),
    ("secret", ("password policy", "weak password", "secret", "credential")),
    ("rce", (r"\brce\b", "remote code execution", "command injection")),
]


def _infer_class(title: str, text: str) -> str:
    # Title is the canonical label; fall back to full text only if the title
    # names no known class (descriptions mention *related* risks and mislead).
    for hay in (title.lower(), (title + " " + text).lower()):
        for cls, needles in _CLASS_HINTS:
            for n in needles:
                if (n.startswith(r"\b") and re.search(n, hay)) or (not n.startswith(r"\b") and n in hay):
                    return cls
    return (title.split()[0].lower() if title else "finding")


def _field(text: str, name: str) -> str:
    m = re.search(rf"\*\*{name}:\*\*\s*(.+)", text)
    return m.group(1).strip() if m else ""


class ScanRunner(EngagementRunner):
    name = "engine"

    def __init__(self, config: SealConfig):
        self.cfg = config
        self.bin = _resolve_engine()
        self.runs_dir = Path(os.environ.get(
            "SEAL_ENGINE_RUNS", os.path.expanduser("~/.strix/strix_runs")))
        self.scan_mode = os.environ.get("SEAL_SCAN_MODE", "standard")  # quick|standard|deep

    # ---- attack round -----------------------------------------------------
    def run_round(self, strategy: Strategy, target: str, workdir: str) -> RoundResult:
        started = time.time()
        before = self._run_dirs()
        err = self._run_engine(target, strategy.instruction)
        run_dir = self._new_run_dir(before)
        findings = self._parse_run(run_dir, strategy) if run_dir else []
        rr = RoundResult(round_index=strategy.round_index, strategy=strategy,
                         findings=findings, raw_log=str(run_dir or ""),
                         error=err, started_at=started)
        rr.ended_at = time.time()
        return rr

    # ---- verification --------------------------------------------------
    # NOTE: the real verification is done by an independent LLM judge
    # (seal.loops.verification.LLMVerifier) that critically reviews each
    # finding and catches false positives by reasoning (the way a human
    # reviewer would), then steers the loop. This runner-level check is only a
    # cheap reachability pre-filter so the judge never wastes a call on a
    # finding whose endpoint 404s.
    def verify_finding(self, finding: Finding, target: str, workdir: str) -> tuple[bool, str]:
        url = _abs_url(target, finding.surface)
        _ctype, status, err = _http_head(url)
        if err:
            return False, f"endpoint not reachable ({err})"
        if status == 404:
            return False, "endpoint 404 on re-test — not a live surface"
        return True, f"endpoint live (HTTP {status})"

    # ---- engine invocation -------------------------------------------------
    def _run_engine(self, target: str, instruction: str) -> str:
        cmd = [self.bin, "-t", target, "--instruction", instruction,
               "-n", "-m", self.scan_mode]
        env = dict(os.environ)
        # Attack model: override the engine's model when SEAL_ATTACK_MODEL is set
        # (the engine reads STRIX_LLM from its env / config).
        if self.cfg.attack_model:
            env["STRIX_LLM"] = self.cfg.attack_model
        try:
            # Stream the engine's native TUI to the user when attached to a terminal;
            # SEAL reads findings from files regardless.
            if sys.stdout.isatty():
                proc = subprocess.run(cmd, env=env, timeout=self.cfg.round_timeout_s or None)
            else:
                proc = subprocess.run(cmd, env=env, capture_output=True, text=True,
                                      timeout=self.cfg.round_timeout_s or None)
        except FileNotFoundError:
            return f"scan engine not found at {self.bin} (set SEAL_ENGINE_BIN)"
        except subprocess.TimeoutExpired:
            return f"scan engine timed out after {self.cfg.round_timeout_s}s"
        return "" if proc.returncode in (0, 1, 2) else f"scan engine exit {proc.returncode}"

    def _run_dirs(self) -> set[str]:
        try:
            return {p.name for p in self.runs_dir.iterdir() if p.is_dir()}
        except OSError:
            return set()

    def _new_run_dir(self, before: set[str]) -> Path | None:
        after = self._run_dirs()
        new = sorted(after - before)
        if new:
            return self.runs_dir / new[-1]
        # fallback: newest dir overall
        try:
            dirs = [p for p in self.runs_dir.iterdir() if p.is_dir()]
            return max(dirs, key=lambda p: p.stat().st_mtime) if dirs else None
        except OSError:
            return None

    # ---- parse engine findings --------------------------------------------
    def _parse_run(self, run_dir: Path, strategy: Strategy | None) -> list[Finding]:
        vdir = run_dir / "vulnerabilities"
        out: list[Finding] = []
        try:
            files = sorted(vdir.glob("vuln-*.md"))
        except OSError:
            files = []
        for f in files:
            try:
                out.append(self._parse_vuln(f.read_text(encoding="utf-8"), strategy))
            except OSError:
                continue
        return out

    def _parse_vuln(self, text: str, strategy: Strategy | None) -> Finding:
        title_m = re.search(r"^#\s+(.+)", text, re.M)
        title = title_m.group(1).strip() if title_m else "finding"
        endpoint = _field(text, "Endpoint") or _field(text, "URL")
        method = _field(text, "Method")
        sev = _field(text, "Severity")
        desc_m = re.search(r"##\s*Description\s*\n(.+?)(?:\n##|\Z)", text, re.S)
        evidence = " ".join((desc_m.group(1) if desc_m else "").split())[:400]
        poc_m = re.search(r"##\s*Proof of Concept\s*\n(.+?)(?:\n##|\Z)", text, re.S)
        poc = (poc_m.group(1).strip() if poc_m else "")[:1200]
        surface = f"{method} {endpoint}".strip() if method else endpoint
        return Finding(
            vuln_class=_infer_class(title, text),
            surface=surface or endpoint,
            severity=Severity.parse(sev or "info"),
            title=title,
            evidence=evidence,
            poc=poc or "engine strategy",
            round_index=strategy.round_index if strategy else 0,
            strategy_id=strategy.id if strategy else "",
        )

# ---- helpers --------------------------------------------------------------
def _abs_url(target: str, surface: str) -> str:
    path = surface.split(" ", 1)[-1] if " " in surface else surface
    path = path.strip()
    if path.startswith("http"):
        return path
    base = target.rstrip("/")
    # strip a template placeholder so the URL is fetchable
    path = re.sub(r"\{[^}]+\}", "1", path)
    return base + (path if path.startswith("/") else "/" + path)


def _http_head(url: str, timeout: float = 8.0) -> tuple[str, int, str]:
    try:
        req = urllib.request.Request(url, method="GET",
                                    headers={"User-Agent": "seal-verifier"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.headers.get("Content-Type", "").lower(), r.status, ""
    except urllib.error.HTTPError as e:
        return "", e.code, ""
    except Exception as e:  # noqa: BLE001
        return "", 0, type(e).__name__
