"""Evolution loop — propose the next attack strategy when the goal is unmet.

Instead of giving up after a round, SEAL *evolves*: it selects a mutation
(a fresh technique family, or an intensification of a productive one aimed at
an uncovered MAP-Elites cell) and emits the next `Strategy`. Diversity comes
from the technique ladder + archive coverage; reward comes from which
techniques produced VERIFIED findings.

The `Mutator` is pluggable: `HeuristicMutator` is deterministic (resume-safe,
offline-testable). An LLM-backed mutator (OpenRouter) can replace it wholesale.
"""
from __future__ import annotations

import abc

from ..models import Strategy
from .archive import EliteArchive

# Escalation ladder of technique families (mutation dimension). Ordered from
# cheap/broad to targeted/expensive.
TECHNIQUE_LADDER: list[tuple[str, str]] = [
    ("baseline", "broad reconnaissance + common injection/enumeration on every discovered parameter"),
    ("encoding-mutation", "mutate payload encodings (URL/unicode/double-encode/case) to slip input filters"),
    ("auth-pivot", "probe authorization boundaries: IDOR, horizontal/vertical privilege, session reuse"),
    ("waf-bypass", "apply WAF-evasion transforms (comment splitting, inline variants, chunked payloads)"),
    ("logic-abuse", "attack business logic: state skips, replay, negative/overflow values, race windows"),
    ("chaining", "chain confirmed primitives across surfaces into a higher-impact exploit path"),
]
_TECH_HINT = dict(TECHNIQUE_LADDER)


class Mutator(abc.ABC):
    @abc.abstractmethod
    def propose(self, target: str, objective: str, archive: EliteArchive,
                round_index: int, history: list[Strategy],
                hints: list[str] | None = None) -> Strategy | None:
        """Return the next Strategy, or None if the search space is exhausted.

        `hints` are the independent judge's "investigate instead" suggestions for
        findings it refuted — the loop uses them to change direction, not just
        walk the ladder.
        """


class HeuristicMutator(Mutator):
    """Deterministic ladder-walk with archive-aware intensification, steered by
    the judge's redirection hints when present."""

    def __init__(self, ladder: list[tuple[str, str]] | None = None):
        self.ladder = ladder or TECHNIQUE_LADDER

    def propose(self, target: str, objective: str, archive: EliteArchive,
                round_index: int, history: list[Strategy],
                hints: list[str] | None = None) -> Strategy | None:
        parent = history[-1].id if history else ""
        hints = hints or []

        # 1) Walk to the first technique we have not tried yet (exploration).
        for tech, hint in self.ladder:
            if tech not in archive.tried_techniques:
                return self._make(tech, hint, target, objective, archive,
                                  round_index, parent, focus="", hints=hints)

        # 2) Everything tried: intensify a *productive* technique against a
        #    still-uncovered vuln class (exploitation of what works).
        productive = [t for t, _ in self.ladder if t in archive.productive_techniques]
        if productive:
            covered = archive.covered_classes
            # Re-run the most recent productive technique with a fresh focus.
            tech = productive[-1]
            focus = _pick_uncovered_focus(objective, covered)
            if focus:
                strat = self._make(tech, _TECH_HINT.get(tech, ""), target, objective,
                                   archive, round_index, parent, focus=focus, hints=hints)
                # Avoid proposing an identical (technique, focus) we already ran.
                if not _already_ran(history, strat):
                    return strat

        # 3) Nothing new to try.
        return None

    def _make(self, tech: str, hint: str, target: str, objective: str,
              archive: EliteArchive, round_index: int, parent: str, focus: str,
              hints: list[str] | None = None) -> Strategy:
        covered = ", ".join(sorted(archive.covered_classes)) or "none yet"
        focus_line = f" Concentrate specifically on {focus} vulnerabilities." if focus else ""
        review_line = ""
        if hints:
            joined = "; ".join(hints[-4:])
            review_line = ("\nIndependent reviewer feedback — prior findings were refuted as "
                           f"false positives; investigate these directions instead: {joined}.")
        instruction = (
            f"Objective: {objective}\n"
            f"Target: {target}\n"
            f"This round's technique — {tech}: {hint}.{focus_line}{review_line}\n"
            f"Already-verified classes (do not re-report, build beyond them): {covered}.\n"
            f"Report each candidate finding with a concrete, reproducible PoC and an "
            f"observable evidence marker so it can be independently verified."
        )
        return Strategy(instruction=instruction, technique=tech, focus_class=focus,
                        round_index=round_index, parent_id=parent)


# Common web vuln classes an objective may care about, used to pick a fresh focus.
_DEFAULT_CLASSES = ["sqli", "xss", "idor", "ssrf", "rce", "auth", "csrf", "xxe", "lfi", "ssti"]


def _pick_uncovered_focus(objective: str, covered: set[str]) -> str:
    obj = objective.lower()
    # Prefer classes explicitly named in the objective, else the default list.
    named = [c for c in _DEFAULT_CLASSES if c in obj]
    pool = named or _DEFAULT_CLASSES
    for c in pool:
        if c not in covered:
            return c
    return ""


def _already_ran(history: list[Strategy], strat: Strategy) -> bool:
    return any(h.technique == strat.technique and h.focus_class == strat.focus_class
               for h in history)


class LLMMutator(Mutator):
    """An LLM orchestrator proposes the next attack strategy from the archive,
    history, and the judge's redirect hints. Falls back to the heuristic mutator
    if the LLM is unavailable, so the loop never stalls."""

    _SYSTEM = (
        "You are the orchestrator of an autonomous web red-team loop. Given the "
        "objective, target, techniques already tried, vuln classes already "
        "VERIFIED, and the independent reviewer's redirect hints (findings it "
        "refuted as false positives), propose the NEXT attack strategy. Prefer "
        "unexplored surfaces/classes and the reviewer's directions over repeating "
        "what failed. Reply with STRICT JSON only."
    )

    def __init__(self, model: str, *, url: str | None = None, api_key: str | None = None,
                 timeout: int = 45, fallback: "Mutator | None" = None):
        self.model = model
        self.url = url
        self.api_key = api_key
        self.timeout = timeout
        self.fallback = fallback or HeuristicMutator()

    def propose(self, target, objective, archive, round_index, history, hints=None):
        from ..llm import chat_json  # noqa: PLC0415
        hints = hints or []
        user = (
            f"Objective: {objective}\nTarget: {target}\n"
            f"Techniques already tried: {sorted(archive.tried_techniques) or 'none'}\n"
            f"Vuln classes already verified: {sorted(archive.covered_classes) or 'none'}\n"
            f"Reviewer redirect hints: {hints or 'none'}\n\n"
            'Reply with STRICT JSON: {"instruction": "<what the scanner should do this round>", '
            '"technique": "<short technique family>", "focus_class": "<vuln class or empty>", '
            '"done": true|false}  (done=true only if nothing new is worth trying)'
        )
        try:
            data = chat_json(model=self.model, system=self._SYSTEM, user=user,
                             url=self.url, api_key=self.api_key, timeout=self.timeout)
        except Exception:  # noqa: BLE001 — never stall the loop; fall back
            return self.fallback.propose(target, objective, archive, round_index, history, hints)
        if data.get("done"):
            return None
        instruction = str(data.get("instruction", "")).strip()
        if not instruction:
            return self.fallback.propose(target, objective, archive, round_index, history, hints)
        return Strategy(
            instruction=instruction,
            technique=(str(data.get("technique", "llm")).strip()[:40] or "llm"),
            focus_class=str(data.get("focus_class", "")).strip()[:30],
            round_index=round_index,
            parent_id=history[-1].id if history else "")
