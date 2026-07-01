"""Engagement runners for SEAL.

A runner is the thing that actually *executes* one attack round against a
target and (independently) *re-tests* a candidate finding. SEAL's loops are
written against this interface, so the exact same verify/evolve machinery
runs on top of either:

  * ScanRunner  — SEAL's scan engine: runs the engine, parses findings (scanner.py).
  * MockRunner   — deterministic, no network; backs the offline tests and `seal demo`.
"""
from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field

from .models import Finding, RoundResult, Severity, Strategy


class EngagementRunner(abc.ABC):
    """Executes attack rounds and verifies findings against a target."""

    name: str = "runner"

    @abc.abstractmethod
    def run_round(self, strategy: Strategy, target: str, workdir: str) -> RoundResult:
        """Run one attack round; return candidate findings (status=CANDIDATE)."""

    @abc.abstractmethod
    def verify_finding(self, finding: Finding, target: str, workdir: str) -> tuple[bool, str]:
        """Independently re-test a finding. Return (reproduced, notes)."""

    # Optional hook: a runner may expose an estimated per-round cost (USD/tokens)
    def last_round_cost(self) -> float:  # pragma: no cover - default
        return 0.0


# --------------------------------------------------------------------------
# Mock target + runner: a deterministic simulated web app with a known set of
# ground-truth vulnerabilities, each revealed only by a specific technique.
# This lets the verify+evolve loops be tested end-to-end with no stack.
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class GroundTruthVuln:
    vuln_class: str
    surface: str
    technique: str                 # the technique family that reveals it
    severity: Severity
    marker: str                    # evidence marker a genuine PoC reproduces


@dataclass
class TargetSpec:
    """Ground truth for a simulated target."""
    truths: list[GroundTruthVuln] = field(default_factory=list)
    # false-positive templates a naive round may over-report (never reproduce)
    fp_templates: list[tuple[str, str]] = field(default_factory=list)  # (vuln_class, surface)

    @classmethod
    def demo(cls) -> "TargetSpec":
        return cls(
            truths=[
                GroundTruthVuln("sqli", "/login?user=", "baseline", Severity.CRITICAL, "SQL-ERR-1930"),
                GroundTruthVuln("xss", "/search?q=", "encoding-mutation", Severity.MEDIUM, "XSS-REFLECT-7"),
                GroundTruthVuln("idor", "/api/orders?id=", "auth-pivot", Severity.HIGH, "IDOR-CROSS-42"),
                GroundTruthVuln("ssrf", "/fetch?url=", "encoding-mutation", Severity.HIGH, "SSRF-OOB-88"),
                GroundTruthVuln("sqli", "/report?col=", "waf-bypass", Severity.HIGH, "SQL-BLIND-551"),
            ],
            fp_templates=[
                ("xss", "/home?ref="),        # naive scanners flag this; not real
                ("open-redirect", "/go?to="),
            ],
        )


class MockRunner(EngagementRunner):
    """Deterministic runner over a TargetSpec. No randomness (resume-safe)."""

    name = "mock"

    def __init__(self, spec: TargetSpec | None = None, fp_on_baseline: bool = True):
        self.spec = spec or TargetSpec.demo()
        self.fp_on_baseline = fp_on_baseline

    def run_round(self, strategy: Strategy, target: str, workdir: str) -> RoundResult:
        started = time.time()
        found: list[Finding] = []
        tech = strategy.technique
        focus = (strategy.focus_class or "").lower()

        for gt in self.spec.truths:
            if gt.technique != tech:
                continue
            if focus and gt.vuln_class != focus:
                continue
            found.append(Finding(
                vuln_class=gt.vuln_class,
                surface=gt.surface,
                severity=gt.severity,
                title=f"{gt.vuln_class.upper()} at {gt.surface}",
                evidence=f"observed marker {gt.marker}",
                poc=f"[{tech}] payload against {gt.surface}",
                round_index=strategy.round_index,
                strategy_id=strategy.id,
            ))

        # Baseline rounds also over-report noisy FPs (to be killed by verification).
        if tech == "baseline" and self.fp_on_baseline:
            for cls, surface in self.spec.fp_templates:
                found.append(Finding(
                    vuln_class=cls,
                    surface=surface,
                    severity=Severity.LOW,
                    title=f"possible {cls} at {surface}",
                    evidence="heuristic signature match (unconfirmed)",
                    poc=f"[{tech}] speculative probe against {surface}",
                    round_index=strategy.round_index,
                    strategy_id=strategy.id,
                ))

        rr = RoundResult(round_index=strategy.round_index, strategy=strategy, findings=found)
        rr.ended_at = time.time() if False else started  # deterministic; keep started
        return rr

    def verify_finding(self, finding: Finding, target: str, workdir: str) -> tuple[bool, str]:
        # A finding is genuine iff it maps to a ground-truth marker on that surface.
        for gt in self.spec.truths:
            if gt.vuln_class == finding.vuln_class and gt.surface == finding.surface:
                if gt.marker in finding.evidence:
                    return True, f"reproduced independently: {gt.marker}"
                return False, "surface matches but PoC did not reproduce the marker"
        return False, "no reproducible effect on re-test (likely false positive)"


# --------------------------------------------------------------------------
# Runner factory. ScanRunner is the engine; MockRunner backs the offline tests.
# --------------------------------------------------------------------------
def build_runner(config) -> "EngagementRunner":
    if (config.runner or "engine").lower() == "mock":
        return MockRunner()
    from .scanner import ScanRunner
    return ScanRunner(config)
