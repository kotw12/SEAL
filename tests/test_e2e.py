"""Offline end-to-end test of the SEAL verify+evolve loop (no stack, no network).

Runnable as `python -m pytest` or directly as `python tests/test_e2e.py`.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from seal.config import SealConfig
from seal.engine import MockRunner, TargetSpec
from seal.models import FindingStatus, Severity
from seal.orchestrator import SealOrchestrator


def _run(**cfg_kw):
    spec = TargetSpec.demo()
    cfg = SealConfig(target="http://demo.local", runner="mock", max_rounds=10, **cfg_kw)
    orch = SealOrchestrator(cfg, MockRunner(spec))
    return orch, orch.run(), spec


def test_all_true_vulns_verified_via_evolution():
    orch, result, spec = _run()
    verified_cells = {(f.vuln_class, f.surface) for f in result.verified}
    truth_cells = {(g.vuln_class, g.surface) for g in spec.truths}
    missing = truth_cells - verified_cells
    assert not missing, f"evolution failed to reach: {missing}"
    # every reported finding is genuinely VERIFIED
    assert all(f.status == FindingStatus.VERIFIED for f in result.verified)


def test_false_positives_are_refuted_not_reported():
    orch, result, spec = _run()
    fp_surfaces = {s for _, s in spec.fp_templates}
    reported_surfaces = {f.surface for f in result.verified}
    assert not (fp_surfaces & reported_surfaces), "a false positive leaked into the report"
    assert any(f.surface in fp_surfaces for f in result.refuted), "FP was never even tested"


def test_evolution_needs_multiple_techniques():
    # The demo target hides vulns behind 4 distinct techniques; a single
    # baseline round cannot find them all — evolution must kick in.
    orch, result, spec = _run()
    techniques_used = {r.strategy.technique for r in result.rounds}
    assert len(techniques_used) >= 3, f"only used {techniques_used}; evolution not exercising the ladder"


def test_dry_streak_stops_the_loop():
    # With nothing to find, the loop must stop on the dry streak, not spin to max.
    orch, result, _ = _run(max_dry_rounds=2)
    empty = SealConfig(target="http://empty.local", runner="mock", max_rounds=10, max_dry_rounds=2)
    o2 = SealOrchestrator(empty, MockRunner(TargetSpec(truths=[], fp_templates=[])))
    r2 = o2.run()
    assert "dry streak" in r2.stop_reason
    assert len(r2.rounds) <= 3


def test_coverage_goal_early_stop():
    orch, result, _ = _run(coverage_goal=2)
    assert "coverage goal" in result.stop_reason
    assert len(result.verified) >= 2


def test_fingerprint_no_separator_collision():
    # Review finding #3: '|'-join let distinct findings collide. JSON encoding fixes it.
    from seal.models import Finding
    a = Finding(vuln_class="a|b", surface="c", poc="d")
    b = Finding(vuln_class="a", surface="b|c", poc="d")
    assert a.id != b.id, "distinct findings must not share a fingerprint"


def test_archive_handles_none_poc():
    # Review finding #1: _tech_of crashed on poc=None.
    from seal.loops.archive import EliteArchive
    from seal.models import Finding, FindingStatus
    f = Finding(vuln_class="sqli", surface="/x", poc=None, status=FindingStatus.VERIFIED)
    EliteArchive().observe(f)  # must not raise


def test_scanner_parses_vuln_markdown():
    # ScanRunner turns an engine vuln-*.md into a SEAL Finding with the right class.
    from seal.scanner import ScanRunner
    from seal.config import SealConfig
    md = ("# Insecure Direct Object Reference (IDOR) in Booking API\n"
          "**ID:** vuln-0001\n**Severity:** MEDIUM\n"
          "**Endpoint:** /api/bookings/{bookingId}\n**Method:** GET\n**CWE:** CWE-639\n"
          "## Description\nUser A reads User B's booking by id.\n"
          "## Proof of Concept\ncurl .../api/bookings/6 -H 'Authorization: Bearer A'\n")
    r = ScanRunner(SealConfig(target="https://x"))
    f = r._parse_vuln(md, None)
    assert f.vuln_class == "idor", f"expected idor, got {f.vuln_class}"
    assert f.severity == Severity.MEDIUM
    assert "/api/bookings/{bookingId}" in f.surface
    assert f.poc  # PoC captured


def test_llm_judge_fails_closed_when_unreachable():
    # The independent judge must NOT auto-pass a finding if it can't be reached.
    from seal.loops.verification import LLMVerifier
    from seal.models import Finding
    v = LLMVerifier(model="x", endpoint="http://127.0.0.1:9/v1", api_key="none", timeout=1)
    f = Finding(vuln_class="xss", surface="/a", poc="p", evidence="e")
    real, notes = v.verify(f, "https://x", "")
    assert real is False and "unavailable" in notes


def test_llm_orchestrator_falls_back_when_unreachable():
    # The LLM orchestrator (SEAL_ORCHESTRATOR_MODEL) must fall back to the
    # heuristic mutator if unreachable — the loop never stalls.
    from seal.loops.evolution import LLMMutator
    from seal.loops.archive import EliteArchive
    m = LLMMutator("x", url="http://127.0.0.1:9/v1", api_key="none", timeout=1)
    s = m.propose("http://x", "find bugs", EliteArchive(), 1, [])
    assert s is not None and s.instruction  # fell back to heuristic


def test_per_role_models_configurable():
    # attack / judge / orchestrator models are independently settable.
    from seal.config import SealConfig
    c = SealConfig(target="https://x", attack_model="or/a", judge_model="or/j",
                   orchestrator_model="or/o")
    assert c.attack_model == "or/a" and c.judge_model == "or/j" and c.orchestrator_model == "or/o"
    assert c.summary()["orchestrator"] == "or/o"


def test_scanner_ignores_previous_target_run_dir():
    # A crashed scan of target A must NOT return a *previous* target B's findings.
    import os, tempfile, pathlib
    from seal.scanner import ScanRunner
    from seal.config import SealConfig
    runs = pathlib.Path(tempfile.mkdtemp())
    (runs / "other-target_old" / "vulnerabilities").mkdir(parents=True)
    (runs / "other-target_old" / "vulnerabilities" / "vuln-0001.md").write_text(
        "# X\n**Severity:** HIGH\n", encoding="utf-8")
    os.environ["SEAL_ENGINE_RUNS"] = str(runs)
    try:
        r = ScanRunner(SealConfig(target="https://frontend.example.com/"))
        before = r._run_dirs()                      # includes other-target_old
        assert r._new_run_dir(before, "https://frontend.example.com/") is None
    finally:
        os.environ.pop("SEAL_ENGINE_RUNS", None)


def test_cli_rejects_invalid_fail_on():
    # Review finding #5: invalid --fail-on silently became INFO (exit 1 on everything).
    from seal.cli import main
    rc = main(["scan", "--target", "http://x", "--fail-on", "GIBBERISH", "--mock"])
    assert rc == 2, f"invalid --fail-on must be rejected with exit 2, got {rc}"


def _main():
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS  {name}")
            passed += 1
    # Also print a human summary of a run.
    orch, result, spec = _run()
    print(f"\n--- demo engagement summary ---")
    print(f"stop_reason : {result.stop_reason}")
    print(f"rounds      : {len(result.rounds)}  techniques={[r.strategy.technique for r in result.rounds]}")
    print(f"verified    : {len(result.verified)} / truths={len(spec.truths)}")
    for f in result.verified:
        print(f"    [{f.severity.name:8}] {f.vuln_class:5} {f.surface:20} ← {f.poc}")
    print(f"refuted(FP) : {len(result.refuted)}")
    print(f"\n{passed} tests passed.")


if __name__ == "__main__":
    _main()
