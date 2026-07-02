"""SEAL orchestrator — the automated loop that ties everything together.

    round → verify → evolve → (repeat) → report

SEAL is the orchestrator: the scan engine does the
actual attacking inside each round; SEAL wraps it with the verification loop
(an independent LLM judge that kills false positives) and the evolution loop
around it. The engine is never modified.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .config import SealConfig
from .engine import EngagementRunner
from .models import EngagementResult, Strategy
from .loops.archive import EliteArchive
from .loops.evolution import HeuristicMutator, Mutator
from .loops.verification import RunnerVerifier, VerificationLoop, Verifier, LLMVerifier

# progress callback: (event_name, payload) -> None
ProgressFn = Callable[[str, dict], None]


def _noop(_event: str, _payload: dict) -> None:
    pass


@dataclass
class _Stop:
    stop: bool
    reason: str = ""


class SealOrchestrator:
    def __init__(self, config: SealConfig, runner: EngagementRunner, *,
                 mutator: Mutator | None = None, verifier: Verifier | None = None,
                 on_progress: ProgressFn | None = None):
        self.cfg = config
        self.runner = runner
        self.mutator = mutator or self._default_mutator(config)
        self.verifier = verifier or self._default_verifier(config, runner)
        self.on_progress = on_progress or _noop
        # the verification loop streams each judge verdict to the same sink
        self.verification = VerificationLoop(self.verifier, on_event=self.on_progress)
        self._hints: list[str] = []   # judge-suggested directions → steer evolution
        self.archive = EliteArchive()

    @staticmethod
    def _default_mutator(config: SealConfig) -> Mutator:
        # An LLM orchestrator drives evolution when SEAL_ORCHESTRATOR_MODEL is
        # set; otherwise the deterministic technique-ladder mutator.
        if config.orchestrator_model:
            from .loops.evolution import LLMMutator
            return LLMMutator(config.orchestrator_model, url=config.llm_url)
        return HeuristicMutator()

    @staticmethod
    def _default_verifier(config: SealConfig, runner: EngagementRunner) -> Verifier:
        # An independent LLM judge is the default for real scanners — it catches
        # false positives the scanner's own validation ships (e.g. "XSS" that is
        # only JSON reflection). The mock runner has deterministic ground-truth
        # verification, so it uses the runner verifier (keeps offline tests hermetic).
        if getattr(runner, "name", "") == "mock" or not config.use_llm_judge:
            return RunnerVerifier(runner)
        from .loops.verification import LLMVerifier
        return LLMVerifier(model=config.judge_model, endpoint=config.llm_url)

    def run(self) -> EngagementResult:
        cfg = self.cfg
        result = EngagementResult(target=cfg.target)
        history: list[Strategy] = []
        dry_streak = 0
        spent = 0.0

        self.on_progress("engagement_start", {"target": cfg.target, "config": cfg.summary()})

        for round_index in range(cfg.max_rounds):
            # ---- pick this round's strategy (evolution) ----
            if round_index == 0:
                strategy = Strategy(
                    instruction=(f"Objective: {cfg.objective}\nTarget: {cfg.target}\n"
                                 f"Technique — baseline: broad reconnaissance + common "
                                 f"injection/enumeration on every discovered parameter. "
                                 f"Report reproducible PoCs with evidence markers."),
                    technique="baseline", round_index=0)
            else:
                strategy = self.mutator.propose(
                    cfg.target, cfg.objective, self.archive, round_index, history,
                    hints=self._hints)
                if strategy is None:
                    result.stop_reason = "search space exhausted (no new strategy to evolve)"
                    break

            history.append(strategy)
            self.archive.note_attempt(strategy.technique)
            self.on_progress("round_start", {"round": round_index, "technique": strategy.technique,
                                             "focus": strategy.focus_class,
                                             "steer": (self._hints[-1] if self._hints else "")})

            # ---- run the attack round (the scan engine does the work) ----
            round_result = self.runner.run_round(strategy, cfg.target, cfg.workdir)
            result.rounds.append(round_result)
            spent += self.runner.last_round_cost()
            if round_result.error:
                self.on_progress("round_error", {"round": round_index, "error": round_result.error})

            # ---- verification loop (kill false positives) ----
            vreport = self.verification.run(
                round_result.findings, cfg.target, cfg.workdir,
                already_seen=set(self.archive.seen_fingerprints))

            # collect the judge's "investigate instead" hints to steer evolution
            if isinstance(self.verifier, LLMVerifier):
                self._hints = list(dict.fromkeys(self.verifier.directions))[-8:]

            new_elites = 0
            for f in vreport.verified:
                if self.archive.observe(f):
                    new_elites += 1
                result.verified.append(f)
            for f in vreport.refuted:
                self.archive.observe(f)
                result.refuted.append(f)

            self.on_progress("round_verified", {
                "round": round_index,
                "candidates": len(round_result.findings),
                "verified": len(vreport.verified),
                "refuted": len(vreport.refuted),
                "fp_rate": round(vreport.fp_rate, 3),
                "new_elites": new_elites,
                "coverage": self.archive.coverage(),
            })

            # ---- stop rules ----
            dry_streak = dry_streak + 1 if new_elites == 0 else 0
            stop = self._should_stop(round_index, dry_streak, spent)
            if stop.stop:
                result.stop_reason = stop.reason
                break
        else:
            result.stop_reason = result.stop_reason or f"reached max_rounds ({cfg.max_rounds})"

        # final report uses archive elites (best verified per cell), deduped
        result.verified = self.archive.verified
        self.on_progress("engagement_end", {
            "stop_reason": result.stop_reason,
            "verified": len(result.verified),
            "rounds": len(result.rounds),
        })
        return result

    def _should_stop(self, round_index: int, dry_streak: int, spent: float) -> _Stop:
        cfg = self.cfg
        if cfg.coverage_goal and self.archive.coverage() >= cfg.coverage_goal:
            return _Stop(True, f"coverage goal reached ({self.archive.coverage()} ≥ {cfg.coverage_goal})")
        if cfg.max_dry_rounds and dry_streak >= cfg.max_dry_rounds:
            return _Stop(True, f"no new verified findings for {dry_streak} rounds (dry streak)")
        if cfg.budget_usd and spent >= cfg.budget_usd:
            return _Stop(True, f"budget exhausted (${spent:.2f} ≥ ${cfg.budget_usd:.2f})")
        return _Stop(False)
