"""SEAL configuration.

Stdlib-only (no pydantic) so the core stays import-light. Values come from
constructor args or environment (SEAL_* / OPENROUTER_*), letting the CLI
configure a run without code changes.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name, "").strip().lower()
    if not v:
        return default
    return v not in ("0", "false", "no", "off")


@dataclass
class SealConfig:
    # ---- engagement ----
    target: str = ""
    objective: str = ("Find and prove high-impact web vulnerabilities "
                      "(injection, auth/IDOR, SSRF, RCE) on the target.")
    workdir: str = field(default_factory=lambda: os.environ.get(
        "SEAL_WORKDIR", os.path.expanduser("~/.seal/engagements")))

    # ---- loop control ----
    max_rounds: int = field(default_factory=lambda: _env_int("SEAL_MAX_ROUNDS", 6))
    max_dry_rounds: int = field(default_factory=lambda: _env_int("SEAL_MAX_DRY_ROUNDS", 2))
    coverage_goal: int = field(default_factory=lambda: _env_int("SEAL_COVERAGE_GOAL", 0))  # 0 = off
    budget_usd: float = field(default_factory=lambda: _env_float("SEAL_BUDGET_USD", 0.0))  # 0 = unlimited

    # ---- per-role models ----
    # attack       = the scan engine's model (exported to it as STRIX_LLM);
    #                "" = leave the engine's own configured model.
    # judge        = the independent verification model (a DIFFERENT model is best).
    # orchestrator = optional LLM that proposes the next evolved strategy;
    #                "" = the deterministic heuristic mutator (no model).
    attack_model: str = field(default_factory=lambda: os.environ.get("SEAL_ATTACK_MODEL", ""))
    use_llm_judge: bool = field(default_factory=lambda: _env_bool("SEAL_USE_LLM_JUDGE", True))
    judge_model: str = field(default_factory=lambda: os.environ.get(
        "SEAL_JUDGE_MODEL", "openrouter/anthropic/claude-sonnet-4-6"))
    orchestrator_model: str = field(default_factory=lambda: os.environ.get(
        "SEAL_ORCHESTRATOR_MODEL", ""))

    # ---- LLM endpoint (shared by judge + orchestrator) ----
    llm_url: str = field(default_factory=lambda: os.environ.get(
        "SEAL_JUDGE_URL", "http://localhost:4000/v1"))

    # ---- scan engine ----
    runner: str = field(default_factory=lambda: os.environ.get("SEAL_RUNNER", "engine"))
    round_timeout_s: int = field(default_factory=lambda: _env_int("SEAL_ROUND_TIMEOUT_S", 1800))

    def summary(self) -> dict:
        return {
            "target": self.target,
            "runner": self.runner,
            "attack": self.attack_model or "(engine default)",
            "judge": self.judge_model if self.use_llm_judge else "off",
            "orchestrator": self.orchestrator_model or "heuristic",
            "max_rounds": self.max_rounds,
            "max_dry_rounds": self.max_dry_rounds,
            "coverage_goal": self.coverage_goal,
            "budget_usd": self.budget_usd,
        }
