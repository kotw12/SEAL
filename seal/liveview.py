"""SEAL live view — a TUI-like, real-time render of the autonomous loop.

Shows every stage as it happens — scan -> judge (real vs false-positive, WITH the
judge's reasoning) -> evolve (next technique + what the judge steered it toward) —
so an autonomous run reads like an interactive session instead of a silent wait.

It's plain scrolling output (so it coexists cleanly with the scan engine's own
live stream on the same terminal); colour + box-drawing degrade to plain ASCII
when stderr is not a TTY or NO_COLOR is set.
"""
from __future__ import annotations

import os
import sys

_W = 62  # rule width


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR", "") != "":
        return False
    try:
        return bool(stream.isatty())
    except Exception:  # noqa: BLE001
        return False


class LiveView:
    """Callable progress sink: pass as `on_progress` to SealOrchestrator."""

    def __init__(self, stream=None):
        self.out = stream or sys.stderr
        self.color = _use_color(self.out)

    # ---- low-level ----
    def _c(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.color else s

    def _p(self, s: str = "") -> None:
        print(s, file=self.out, flush=True)

    def _rule(self, title: str = "", *, color: str | None = None) -> None:
        ch = "━"  # heavy horizontal
        if title:
            t = f" {title} "
            bar = ch * 3 + t + ch * max(3, _W - 3 - len(t))
        else:
            bar = ch * _W
        self._p(self._c(color, bar) if color else bar)

    def _row(self, label: str, value: str, note: str = "") -> None:
        line = f"   {self._c('2', label.ljust(8))} {value}"
        if note:
            line += self._c("2", f"   ({note})")
        self._p(line)

    # ---- dispatch ----
    def __call__(self, event: str, payload: dict) -> None:
        m = getattr(self, f"_on_{event}", None)
        if m:
            m(payload)

    # ---- events ----
    def _on_engagement_start(self, p: dict) -> None:
        cfg = p.get("config", {}) or {}
        self._p()
        self._rule("\U0001f9ad  SEAL · autonomous red-team loop", color="1;36")
        self._row("target", str(cfg.get("target", p.get("target", ""))))
        self._row("attack", str(cfg.get("attack", "")), "scan engine")
        self._row("judge", str(cfg.get("judge", "")), "independent verifier")
        self._row("evolve", str(cfg.get("orchestrator", "")))
        self._row("loop", "find → judge → evolve", f"max {cfg.get('max_rounds', '?')} rounds")
        self._rule()

    def _on_round_start(self, p: dict) -> None:
        self._p()
        head = (f"   {self._c('1;36', '▸ round ' + str(p['round']))}"
                f"  {self._c('1', 'technique=' + str(p.get('technique', '')))}")
        if p.get("focus"):
            head += self._c("2", f"  focus={p['focus']}")
        self._p(head)
        if p.get("steer"):
            self._p("   " + self._c("2", f"↳ steered by judge: {p['steer']}"))

    def _on_round_error(self, p: dict) -> None:
        self._p("   " + self._c("1;31", "! ") + self._c("33", str(p.get("error", ""))))

    def _on_judge_start(self, p: dict) -> None:
        n = int(p.get("count", 0))
        if n:
            self._p("   " + self._c("35", f"⚖ judging {n} candidate finding"
                                          + ("s" if n != 1 else "") + " …"))
        else:
            self._p("   " + self._c("2", "⚖ no candidate findings this round"))

    def _on_judge_finding(self, p: dict) -> None:
        real = bool(p.get("real"))
        tag = self._c("1;32", "✔ REAL") if real else self._c("1;31", "✘ FP  ")
        title = str(p.get("title", ""))[:34].ljust(34)
        notes = str(p.get("notes", ""))[:58]
        self._p(f"      {tag}  {title} {self._c('2', notes)}")
        hint = p.get("hint")
        if hint and not real:
            self._p("              " + self._c("2", f"↳ evolve hint: {str(hint)[:66]}"))

    def _on_round_verified(self, p: dict) -> None:
        fp = int(round(float(p.get("fp_rate", 0)) * 100))
        self._p(f"   {self._c('2', '└')} round {p['round']} → "
                f"{self._c('1;32', str(p['verified']) + ' verified')} · "
                f"{p['refuted']} refuted ({self._c('2', 'FP ' + str(fp) + '%')}) · "
                f"coverage {p['coverage']} · +{p['new_elites']} new")

    def _on_engagement_end(self, p: dict) -> None:
        self._p()
        self._rule("■ SEAL done", color="1;36")
        self._row("stop", str(p.get("stop_reason", "")))
        self._row("result", f"{p.get('verified', 0)} verified over {p.get('rounds', 0)} rounds")
        self._rule()
        self._p()
