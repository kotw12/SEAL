"""SEAL command-line interface.

    seal banner                 show the banner
    seal demo                   run the offline mock engagement (no stack/network)
    seal doctor                 preflight: scan engine, judge endpoint, keys, docker
    seal scan --target <URL>    run a real verify+evolve engagement

Uses only the stdlib (argparse) so `seal` stays import-light and starts fast.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__
from .banner import print_banner
from .config import SealConfig
from .models import EngagementResult
from .report import render


# --------------------------------------------------------------------------
def _progress(event: str, payload: dict) -> None:
    if event == "round_start":
        f = f" focus={payload['focus']}" if payload.get("focus") else ""
        print(f"  ▸ round {payload['round']}  technique={payload['technique']}{f}", file=sys.stderr)
    elif event == "round_verified":
        print(f"    verified {payload['verified']}/{payload['candidates']} "
              f"(refuted {payload['refuted']}, FP-rate {payload['fp_rate']}), "
              f"coverage={payload['coverage']}, +{payload['new_elites']} new",
              file=sys.stderr)
    elif event == "round_error":
        print(f"    ! round error: {payload['error']}", file=sys.stderr)
    elif event == "engagement_end":
        print(f"  ■ done: {payload['stop_reason']} "
              f"({payload['verified']} verified over {payload['rounds']} rounds)", file=sys.stderr)


def _run_engagement(cfg: SealConfig, show_banner: bool = True) -> EngagementResult:
    from .orchestrator import SealOrchestrator
    from .engine import build_runner
    if show_banner:
        print_banner(version=__version__)
    runner = build_runner(cfg)
    orch = SealOrchestrator(cfg, runner, on_progress=_progress)
    return orch.run()


def _emit(result: EngagementResult, fmt: str, out: str | None) -> None:
    text = render(result, fmt)
    if out:
        Path(out).expanduser().write_text(text, encoding="utf-8")
        print(f"[seal] {fmt} report written to {out}", file=sys.stderr)
    else:
        print(text)


# --------------------------------------------------------------------------
def cmd_banner(args: argparse.Namespace) -> int:
    print_banner(version=__version__)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    cfg = SealConfig(target="http://demo.local", runner="mock",
                     max_rounds=args.max_rounds, max_dry_rounds=2)
    result = _run_engagement(cfg, show_banner=not args.quiet)
    _emit(result, args.format, args.output)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    from .models import Severity
    if not args.target:
        print("error: --target is required", file=sys.stderr)
        return 2
    if args.fail_on and args.fail_on.strip().upper() not in Severity.__members__:
        valid = ", ".join(Severity.__members__)
        print(f"error: --fail-on must be one of: {valid}", file=sys.stderr)
        return 2
    cfg = SealConfig(
        target=args.target,
        runner="mock" if args.mock else "engine",
        objective=args.objective or SealConfig.objective,
        max_rounds=args.max_rounds,
        max_dry_rounds=args.max_dry_rounds,
        coverage_goal=args.coverage_goal,
        budget_usd=args.budget,
    )
    if args.attack_model:
        cfg.attack_model = args.attack_model
    if args.judge_model or args.model:
        cfg.judge_model = args.judge_model or args.model
    if args.orchestrator_model:
        cfg.orchestrator_model = args.orchestrator_model
    if not args.mock and not _preflight_ok(cfg, strict=not args.no_preflight):
        return 3
    result = _run_engagement(cfg, show_banner=not args.quiet)
    _emit(result, args.format, args.output)
    # exit non-zero if a finding at/above --fail-on was verified
    if args.fail_on:
        from .models import Severity
        thresh = Severity.parse(args.fail_on)
        if any(f.severity >= thresh for f in result.verified):
            return 1
    return 0


def cmd_model(args: argparse.Namespace) -> int:
    """Interactive config: OpenRouter key + per-role models → ~/.seal/config.env."""
    import getpass  # noqa: PLC0415
    from . import settings  # noqa: PLC0415
    cur = settings.current()
    if args.show:
        print("SEAL saved settings (" + str(settings.CONFIG_PATH) + ")")
        for k in settings.KEYS:
            v = cur.get(k, "")
            if k == "OPENROUTER_API_KEY" and v:
                v = "****" + v[-4:]
            print(f"  {k:24} = {v or '(unset)'}")
        return 0
    if not sys.stdin.isatty():
        print("seal model needs a terminal (or use `seal model --show`).", file=sys.stderr)
        return 2
    print_banner(version=__version__)
    print("Configure SEAL — press Enter to keep the current value.\n")

    def ask(label: str, key: str, *, secret: bool = False, default: str = "") -> str:
        c = cur.get(key, "") or default
        shown = ("****" + c[-4:]) if (secret and c) else (c or "(unset)")
        prompt = f"  {label}\n    [{shown}] > "
        try:
            v = getpass.getpass(prompt) if secret else input(prompt)
        except EOFError:
            v = ""
        return v.strip() or c

    vals = {
        "OPENROUTER_API_KEY": ask("OpenRouter API key", "OPENROUTER_API_KEY", secret=True),
        "SEAL_ATTACK_MODEL": ask("attack model — scan engine",
                                 "SEAL_ATTACK_MODEL", default="openrouter/deepseek/deepseek-v4-flash"),
        "SEAL_JUDGE_MODEL": ask("judge model — independent verification",
                                "SEAL_JUDGE_MODEL", default="openrouter/anthropic/claude-sonnet-4-6"),
        "SEAL_ORCHESTRATOR_MODEL": ask("orchestrator model — evolution (blank = heuristic)",
                                       "SEAL_ORCHESTRATOR_MODEL"),
    }
    path = settings.save(vals)
    print(f"\n[seal] saved to {path} (chmod 600). `seal doctor` to verify.")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    print_banner(version=__version__)
    cfg = SealConfig(target=args.target or "http://example.test")
    checks = _doctor_checks(cfg)
    ok = True
    print("SEAL preflight\n" + "-" * 40)
    for name, passed, detail in checks:
        mark = "✓" if passed else "✗"
        print(f"  [{mark}] {name:28} {detail}")
        ok = ok and (passed or name.endswith("(optional)"))
    print("-" * 40)
    print("READY" if ok else "NOT READY — resolve the ✗ items above")
    return 0 if ok else 1


# --------------------------------------------------------------------------
def _doctor_checks(cfg: SealConfig) -> list[tuple[str, bool, str]]:
    checks: list[tuple[str, bool, str]] = []

    # scan engine binary/command + Docker (the engine runs its sandbox in Docker)
    from .scanner import _resolve_engine
    engine = _resolve_engine()
    ok_bin = bool(shutil.which(engine) or (os.path.isfile(engine) and os.access(engine, os.X_OK)))
    checks.append(("scan engine", ok_bin, engine if ok_bin
                   else f"not found ({engine}) — install the scan engine (see NOTICE) or set SEAL_ENGINE_BIN"))
    docker = shutil.which("docker")
    checks.append(("docker (sandbox)", bool(docker), docker or "not found — the scan engine needs Docker"))

    # judge key (OpenRouter, or SEAL_JUDGE_API_KEY / LITELLM_MASTER_KEY)
    if cfg.use_llm_judge:
        has_key = bool(os.environ.get("SEAL_JUDGE_API_KEY") or os.environ.get("OPENROUTER_API_KEY")
                       or os.environ.get("LITELLM_MASTER_KEY"))
        checks.append(("judge API key", has_key,
                       f"set (model {cfg.judge_model})" if has_key
                       else "missing — export OPENROUTER_API_KEY=sk-or-... for the LLM judge"))
        # judge endpoint reachable (optional)
        judge_url = os.environ.get("SEAL_JUDGE_URL", "http://localhost:4000/v1")
        reachable, detail = _http_ok(judge_url.rsplit("/v1", 1)[0])
        checks.append(("judge endpoint (optional)", reachable, f"{judge_url} — {detail}"))
    # per-role models (informational)
    checks.append(("models (info)", True,
                   f"attack={cfg.attack_model or '(engine default)'}  "
                   f"judge={cfg.judge_model if cfg.use_llm_judge else 'off'}  "
                   f"orchestrator={cfg.orchestrator_model or 'heuristic'}"))
    return checks


def _preflight_ok(cfg: SealConfig, strict: bool) -> bool:
    checks = _doctor_checks(cfg)
    hard_fail = [c for c in checks if not c[1] and not c[0].endswith("(optional)")]
    if hard_fail:
        print("[seal] preflight failed:", file=sys.stderr)
        for name, _, detail in hard_fail:
            print(f"        ✗ {name}: {detail}", file=sys.stderr)
        print("        run `seal doctor` for the full report, or add --no-preflight to override.",
              file=sys.stderr)
        return not strict
    return True


def _http_ok(url: str, timeout: float = 2.0) -> tuple[bool, str]:
    if not url:
        return False, "no url configured"
    for path in ("/ok", "/health", "/"):
        try:
            req = urllib.request.Request(url.rstrip("/") + path, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return True, f"reachable (HTTP {r.status})"
        except urllib.error.HTTPError as e:
            return True, f"reachable (HTTP {e.code})"
        except (urllib.error.URLError, OSError):
            continue
    return False, "unreachable (is the stack up?)"


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="seal",
                                description="SEAL — Security Evolution from Automated Loop")
    p.add_argument("--version", action="version", version=f"seal {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("banner", help="print the SEAL banner")
    b.set_defaults(func=cmd_banner)

    d = sub.add_parser("demo", help="run the offline mock engagement (no stack/network)")
    d.add_argument("--max-rounds", type=int, default=6)
    d.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    d.add_argument("--output", "-o", default=None)
    d.add_argument("--quiet", action="store_true")
    d.set_defaults(func=cmd_demo)

    s = sub.add_parser("scan", help="run a real verify+evolve engagement")
    s.add_argument("--target", "-t", required=True, help="target URL (authorized only)")
    s.add_argument("--objective", default="", help="engagement objective")
    # per-role models (all optional; OpenRouter model ids, e.g. openrouter/vendor/name)
    s.add_argument("--attack-model", default="", help="scan-engine model (STRIX_LLM)")
    s.add_argument("--judge-model", default="", help="independent verification model")
    s.add_argument("--orchestrator-model", default="",
                   help="LLM that drives evolution (empty = heuristic)")
    s.add_argument("--model", default="", help="alias for --judge-model")
    s.add_argument("--max-rounds", type=int, default=6)
    s.add_argument("--max-dry-rounds", type=int, default=2)
    s.add_argument("--coverage-goal", type=int, default=0)
    s.add_argument("--budget", type=float, default=0.0, help="USD budget cap (0 = unlimited)")
    s.add_argument("--fail-on", default="", help="min verified severity for non-zero exit")
    s.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    s.add_argument("--output", "-o", default=None)
    s.add_argument("--mock", action="store_true", help="use the mock runner (no stack)")
    s.add_argument("--no-preflight", action="store_true", help="skip the preflight gate")
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(func=cmd_scan)

    mdl = sub.add_parser("model", help="configure OpenRouter key + per-role models")
    mdl.add_argument("--show", action="store_true", help="print saved settings and exit")
    mdl.set_defaults(func=cmd_model)

    doc = sub.add_parser("doctor", help="preflight checks for a real engagement")
    doc.add_argument("--target", default="")
    doc.set_defaults(func=cmd_doctor)
    return p


def main(argv: list[str] | None = None) -> int:
    from . import settings  # noqa: PLC0415
    settings.load_into_env()   # ~/.seal/config.env fills gaps (real env wins)
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n[seal] interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
