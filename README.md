# SEAL — Security Evolution from Automated Loop

> Autonomous web red-team that **finds fast, verifies hard, and evolves** — an
> independent LLM judge kills the scanner's false positives and steers each round.

SEAL is an Apache-2.0 orchestration layer that turns a raw autonomous scanner
into a disciplined red-team loop:

```
scan (find)  →  LLM judge (verify)  →  evolve (redirect)  →  repeat  →  report
```

- **Find — the scan engine.** SEAL drives an autonomous scanning engine that
  discovers endpoints, fingerprints the stack, and runs class-by-class exploit
  attempts. Fast and cheap (a full API scan runs on a budget model for ~$0.002).
- **Verify — an independent LLM judge.** A *different* model than the scanner
  critically re-reviews every candidate finding and rules it **real** or
  **false positive** by reasoning — catching FPs the scanner's own validation
  ships (e.g. flagging "Stored XSS" when the API merely returns raw input in a
  JSON body, which is not an execution context). Only verified findings reach
  the report. Fail-closed: an unreachable judge never auto-passes a finding.
- **Evolve — judge-steered.** When the judge refutes a finding it also says
  *what to investigate instead*; those hints are injected into the next round's
  instruction, so SEAL changes direction instead of repeating dead ends. A
  MAP-Elites-lite archive keeps the best verified finding per (class × surface).

LLM backend is **OpenRouter**. Targets are **arbitrary authorized URLs**.

```
 ███████╗███████╗ █████╗ ██╗
 ██╔════╝██╔════╝██╔══██╗██║
 ███████╗█████╗  ███████║██║
 ╚════██║██╔══╝  ██╔══██║██║
 ███████║███████╗██║  ██║███████╗
 ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝
```

## Why the judge matters (real example)

Against a Spring Boot API the scan engine reported 8 findings. SEAL's independent
judge (a different model reviewing the scanner's output) ruled:

| verdict | finding | judge reasoning |
|---|---|---|
| ✅ real | IDOR (bookings, chat) | PoC shows concrete cross-user access |
| ✅ real | SSRF (portfolio viewer) | server fetched an external URL, leaked its IP |
| ✅ real | insecure refresh-token, user enumeration | reproducible steps |
| ❌ **FP** | **Stored XSS** | "raw input in a JSON body is not an execution context" |
| ❌ FP | weak password policy | "a policy concern, not an exploitable bug" |

**5 verified, 3 false positives removed** — and the judge handed the loop a new
direction for each FP (e.g. *"check if the frontend renders these fields via
`dangerouslySetInnerHTML`"*).

## Install

```bash
./install.sh                 # venv + SEAL; checks the engine, Docker, and key
# or manually:
pip install .                # stdlib-only core: loop + judge + demo (zero third-party deps)
```
SEAL drives an external scan engine (a separate open-source tool, credited in
[`NOTICE`](./NOTICE)) which you install alongside; it runs its sandbox in Docker.

## Use

```bash
seal banner                 # show the banner
seal demo                   # offline mock engagement — no engine, no network
seal model                  # configure the OpenRouter key + per-role models (saved)
seal doctor                 # preflight: scan engine, judge endpoint, keys, docker
seal scan --target https://TARGET.example --max-rounds 3
```

`seal scan` runs the full autonomous loop against an **authorized** target:
the engine attacks → the LLM judge verifies each finding → refuted findings steer
the next evolved round → repeat until the goal, a dry streak, or the round cap.

`seal model` saves the OpenRouter key + per-role models to `~/.seal/config.env`
(chmod 600); SEAL loads them on startup (real env vars always win).

## Configuration (`.env` / env)

| var | meaning | default |
|---|---|---|
| `SEAL_RUNNER` | `engine` (default) · `mock` (offline tests) | `engine` |
| `SEAL_ENGINE_BIN` | path to the scan-engine command | auto (PATH / standalone) |
| `SEAL_SCAN_MODE` | `quick` · `standard` · `deep` | `standard` |
| `SEAL_ATTACK_MODEL` / `--attack-model` | scan-engine model (empty = engine's own) | — |
| `SEAL_JUDGE_MODEL` / `--judge-model` | judge model (use a *different* one than the scanner) | `openrouter/anthropic/claude-sonnet-4-6` |
| `SEAL_ORCHESTRATOR_MODEL` / `--orchestrator-model` | LLM that drives evolution (empty = heuristic) | — |
| `SEAL_USE_LLM_JUDGE` | independent LLM judge verification | `1` |
| `SEAL_JUDGE_URL` | OpenAI-compatible endpoint (OpenRouter / LiteLLM proxy) | `http://localhost:4000/v1` |
| `OPENROUTER_API_KEY` | key for the LLM roles (or `SEAL_JUDGE_API_KEY`) | — |
| `--max-rounds` / `SEAL_MAX_ROUNDS` | round cap | 6 |
| `--max-dry-rounds` | stop after N rounds with no new verified finding | 2 |

## Architecture

```
seal/
  scanner.py           ScanRunner — drives the scan engine, parses findings   (default)
  loops/
    verification.py    LLMVerifier — independent judge (real vs FP + redirect)
    evolution.py       Mutator — technique ladder + judge-hint steering
    archive.py         MAP-Elites-lite elite archive
  orchestrator.py      SealOrchestrator — find → verify → evolve → stop rules
  engine.py            EngagementRunner interface + MockRunner (offline) + build_runner
  models.py            Finding / Strategy / RoundResult / EngagementResult
  report.py            text / json / SARIF report
  cli.py               `seal` CLI (banner / demo / doctor / scan)
```

The `EngagementRunner` interface keeps the engine swappable behind the loop.

## Tests

```bash
python -m pytest -q      # loop mechanics, judge fail-closed, finding parsing
```

## License & authorized use

Apache-2.0 ([`LICENSE`](./LICENSE)). SEAL drives a third-party open-source scan
engine as an external tool (not bundled) — attribution and license details in
[`NOTICE`](./NOTICE). **Run only against systems you are explicitly authorized to test.**
