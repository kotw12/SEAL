#!/usr/bin/env bash
# SEAL installer — sets up a venv, installs SEAL, and checks the engine.
#
#   ./install.sh              # install SEAL core (loop + judge + demo)
#   ./install.sh --with-strix # also `pip install strix-agent` (the engine)
#
set -euo pipefail
cd "$(dirname "$0")"

WITH_STRIX=0
[ "${1:-}" = "--with-strix" ] && WITH_STRIX=1

PY="${PYTHON:-python3}"
echo "==> Creating virtualenv (.venv) with $PY"
"$PY" -m venv .venv 2>/dev/null || python3 -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --quiet --upgrade pip

echo "==> Installing SEAL"
if [ "$WITH_STRIX" = "1" ]; then
  pip install --quiet ".[strix]"
else
  pip install --quiet .
fi
echo "    installed: $(seal --version)"

echo
echo "==> Engine / environment check"
have() { command -v "$1" >/dev/null 2>&1; }
if have strix; then echo "  [ok] strix on PATH: $(command -v strix)"
elif [ -x "$HOME/.strix/bin/strix" ]; then echo "  [ok] strix binary: $HOME/.strix/bin/strix"
else echo "  [!!] strix not found — run ./install.sh --with-strix, or install the strix binary,"
     echo "       or set SEAL_STRIX_BIN=/path/to/strix"; fi
have docker && echo "  [ok] docker: $(command -v docker)" || echo "  [!!] docker not found — strix needs Docker running"
[ -n "${OPENROUTER_API_KEY:-}" ] && echo "  [ok] OPENROUTER_API_KEY set (LLM judge)" \
  || echo "  [!!] OPENROUTER_API_KEY not set — export it for the LLM judge"

cat <<'EOF'

==> Next steps
  source .venv/bin/activate
  export OPENROUTER_API_KEY=sk-or-...
  seal doctor                                  # preflight
  seal demo                                    # offline sanity (no engine/network)
  seal scan --target https://AUTHORIZED --max-rounds 3
EOF
