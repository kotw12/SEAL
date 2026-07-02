"""Persisted SEAL settings — an OpenRouter key + per-role models saved to
``~/.seal/config.env`` by ``seal model`` and loaded on startup.

Real environment variables always win; the saved file only fills gaps.
"""
from __future__ import annotations

import os
from pathlib import Path

CONFIG_PATH = Path(os.environ.get("SEAL_CONFIG",
                                  os.path.expanduser("~/.seal/config.env")))

# keys managed by `seal model`
KEYS = ("OPENROUTER_API_KEY", "SEAL_ATTACK_MODEL", "SEAL_JUDGE_MODEL",
        "SEAL_ORCHESTRATOR_MODEL", "SEAL_JUDGE_URL")


def current() -> dict:
    out: dict[str, str] = {}
    try:
        for line in CONFIG_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def load_into_env() -> None:
    """Set saved values as defaults (never override a real env var)."""
    for k, v in current().items():
        if v and not os.environ.get(k):
            os.environ[k] = v


def save(values: dict) -> Path:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing = current()
    existing.update({k: v for k, v in values.items() if v is not None})
    lines = ["# SEAL settings — written by `seal model`. Do not commit.\n"]
    for k in KEYS:
        if existing.get(k):
            lines.append(f"{k}={existing[k]}\n")
    CONFIG_PATH.write_text("".join(lines), encoding="utf-8")
    try:
        CONFIG_PATH.chmod(0o600)   # contains the API key
    except OSError:
        pass
    return CONFIG_PATH
