"""SEAL — Security Evolution from Automated Loop.

Terminal banner: a seal (물범) rendered from seal/art/seal.txt + an
ANSI-shadow "SEAL" title. Colours degrade gracefully when NO_COLOR is set
or stdout is not a TTY.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "cyan": "\033[36m",
    "bcyan": "\033[96m",
    "white": "\033[97m",
    "grey": "\033[90m",
}

_ART_PATH = Path(__file__).with_name("art") / "seal.txt"


def _supports_colour(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("SEAL_FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def _c(code: str, text: str, enabled: bool) -> str:
    return f"{_ANSI[code]}{text}{_ANSI['reset']}" if enabled else text


def _load_seal() -> str:
    try:
        return _ART_PATH.read_text(encoding="utf-8").rstrip("\n")
    except OSError:
        return "( seal art missing )"


# "SEAL" in ANSI-shadow block letters.
_TITLE = r"""
 ███████╗███████╗ █████╗ ██╗
 ██╔════╝██╔════╝██╔══██╗██║
 ███████╗█████╗  ███████║██║
 ╚════██║██╔══╝  ██╔══██║██║
 ███████║███████╗██║  ██║███████╗
 ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝
"""

_SUBTITLE = "Security Evolution from Automated Loop"
_TAGLINE = "verify · evolve · repeat  —  autonomous web red-team"


def render(version: str = "0.1.0", stream=None) -> str:
    """Return the full banner as a string (also usable for tests)."""
    stream = stream or sys.stdout
    on = _supports_colour(stream)

    seal = _c("bcyan", _load_seal(), on)
    title = _c("bold", _c("cyan", _TITLE.strip("\n"), on), on)
    sub = _c("white", _SUBTITLE, on)
    tag = _c("dim", _TAGLINE, on)
    ver = _c("dim", f"v{version}", on)

    return (
        f"{seal}\n\n"
        f"{title}\n"
        f"   {sub}\n"
        f"   {tag}   {ver}\n"
    )


def print_banner(version: str = "0.1.0", stream=None) -> None:
    stream = stream or sys.stdout
    stream.write(render(version=version, stream=stream))
    stream.write("\n")
    stream.flush()


if __name__ == "__main__":
    os.environ.setdefault("SEAL_FORCE_COLOR", "1")
    print_banner()
