"""KING REAPER X colour palette and ANSI primitives.

This is the single place that knows about escape codes. Everything else in the
UI layer asks :func:`c` for a coloured string, so ``NO_COLOR``, a redirected
stdout and the ``color`` config setting all switch the whole interface to plain
text at once.

Palette (v2.0.0 command-centre spec):

    pure black background   #080808
    Blood Red               #FF0033
    Neon Red                #FF0000
    Dark Crimson            #8B0000
    White                   #FFFFFF
    Cyber Grey              #808080
    Neon Green (success)    #00FF66
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
UNDERLINE = "\033[4m"

# -- palette --------------------------------------------------------------- #
BLACK = "\033[38;5;232m"      # #080808
BLOOD = "\033[38;5;197m"      # #FF0033
NEON_RED = "\033[38;5;196m"   # #FF0000
CRIMSON = "\033[38;5;88m"     # #8B0000
WHITE = "\033[97m"            # #FFFFFF
GRAPHITE = "\033[38;5;240m"
GREY = "\033[38;5;244m"       # #808080
GOLD = "\033[38;5;178m"
GREEN = "\033[38;5;47m"       # #00FF66
YELLOW = "\033[38;5;214m"
CYAN = "\033[38;5;51m"
MAGENTA = "\033[38;5;201m"

#: severity -> colour, shared by the CLI and the menu renderers
SEVERITY_COLORS = {
    "critical": BLOOD,
    "high": NEON_RED,
    "medium": YELLOW,
    "low": GREY,
    "info": GRAPHITE,
}

_state: dict = {"color": None}


def color_enabled() -> bool:
    """True when ANSI colour should be emitted."""
    if _state["color"] is not None:
        return bool(_state["color"])
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return bool(sys.stdout.isatty())
    except (AttributeError, ValueError):
        return False


def set_color(enabled: bool) -> None:
    """Force colour on or off for the rest of the process."""
    _state["color"] = bool(enabled)


def reset_color_state() -> None:
    """Forget any forced value (used by tests)."""
    _state["color"] = None


def c(text: Any, color: str = "") -> str:
    """Wrap *text* in *color* when colours are enabled."""
    text = str(text)
    if not color or not color_enabled():
        return text
    return f"{color}{text}{RESET}"


_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _visible_len(value: str) -> int:
    """Length without ANSI escapes, for column alignment."""
    return len(_ANSI_RE.sub("", value))


def strip_ansi(value: str) -> str:
    return _ANSI_RE.sub("", value)
