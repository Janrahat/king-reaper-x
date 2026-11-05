"""Colour handling, banners, tables and progress output.

Colours are plain ANSI and are disabled when ``NO_COLOR`` is set, when stdout is
not a tty, or when the config says so — the dashboard and CI logs must stay
readable.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import Any, Dict, Iterable, List, Optional, Sequence

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

# KING REAPER X palette
BLACK = "\033[38;5;232m"
BLOOD = "\033[38;5;196m"
CRIMSON = "\033[38;5;88m"
WHITE = "\033[97m"
GRAPHITE = "\033[38;5;240m"
GREY = "\033[38;5;245m"
GOLD = "\033[38;5;178m"
GREEN = "\033[38;5;40m"
YELLOW = "\033[38;5;214m"
CYAN = "\033[38;5;51m"
MAGENTA = "\033[38;5;201m"

BANNER = r"""
  ██╗  ██╗██╗███╗   ██╗ ██████╗     ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗     ██╗  ██╗
  ██║ ██╔╝██║████╗  ██║██╔════╝     ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗    ╚██╗██╔╝
  █████╔╝ ██║██╔██╗ ██║██║  ███╗    ██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝     ╚███╔╝
  ██╔═██╗ ██║██║╚██╗██║██║   ██║    ██╔══██╗██╔══╝  ██╔══██║██╔══██╗██╔══╝  ██╔══██╗     ██╔██╗
  ██║  ██╗██║██║ ╚████║╚██████╔╝    ██║  ██║███████╗██║  ██║██║  ██║███████╗██║  ██║    ██╔╝ ██╗
  ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝
"""

TAGLINE = "ULTIMATE CYBER INTELLIGENCE & SECURITY FRAMEWORK"

_state = {"color": None}


def color_enabled() -> bool:
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
    _state["color"] = bool(enabled)


def c(text: Any, color: str = "") -> str:
    """Wrap *text* in *color* when colours are enabled."""
    text = str(text)
    if not color or not color_enabled():
        return text
    return f"{color}{text}{RESET}"


def load_banner() -> str:
    return BANNER


def banner(version: str = "1.0.0", compact: bool = False) -> str:
    """ASCII logo. Falls back to plain text on narrow terminals."""
    width = shutil.get_terminal_size((80, 24)).columns
    lines: List[str] = []
    if not compact and width >= 100:
        lines.append(c(BANNER.rstrip("\n"), BLOOD))
    else:
        lines.append(c(f"╔══ {c('KING REAPER X', BLOOD + BOLD)} ══╗", CRIMSON))
        lines.append(c("   ultimate cyber intelligence", GREY))
        lines.append(c("╚" + "═" * 34 + "╝", CRIMSON))
    lines.append(c(f"  {TAGLINE}  ·  v{version}", GRAPHITE))
    lines.append("")
    return "\n".join(lines)


def title(text: str) -> str:
    return c(f"\n▶ {text}", BLOOD + BOLD)


def section(text: str) -> str:
    return c(f"\n── {text} " + "─" * max(0, 60 - len(text)), CRIMSON)


def success(text: str) -> str:
    return c(f"[+] {text}", GREEN)


def warn(text: str) -> str:
    return c(f"[!] {text}", YELLOW)


def error(text: str) -> str:
    return c(f"[x] {text}", BLOOD)


def info(text: str) -> str:
    return c(f"[i] {text}", CYAN)


def hint(text: str) -> str:
    return c(f"    {text}", GREY)


def kv(key: str, value: Any, width: int = 22) -> str:
    return f"  {c(key.ljust(width), GREY)}{value}"


def _visible_len(value: str) -> int:
    """Length without ANSI escapes, for column alignment."""
    import re

    return len(re.sub(r"\033\[[0-9;]*m", "", value))


def table(headers: Sequence[str], rows: Iterable[Sequence[Any]], max_width: int = 60) -> str:
    """Plain-text table with correct alignment even when cells are coloured."""
    rows = [[("" if cell is None else str(cell))[:max_width] for cell in row] for row in rows]
    if not rows:
        return c("  (no results)", GRAPHITE)
    widths = [len(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            if index < len(widths):
                widths[index] = min(max(widths[index], _visible_len(cell)), max_width)

    out = ["  " + c("  ".join(h[: widths[i]].ljust(widths[i]) for i, h in enumerate(headers)), WHITE + BOLD)]
    out.append("  " + c("  ".join("─" * w for w in widths), GRAPHITE))
    for row in rows:
        cells = []
        for index, cell in enumerate(row):
            width = widths[index] if index < len(widths) else len(cell)
            pad = width - _visible_len(cell)
            cells.append(cell + " " * max(0, pad))
        out.append("  " + "  ".join(cells))
    return "\n".join(out)


def progress(current: int, total: int, label: str = "", width: int = 28) -> str:
    total = max(1, total)
    filled = int(width * current / total)
    bar = "█" * filled + "░" * (width - filled)
    suffix = f" {current}/{total}"
    if label:
        suffix = f" {label}" + suffix
    return c(f"  [{bar}]", BLOOD) + c(suffix, GREY)


class ProgressPrinter:
    """Single-line progress that degrades to periodic lines in a non-tty."""

    def __init__(self, total: int, label: str = "", quiet: bool = False) -> None:
        self.total = max(1, total)
        self.label = label
        self.quiet = quiet
        self.count = 0
        self._tty = color_enabled()
        self._last_line = 0

    def tick(self, item: Any = None) -> None:
        self.count += 1
        if self.quiet:
            return
        if self._tty:
            sys.stdout.write("\r" + progress(self.count, self.total, self.label))
            sys.stdout.flush()
        elif self.count % max(1, self.total // 5) == 0:
            print(progress(self.count, self.total, self.label))

    def done(self) -> None:
        if self.quiet:
            return
        if self._tty:
            sys.stdout.write("\r" + progress(self.total, self.total, self.label) + "\n")
            sys.stdout.flush()
        else:
            print(progress(self.total, self.total, self.label))


def status_badge(ok: Optional[bool]) -> str:
    if ok is True:
        return c("ONLINE", GREEN)
    if ok is False:
        return c("OFFLINE", BLOOD)
    return c("UNKNOWN", GREY)


def mask(value: Optional[str], keep: int = 3) -> str:
    if not value:
        return c("(not set)", GRAPHITE)
    value = str(value)
    if len(value) <= keep * 2:
        return c("***", GRAPHITE)
    return c(f"{'*' * 10}{value[-keep:]}", GREY)
