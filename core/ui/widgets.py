"""Reusable output widgets: separators, key/value blocks, tables, findings.

Everything here returns or prints plain text and never raises on a missing
value — a module returning a partial dict must still render.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .animation import animations_enabled
from .theme import (
    BLOOD,
    BOLD,
    CRIMSON,
    CYAN,
    GRAPHITE,
    GREEN,
    GREY,
    NEON_RED,
    SEVERITY_COLORS,
    WHITE,
    YELLOW,
    _visible_len,
    c,
)

WIDTH = 66


# --------------------------------------------------------------------------- #
# terminal control
# --------------------------------------------------------------------------- #

def clear_terminal() -> None:
    """Clear the screen, but never emit escapes into a pipe or a dumb terminal."""
    if not animations_enabled() and not sys.stdout.isatty():
        return
    if os.environ.get("TERM", "") == "dumb":
        return
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


# --------------------------------------------------------------------------- #
# separators and headings
# --------------------------------------------------------------------------- #

def rule(char: str = "─", width: int = WIDTH, color: str = CRIMSON) -> str:
    return c(char * width, color)


def double_rule(width: int = WIDTH) -> str:
    return c("═" * width, CRIMSON)


def section(text: str, width: int = WIDTH) -> str:
    """A titled separator: ``── TITLE ──────────``."""
    label = f" {text.upper()} "
    remaining = max(0, width - len(label) - 2)
    return c("──", CRIMSON) + c(label, BLOOD + BOLD) + c("─" * remaining, CRIMSON)


def title(text: str) -> str:
    return c(f"\n▶ {text}", BLOOD + BOLD)


def subtitle(text: str) -> str:
    return c(f"  {text}", GREY)


# --------------------------------------------------------------------------- #
# status lines
# --------------------------------------------------------------------------- #

def display_success(text: str) -> str:
    """Green success line. Returns the string so callers can also print it."""
    return c("[+] ", GREEN + BOLD) + c(text, GREEN)


def display_error(text: str) -> str:
    """Red error line."""
    return c("[x] ", BLOOD + BOLD) + c(text, NEON_RED)


def display_warning(text: str) -> str:
    return c("[!] ", YELLOW + BOLD) + c(text, YELLOW)


def display_info(text: str) -> str:
    return c("[i] ", CYAN) + c(text, CYAN)


def display_hint(text: str) -> str:
    return c(f"    {text}", GREY)


def badge(ok: Optional[bool]) -> str:
    if ok is True:
        return c(" ONLINE ", GREEN + BOLD)
    if ok is False:
        return c(" OFFLINE ", BLOOD + BOLD)
    return c(" UNKNOWN ", GREY)


# --------------------------------------------------------------------------- #
# key/value and tables
# --------------------------------------------------------------------------- #

def kv(key: str, value: Any, width: int = 24) -> str:
    return f"  {c(key.ljust(width), GREY)}{value}"


def kv_block(pairs: Sequence[tuple], width: int = 24) -> str:
    return "\n".join(kv(str(k), "" if v is None else v, width) for k, v in pairs)


def table(
    headers: Sequence[str],
    rows: Iterable[Sequence[Any]],
    max_width: int = 48,
) -> str:
    """Aligned table that stays correct when cells contain ANSI colour."""
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
            cells.append(cell + " " * max(0, width - _visible_len(cell)))
        out.append("  " + "  ".join(cells))
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# progress
# --------------------------------------------------------------------------- #

def progress_bar(current: int, total: int, label: str = "", width: int = 30) -> str:
    total = max(1, total)
    current = max(0, min(current, total))
    filled = int(width * current / total)
    bar = "█" * filled + "░" * (width - filled)
    suffix = f" {current}/{total}"
    if label:
        suffix = f" {label}" + suffix
    return c(f"  [{bar}]", BLOOD) + c(suffix, GREY)


def progress_animation(total: int, label: str = "", delay: float = 0.02) -> None:
    """Animate a bar to completion, or print the final frame when animation is off."""
    import time

    total = max(1, total)
    if not animations_enabled():
        print(progress_bar(total, total, label))
        return
    for step in range(total + 1):
        sys.stdout.write("\r" + progress_bar(step, total, label))
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\n")
    sys.stdout.flush()


# --------------------------------------------------------------------------- #
# findings
# --------------------------------------------------------------------------- #

def findings_block(findings: Optional[List[Dict[str, Any]]]) -> str:
    """Render a module's findings, worst first."""
    if not findings:
        return c("  no findings", GRAPHITE)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    lines: List[str] = []
    for item in sorted(findings, key=lambda f: order.get(str(f.get("severity", "info")).lower(), 9)):
        severity = str(item.get("severity", "info")).lower()
        color = SEVERITY_COLORS.get(severity, GREY)
        lines.append(f"  {c(severity.upper().ljust(9), color + BOLD)}{item.get('title', '')}")
        detail = item.get("detail")
        if detail:
            lines.append(c(f"    {str(detail)[:150]}", GREY))
    return "\n".join(lines)


def result_block(result: Dict[str, Any], module_name: str = "") -> str:
    """The standard rendering of one module result."""
    lines: List[str] = []
    if module_name:
        lines.append(section(module_name))
    lines.append(kv("target", result.get("target", "")))
    if result.get("degraded"):
        lines.append(kv("status", c("DEGRADED", YELLOW + BOLD)))
    else:
        lines.append(kv("status", badge(bool(result.get("ok")))))
    if result.get("summary"):
        lines.append(kv("summary", result["summary"]))
    if not result.get("ok"):
        lines.append(display_error(f"{result.get('error')}: {result.get('message', '')}"))
        if result.get("hint"):
            lines.append(display_hint(str(result["hint"])))
        return "\n".join(lines)
    if result.get("degraded"):
        lines.append("")
        lines.append(display_warning(str(result.get("message") or "optional provider not configured")))
        requires = result.get("requires") or result.get("requires_key")
        if requires:
            lines.append(display_hint(f"required: {requires}"))
        if result.get("hint"):
            lines.append(display_hint(f"→ {result['hint']}"))
    if result.get("risk"):
        lines.append(kv("risk", f"{result['risk']} (score {result.get('score', 0)}/100)"))
    lines.append("")
    lines.append(c("  FINDINGS", WHITE + BOLD))
    lines.append(findings_block(result.get("findings")))
    return "\n".join(lines)
