"""ASCII identity: the KING REAPER X wordmark and its double-line frame.

The wordmark is composed from a small block font rather than pasted as one
literal, so it can be re-rendered at a different width, tested for line count,
and degraded to a compact form on a narrow terminal (Termux in portrait is
about 40 columns).
"""

from __future__ import annotations

import shutil
from typing import Dict, List

from .theme import BLOOD, BOLD, CRIMSON, GREY, NEON_RED, WHITE, c

#: 5-row block font. Every glyph is padded to the same height.
FONT: Dict[str, List[str]] = {
    "K": ["█   █", "█  █ ", "███  ", "█  █ ", "█   █"],
    "I": ["███", " █ ", " █ ", " █ ", "███"],
    "N": ["█   █", "██  █", "█ █ █", "█  ██", "█   █"],
    "G": [" ████", "█    ", "█  ██", "█   █", " ███ "],
    "R": ["████ ", "█   █", "████ ", "█  █ ", "█   █"],
    "E": ["█████", "█    ", "████ ", "█    ", "█████"],
    "A": [" ███ ", "█   █", "█████", "█   █", "█   █"],
    "P": ["████ ", "█   █", "████ ", "█    ", "█    "],
    "X": ["█   █", " █ █ ", "  █  ", " █ █ ", "█   █"],
    " ": ["  ", "  ", "  ", "  ", "  "],
}

TAGLINE = "ULTIMATE CYBER INTELLIGENCE & SECURITY FRAMEWORK"
HEIGHT = 5


def render_word(text: str) -> List[str]:
    """Render *text* in the block font, one string per row."""
    rows = [""] * HEIGHT
    for index, char in enumerate(text.upper()):
        glyph = FONT.get(char)
        if glyph is None:
            glyph = FONT[" "]
        for row in range(HEIGHT):
            rows[row] += glyph[row]
            if index != len(text) - 1:
                rows[row] += " "
    return [row.rstrip() for row in rows]


def wordmark() -> List[str]:
    """The two-line wordmark: KING over REAPER X."""
    top = render_word("KING")
    bottom = render_word("REAPER X")
    width = max(len(line) for line in top + bottom)
    return [line.ljust(width) for line in top] + [""] + [line.ljust(width) for line in bottom]


def _box(lines: List[str], pad: int = 3) -> List[str]:
    """Wrap *lines* in a double-line box."""
    inner = max(len(line) for line in lines) + pad * 2
    out = ["╔" + "═" * inner + "╗"]
    for line in lines:
        out.append("║" + " " * pad + line.ljust(inner - pad * 2) + " " * pad + "║")
    out.append("╚" + "═" * inner + "╝")
    return out


def banner(version: str = "2.0.0", compact: bool = False) -> str:
    """Full identity block, or a compact one for narrow terminals."""
    width = shutil.get_terminal_size((80, 24)).columns
    lines: List[str] = []

    if compact or width < 70:
        inner = 44
        lines.append(c("╔" + "═" * inner + "╗", CRIMSON))
        lines.append(c("║", CRIMSON) + c("  KING REAPER X".ljust(inner), BLOOD + BOLD) + c("║", CRIMSON))
        lines.append(c("║", CRIMSON) + c("  ultimate cyber intelligence".ljust(inner), GREY) + c("║", CRIMSON))
        lines.append(c("╚" + "═" * inner + "╝", CRIMSON))
        # A 40-column Termux window cannot fit the full tagline, so the compact
        # form uses the short one and keeps every line inside the box width.
        lines.append(c(f"  v{version}  ·  cyber intelligence", GREY))
        lines.append("")
        return "\n".join(lines)

    art = wordmark()
    boxed = _box(art)
    for index, line in enumerate(boxed):
        if index in (0, len(boxed) - 1):
            lines.append(c(line, CRIMSON))
        else:
            # Colour only the glyphs, keep the frame crimson.
            body = line[1:-1]
            lines.append(c("║", CRIMSON) + c(body, BLOOD) + c("║", CRIMSON))
    lines.append(c(f"  {TAGLINE}", GREY))
    lines.append(c(f"  v{version}  ·  authorized security testing only", GREY))
    lines.append("")
    return "\n".join(lines)


def logo_lines() -> List[str]:
    """The bare wordmark, no frame — used by the boot animation."""
    return wordmark()


def mini_logo() -> str:
    """One-line mark for prompts and section headers."""
    return c("⟦", CRIMSON) + c("KING REAPER X", BLOOD + BOLD) + c("⟧", CRIMSON)


def prompt_string() -> str:
    """The shell-style prompt used by the interactive console."""
    return c("REAPER-X", BLOOD + BOLD) + c("@", GREY) + c("TERMUX", NEON_RED) + c(":~#", WHITE)
