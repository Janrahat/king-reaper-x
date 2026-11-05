"""Animation gate.

Every animated effect in the interface asks :func:`animations_enabled` first.
Animations are switched off automatically when:

* ``REAPER_NO_ANIM=1`` is set (explicit opt-out),
* stdout is not a tty (pipes, CI logs, the dashboard),
* ``TERM`` is ``dumb``,
* the config setting ``animations`` is false,
* the device looks low-end (Termux without a fast CPU, or ``REAPER_LOW_END=1``).

The point is that nothing in this layer can make Termux feel slow: the same
code path renders instantly when animation is off, it just prints the final
frame.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Callable, Optional

_state: dict = {"enabled": None}


def _looks_low_end() -> bool:
    """Cheap heuristics only — no subprocess, no file reads on the hot path."""
    if os.environ.get("REAPER_LOW_END"):
        return True
    # Termux on a phone: keep the interface snappy by default.
    if "com.termux" in os.environ.get("PREFIX", ""):
        return True
    try:
        if os.cpu_count() and os.cpu_count() <= 2:
            return True
    except (AttributeError, NotImplementedError):
        pass
    return False


def animations_enabled(config: Optional[object] = None) -> bool:
    """Decide once per process whether to animate."""
    if _state["enabled"] is not None:
        return bool(_state["enabled"])

    if os.environ.get("REAPER_NO_ANIM"):
        _state["enabled"] = False
        return False
    if os.environ.get("TERM", "") == "dumb":
        _state["enabled"] = False
        return False
    try:
        if not sys.stdout.isatty():
            _state["enabled"] = False
            return False
    except (AttributeError, ValueError):
        _state["enabled"] = False
        return False

    if config is not None:
        try:
            if not config.get_bool("animations", True):
                _state["enabled"] = False
                return False
        except (AttributeError, TypeError):
            pass

    if _looks_low_end():
        _state["enabled"] = False
        return False

    _state["enabled"] = True
    return True


def set_animations(enabled: bool) -> None:
    """Force animation on or off (tests use this)."""
    _state["enabled"] = bool(enabled)


def reset_animation_state() -> None:
    _state["enabled"] = None


def sleep(seconds: float) -> None:
    """Sleep only when animating, so non-tty runs are instant."""
    if animations_enabled() and seconds > 0:
        time.sleep(seconds)


def frames(sequence, delay: float = 0.06, render: Optional[Callable] = None) -> None:
    """Play a short frame sequence, or nothing at all when animation is off."""
    if not animations_enabled():
        return
    for frame in sequence:
        text = render(frame) if render else str(frame)
        sys.stdout.write("\r" + text)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\r")
    sys.stdout.flush()
