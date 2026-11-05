"""KING REAPER X interface layer (v2.0.0).

Strictly separate from the security modules: nothing in here performs a scan,
opens a socket to a target, or reads a credential. It only renders state that
the modules and the core runtime already produced.

Public surface (the names the spec requires):

    display_banner()        banner.banner
    startup_animation()     boot.startup_animation
    system_dashboard()      boot.system_dashboard
    main_menu()             menu.main_menu
    module_menu()           menu.module_menu
    progress_animation()    widgets.progress_animation
    display_success()       widgets.display_success
    display_error()         widgets.display_error
    clear_terminal()        widgets.clear_terminal

The old flat ``core/ui.py`` module was replaced by this package; the short
names it exported are kept as aliases below so existing imports
(``from core import ui``) and the dashboard keep working unchanged.
"""

from __future__ import annotations

from .animation import (
    animations_enabled,
    reset_animation_state,
    set_animations,
)
from .banner import banner as display_banner
from .banner import mini_logo, prompt_string, wordmark
from .boot import run_boot_checks, startup_animation, system_dashboard
from .menu import (
    EXIT_KEY,
    MENU_ITEMS,
    SUBMENUS,
    MenuItem,
    all_keys,
    main_menu,
    module_menu,
    resolve,
    resolve_submenu,
    run_menu,
)
from .theme import (
    BLACK,
    BLOOD,
    BOLD,
    CRIMSON,
    CYAN,
    DIM,
    GOLD,
    GRAPHITE,
    GREEN,
    GREY,
    MAGENTA,
    NEON_RED,
    RESET,
    SEVERITY_COLORS,
    WHITE,
    YELLOW,
    c,
    color_enabled,
    set_color,
    strip_ansi,
)
from .widgets import (
    badge,
    clear_terminal,
    display_error,
    display_hint,
    display_info,
    display_success,
    display_warning,
    double_rule,
    findings_block,
    kv,
    kv_block,
    progress_animation,
    progress_bar,
    result_block,
    rule,
    section,
    subtitle,
    table,
    title,
)

# --------------------------------------------------------------------------- #
# legacy aliases
# --------------------------------------------------------------------------- #
# The v1.0.0 interface was a flat ``core/ui.py`` with shorter names. The CLI and
# the dashboard still call those, so they are kept as aliases rather than
# rewritten — a rename here would touch every module for no functional gain.

banner = display_banner
success = display_success
error = display_error
warn = display_warning
info = display_info
hint = display_hint
status_badge = badge

__all__ = [
    # required API
    "display_banner",
    "startup_animation",
    "system_dashboard",
    "main_menu",
    "module_menu",
    "progress_animation",
    "display_success",
    "display_error",
    "clear_terminal",
    # menu model
    "MENU_ITEMS",
    "SUBMENUS",
    "MenuItem",
    "EXIT_KEY",
    "resolve",
    "resolve_submenu",
    "all_keys",
    "run_menu",
    # theme
    "c",
    "set_color",
    "color_enabled",
    "strip_ansi",
    "BLACK",
    "BLOOD",
    "NEON_RED",
    "CRIMSON",
    "WHITE",
    "GREY",
    "GRAPHITE",
    "GREEN",
    "YELLOW",
    "CYAN",
    "GOLD",
    "MAGENTA",
    "BOLD",
    "DIM",
    "RESET",
    "SEVERITY_COLORS",
    # widgets
    "rule",
    "double_rule",
    "section",
    "title",
    "subtitle",
    "kv",
    "kv_block",
    "table",
    "badge",
    "display_warning",
    "display_info",
    "display_hint",
    "progress_bar",
    "findings_block",
    "result_block",
    # animation
    "animations_enabled",
    "set_animations",
    "reset_animation_state",
    # identity
    "wordmark",
    "mini_logo",
    "prompt_string",
    "run_boot_checks",
]
