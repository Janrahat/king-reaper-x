"""The interactive console: main menu, module sub-menus and the input loop.

Design rules that the tests enforce:

* every menu entry resolves to a real callable (``resolve`` never returns None
  for a listed key),
* the renderer is a pure function returning a string, so it can be asserted on
  without a terminal,
* the loop takes ``input_fn``/``output_fn`` so a harness can drive it,
* ``Ctrl+C`` and ``Ctrl+D`` return to the menu or exit cleanly, never traceback,
* an unknown selection prints a warning and re-renders.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import banner as banner_mod
from .theme import BLOOD, BOLD, CRIMSON, CYAN, GRAPHITE, GREEN, GREY, NEON_RED, WHITE, YELLOW, c
from .widgets import (
    display_error,
    display_hint,
    display_info,
    display_success,
    display_warning,
    double_rule,
    kv,
    result_block,
    rule,
    section,
)


@dataclass
class MenuItem:
    """One row of the main menu."""

    key: str
    label: str
    hint: str = ""
    module: str = ""
    gated: bool = False
    submenu: Optional[str] = None


#: The 16 entries, in the order the spec requires.
MENU_ITEMS: List[MenuItem] = [
    MenuItem("01", "Mobile Intelligence", "phone · whatsapp", submenu="mobile"),
    MenuItem("02", "IP Geo Intelligence", "geoip", module="geoip"),
    MenuItem("03", "Domain Reconnaissance", "domain", module="domain"),
    MenuItem("04", "SSL/TLS Security Audit", "ssl", module="ssl"),
    MenuItem("05", "Technology Fingerprint", "fingerprint", module="fingerprint"),
    MenuItem("06", "Subdomain Intelligence", "subdomains", module="subdomains"),
    MenuItem("07", "Web Security Assessment", "webscan", module="webscan"),
    MenuItem("08", "Username/Email OSINT", "username", module="username"),
    MenuItem("09", "Threat Intelligence", "threat", module="threat"),
    MenuItem("10", "Dependency Security Audit", "deps", module="deps"),
    MenuItem("11", "Authorized Port Scanner", "ports", module="ports", gated=True),
    MenuItem("12", "System Status", "status"),
    MenuItem("13", "Scan History", "history"),
    MenuItem("14", "Full Target Audit", "audit"),
    MenuItem("15", "API Providers & Configuration", "config"),
    MenuItem("16", "Settings", "settings", submenu="settings"),
]

EXIT_KEY = "00"

#: Sub-menu definitions: key -> (label, module or action, needs target)
SUBMENUS: Dict[str, List[MenuItem]] = {
    "mobile": [
        MenuItem("1", "Phone number intelligence", "offline numbering plan", module="phone"),
        MenuItem("2", "Phone + carrier enrichment", "needs numverify key", module="phone"),
        MenuItem("3", "WhatsApp business profile", "needs Meta token", module="whatsapp"),
        MenuItem("0", "Back"),
    ],
    "settings": [
        MenuItem("1", "Show configuration", "config show"),
        MenuItem("2", "Set a scalar setting", "config set"),
        MenuItem("3", "Toggle colour", "config set color"),
        MenuItem("4", "Toggle animations", "config set animations"),
        MenuItem("5", "Show config file path", "config show"),
        MenuItem("0", "Back"),
    ],
}


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

def main_menu(version: str = "2.0.0", width: int = 66) -> str:
    """Render the main menu as a string."""
    lines: List[str] = []
    lines.append(double_rule(width))
    lines.append(
        c("  KING REAPER X", BLOOD + BOLD)
        + c("  ·  MAIN MENU", GREY)
        + c(f"  v{version}", CRIMSON)
    )
    lines.append(double_rule(width))
    lines.append("")
    for item in MENU_ITEMS:
        number = c(f"[{item.key}]", BLOOD + BOLD)
        label = c(item.label.ljust(30), WHITE)
        hint = c(item.hint, GRAPHITE)
        gate = c(" ⚿", YELLOW) if item.gated else ""
        lines.append(f"  {number} {label}{hint}{gate}")
    lines.append("")
    lines.append(f"  {c('[00]', CRIMSON + BOLD)} {c('Exit', GREY)}")
    lines.append("")
    lines.append(rule(width=width))
    lines.append(c("  ⚿ = requires an authorization confirmation for the target", GRAPHITE))
    return "\n".join(lines)


def module_menu(name: str, version: str = "2.0.0") -> str:
    """Render a sub-menu, or an empty string when the name is unknown."""
    items = SUBMENUS.get(name)
    if items is None:
        return ""
    lines: List[str] = []
    lines.append(double_rule())
    lines.append(c(f"  {name.upper()}", BLOOD + BOLD) + c("  ·  SUB-MENU", GREY))
    lines.append(double_rule())
    lines.append("")
    for item in items:
        number = c(f"[{item.key}]", BLOOD + BOLD)
        label = c(item.label.ljust(32), WHITE)
        hint = c(item.hint, GRAPHITE)
        lines.append(f"  {number} {label}{hint}")
    lines.append("")
    lines.append(rule())
    return "\n".join(lines)


def prompt_line() -> str:
    return banner_mod.prompt_string() + " "


# --------------------------------------------------------------------------- #
# resolution — every key must map to something real
# --------------------------------------------------------------------------- #

def resolve(key: str) -> Optional[MenuItem]:
    """Return the MenuItem for *key*, or None when it is not a menu entry."""
    for item in MENU_ITEMS:
        if item.key == key:
            return item
    return None


def resolve_submenu(name: str, key: str) -> Optional[MenuItem]:
    for item in SUBMENUS.get(name, []):
        if item.key == key:
            return item
    return None


def all_keys() -> List[str]:
    return [item.key for item in MENU_ITEMS] + [EXIT_KEY]


# --------------------------------------------------------------------------- #
# the loop
# --------------------------------------------------------------------------- #

def _ask(prompt: str, input_fn: Callable[[str], str], default: str = "") -> str:
    """Read one line, tolerating EOF and Ctrl+C."""
    suffix = f" [{default}]" if default else ""
    try:
        value = input_fn(c(f"  {prompt}", BLOOD) + suffix + ": ")
    except (EOFError, KeyboardInterrupt):
        return ""
    return (value or "").strip() or default


def _confirm(prompt: str, input_fn: Callable[[str], str]) -> bool:
    answer = _ask(prompt + " (yes/no)", input_fn)
    return answer.lower() in ("y", "yes")


def _run_module(module: str, target: str, output_fn: Callable[[str], None], **options: Any) -> Dict[str, Any]:
    """Call a module through the registry and render the result."""
    from core import registry

    result = registry.call(module, target, **options)
    output_fn(result_block(result, module))
    return result


def _phone_flow(enrich: bool, input_fn: Callable[[str], str], output_fn: Callable[[str], None]) -> None:
    """Phone intelligence: every field the spec asks for, from real analysis."""
    number = _ask("phone number (E.164, e.g. +966501234567)", input_fn)
    if not number:
        output_fn(display_warning("no number entered"))
        return

    from core import registry

    result = registry.call("phone", number, enrich=enrich)
    if not result.get("ok"):
        output_fn(result_block(result, "phone"))
        return

    country = result.get("country") or {}
    formats = result.get("formats") or {}
    length = result.get("length") or {}
    validity = result.get("validity") or {}

    output_fn(section("PHONE INTELLIGENCE"))
    output_fn(kv("input", number))
    output_fn(kv("country", f"{country.get('name', '?')} ({country.get('iso', '?')})"))
    output_fn(kv("calling code", country.get("calling_code", "?")))
    output_fn(kv("national number", result.get("national_number", "?")))
    output_fn(kv("E.164", c(result.get("e164", "?"), WHITE + BOLD)))
    output_fn("")
    output_fn(c("  FORMATS", WHITE + BOLD))
    output_fn(kv("international", formats.get("international", "?")))
    output_fn(kv("national", formats.get("national", "?")))
    output_fn(kv("uri", formats.get("uri", "?")))
    output_fn("")
    output_fn(c("  CLASSIFICATION", WHITE + BOLD))
    line_type = result.get("line_type", "unknown")
    type_color = GREEN if line_type == "mobile" else (YELLOW if line_type == "landline" else GREY)
    output_fn(kv("line type", c(str(line_type), type_color + BOLD)))
    output_fn(kv("basis", c(str(result.get("line_type_basis", "n/a")), GREY)))
    output_fn("")
    output_fn(c("  VALIDATION", WHITE + BOLD))
    plausible = length.get("plausible")
    output_fn(kv("national digits", str(length.get("national_digits", "?"))))
    output_fn(kv("expected range", str(length.get("expected_range", "?"))))
    output_fn(kv("length valid", c("YES", GREEN) if plausible else c("NO", BLOOD)))
    output_fn(kv("format valid", c("YES", GREEN) if validity.get("format_valid") else c("NO", BLOOD)))
    output_fn(kv("confidence", c(str(validity.get("confidence", "?")), GREY)))
    if validity.get("note"):
        output_fn(display_hint(str(validity["note"])))

    enrichment = result.get("enrichment")
    output_fn("")
    output_fn(c("  CARRIER ENRICHMENT", WHITE + BOLD))
    if enrichment is None:
        output_fn(display_hint("not requested — choose option 2 to query numverify"))
    elif enrichment.get("ok"):
        output_fn(kv("carrier", str(enrichment.get("carrier") or "unknown")))
        output_fn(kv("location", str(enrichment.get("location") or "unknown")))
        output_fn(kv("provider line type", str(enrichment.get("line_type") or "unknown")))
    else:
        output_fn(display_warning(str(enrichment.get("message") or "provider unavailable")))
        if enrichment.get("provider"):
            output_fn(display_hint(f"provider: {enrichment['provider']}"))
    output_fn("")


def _settings_flow(input_fn: Callable[[str], str], output_fn: Callable[[str], None]) -> None:
    from core.config import load_config

    config = load_config()
    output_fn(section("SETTINGS"))
    output_fn(kv("config file", str(config.path)))
    output_fn(kv("permissions", "0600" if config.mode_is_secure() else "NOT 0600"))
    output_fn("")
    for key in ("timeout", "threads", "rate_limit", "color", "animations", "dashboard_port"):
        output_fn(kv(key, str(config.get(key, "unset"))))
    output_fn("")
    output_fn(display_hint("change with: config set <name> <value>"))
    output_fn("")


def run_menu(
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    version: str = "2.0.0",
    boot: bool = True,
) -> int:
    """The interactive console. Returns a process exit code."""
    from core.config import load_config

    config = load_config()

    if boot:
        from .boot import startup_animation

        startup_animation(version)

    while True:
        output_fn("")
        output_fn(main_menu(version))
        choice = _ask("select", input_fn)

        if not choice:
            output_fn(display_info("no selection — exiting"))
            return 0
        if choice == EXIT_KEY:
            output_fn(display_success("session closed"))
            return 0

        item = resolve(choice)
        if item is None:
            output_fn(display_warning(f"'{choice}' is not a menu option (00-16)"))
            continue

        try:
            _dispatch(item, config, input_fn, output_fn)
        except KeyboardInterrupt:
            output_fn("")
            output_fn(display_warning("interrupted — back to menu"))
            continue
        except Exception as exc:  # noqa: BLE001 - the console must survive anything
            output_fn(display_error(f"{type(exc).__name__}: {exc}"))


def _dispatch(
    item: MenuItem,
    config: Any,
    input_fn: Callable[[str], str],
    output_fn: Callable[[str], None],
) -> None:
    """Route one menu selection to its real implementation."""
    from core import registry

    # -- sub-menus --------------------------------------------------------- #
    if item.submenu == "mobile":
        output_fn(module_menu("mobile"))
        sub = _ask("select", input_fn)
        if sub in ("", "0"):
            return
        if sub == "1":
            _phone_flow(False, input_fn, output_fn)
        elif sub == "2":
            _phone_flow(True, input_fn, output_fn)
        elif sub == "3":
            number = _ask("WhatsApp business number", input_fn)
            if number:
                _run_module("whatsapp", number, output_fn, check_contact_status=True)
        else:
            output_fn(display_warning(f"'{sub}' is not a sub-menu option"))
        return

    if item.submenu == "settings":
        output_fn(module_menu("settings"))
        sub = _ask("select", input_fn)
        if sub in ("", "0"):
            return
        if sub == "1" or sub == "5":
            _settings_flow(input_fn, output_fn)
        elif sub == "2":
            name = _ask("setting name", input_fn)
            value = _ask("value", input_fn)
            if name:
                from core.cli import _namespace, cmd_config

                cmd_config(_namespace(config_action="set", name=name, value=value))
        elif sub == "3":
            current = config.get_bool("color", True)
            config.set("color", not current)
            config.save()
            output_fn(display_success(f"color = {not current}"))
        elif sub == "4":
            current = config.get_bool("animations", True)
            config.set("animations", not current)
            config.save()
            output_fn(display_success(f"animations = {not current}"))
        else:
            output_fn(display_warning(f"'{sub}' is not a sub-menu option"))
        return

    # -- meta commands ----------------------------------------------------- #
    if item.key == "12":
        from .boot import system_dashboard

        output_fn(system_dashboard(config))
        return

    if item.key == "13":
        from core.cli import _namespace, cmd_history

        cmd_history(_namespace(limit=15))
        return

    if item.key == "15":
        from core.cli import _namespace, cmd_config

        cmd_config(_namespace(config_action="providers"))
        return

    if item.key == "14":
        target = _ask("domain to audit", input_fn)
        if not target:
            output_fn(display_warning("no target entered"))
            return
        from core.cli import _namespace, cmd_audit

        cmd_audit(_namespace(target=target))
        return

    # -- module entries ---------------------------------------------------- #
    if not item.module:
        output_fn(display_warning(f"menu item {item.key} has no implementation"))
        return

    if item.module == "deps":
        _run_module("deps", "", output_fn, config=config)
        return

    target = _ask(_target_prompt(item.module), input_fn)
    if not target:
        output_fn(display_warning("no target entered"))
        return

    if item.gated:
        output_fn("")
        output_fn(c("  AUTHORIZATION REQUIRED", BLOOD + BOLD))
        output_fn(display_hint("only scan systems you own or hold written permission to test"))
        if not _confirm(f"confirm you may test {target}", input_fn):
            output_fn(display_warning("authorization not confirmed — skipped"))
            return
        _run_module(item.module, target, output_fn, config=config, authorized=True, ports="top")
        return

    _run_module(item.module, target, output_fn, config=config)


def _target_prompt(module: str) -> str:
    return {
        "geoip": "IP address or hostname",
        "domain": "domain name",
        "ssl": "host or host:port",
        "fingerprint": "host or URL",
        "subdomains": "domain name",
        "webscan": "host or URL",
        "username": "username or email",
        "threat": "domain or IP",
        "ports": "host or IP",
        "phone": "phone number",
        "whatsapp": "WhatsApp business number",
    }.get(module, "target")
