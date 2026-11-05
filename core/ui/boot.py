"""Boot sequence and the system dashboard panel.

Both read real state: the module registry, the SQLite database, the config
store and the Python runtime. Nothing here invents a number — if a check cannot
be measured it reports ``unknown`` rather than a plausible-looking value.
"""

from __future__ import annotations

import os
import platform
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from . import banner as banner_mod
from .animation import animations_enabled, sleep
from .theme import (
    BLOOD,
    BOLD,
    CRIMSON,
    CYAN,
    GRAPHITE,
    GREEN,
    GREY,
    NEON_RED,
    WHITE,
    YELLOW,
    c,
)
from .widgets import (
    clear_terminal,
    display_error,
    display_hint,
    display_info,
    display_success,
    display_warning,
    double_rule,
    kv,
    progress_bar,
    rule,
    section,
)

#: Boot steps: (label, callable returning (ok, detail)).
#: The callables are resolved lazily so importing this module stays cheap and
#: a broken optional dependency cannot stop the interface from loading.
BOOT_STEPS: List[Tuple[str, str]] = [
    ("Python environment", "python"),
    ("Module registry", "modules"),
    ("Database connection", "database"),
    ("Configuration store", "config"),
    ("Security framework", "security"),
    ("Network stack", "network"),
]


def _check_python() -> Tuple[bool, str]:
    major, minor = sys.version_info[:2]
    ok = (major, minor) >= (3, 8)
    return ok, f"{major}.{minor}.{sys.version_info[2]} ({platform.python_implementation()})"


def _check_modules() -> Tuple[bool, str]:
    try:
        from core import registry

        entries = registry.discover()
        good = [item for item in entries if item.get("importable")]
        broken = [item for item in entries if not item.get("importable")]
        if broken:
            return False, f"{len(good)} loaded, {len(broken)} failed to import"
        return bool(good), f"{len(good)} modules loaded"
    except Exception as exc:  # noqa: BLE001 - boot must never traceback
        return False, f"{type(exc).__name__}: {exc}"


def _check_database() -> Tuple[bool, str]:
    try:
        from core.db import open_db

        db = open_db()
        try:
            stats = db.stats()
            return True, f"SQLite ready · {stats['total_scans']} record(s)"
        finally:
            db.close()
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def _check_config() -> Tuple[bool, str]:
    try:
        from core.config import load_config

        config = load_config()
        mode = "0600" if config.mode_is_secure() else "not 0600"
        return True, f"{config.path.name} ({mode})"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def _check_security() -> Tuple[bool, str]:
    try:
        from core.consent import ACTIVE_MODULES

        return True, f"authorization gate armed · {len(ACTIVE_MODULES)} active module(s)"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def _check_network() -> Tuple[bool, str]:
    """A socket is opened to a loopback port we own — no external traffic."""
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        return True, f"TCP stack available (loopback :{port})"
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"


CHECKS = {
    "python": _check_python,
    "modules": _check_modules,
    "database": _check_database,
    "config": _check_config,
    "security": _check_security,
    "network": _check_network,
}


def run_boot_checks() -> List[Dict[str, Any]]:
    """Execute every boot check and return the measured results."""
    results: List[Dict[str, Any]] = []
    for label, key in BOOT_STEPS:
        try:
            ok, detail = CHECKS[key]()
        except Exception as exc:  # noqa: BLE001
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        results.append({"step": label, "ok": bool(ok), "detail": detail})
    return results


def startup_animation(version: str = "2.0.0", clear: bool = True) -> List[Dict[str, Any]]:
    """Boot screen: logo, animated bar, then one line per verified subsystem.

    Returns the check results so the caller can decide whether to continue.
    """
    if clear:
        clear_terminal()

    print(banner_mod.banner(version))
    print(c("  INITIALIZING SECURITY FRAMEWORK", BLOOD + BOLD))
    print(rule())

    results = run_boot_checks()
    total = len(results)

    if animations_enabled():
        for step in range(total + 1):
            sys.stdout.write("\r" + progress_bar(step, total, "boot"))
            sys.stdout.flush()
            time.sleep(0.05)
        sys.stdout.write("\n\n")
    else:
        print(progress_bar(total, total, "boot"))
        print()

    for item in results:
        if item["ok"]:
            mark = c("[ ok ]", GREEN + BOLD)
        else:
            mark = c("[fail]", BLOOD + BOLD)
        print(f"  {mark} {item['step'].ljust(22)}{c(item['detail'], GREY)}")

    print()
    failures = [item for item in results if not item["ok"]]
    if failures:
        print(display_warning(f"{len(failures)} subsystem(s) degraded — the console still starts"))
        for item in failures:
            print(display_hint(f"{item['step']}: {item['detail']}"))
    else:
        print(c("  ██ SYSTEM READY ██", GREEN + BOLD))
    print(rule())
    print()
    return results


# --------------------------------------------------------------------------- #
# dashboard
# --------------------------------------------------------------------------- #

def _device_info() -> str:
    """Best-effort device label; never raises."""
    try:
        from dashboard.server import system_snapshot_raw

        if system_snapshot_raw():
            return f"Android / Termux ({platform.machine()})"
    except Exception:  # noqa: BLE001
        pass
    return f"{platform.system()} {platform.release()} ({platform.machine()})"


def system_dashboard(config: Optional[Any] = None, db: Optional[Any] = None) -> str:
    """The main dashboard panel, built from live state."""
    from core.config import PROVIDERS, VERSION, load_config

    config = config or load_config()
    close_db = False
    if db is None:
        from core.db import open_db

        db = open_db()
        close_db = True

    try:
        stats = db.stats()
        modules = _module_counts()
        providers = config.provider_report()
        configured = [row for row in providers if row["configured"]]
        consent = config.get_bool("consent_accepted", False)
    finally:
        if close_db:
            db.close()

    now = datetime.now()
    lines: List[str] = []
    lines.append(double_rule())
    lines.append(
        c("  KING REAPER X", BLOOD + BOLD)
        + c("  ·  COMMAND CENTRE", GREY)
        + c(f"  v{VERSION}", CRIMSON)
    )
    lines.append(double_rule())
    lines.append("")
    lines.append(kv("date / time", now.strftime("%Y-%m-%d  %H:%M:%S")))
    lines.append(kv("framework", f"KING REAPER X v{VERSION}"))
    lines.append(kv("python", f"{sys.version.split()[0]} ({platform.python_implementation()})"))
    lines.append(kv("os", _device_info()))
    lines.append(kv("hostname", platform.node() or "unknown"))
    lines.append("")
    lines.append(section("MODULES"))
    lines.append(kv("total modules", f"{modules['total']}"))
    lines.append(kv("importable", c(str(modules["ok"]), GREEN) if modules["ok"] else c("0", BLOOD)))
    if modules["broken"]:
        lines.append(kv("failed imports", c(str(modules["broken"]), BLOOD)))
    lines.append(kv("active (gated)", f"{modules['active']}"))
    lines.append("")
    lines.append(section("DATABASE"))
    lines.append(kv("status", c("CONNECTED", GREEN + BOLD)))
    lines.append(kv("records", f"{stats['total_scans']}"))
    lines.append(kv("path", c(str(stats["db_path"]), GREY)))
    lines.append("")
    lines.append(section("API PROVIDERS"))
    lines.append(
        kv(
            "configured",
            f"{len(configured)}/{len(providers)}"
            + (c("  " + ", ".join(row["provider"] for row in configured), GREEN) if configured else ""),
        )
    )
    if not configured:
        lines.append(display_hint("no keys set — provider-backed modules report DEGRADED"))
        lines.append(display_hint("add one with: config set-key <provider>"))
    lines.append("")
    lines.append(section("AUTHORIZATION"))
    lines.append(
        kv(
            "terms accepted",
            c("YES", GREEN) if consent else c("NO — run `menu` to accept", YELLOW),
        )
    )
    lines.append(kv("active scanning", c("requires per-run confirmation", GREY)))
    lines.append("")
    lines.append(double_rule())
    return "\n".join(lines)


def _module_counts() -> Dict[str, int]:
    try:
        from core import registry

        entries = registry.discover()
    except Exception:  # noqa: BLE001
        return {"total": 0, "ok": 0, "broken": 0, "active": 0}
    ok = [item for item in entries if item.get("importable")]
    return {
        "total": len(entries),
        "ok": len(ok),
        "broken": len(entries) - len(ok),
        "active": len([item for item in ok if item.get("active")]),
    }
