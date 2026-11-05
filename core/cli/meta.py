"""KING REAPER X command line interface — meta layer.

Split out of the original single-module ``core/cli.py`` so each layer can be
read and tested on its own. ``core.cli`` re-exports every public name, so
``from core.cli import build_parser, main`` keeps working unchanged.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core import registry, report, ui
from core.config import PROVIDERS, VERSION, Config, DB_FILE, REPORT_DIR, load_config
from core.consent import require_authorization, require_terms, request_terms, ACTIVE_MODULES
from core.db import open_db
from core.errors import ReaperError
from core.logging_setup import AuditLogger, get_logger, log_path
from core.utils import dedupe, elapsed_ms, now_iso, parse_ports, truncate

from core.cli.parser import SCAN_VERBS, build_parser

logger = get_logger("cli")

# --------------------------------------------------------------------------- #
# meta commands
# --------------------------------------------------------------------------- #


def cmd_info(args: argparse.Namespace) -> int:
    entries = registry.discover()
    payload = {
        "ok": True,
        "name": "KING REAPER X",
        "version": VERSION,
        "tagline": "Ultimate Cyber Intelligence & Security Framework",
        "modules": len([item for item in entries if item.get("importable")]),
        "categories": sorted({item.get("category", "general") for item in entries}),
        "providers": sorted(PROVIDERS.keys()),
        "python": sys.version.split()[0],
        "platform": sys.platform,
    }
    if getattr(args, "json_output", False):
        print(json.dumps(payload, indent=2))
        return 0
    print(ui.banner(VERSION))
    print(ui.kv("modules", payload["modules"]))
    print(ui.kv("categories", ", ".join(payload["categories"])))
    print(ui.kv("providers", ", ".join(payload["providers"])))
    print(ui.kv("python", payload["python"]))
    return 0


def cmd_tools(args: argparse.Namespace) -> int:
    entries = [item for item in registry.discover() if item.get("importable")]
    if getattr(args, "json_output", False):
        print(json.dumps({"ok": True, "modules": entries}, indent=2, default=str))
        return 0
    print(ui.banner(VERSION, compact=True))
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for item in entries:
        grouped.setdefault(item.get("category", "general"), []).append(item)
    for category in sorted(grouped):
        print(ui.title(category.upper()))
        rows = [
            [item["name"], item["title"], "yes" if item["active"] else "-",
             ", ".join(item["requires"]) or "-"]
            for item in sorted(grouped[category], key=lambda x: x["name"])
        ]
        print(ui.table(["command", "title", "auth", "providers"], rows))
    print()
    print(ui.hint(f"{len(entries)} modules. Run `python main.py <command> --help` for flags."))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Real environment checks — every line is measured, none is assumed."""
    from core import net
    from core.config import CONFIG_FILE, DB_FILE, LOG_DIR, DATA_DIR
    from core.dnsclient import resolve

    checks: List[Dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str, hint: str = "") -> None:
        checks.append({"check": name, "ok": bool(ok), "detail": detail, "hint": hint})

    config = load_config()

    major, minor = sys.version_info[:2]
    check("python", (major, minor) >= (3, 8), f"{major}.{minor}", "upgrade to Python 3.8+")

    try:
        config_dir_ok = CONFIG_FILE.parent.exists()
        check("config_dir", config_dir_ok, str(CONFIG_FILE.parent),
              "created automatically on first write")
    except OSError as exc:
        check("config_dir", False, str(exc))

    check("config_file", config.path.exists(),
          f"{config.path} (mode {'0600' if config.mode_is_secure() else 'not 0600'})")

    db = open_db()
    try:
        stats = db.stats()
        check("database", True, f"{stats['total_scans']} scan(s) in {stats['db_path']}")
    except Exception as exc:  # noqa: BLE001
        check("database", False, str(exc))
    finally:
        db.close()

    for label, path in (("log_dir", LOG_DIR), ("report_dir", REPORT_DIR), ("data_dir", DATA_DIR)):
        check(label, Path(path).exists(), str(path))

    wordlist = DATA_DIR / "subdomains.txt"
    count = 0
    if wordlist.exists():
        count = len([
            line for line in wordlist.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip() and not line.startswith("#")
        ])
    check("subdomain_wordlist", count > 0, f"{count} entries")

    try:
        dns = resolve("example.com", "A", timeout=5.0)
        check("dns", bool(dns.get("ok")), f"{dns.get('status')} via {dns.get('server')}",
              "DNS is blocked in this network")
    except Exception as exc:  # noqa: BLE001
        check("dns", False, str(exc))

    probe = net.http_request("https://example.com", timeout=8.0, max_body=1024)
    check("https", bool(probe.get("ok")), f"HTTP {probe.get('status')}",
          "outbound HTTPS is blocked")

    from dashboard.server import system_snapshot_raw

    check("termux", system_snapshot_raw(), "yes" if system_snapshot_raw() else "no (not Android)")
    check("cert_decoder", hasattr(getattr(__import__("ssl"), "_ssl", None), "_test_decode_cert"),
          "available" if hasattr(getattr(__import__("ssl"), "_ssl", None), "_test_decode_cert")
          else "absent — certificate details limited")

    configured = config.configured_providers()
    check("providers", True, f"{len(configured)}/{len(PROVIDERS)} key(s) configured"
          + (f": {', '.join(configured)}" if configured else ""))

    failures = [item for item in checks if not item["ok"]]
    payload = {"ok": not [f for f in failures if f["check"] in ("python", "database", "dns")],
               "checks": checks, "failures": len(failures)}
    if getattr(args, "json_output", False):
        print(json.dumps(payload, indent=2))
        return 0 if payload["ok"] else 1

    print(ui.banner(VERSION, compact=True))
    for item in checks:
        mark = ui.c("[ok]", ui.GREEN) if item["ok"] else ui.c("[!!]", ui.YELLOW)
        print(f"  {mark} {item['check'].ljust(20)}{item['detail']}")
        if item["hint"] and not item["ok"]:
            print(ui.hint(f"→ {item['hint']}"))
    print()
    if payload["ok"]:
        print(ui.success("core checks passed"))
    else:
        print(ui.warn("some core checks failed — see above"))
    return 0 if payload["ok"] else 1


def cmd_selftest(args: argparse.Namespace) -> int:
    """Exercise the framework end to end and report what actually worked.

    Every check below performs a real operation and inspects its real result:
    a record is written to a throwaway database and read back, a report is
    rendered and its bytes counted, the phone module analyses a known number,
    and the authorization gate is asked to refuse an unauthorized scan. A
    check that cannot be measured is reported as failed, never assumed.
    """
    import tempfile

    from core import registry, report, ui
    from core.config import VERSION

    checks: List[Dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    # -- 1. python --------------------------------------------------------- #
    major, minor = sys.version_info[:2]
    check("python", (major, minor) >= (3, 8), f"{major}.{minor}.{sys.version_info[2]}")

    # -- 2. module registry ------------------------------------------------ #
    try:
        entries = registry.discover()
        broken = [item["name"] for item in entries if not item.get("importable")]
        check("modules", bool(entries) and not broken,
              f"{len(entries)} registered, {len(entries) - len(broken)} importable"
              + (f", broken: {', '.join(broken)}" if broken else ""))
    except Exception as exc:  # noqa: BLE001
        check("modules", False, f"{type(exc).__name__}: {exc}")

    # -- 3. database round trip (throwaway file, never the user's db) ------- #
    try:
        from core.db import open_db

        with tempfile.TemporaryDirectory() as tmp:
            db = open_db(Path(tmp) / "selftest.db")
            try:
                scan_id = db.record(
                    "selftest", "selftest-target",
                    {"ok": True, "summary": "selftest", "findings": [
                        {"severity": "info", "title": "selftest finding", "detail": "round trip"}]},
                    duration_ms=1,
                )
                back = db.get_scan(scan_id)
                stats = db.stats()
                ok = bool(back) and stats["total_scans"] == 1
                check("database", ok,
                      f"wrote scan #{scan_id}, read back {len(back.get('findings', [])) if back else 0} finding(s), "
                      f"{stats['total_scans']} record(s)")
            finally:
                db.close()
    except Exception as exc:  # noqa: BLE001
        check("database", False, f"{type(exc).__name__}: {exc}")

    # -- 4. report rendering ----------------------------------------------- #
    try:
        sample = {
            "ok": True, "module": "selftest", "target": "selftest-target",
            "summary": "selftest report", "risk": "info", "score": 0,
            "findings": [{"severity": "low", "title": "sample", "detail": "sample detail"}],
            "started": now_iso(), "finished": now_iso(), "duration_ms": 1,
        }
        md = report.render_markdown(sample)
        html = report.render_html(sample)
        ok = "selftest-target" in md and "selftest-target" in html and len(html) > len(md)
        check("reports", ok, f"markdown {len(md)}B, html {len(html)}B")
    except Exception as exc:  # noqa: BLE001
        check("reports", False, f"{type(exc).__name__}: {exc}")

    # -- 5. UI layer ------------------------------------------------------- #
    try:
        from core.ui import menu as menu_mod

        required = ("display_banner", "startup_animation", "system_dashboard", "main_menu",
                    "module_menu", "progress_animation", "display_success", "display_error",
                    "clear_terminal")
        missing = [name for name in required if not callable(getattr(ui, name, None))]
        keys = menu_mod.all_keys()
        unresolved = [key for key in keys if key != menu_mod.EXIT_KEY and menu_mod.resolve(key) is None]
        rendered = menu_mod.main_menu()
        ok = not missing and not unresolved and len(keys) == 17 and "KING REAPER X" in rendered
        check("ui", ok,
              f"{len(required) - len(missing)}/{len(required)} functions, "
              f"{len(keys) - len(unresolved)}/{len(keys)} menu keys resolve"
              + (f", missing: {', '.join(missing)}" if missing else ""))
    except Exception as exc:  # noqa: BLE001
        check("ui", False, f"{type(exc).__name__}: {exc}")

    # -- 6. CLI parser ----------------------------------------------------- #
    try:
        parser = build_parser()
        expected = ["menu", "info", "tools", "doctor", "selftest", "status", "history", "show",
                    "config", "dashboard", "audit"] + list(SCAN_VERBS)
        parsed = []
        for verb in expected:
            if verb in SCAN_VERBS or verb == "audit":
                argv = [verb, "example.com"]
            elif verb == "show":
                argv = [verb, "1"]
            else:
                argv = [verb]
            try:
                parser.parse_args(argv)
                parsed.append(verb)
            except SystemExit:
                pass
        ok = len(parsed) == len(expected)
        check("cli", ok, f"{len(parsed)}/{len(expected)} subcommands parse")
    except Exception as exc:  # noqa: BLE001
        check("cli", False, f"{type(exc).__name__}: {exc}")

    # -- 7. authorization gate --------------------------------------------- #
    try:
        result = registry.call("ports", "127.0.0.1", authorized=False)
        refused = (not result.get("ok")) and result.get("error") == "authorization_required"
        check("authorization", refused,
              "unauthorized port scan refused" if refused
              else f"gate did NOT refuse (error={result.get('error')!r})")
    except Exception as exc:  # noqa: BLE001
        check("authorization", False, f"{type(exc).__name__}: {exc}")

    # -- 8. a real module run ---------------------------------------------- #
    try:
        result = registry.call("phone", "+966501234567")
        ok = bool(result.get("ok")) and result.get("e164") == "+966501234567" \
            and (result.get("country") or {}).get("iso") == "SA"
        check("module_run", ok,
              f"phone -> {result.get('summary') or result.get('error')}")
    except Exception as exc:  # noqa: BLE001
        check("module_run", False, f"{type(exc).__name__}: {exc}")

    failures = [item for item in checks if not item["ok"]]
    payload = {"ok": not failures, "version": VERSION, "checks": checks,
               "passed": len(checks) - len(failures), "failed": len(failures)}

    if getattr(args, "json_output", False):
        print(json.dumps(payload, indent=2, default=str))
        return 0 if payload["ok"] else 1

    print(ui.banner(VERSION, compact=True))
    print(ui.section("SELF TEST"))
    for item in checks:
        mark = ui.c("[ok]", ui.GREEN) if item["ok"] else ui.c("[!!]", ui.BLOOD)
        print(f"  {mark} {item['check'].ljust(16)}{item['detail']}")
    print()
    if payload["ok"]:
        print(ui.success(f"all {len(checks)} checks passed"))
    else:
        print(ui.error(f"{len(failures)} of {len(checks)} checks failed"))
    return 0 if payload["ok"] else 1
