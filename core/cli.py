"""KING REAPER X command line interface.

One code path for both entry points: argparse subcommands and the interactive
menu both build an ``argparse.Namespace`` and call the same ``cmd_*`` handlers.
That is why the menu never raises ``AttributeError`` on a flag it forgot.
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

logger = get_logger("cli")

#: subcommand -> module name, for the direct scan verbs
SCAN_VERBS = {
    "phone": "phone",
    "whatsapp": "whatsapp",
    "geoip": "geoip",
    "location": "consented_location",
    "username": "username",
    "domain": "domain",
    "subdomains": "subdomains",
    "ssl": "ssl",
    "ports": "ports",
    "fingerprint": "fingerprint",
    "webscan": "webscan",
    "threat": "threat",
    "deps": "deps",
}

#: flags a module needs, mapped from the CLI namespace
MODULE_OPTION_KEYS = (
    "authorized", "brute", "enrich", "check_contact_status", "shared_by", "ttl_hours",
    "banner", "check_paths", "include_feeds", "online", "max_hosts", "words", "ports",
)


# --------------------------------------------------------------------------- #
# argument plumbing
# --------------------------------------------------------------------------- #


def _common_options(parser: argparse.ArgumentParser) -> None:
    # ``default=SUPPRESS`` is essential: without it the subparser's own default
    # (False) overwrites the value parsed from the global ``reaper --json …``
    # position, so `main.py --json scan` would silently print human output.
    parser.add_argument("--json", dest="json_output", action="store_true",
                        default=argparse.SUPPRESS,
                        help="machine readable JSON on stdout")
    parser.add_argument("--out", dest="out_dir", default=None,
                        help=f"report directory (default {REPORT_DIR})")
    parser.add_argument("--format", dest="formats", default="",
                        help="comma list of json,md,html,print (default: none)")
    parser.add_argument("--quiet", action="store_true", default=argparse.SUPPRESS,
                        help="suppress progress output")
    parser.add_argument("--timeout", type=float, default=None, help="per-request timeout in seconds")
    parser.add_argument("--threads", type=int, default=None, help="worker threads")
    parser.add_argument("--rate", type=float, default=None, help="requests per second limit")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reaper",
        description="KING REAPER X — cyber intelligence & security framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python main.py phone +966501234567\n"
            "  python main.py domain example.com --json\n"
            "  python main.py ports example.com --authorized --ports top\n"
            "  python main.py webscan https://example.com --format html\n"
            "  python main.py dashboard\n"
            "  python main.py menu\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"KING REAPER X {VERSION}")
    parser.add_argument("--accept-terms", action="store_true",
                        help="accept the authorized-use notice without prompting")
    parser.add_argument("--json", dest="json_output", action="store_true", help="JSON output")
    parser.add_argument("--quiet", action="store_true")

    sub = parser.add_subparsers(dest="command")

    # -- discovery / meta -------------------------------------------------- #
    sub.add_parser("menu", help="interactive menu")
    info = sub.add_parser("info", help="framework identity and capability summary")
    info.add_argument("--json", dest="json_output", action="store_true")
    info.add_argument("--quiet", action="store_true")

    tools = sub.add_parser("tools", help="list every module")
    tools.add_argument("--json", dest="json_output", action="store_true")
    tools.add_argument("--quiet", action="store_true")

    doctor = sub.add_parser("doctor", help="environment diagnostics")
    doctor.add_argument("--json", dest="json_output", action="store_true")
    doctor.add_argument("--quiet", action="store_true")

    status = sub.add_parser("status", help="runtime status, database and provider state")
    status.add_argument("--json", dest="json_output", action="store_true")
    status.add_argument("--quiet", action="store_true")

    hist = sub.add_parser("history", help="recent operations")
    hist.add_argument("--limit", type=int, default=20)
    hist.add_argument("--module", default=None)
    hist.add_argument("--json", dest="json_output", action="store_true")
    hist.add_argument("--quiet", action="store_true")

    show = sub.add_parser("show", help="full stored result for one scan id")
    show.add_argument("scan_id", type=int)
    show.add_argument("--json", dest="json_output", action="store_true")
    show.add_argument("--quiet", action="store_true")

    # -- configuration ----------------------------------------------------- #
    cfg = sub.add_parser("config", help="view or change configuration")
    cfg_sub = cfg.add_subparsers(dest="config_action")
    cfg_sub.add_parser("show", help="print current settings (secrets redacted)")
    set_key = cfg_sub.add_parser("set-key", help="store an API key (mode 0600)")
    set_key.add_argument("provider", choices=sorted(PROVIDERS.keys()))
    set_key.add_argument("key", nargs="?", default=None,
                         help="omit to read from stdin, which keeps it out of shell history")
    clear_key = cfg_sub.add_parser("clear-key", help="remove a stored API key")
    clear_key.add_argument("provider", choices=sorted(PROVIDERS.keys()))
    cfg_sub.add_parser("providers", help="provider requirements and signup links")
    set_opt = cfg_sub.add_parser("set", help="set a scalar setting")
    set_opt.add_argument("name")
    set_opt.add_argument("value")
    for action_name in ("show", "providers"):
        pass
    cfg.add_argument("--json", dest="json_output", action="store_true")
    cfg.add_argument("--quiet", action="store_true")

    # -- dashboard --------------------------------------------------------- #
    dash = sub.add_parser("dashboard", help="start the local web dashboard")
    dash.add_argument("--host", default=None)
    dash.add_argument("--port", type=int, default=None)
    dash.add_argument("--allow-public", action="store_true",
                      help="permit binding to a non-loopback interface")
    dash.add_argument("--json", dest="json_output", action="store_true")
    dash.add_argument("--quiet", action="store_true")

    # -- scan verbs -------------------------------------------------------- #
    scan_specs = {
        "phone": ("international phone number", ["--enrich"]),
        "whatsapp": ("WhatsApp business number", ["--check-contact"]),
        "geoip": ("IP address or hostname", []),
        "location": ("lat,lon or a JSON share payload", ["--shared-by"]),
        "username": ("username, or an email address", []),
        "domain": ("domain name", []),
        "subdomains": ("domain name", ["--brute"]),
        "ssl": ("host or host:port", []),
        "ports": ("host or IP", ["--ports"]),
        "fingerprint": ("host or URL", []),
        "webscan": ("host or URL", ["--no-paths"]),
        "threat": ("domain or IP", []),
        "deps": ("optional path (default: project root)", []),
    }
    for verb, (metavar, extras) in scan_specs.items():
        p = sub.add_parser(verb, help=f"run the {SCAN_VERBS[verb]} module")
        p.add_argument("target", nargs="?", default="", metavar=metavar)
        if "--enrich" in extras:
            p.add_argument("--enrich", action="store_true",
                           help="also query numverify when a key is configured")
        if "--check-contact" in extras:
            p.add_argument("--check-contact", action="store_true",
                           help="also run the official WhatsApp contact-status lookup")
        if "--shared-by" in extras:
            p.add_argument("--shared-by", default="", help="name of the person who shared")
            p.add_argument("--ttl-hours", type=int, default=24)
            p.add_argument("--payload", default=None,
                           help="JSON share payload emitted by `location --shared-by`")
        if "--brute" in extras:
            p.add_argument("--brute", action="store_true", help="also brute force (needs --authorized)")
            p.add_argument("--words", default=None, help="path to a custom wordlist")
            p.add_argument("--max-hosts", type=int, default=2000)
        if "--ports" in extras:
            p.add_argument("--ports", default="top", help="top|all|22,80|1-1024")
            p.add_argument("--no-banner", dest="banner", action="store_false", default=True)
        if "--no-paths" in extras:
            p.add_argument("--no-paths", dest="check_paths", action="store_false", default=True)
        if verb == "threat":
            p.add_argument("--no-feeds", dest="include_feeds", action="store_false", default=True)
        if verb == "deps":
            p.add_argument("--offline", dest="online", action="store_false", default=True)
        if verb in ("ports", "subdomains", "webscan"):
            p.add_argument("--authorized", action="store_true",
                           help="confirm you own the target or hold written permission")
        _common_options(p)

    # -- legacy aliases people type from muscle memory --------------------- #
    audit = sub.add_parser("audit", help="run a full non-invasive assessment of one target")
    audit.add_argument("target")
    audit.add_argument("--authorized", action="store_true")
    audit.add_argument("--json", dest="json_output", action="store_true")
    audit.add_argument("--quiet", action="store_true")
    audit.add_argument("--out", dest="out_dir", default=None)

    return parser


def _namespace(**overrides: Any) -> argparse.Namespace:
    """A complete namespace so menu handlers never hit a missing attribute."""
    base: Dict[str, Any] = {
        "command": None,
        "target": "",
        "json_output": False,
        "quiet": False,
        "out_dir": None,
        "formats": "",
        "timeout": None,
        "threads": None,
        "rate": None,
        "accept_terms": False,
        "authorized": False,
        "brute": False,
        "enrich": False,
        "check_contact_status": False,
        "shared_by": "",
        "ttl_hours": 24,
        "payload": None,
        "banner": True,
        "check_paths": True,
        "include_feeds": True,
        "online": True,
        "max_hosts": 2000,
        "words": None,
        "ports": "top",
        "limit": 20,
        "module": None,
        "scan_id": 0,
        "host": None,
        "port": None,
        "allow_public": False,
        "config_action": None,
        "provider": None,
        "key": None,
        "name": None,
        "value": None,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


# --------------------------------------------------------------------------- #
# output helpers
# --------------------------------------------------------------------------- #


def emit(payload: Dict[str, Any], args: argparse.Namespace, exit_code: Optional[int] = None) -> int:
    """Print a result as JSON or human text, and return the exit code."""
    if getattr(args, "json_output", False):
        print(json.dumps(payload, indent=2, default=str))
    return exit_code if exit_code is not None else (0 if payload.get("ok") else 1)


def _print_findings(findings: List[Dict[str, Any]]) -> None:
    if not findings:
        print(ui.hint("no findings"))
        return
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for item in sorted(findings, key=lambda f: order.get(str(f.get("severity", "info")).lower(), 9)):
        color = {
            "critical": ui.BLOOD, "high": ui.BLOOD, "medium": ui.YELLOW,
            "low": ui.GREY, "info": ui.GRAPHITE,
        }.get(str(item.get("severity", "info")).lower(), ui.GREY)
        print(f"  {ui.c(str(item.get('severity', 'info')).upper().ljust(8), color)}"
              f"{item.get('title', '')}")
        detail = item.get("detail")
        if detail:
            print(ui.hint(truncate(str(detail), 160)))


def _render_result(result: Dict[str, Any], args: argparse.Namespace, module_name: str) -> None:
    if getattr(args, "json_output", False):
        return
    print(ui.section(module_name.upper()))
    print(ui.kv("target", result.get("target", "")))
    if result.get("degraded"):
        print(ui.kv("status", ui.c("DEGRADED", ui.YELLOW)))
    else:
        print(ui.kv("status", ui.status_badge(bool(result.get("ok")))))
    if result.get("summary"):
        print(ui.kv("summary", result["summary"]))
    if not result.get("ok"):
        print(ui.error(f"{result.get('error')}: {result.get('message', '')}"))
        hint = result.get("hint")
        if hint:
            print(ui.hint(str(hint)))
        return
    # A provider-backed module that is missing its key must say so plainly
    # rather than looking like a successful empty result.
    if result.get("degraded"):
        print()
        print(ui.warn(str(result.get("message") or "optional provider not configured")))
        requires = result.get("requires") or result.get("requires_key")
        if requires:
            print(ui.hint(f"required: {requires}"))
        if result.get("hint"):
            print(ui.hint(f"→ {result['hint']}"))
        for step in result.get("steps") or []:
            print(ui.hint(f"  · {step}"))
    if result.get("risk"):
        print(ui.kv("risk", f"{result['risk']} (score {result.get('score', 0)}/100)"))
    print()
    print(ui.c("  findings", ui.WHITE + ui.BOLD))
    _print_findings(result.get("findings") or [])


def _maybe_write_reports(result: Dict[str, Any], args: argparse.Namespace) -> Dict[str, str]:
    wanted = [item.strip().lower() for item in str(getattr(args, "formats", "") or "").split(",") if item.strip()]
    if not wanted:
        return {}
    directory = Path(args.out_dir) if getattr(args, "out_dir", None) else None
    paths: Dict[str, str] = {}
    if "all" in wanted:
        return report.write_all(result, directory)
    if "json" in wanted:
        paths["json"] = str(report.write_json(result, (directory or REPORT_DIR) / "report.json"))
    if wanted and any(item in ("md", "markdown") for item in wanted):
        paths["markdown"] = str(report.write_markdown(result, (directory or REPORT_DIR) / "report.md"))
    if "html" in wanted:
        paths["html"] = str(report.write_html(result, (directory or REPORT_DIR) / "report.html"))
    if "print" in wanted:
        paths["print_html"] = str(
            report.write_html(result, (directory or REPORT_DIR) / "report_print.html", printable=True)
        )
    if paths and not getattr(args, "json_output", False):
        print()
        for kind, path in paths.items():
            print(ui.success(f"{kind} report → {path}"))
        if "print_html" in paths:
            print(ui.hint("open the *_print.html file and use your browser's Print → Save as PDF"))
    return paths


# --------------------------------------------------------------------------- #
# scan dispatch
# --------------------------------------------------------------------------- #


def _resolve_options(args: argparse.Namespace) -> Dict[str, Any]:
    config = load_config()
    options: Dict[str, Any] = {
        "config": config,
        "authorized": bool(getattr(args, "authorized", False)),
    }
    timeout = getattr(args, "timeout", None)
    options["timeout"] = float(timeout if timeout is not None else config.get_float("timeout", 8.0))
    threads = getattr(args, "threads", None)
    options["threads"] = int(threads if threads is not None else config.get_int("threads", 16))
    for key in MODULE_OPTION_KEYS:
        if hasattr(args, key) and key not in options:
            options[key] = getattr(args, key)
    if getattr(args, "check_contact", False):
        options["check_contact_status"] = True
    if getattr(args, "payload", None):
        try:
            options["payload"] = json.loads(args.payload)
        except ValueError:
            options["payload"] = None
    return options


def cmd_scan(args: argparse.Namespace) -> int:
    verb = args.command
    module_name = SCAN_VERBS.get(verb or "")
    if not module_name:
        return 1
    config = load_config()
    ui.set_color(config.get_bool("color", True) and not getattr(args, "quiet", False))

    refusal = require_terms(config, args)
    if refusal:
        print(json.dumps(refusal) if getattr(args, "json_output", False) else ui.error(refusal["message"]))
        if not getattr(args, "json_output", False):
            print(ui.hint("add --accept-terms to continue"))
        return 2

    target = str(getattr(args, "target", "") or "")
    if not target and module_name != "deps":
        payload = {"ok": False, "error": "missing_target", "message": f"{verb} needs a target."}
        print(json.dumps(payload) if getattr(args, "json_output", False) else ui.error(payload["message"]))
        return 2

    if module_name in ACTIVE_MODULES or module_name == "ports":
        gate = require_authorization(target, bool(options_authorized(args)), module_name)
        if gate and module_name == "ports":
            print(json.dumps(gate) if getattr(args, "json_output", False) else ui.error(gate["message"]))
            if not getattr(args, "json_output", False):
                print(ui.hint("only scan systems you own or are authorised to test"))
            return 3

    options = _resolve_options(args)
    started = elapsed_ms_start()
    result = registry.call(module_name, target, **options)
    duration = elapsed_ms(started)
    result["duration_ms"] = duration

    db = open_db()
    try:
        scan_id = db.record(module_name, target, result, duration_ms=duration)
        result["scan_id"] = scan_id
        AuditLogger(db).log(f"scan:{module_name}", target, f"id={scan_id} ok={result.get('ok')}")
    except Exception as exc:  # noqa: BLE001 - persistence must not hide the scan result
        logger.warning("could not persist scan: %s", exc)
    finally:
        db.close()

    if not getattr(args, "json_output", False):
        print(ui.banner(VERSION, compact=True))
    _render_result(result, args, module_name)
    paths = _maybe_write_reports(result, args)
    if paths:
        result["reports"] = paths
    return emit(result, args)


def options_authorized(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "authorized", False))


def elapsed_ms_start() -> float:
    import time

    return time.time()


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


def cmd_status(args: argparse.Namespace) -> int:
    from dashboard.server import system_snapshot

    db = open_db()
    try:
        snapshot = system_snapshot(load_config(), db)
    finally:
        db.close()
    if getattr(args, "json_output", False):
        print(json.dumps(snapshot, indent=2, default=str))
        return 0
    print(ui.banner(VERSION, compact=True))
    host = snapshot["host"]
    print(ui.kv("host", f"{host['hostname']} ({host['machine']}, python {host['python']})"))
    print(ui.kv("termux", "yes" if host["is_termux"] else "no"))
    print(ui.kv("modules", f"{len(snapshot['modules'])} registered"))
    print(ui.kv("operations", snapshot["database"]["total_scans"]))
    print(ui.kv("database", snapshot["database"]["db_path"]))
    print(ui.kv("log", str(log_path())))
    print(ui.kv("providers", f"{snapshot['providers_configured']}/{snapshot['providers_total']} configured"))
    for row in snapshot["providers"]:
        state = ui.c(row["source"] or "not set", ui.GREEN if row["configured"] else ui.GRAPHITE)
        print(ui.hint(f"{row['provider'].ljust(16)}{state}"))
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    db = open_db()
    try:
        rows = db.recent_scans(limit=int(getattr(args, "limit", 20) or 20),
                               module=getattr(args, "module", None))
    finally:
        db.close()
    if getattr(args, "json_output", False):
        print(json.dumps({"ok": True, "scans": rows}, indent=2, default=str))
        return 0
    if not rows:
        print(ui.warn("no operations recorded yet"))
        return 0
    print(ui.table(
        ["id", "module", "target", "status", "risk", "score", "when"],
        [[r["id"], r["module"], truncate(str(r["target"]), 34), r["status"],
          r.get("risk") or "-", r.get("score") if r.get("score") is not None else "-",
          r["created_at"]] for r in rows],
    ))
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    db = open_db()
    try:
        scan = db.get_scan(int(getattr(args, "scan_id", 0) or 0))
    finally:
        db.close()
    if scan is None:
        payload = {"ok": False, "error": "not_found", "message": "no scan with that id"}
        print(json.dumps(payload) if getattr(args, "json_output", False) else ui.error(payload["message"]))
        return 1
    if getattr(args, "json_output", False):
        print(json.dumps(scan, indent=2, default=str))
        return 0
    print(ui.section(f"SCAN {scan['id']}"))
    print(ui.kv("module", scan["module"]))
    print(ui.kv("target", scan["target"]))
    print(ui.kv("created", scan["created_at"]))
    print(ui.kv("risk", f"{scan.get('risk')} ({scan.get('score')})"))
    print(ui.kv("summary", truncate(str(scan.get("summary") or ""), 200)))
    print()
    _print_findings(scan.get("findings") or [])
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    config = load_config()
    action = getattr(args, "config_action", None) or "show"
    json_mode = getattr(args, "json_output", False)

    if action == "show":
        payload = {"ok": True, **config.as_dict(redact=True),
                   "config_path": str(config.path),
                   "mode_secure": config.mode_is_secure()}
        if json_mode:
            print(json.dumps(payload, indent=2, default=str))
            return 0
        print(ui.section("CONFIGURATION"))
        print(ui.kv("file", str(config.path)))
        print(ui.kv("permissions", "0600" if config.mode_is_secure() else "NOT 0600 — fix with chmod 600"))
        for key, value in config.as_dict(redact=True).items():
            print(ui.kv(key, value))
        return 0

    if action == "providers":
        rows = config.provider_report()
        if json_mode:
            print(json.dumps({"ok": True, "providers": rows}, indent=2))
            return 0
        print(ui.table(
            ["provider", "state", "env var", "free tier"],
            [[r["provider"], r["source"] or "not set", r["env_var"], r["free_tier"] or "-"] for r in rows],
        ))
        print()
        for row in rows:
            print(ui.hint(f"{row['provider']}: {row['purpose']}"))
            if row["signup"]:
                print(ui.hint(f"  key: {row['signup']}"))
        return 0

    if action == "set-key":
        provider = args.provider
        key = args.key
        if not key:
            if sys.stdin.isatty():
                import getpass

                key = getpass.getpass(f"{provider} API key (input hidden): ").strip()
            else:
                key = sys.stdin.read().strip()
        if not key:
            print(ui.error("no key supplied"))
            return 2
        config.set_api_key(provider, key)
        payload = {"ok": True, "provider": provider, "stored": str(config.path),
                   "mode_secure": config.mode_is_secure()}
        if json_mode:
            print(json.dumps(payload, indent=2))
        else:
            print(ui.success(f"{provider} key stored in {config.path} (mode 0600)"))
            print(ui.hint("environment variables override the stored value"))
        return 0

    if action == "clear-key":
        config.clear_api_key(args.provider)
        if json_mode:
            print(json.dumps({"ok": True, "provider": args.provider, "cleared": True}))
        else:
            print(ui.success(f"{args.provider} key removed"))
        return 0

    if action == "set":
        name = str(args.name or "").strip()
        if not name:
            print(ui.error("setting name required"))
            return 2
        raw = args.value
        current = config.get(name)
        if isinstance(current, bool):
            value: Any = str(raw).strip().lower() in ("1", "true", "yes", "on")
        elif isinstance(current, int):
            try:
                value = int(raw)
            except (TypeError, ValueError):
                print(ui.error(f"{name} expects an integer"))
                return 2
        elif isinstance(current, float):
            try:
                value = float(raw)
            except (TypeError, ValueError):
                print(ui.error(f"{name} expects a number"))
                return 2
        else:
            value = raw
        config.set(name, value)
        config.save()
        if json_mode:
            print(json.dumps({"ok": True, "name": name, "value": value}))
        else:
            print(ui.success(f"{name} = {value}"))
        return 0

    print(ui.error(f"unknown config action: {action}"))
    return 2


def cmd_dashboard(args: argparse.Namespace) -> int:
    from dashboard.server import serve

    config = load_config()
    host = getattr(args, "host", None) or config.get("dashboard_host", "127.0.0.1")
    port = int(getattr(args, "port", None) or config.get_int("dashboard_port", 8899))
    allow_public = bool(getattr(args, "allow_public", False))

    try:
        server, thread = serve(host=host, port=port, config=config,
                               allow_public=allow_public,
                               quiet=bool(getattr(args, "quiet", False)), block=False)
    except ValueError as exc:
        payload = {"ok": False, "error": "unsafe_bind", "message": str(exc)}
        print(json.dumps(payload) if getattr(args, "json_output", False) else ui.error(str(exc)))
        if not getattr(args, "json_output", False):
            print(ui.hint("use --allow-public to override"))
        return 2
    except OSError as exc:
        payload = {"ok": False, "error": "bind_failed", "message": str(exc)}
        print(json.dumps(payload) if getattr(args, "json_output", False) else ui.error(str(exc)))
        if not getattr(args, "json_output", False):
            print(ui.hint(f"port {port} may already be in use; try --port 8900"))
        return 2

    url = f"http://{host}:{port}/"
    payload = {"ok": True, "url": url, "host": host, "port": port}
    if getattr(args, "json_output", False):
        print(json.dumps(payload, indent=2))
    else:
        print(ui.banner(VERSION, compact=True))
        print(ui.success(f"dashboard listening on {url}"))
        print(ui.hint(f"binding: {host} — data: local SQLite only"))
        print(ui.hint("Ctrl+C to stop"))
    try:
        while thread.is_alive():
            import time as _time

            _time.sleep(0.5)
    except KeyboardInterrupt:
        print()
        print(ui.info("shutting down"))
    finally:
        server.shutdown()
        server.server_close()
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Run every non-invasive module against one target and bundle the report."""
    config = load_config()
    target = str(getattr(args, "target", "") or "")
    refusal = require_terms(config, args)
    if refusal:
        print(json.dumps(refusal) if getattr(args, "json_output", False) else ui.error(refusal["message"]))
        return 2

    plan = ["domain", "ssl", "fingerprint", "webscan", "threat"]
    results: List[Dict[str, Any]] = []
    for name in plan:
        if not getattr(args, "json_output", False) and not getattr(args, "quiet", False):
            print(ui.info(f"running {name}…"))
        result = registry.call(name, target, config=config, authorized=False)
        results.append(result)

    if getattr(args, "authorized", False):
        result = registry.call("ports", target, config=config, authorized=True, ports="top")
        results.append(result)

    db = open_db()
    try:
        for item in results:
            db.record(item.get("module", "?"), target, item)
        AuditLogger(db).log("scan:audit", target, f"{len(results)} modules")
    finally:
        db.close()

    directory = Path(args.out_dir) if getattr(args, "out_dir", None) else None
    paths = report.write_bundle(results, title=target.replace(".", "_"), directory=directory)

    payload = {
        "ok": all(item.get("ok") for item in results),
        "target": target,
        "modules": len(results),
        "findings": sum(len(item.get("findings") or []) for item in results),
        "results": results,
        "reports": paths,
    }
    if getattr(args, "json_output", False):
        print(json.dumps(payload, indent=2, default=str))
        return 0
    print(ui.banner(VERSION, compact=True))
    for item in results:
        status = ui.c("ok", ui.GREEN) if item.get("ok") else ui.c("fail", ui.BLOOD)
        print(f"  {status.ljust(14)}{item.get('module'):<14}{truncate(str(item.get('summary') or item.get('error')), 90)}")
    print()
    print(ui.success(f"{payload['findings']} finding(s) across {payload['modules']} modules"))
    for kind, path in paths.items():
        if kind == "pdf_note":
            print(ui.hint(path))
        else:
            print(ui.hint(f"{kind}: {path}"))
    return 0


# --------------------------------------------------------------------------- #
# interactive menu
# --------------------------------------------------------------------------- #


def _ask(prompt: str, default: str = "") -> str:
    try:
        value = input(ui.c(f"  {prompt}", ui.BLOOD) + (f" [{default}]" if default else "") + ": ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""
    return value or default


MENU_ITEMS = [
    ("Phone intelligence", lambda: cmd_scan(_namespace(command="phone", target=_ask("international number"))), "phone"),
    ("IP geolocation", lambda: cmd_scan(_namespace(command="geoip", target=_ask("IP or host"))), "geoip"),
    ("Domain intelligence", lambda: cmd_scan(_namespace(command="domain", target=_ask("domain"))), "domain"),
    ("TLS / SSL audit", lambda: cmd_scan(_namespace(command="ssl", target=_ask("host[:port]"))), "ssl"),
    ("Technology fingerprint", lambda: cmd_scan(_namespace(command="fingerprint", target=_ask("host or URL"))), "fingerprint"),
    ("Subdomain discovery", lambda: cmd_scan(_namespace(command="subdomains", target=_ask("domain"))), "subdomains"),
    ("Web security assessment", lambda: cmd_scan(_namespace(command="webscan", target=_ask("host or URL"))), "webscan"),
    ("Username / email OSINT", lambda: cmd_scan(_namespace(command="username", target=_ask("username or email"))), "username"),
    ("Threat intelligence", lambda: cmd_scan(_namespace(command="threat", target=_ask("domain or IP"))), "threat"),
    ("Dependency audit", lambda: cmd_scan(_namespace(command="deps", target="")), "deps"),
]


def cmd_menu(args: argparse.Namespace) -> int:
    config = load_config()
    ui.set_color(config.get_bool("color", True))
    print(ui.banner(VERSION))
    refusal = request_terms(config, quiet=False)
    if not refusal["accepted"]:
        print(ui.error("terms not accepted — exiting"))
        return 2

    while True:
        print(ui.title("MODULES"))
        for index, (label, _fn, _name) in enumerate(MENU_ITEMS, start=1):
            print(f"    {index:>2}. {label}")
        print(f"    {len(MENU_ITEMS) + 1:>2}. Port scan (requires authorization)")
        print(f"    {len(MENU_ITEMS) + 2:>2}. Status")
        print(f"    {len(MENU_ITEMS) + 3:>2}. History")
        print(f"    {len(MENU_ITEMS) + 4:>2}. Full audit of one target")
        print(f"    {len(MENU_ITEMS) + 5:>2}. Providers / API keys")
        print("     0. Exit")
        choice = _ask("select")
        if not choice or choice == "0":
            print(ui.info("bye"))
            return 0
        if not choice.isdigit():
            print(ui.warn("enter a number"))
            continue
        index = int(choice)
        if 1 <= index <= len(MENU_ITEMS):
            MENU_ITEMS[index - 1][1]()
        elif index == len(MENU_ITEMS) + 1:
            target = _ask("host or IP")
            confirm = _ask(f"confirm you may test {target} (yes/no)")
            if confirm.lower() in ("y", "yes"):
                cmd_scan(_namespace(command="ports", target=target, authorized=True))
            else:
                print(ui.warn("authorization not confirmed — skipped"))
        elif index == len(MENU_ITEMS) + 2:
            cmd_status(_namespace())
        elif index == len(MENU_ITEMS) + 3:
            cmd_history(_namespace(limit=15))
        elif index == len(MENU_ITEMS) + 4:
            target = _ask("domain to audit")
            if target:
                cmd_audit(_namespace(target=target))
        elif index == len(MENU_ITEMS) + 5:
            cmd_config(_namespace(config_action="providers"))
        else:
            print(ui.warn("no such option"))


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #


HANDLERS: Dict[str, Callable[[argparse.Namespace], int]] = {
    "menu": cmd_menu,
    "info": cmd_info,
    "tools": cmd_tools,
    "doctor": cmd_doctor,
    "status": cmd_status,
    "history": cmd_history,
    "show": cmd_show,
    "config": cmd_config,
    "dashboard": cmd_dashboard,
    "audit": cmd_audit,
}


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        print()
        print(ui.hint("tip: `python main.py menu` for the interactive console"))
        return 0

    os.environ.setdefault("REAPER_CLI", "1")

    if args.command in SCAN_VERBS:
        try:
            return cmd_scan(args)
        except KeyboardInterrupt:
            print()
            print(ui.warn("interrupted"))
            return 130
        except ReaperError as exc:
            payload = exc.as_dict()
            print(json.dumps(payload) if getattr(args, "json_output", False) else ui.error(exc.message))
            return 1

    handler = HANDLERS.get(args.command)
    if handler is None:
        parser.print_help()
        return 2
    try:
        return handler(args)
    except KeyboardInterrupt:
        print()
        print(ui.warn("interrupted"))
        return 130
