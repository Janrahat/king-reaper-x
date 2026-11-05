"""KING REAPER X command line interface — menu layer.

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

from core.cli.admin import (
    cmd_audit, cmd_config, cmd_dashboard, cmd_history, cmd_show, cmd_status,
)
from core.cli.meta import cmd_doctor, cmd_info, cmd_selftest, cmd_tools
from core.cli.parser import SCAN_VERBS, _namespace, build_parser
from core.cli.scan import cmd_scan

logger = get_logger("cli")

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
    "selftest": cmd_selftest,
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
