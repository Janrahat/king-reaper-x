"""KING REAPER X command line interface — scan layer.

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

from core.cli.output import _maybe_write_reports, _render_result, emit
from core.cli.parser import MODULE_OPTION_KEYS, SCAN_VERBS, build_parser

logger = get_logger("cli")

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
