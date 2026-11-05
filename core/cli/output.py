"""KING REAPER X command line interface — output layer.

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

logger = get_logger("cli")

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
        print(f"  {ui.c(str(item.get('severity', 'info')).upper().ljust(8)}"
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
