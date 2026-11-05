"""KING REAPER X command line interface.

The implementation is split across layers; this package re-exports the public
surface so ``from core.cli import build_parser, main`` is unchanged.
"""

from core.cli.parser import (  # noqa: F401
    MODULE_OPTION_KEYS,
    SCAN_VERBS,
    _common_options,
    _namespace,
    build_parser,
)
from core.cli.output import (  # noqa: F401
    _maybe_write_reports,
    _print_findings,
    _render_result,
    emit,
)
from core.cli.scan import (  # noqa: F401
    _resolve_options,
    cmd_scan,
    elapsed_ms_start,
    options_authorized,
)
from core.cli.meta import (  # noqa: F401
    cmd_doctor,
    cmd_info,
    cmd_selftest,
    cmd_tools,
)
from core.cli.admin import (  # noqa: F401
    cmd_audit,
    cmd_config,
    cmd_dashboard,
    cmd_history,
    cmd_show,
    cmd_status,
)
from core.cli.menu import (  # noqa: F401
    HANDLERS,
    _ask,
    cmd_menu,
    main,
)

__all__ = [
    "build_parser", "main", "HANDLERS", "SCAN_VERBS", "MODULE_OPTION_KEYS",
    "cmd_scan", "cmd_info", "cmd_tools", "cmd_doctor", "cmd_selftest",
    "cmd_status", "cmd_history", "cmd_show", "cmd_config", "cmd_dashboard",
    "cmd_audit", "cmd_menu", "emit",
]
