#!/usr/bin/env python3
"""KING REAPER X launcher.

Run from any working directory: the project root is put on ``sys.path`` first so
``python main.py`` and ``python /path/to/main.py`` both work, which matters on
Termux where people launch from $HOME.

``menu`` (and a bare invocation with no arguments) is routed to the v2.0.0
command-centre console in :mod:`core.ui`. Everything else goes through the
argparse CLI in :mod:`core.cli` unchanged.
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _launch_console(force_accept: bool = False) -> int:
    """Start the interactive console, honouring the terms gate."""
    from core import ui
    from core.cli import request_terms
    from core.config import VERSION, load_config

    config = load_config()
    ui.set_color(config.get_bool("color", True))
    ui.set_animations(config.get_bool("animations", True))

    # --accept-terms is normally handled by argparse, which this path bypasses,
    # so it is honoured here too.
    refusal = request_terms(config, force_accept=force_accept, quiet=False)
    if not refusal["accepted"]:
        print(ui.display_error("terms not accepted — exiting"))
        return 2

    try:
        return ui.run_menu(version=VERSION)
    except KeyboardInterrupt:
        print()
        print(ui.display_warning("interrupted"))
        return 130


def _wants_console(argv) -> bool:
    """True when the console should start.

    A bare invocation opens it, and so does ``menu`` — but global flags may come
    first (``--accept-terms menu``), so the check looks at the first *non-flag*
    token rather than argv[0].
    """
    if not argv:
        return True
    for token in argv:
        if token.startswith("-"):
            continue
        return token == "menu"
    return False


def main() -> int:
    argv = sys.argv[1:]

    # `python main.py`, `python main.py menu` and `python main.py --accept-terms
    # menu` all open the console. `--help`, `--version` and every real
    # subcommand still go to argparse.
    if _wants_console(argv):
        return _launch_console(force_accept="--accept-terms" in argv)

    from core.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
