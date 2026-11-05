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


def _launch_console() -> int:
    """Start the interactive console, honouring the terms gate."""
    from core import ui
    from core.cli import request_terms
    from core.config import VERSION, load_config

    config = load_config()
    ui.set_color(config.get_bool("color", True))
    ui.set_animations(config.get_bool("animations", True))

    refusal = request_terms(config, quiet=False)
    if not refusal["accepted"]:
        print(ui.display_error("terms not accepted — exiting"))
        return 2

    try:
        return ui.run_menu(version=VERSION)
    except KeyboardInterrupt:
        print()
        print(ui.display_warning("interrupted"))
        return 130


def main() -> int:
    argv = sys.argv[1:]

    # A bare `python main.py` and `python main.py menu` both open the console.
    # `--help`, `--version` and every real subcommand still go to argparse.
    if not argv or argv[0] == "menu":
        return _launch_console()

    from core.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
