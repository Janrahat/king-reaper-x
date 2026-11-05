#!/usr/bin/env python3
"""KING REAPER X launcher.

Run from any working directory: the project root is put on ``sys.path`` first so
``python main.py`` and ``python /path/to/main.py`` both work, which matters on
Termux where people launch from $HOME.
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.cli import main  # noqa: E402 - path must be set first

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
