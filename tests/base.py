"""Shared test support.

``core.config`` resolves its directories at import time, so the isolated HOME
must be in place *before* anything imports it. This module therefore sets the
environment at import time and every test module imports this first.
"""

import atexit
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

#: One sandbox for the whole test session, created before core is imported.
TEST_HOME = tempfile.mkdtemp(prefix="rkx-tests-")
os.environ["HOME"] = TEST_HOME
os.environ["REAPER_CONFIG_DIR"] = os.path.join(TEST_HOME, ".king-reaper-x")
os.environ["REAPER_LOG_DIR"] = os.path.join(TEST_HOME, ".king-reaper-x", "logs")
os.environ["REAPER_REPORT_DIR"] = os.path.join(TEST_HOME, "reports")
os.environ["REAPER_ACCEPT_TERMS"] = "1"
os.environ["NO_COLOR"] = "1"
# tmux/CI hand us a tty with no human behind it; force the non-interactive path
# so a consent test can never hang the suite.
os.environ["REAPER_NONINTERACTIVE"] = "1"
# Keep the suite offline: no provider keys inherited from the developer shell.
for _key in ("NUMVERIFY_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY",
             "SHODAN_API_KEY", "IPINFO_TOKEN", "WHATSAPP_BUSINESS_TOKEN"):
    os.environ.pop(_key, None)


@atexit.register
def _cleanup() -> None:
    shutil.rmtree(TEST_HOME, ignore_errors=True)


class IsolatedHomeCase(unittest.TestCase):
    """Gives each test a clean config file, database and report directory."""

    def setUp(self):
        from core import config
        shutil.rmtree(config.CONFIG_DIR, ignore_errors=True)
        shutil.rmtree(config.REPORT_DIR, ignore_errors=True)
        config.ensure_dirs()
        self.home = TEST_HOME

    def tearDown(self):
        pass
