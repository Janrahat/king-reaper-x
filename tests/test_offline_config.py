"""Offline unit tests: config, consent and the scan database.

Nothing here touches the network.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.base import IsolatedHomeCase


class TestConfig(IsolatedHomeCase):
    def test_roundtrip_and_types(self):
        from core.config import Config
        cfg = Config()
        cfg.set("threads", 8)
        cfg.set("rate_limit", 1.5)
        cfg.set("verbose", True)
        cfg.save()
        again = Config()
        self.assertEqual(again.get_int("threads"), 8)
        self.assertEqual(again.get_float("rate_limit"), 1.5)
        self.assertTrue(again.get_bool("verbose"))

    def test_defaults_when_missing(self):
        from core.config import Config
        cfg = Config()
        self.assertEqual(cfg.get("nope", "fallback"), "fallback")
        self.assertEqual(cfg.get_int("nope", 3), 3)
        self.assertFalse(cfg.get_bool("nope"))

    def test_api_key_never_plain_in_redacted_dump(self):
        from core.config import Config
        cfg = Config()
        cfg.set_api_key("virustotal", "vt-" + "0123456789abcdef")
        dump = str(cfg.as_dict(redact=True))
        self.assertNotIn("0123456789abcdef", dump)
        self.assertEqual(cfg.api_key("virustotal"), "vt-" + "0123456789abcdef")

    def test_clear_api_key(self):
        from core.config import Config
        cfg = Config()
        cfg.set_api_key("shodan", "sh-" + "abcdef0123456789")
        cfg.clear_api_key("shodan")
        self.assertIsNone(cfg.api_key("shodan"))


class TestConsent(IsolatedHomeCase):
    def test_terms_flag_short_circuits(self):
        from core import consent
        from core.config import Config
        os.environ["REAPER_ACCEPT_TERMS"] = "1"
        self.assertTrue(consent.terms_accepted(Config()))

    def test_terms_persisted(self):
        from core import consent
        from core.config import Config
        os.environ.pop("REAPER_ACCEPT_TERMS", None)
        cfg = Config()
        self.assertFalse(consent.terms_accepted(cfg))
        cfg.set("consent_accepted", True)
        cfg.save()
        self.assertTrue(consent.terms_accepted(Config()))
        os.environ["REAPER_ACCEPT_TERMS"] = "1"

    def test_noninteractive_never_prompts(self):
        from core import consent
        self.assertFalse(consent.is_interactive())


class TestDatabase(IsolatedHomeCase):
    def test_record_and_read_back(self):
        from core.db import open_db
        db = open_db()
        sid = db.record(
            "dns", "example.com",
            {"ok": True, "risk": "low", "score": 10, "summary": "fine"},
            duration_ms=12,
            findings=[{"severity": "low", "title": "t", "detail": "d"}],
        )
        self.assertIsInstance(sid, int)
        scan = db.get_scan(sid)
        self.assertEqual(scan["module"], "dns")
        self.assertEqual(scan["status"], "ok")
        self.assertEqual(db.severity_counts(sid)["low"], 1)
        db.close()

    def test_error_status_recorded(self):
        from core.db import open_db
        db = open_db()
        sid = db.record("dns", "x", {"ok": False, "error": "boom"})
        self.assertEqual(db.get_scan(sid)["status"], "error")
        db.close()

    def test_assets_upsert_is_idempotent(self):
        from core.db import open_db
        db = open_db()
        db.remember_asset("example.com", "ip", "1.2.3.4")
        db.remember_asset("example.com", "ip", "1.2.3.4")
        self.assertEqual(len(db.assets("example.com")), 1)
        db.close()

    def test_clear_empties_tables(self):
        from core.db import open_db
        db = open_db()
        db.record("dns", "x", {"ok": True})
        db.clear()
        self.assertEqual(db.recent_scans(), [])
        db.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
