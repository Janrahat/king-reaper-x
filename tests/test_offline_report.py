"""Offline unit tests: DNS wire format, WHOIS parsing and report rendering.

Nothing here touches the network.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.base import IsolatedHomeCase


class TestDnsWire(IsolatedHomeCase):
    def test_encode_name(self):
        from core.dnsclient import _encode_name
        self.assertEqual(_encode_name("a.com"), b"\x01a\x03com\x00")
        self.assertEqual(_encode_name("a.com."), b"\x01a\x03com\x00")
        self.assertEqual(_encode_name(""), b"\x00")

    def test_label_too_long_rejected(self):
        from core.dnsclient import DnsError, _encode_name
        with self.assertRaises(DnsError):
            _encode_name("a" * 64 + ".com")

    def test_build_query_header(self):
        from core.dnsclient import _build_query
        packet = _build_query("example.com", "A", 0x1234)
        self.assertEqual(packet[:2], b"\x12\x34")
        self.assertEqual(packet[4:6], b"\x00\x01")  # one question
        self.assertTrue(packet.endswith(b"\x00\x01\x00\x01"))


class TestWhoisParsing(unittest.TestCase):
    def test_fields_and_dedup(self):
        from core.whois_client import parse_whois
        text = (
            "% comment line\n"
            "Domain Name: EXAMPLE.COM\n"
            "Registrar: Example Registrar\n"
            "Name Server: NS1.EXAMPLE.COM\n"
            "Name Server: ns1.example.com\n"
            "Name Server: NS2.EXAMPLE.COM\n"
        )
        parsed = parse_whois(text)
        self.assertEqual(parsed["domain"], "EXAMPLE.COM")
        self.assertEqual(parsed["registrar"], "Example Registrar")
        self.assertEqual(len(parsed["name_servers"]), 2)

    def test_empty_input(self):
        from core.whois_client import parse_whois
        self.assertEqual(parse_whois(""), {})


class TestReport(IsolatedHomeCase):
    RESULT = {
        "ok": True, "module": "dns", "target": "example.com",
        "started": "2026-01-01T00:00:00Z", "finished": "2026-01-01T00:00:01Z",
        "risk": "medium", "score": 40, "summary": "two findings",
        "findings": [
            {"severity": "low", "title": "Low one", "detail": "d"},
            {"severity": "high", "title": "High one", "detail": "d"},
        ],
    }

    def test_json_roundtrip(self):
        import json
        from core import report
        path = report.write_json(self.RESULT)
        self.assertTrue(path.exists())
        self.assertEqual(json.loads(path.read_text())["target"], "example.com")

    def test_markdown_orders_by_severity(self):
        from core import report
        md = report.render_markdown(self.RESULT)
        self.assertLess(md.index("High one"), md.index("Low one"))

    def test_html_escapes_target(self):
        from core import report
        evil = dict(self.RESULT, target="<script>alert(1)</script>")
        html = report.render_html(evil)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_write_all_produces_every_format(self):
        from core import report
        out = report.write_all(self.RESULT)
        # json + markdown + html + print-html; pdf_note is a hint, not a file.
        for key in ("json", "markdown", "html", "print_html"):
            self.assertIn(key, out)
            self.assertTrue(os.path.exists(out[key]), key)
        self.assertIn("pdf_note", out)
        self.assertFalse(os.path.exists(out["pdf_note"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
