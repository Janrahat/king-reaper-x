"""Offline unit tests: parsing, validation, storage, consent, reporting.

Nothing in this module touches the network, so it must stay green with no
connectivity and no provider keys configured.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.base import IsolatedHomeCase


class TestPhoneCodes(unittest.TestCase):
    def test_split_international(self):
        from data import phone_codes as pc
        self.assertEqual(pc.split_international("966501234567"), ("966", "501234567"))
        self.assertEqual(pc.split_international("919876543210"), ("91", "9876543210"))

    def test_three_digit_code_wins(self):
        from data import phone_codes as pc
        # +971 (UAE) must not be parsed as +97 (which is unassigned here).
        self.assertEqual(pc.split_international("971501234567")[0], "971")

    def test_nanp_territory_not_swallowed_by_one(self):
        from data import phone_codes as pc
        self.assertEqual(pc.resolve_nanp("2425551234")[0], "BS")
        self.assertEqual(pc.resolve_nanp("4155552671")[0], "US")

    def test_lookup_calling_code(self):
        from data import phone_codes as pc
        self.assertEqual(pc.lookup_calling_code("966"), ("SA", "Saudi Arabia", "+966"))
        self.assertIsNone(pc.lookup_calling_code("999"))

    def test_length_hint(self):
        from data import phone_codes as pc
        hint = pc.length_hint("966")
        self.assertIsNotNone(hint)
        self.assertEqual(len(hint), 2)

    def test_no_digits(self):
        from data import phone_codes as pc
        self.assertEqual(pc.split_international(""), (None, None))
        self.assertEqual(pc.split_international("abc"), (None, None))


class TestPhoneIntel(unittest.TestCase):
    def analyse(self, raw):
        from modules.mobile_intelligence import phone_intel
        return phone_intel.analyse(raw)

    def test_valid_saudi_mobile(self):
        r = self.analyse("+966501234567")
        self.assertTrue(r["ok"])
        self.assertEqual(r["e164"], "+966501234567")
        self.assertEqual(r["country"]["iso"], "SA")
        self.assertEqual(r["country"]["calling_code"], "+966")
        self.assertEqual(r["line_type"], "mobile")

    def test_formatted_variant_normalises(self):
        r = self.analyse("+1 (415) 555-2671")
        self.assertTrue(r["ok"])
        self.assertEqual(r["e164"], "+14155552671")
        self.assertEqual(r["country"]["iso"], "US")

    def test_landline_detected(self):
        r = self.analyse("+966112345678")
        self.assertTrue(r["ok"])
        self.assertEqual(r["line_type"], "landline")

    def test_formats_block_present(self):
        r = self.analyse("+966501234567")
        self.assertIn("formats", r)
        self.assertTrue(r["formats"])

    def test_rejects_empty_and_garbage(self):
        for bad in ("", "   ", "abc", "+"):
            r = self.analyse(bad)
            self.assertFalse(r["ok"], bad)
            self.assertTrue(r.get("error"))
            self.assertTrue(r.get("message"))

    def test_00_prefix_equals_plus(self):
        r = self.analyse("00966501234567")
        self.assertTrue(r["ok"])
        self.assertEqual(r["e164"], "+966501234567")

    def test_extension_captured(self):
        r = self.analyse("+966501234567 ext 42")
        self.assertTrue(r["ok"])
        self.assertEqual(r["normalised"]["extension"], "42")

    def test_analysis_never_raises_on_odd_input(self):
        from modules.mobile_intelligence import phone_intel
        for weird in ("+++", "١٢٣", "0", "tel:+966501234567", "x" * 100):
            phone_intel.analyse(weird)  # must simply not raise


class TestValidation(unittest.TestCase):
    def test_domain(self):
        from core import utils
        self.assertTrue(utils.is_domain("example.com"))
        self.assertTrue(utils.is_domain("sub.example.co.uk"))
        for bad in ("", "example", "-bad.com", "a..b", "http://x.com", "x .com"):
            self.assertFalse(utils.is_domain(bad), bad)

    def test_ip(self):
        from core import utils
        self.assertTrue(utils.is_ip("8.8.8.8"))
        self.assertTrue(utils.is_ip("2001:4860:4860::8888"))
        for bad in ("999.1.1.1", "8.8.8", "example.com", ""):
            self.assertFalse(utils.is_ip(bad), bad)

    def test_private_ip(self):
        from core import utils
        self.assertTrue(utils.is_private_ip("10.0.0.1"))
        self.assertTrue(utils.is_private_ip("192.168.1.1"))
        self.assertTrue(utils.is_private_ip("127.0.0.1"))
        self.assertFalse(utils.is_private_ip("8.8.8.8"))

    def test_email(self):
        from core import utils
        self.assertTrue(utils.is_email("a.b@example.com"))
        self.assertFalse(utils.is_email("nope"))
        self.assertFalse(utils.is_email("a@b"))
        self.assertFalse(utils.is_email(""))

    def test_parse_ports(self):
        from core import utils
        self.assertEqual(utils.parse_ports("80,443"), [80, 443])
        self.assertEqual(utils.parse_ports("100-102"), [100, 101, 102])
        self.assertEqual(utils.parse_ports("90-88"), [88, 89, 90])
        self.assertEqual(utils.parse_ports("80,80,80"), [80])
        self.assertGreater(len(utils.parse_ports("top")), 10)
        self.assertGreater(len(utils.parse_ports("all")), 1000)
        for bad in ("abc", "0", "70000", "10-"):
            with self.assertRaises(ValueError, msg=bad):
                utils.parse_ports(bad)

    def test_service_name(self):
        from core import utils
        self.assertEqual(utils.service_name(443), "https")
        self.assertTrue(utils.service_name(65000))

    def test_mask_secret(self):
        from core import utils
        masked = utils.mask_secret("sk-abcdefghijklmnop")
        self.assertNotIn("abcdefghij", masked)
        self.assertLessEqual(len(masked), 16)


class TestRateLimiter(unittest.TestCase):
    def test_disabled_is_noop(self):
        import time
        from core.utils import RateLimiter
        limiter = RateLimiter(0)
        start = time.monotonic()
        for _ in range(20):
            limiter.wait()
        self.assertLess(time.monotonic() - start, 0.5)

    def test_enforces_interval(self):
        import time
        from core.utils import RateLimiter
        limiter = RateLimiter(50)  # 20 ms apart
        start = time.monotonic()
        limiter.wait()
        limiter.wait()
        limiter.wait()
        self.assertGreaterEqual(time.monotonic() - start, 0.03)


class TestRunThreaded(unittest.TestCase):
    def test_order_preserved_and_errors_isolated(self):
        from core.utils import run_threaded

        def work(item):
            if item == 2:
                raise ValueError("boom")
            return item * 10

        results = run_threaded(work, [1, 2, 3], threads=3)
        self.assertEqual([r[0] for r in results], [1, 2, 3])
        by_item = {r[0]: r for r in results}
        self.assertEqual(by_item[1][1], 10)
        self.assertIsNone(by_item[2][1])
        self.assertIn("boom", str(by_item[2][2]))
        self.assertEqual(by_item[3][1], 30)


class TestRegistryNormalisation(unittest.TestCase):
    def test_envelope_guaranteed(self):
        from core import registry
        out = registry.normalize({"findings": []}, "dns", "example.com", "2026-01-01T00:00:00Z")
        for key in ("ok", "module", "target", "started", "finished", "findings", "risk"):
            self.assertIn(key, out)

    def test_worst_severity_wins(self):
        from core import registry
        out = registry.normalize(
            {"findings": [{"severity": "low"}, {"severity": "critical"}]},
            "webscan", "x", "t0",
        )
        self.assertEqual(out["risk"], "critical")

    def test_bad_module_return_handled(self):
        from core import registry
        out = registry.normalize("not a dict", "x", "t", "t0")
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], "bad_module_return")


class TestDatabase(IsolatedHomeCase):
    def test_record_and_fetch(self):
        from core import db
        conn = db.open_db()
        scan_id = conn.record("phone", "+966501234567", {"ok": True, "summary": "ok"})
        self.assertGreater(scan_id, 0)
        rows = conn.recent_scans(limit=10)
        self.assertGreaterEqual(len(rows), 1)
        got = conn.get_scan(scan_id)
        self.assertIsNotNone(got)
        self.assertEqual(got["target"], "+966501234567")

    def test_missing_scan_returns_none(self):
        from core import db
        self.assertIsNone(db.open_db().get_scan(999999))

    def test_stats_and_modules(self):
        from core import db
        conn = db.open_db()
        conn.record("dns", "example.com", {"ok": True})
        conn.record("dns", "example.org", {"ok": True})
        stats = conn.stats()
        self.assertGreaterEqual(stats["total_scans"], 2)
        modules = {row["module"] for row in stats["by_module"]}
        self.assertIn("dns", modules)

    def test_findings_stored(self):
        from core import db
        conn = db.open_db()
        sid = conn.record("webscan", "https://x", {"ok": True},
                          findings=[{"severity": "high", "title": "CSP missing"}])
        counts = conn.severity_counts(sid)
        self.assertEqual(counts.get("high"), 1)

    def test_audit_log(self):
        from core import db
        conn = db.open_db()
        conn.audit("test.action", target="example.com", detail="unit")
        rows = conn.audit_log(limit=5)
        self.assertTrue(any(r["action"] == "test.action" for r in rows))

    def test_payload_roundtrip(self):
        from core import db
        conn = db.open_db()
        sid = conn.record("t", "x", {"ok": True, "nested": {"a": [1, 2, 3]}})
        self.assertEqual(conn.get_scan(sid)["payload"]["nested"]["a"], [1, 2, 3])

    def test_filter_by_module(self):
        from core import db
        conn = db.open_db()
        conn.record("aaa", "t1", {"ok": True})
        conn.record("bbb", "t2", {"ok": True})
        rows = conn.recent_scans(limit=10, module="aaa")
        self.assertTrue(all(r["module"] == "aaa" for r in rows))
        self.assertGreaterEqual(len(rows), 1)


class TestConsent(IsolatedHomeCase):
    def test_env_accepts_terms(self):
        from core import consent, config
        cfg = config.load_config()
        self.assertTrue(consent.terms_accepted(cfg))

    def test_terms_gate_persists(self):
        from core import consent, config
        saved = os.environ.pop("REAPER_ACCEPT_TERMS", None)
        self.addCleanup(lambda: os.environ.__setitem__("REAPER_ACCEPT_TERMS", saved)
                        if saved is not None else None)
        cfg = config.load_config()
        self.assertFalse(consent.terms_accepted(cfg))
        consent.request_terms(cfg, force_accept=True, quiet=True)
        cfg.reload()
        self.assertTrue(consent.terms_accepted(cfg))

    def test_require_terms_returns_none_when_accepted(self):
        from core import consent, config
        self.assertIsNone(consent.require_terms(config.load_config()))

    def test_require_terms_blocks_and_is_machine_readable(self):
        from core import consent, config
        saved = os.environ.pop("REAPER_ACCEPT_TERMS", None)
        self.addCleanup(lambda: os.environ.__setitem__("REAPER_ACCEPT_TERMS", saved)
                        if saved is not None else None)
        failure = consent.require_terms(config.load_config())
        self.assertIsNotNone(failure)
        self.assertEqual(failure["error"], "terms_not_accepted")

    def test_authorization_required(self):
        from core import consent
        refusal = consent.require_authorization("10.0.0.1", False, module="ports")
        self.assertIsNotNone(refusal)
        self.assertEqual(refusal["error"], "authorization_required")
        self.assertIn("--authorized", refusal["hint"])

    def test_authorization_passes_when_granted(self):
        from core import consent
        self.assertIsNone(consent.require_authorization("10.0.0.1", True, module="ports"))

    def test_authorization_mentions_scope(self):
        from core import consent
        refusal = consent.require_authorization("192.168.1.1", False, module="webscan")
        self.assertIn("192.168.1.1", refusal["message"])


class TestConfig(IsolatedHomeCase):
    def test_config_dir_made_private(self):
        from core import config
        config.ensure_dirs()
        self.assertTrue(config.CONFIG_DIR.exists())
        self.assertEqual(os.stat(config.CONFIG_DIR).st_mode & 0o777, 0o700)

    def test_api_key_roundtrip_and_storage_mode(self):
        from core import config
        cfg = config.load_config()
        cfg.set_api_key("numverify", "abc123")
        self.assertEqual(cfg.api_key("numverify"), "abc123")
        cfg.reload()
        self.assertEqual(cfg.api_key("numverify"), "abc123")
        self.assertEqual(os.stat(config.CONFIG_FILE).st_mode & 0o777, 0o600)

    def test_key_masking_hides_value(self):
        from core import config
        cfg = config.load_config()
        cfg.set_api_key("virustotal", "sk-verysecretvalue123")
        report = cfg.provider_report()
        entry = [e for e in report if e["provider"] == "virustotal"][0]
        self.assertTrue(entry["configured"])
        self.assertNotIn("verysecret", json.dumps(report))

    def test_no_key_means_not_configured(self):
        from core import config
        cfg = config.load_config()
        report = cfg.provider_report()
        self.assertEqual(len(report), len(config.PROVIDERS))
        for entry in report:
            self.assertFalse(entry["configured"], entry["provider"])

    def test_clear_api_key(self):
        from core import config
        cfg = config.load_config()
        cfg.set_api_key("abuseipdb", "k")
        cfg.clear_api_key("abuseipdb")
        self.assertIsNone(cfg.api_key("abuseipdb"))

    def test_db_path_is_inside_config_dir(self):
        from core import config
        self.assertTrue(str(config.CONFIG_DIR) in str(config.LOG_DIR))

    def test_defaults_are_sane(self):
        from core import config
        cfg = config.load_config()
        self.assertGreater(cfg.get_float("rate_limit"), 0)
        self.assertGreater(cfg.get_int("timeout"), 0)
        self.assertFalse(cfg.get_bool("telemetry"))


class TestReport(IsolatedHomeCase):
    def result(self):
        return {
            "ok": True,
            "module": "webscan",
            "target": "https://example.com",
            "summary": "1 finding",
            "risk": "low",
            "score": 92,
            "findings": [
                {"id": "x", "severity": "low", "title": "Missing header",
                 "detail": "no CSP", "reference": "https://owasp.org"},
            ],
        }

    def test_writes_all_formats(self):
        from core import report
        out = os.path.join(self.home, "reports")
        paths = report.write_all(self.result(), stem_dir=out)
        for key in ("json", "markdown", "html", "print_html"):
            self.assertIn(key, paths)
            self.assertTrue(os.path.exists(paths[key]), key)
            self.assertGreater(os.path.getsize(paths[key]), 50)

    def test_json_is_parseable(self):
        from core import report
        out = os.path.join(self.home, "reports")
        paths = report.write_all(self.result(), stem_dir=out)
        with open(paths["json"], encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["target"], "https://example.com")

    def test_html_escapes_injected_target(self):
        from core import report
        res = self.result()
        res["target"] = "<script>alert(1)</script>"
        out = os.path.join(self.home, "reports")
        html = report.render_html(res)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_pdf_note_present(self):
        from core import report
        paths = report.write_all(self.result(), stem_dir=os.path.join(self.home, "r"))
        self.assertIn("pdf_note", paths)


class TestWhoisParsing(unittest.TestCase):
    RAW = (
        "Domain Name: EXAMPLE.COM\r\n"
        "Registrar: RESERVED-Internet Assigned Numbers Authority\r\n"
        "Creation Date: 1995-08-14T04:00:00Z\r\n"
        "Registry Expiry Date: 2025-08-13T04:00:00Z\r\n"
        "Name Server: A.IANA-SERVERS.NET\r\n"
        "Name Server: B.IANA-SERVERS.NET\r\n"
        ">>> Last update of whois database: 2024-01-01T00:00:00Z <<<\r\n"
    )

    def test_parses_common_fields(self):
        from core import whois_client
        parsed = whois_client.parse_whois(self.RAW)
        self.assertEqual(parsed["registrar"],
                         "RESERVED-Internet Assigned Numbers Authority")
        self.assertEqual(len(parsed["name_servers"]), 2)
        self.assertTrue(parsed["created"].startswith("1995"))
        self.assertTrue(parsed["expires"].startswith("2025"))

    def test_comment_and_noise_lines_ignored(self):
        from core import whois_client
        parsed = whois_client.parse_whois("% comment\n\nDomain Name: EXAMPLE.COM\n")
        self.assertEqual(parsed.get("domain"), "EXAMPLE.COM")
        self.assertNotIn("comment", json.dumps(parsed))

    def test_empty_input(self):
        from core import whois_client
        self.assertEqual(whois_client.parse_whois(""), {})

    def test_no_duplicate_name_servers(self):
        from core import whois_client
        text = "Name Server: ns1.example.com\nName Server: NS1.EXAMPLE.COM\n"
        parsed = whois_client.parse_whois(text)
        self.assertEqual(len(parsed["name_servers"]), 1)


class TestDnsWire(unittest.TestCase):
    def test_build_query_has_twelve_byte_header(self):
        from core import dnsclient
        q = dnsclient._build_query("example.com", "A", 1234)
        self.assertEqual(q[:2], b"\x04\xd2")
        self.assertEqual(q[4:6], b"\x00\x01")  # one question
        self.assertEqual(dnsclient._decode_name(q[12:], 0)[0], "example.com")

    def test_encode_name_roundtrip(self):
        from core import dnsclient
        encoded = dnsclient._encode_name("a.b.example.com")
        self.assertEqual(dnsclient._decode_name(encoded, 0)[0], "a.b.example.com")

    def test_rdata_a(self):
        from core import dnsclient
        self.assertEqual(dnsclient._parse_rdata(b"\x08\x08\x08\x08", 1, b"", 0), "8.8.8.8")

    def test_rdata_aaaa_compressed(self):
        import ipaddress
        from core import dnsclient
        packed = ipaddress.IPv6Address("2001:4860:4860::8888").packed
        self.assertEqual(dnsclient._parse_rdata(packed, 28, b"", 0),
                         "2001:4860:4860::8888")

    def test_rdata_txt_decoded(self):
        from core import dnsclient
        self.assertEqual(dnsclient._parse_rdata(b"\x0bhello world", 16, b"", 0),
                         "hello world")

    def test_rdata_mx_returns_hostname(self):
        from core import dnsclient
        # An MX rdata is preference(2) + exchange name. The name is resolved
        # inside the rdata, so the packet argument must be the rdata itself.
        rdata = b"\x00\x0a\x04mail\x07example\x03com\x00"
        out = dnsclient._parse_rdata(rdata, 15, rdata, 0)
        self.assertIn("mail.example.com", str(out))

    def test_rdata_unknown_type_does_not_raise(self):
        from core import dnsclient
        dnsclient._parse_rdata(b"\x00\x01\x02", 99, b"", 0)


class TestNameEncodingEdgeCases(unittest.TestCase):
    def test_rejects_overlong_label(self):
        from core import dnsclient
        with self.assertRaises(dnsclient.DnsError):
            dnsclient._encode_name("a" * 70 + ".com")

    def test_empty_name_encodes_to_root(self):
        from core import dnsclient
        # The root label is a single zero byte, not an error.
        self.assertEqual(dnsclient._encode_name(""), b"\x00")


if __name__ == "__main__":
    unittest.main()
