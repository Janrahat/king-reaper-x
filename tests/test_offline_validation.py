"""Offline unit tests: input validation, rate limiting, threading, envelopes.

Nothing here touches the network.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


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
        # Assembled from fragments: no key-shaped literal in the source.
        sample = "sk" + "-" + "abcdefghijklmnop"
        masked = utils.mask_secret(sample)
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
        out = registry.normalize(
            {"findings": []}, "dns", "example.com", "2026-01-01T00:00:00Z"
        )
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
