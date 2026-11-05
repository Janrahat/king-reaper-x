"""Offline unit tests: calling-code table and phone analysis.

Nothing here touches the network.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


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
        self.assertEqual(
            pc.lookup_calling_code("966"), ("SA", "Saudi Arabia", "+966")
        )
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
        for weird in ("+++", "123", "0", "tel:+966501234567", "x" * 100):
            phone_intel.analyse(weird)  # must simply not raise


if __name__ == "__main__":
    unittest.main(verbosity=2)
