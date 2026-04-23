"""
Tests for Phishing URL Detector
Run: python test_detector.py
"""

import unittest
from detector import analyze_url

class TestPhishingDetector(unittest.TestCase):

    # ── Safe URLs ─────────────────────────────────────────────
    def test_safe_https_trusted(self):
        result = analyze_url("https://github.com")
        self.assertLessEqual(result["score"], 15)
        self.assertEqual(result["verdict"], "LIKELY SAFE")

    def test_safe_google(self):
        result = analyze_url("https://google.com")
        self.assertLessEqual(result["score"], 15)

    # ── Suspicious URLs ───────────────────────────────────────
    def test_http_only(self):
        result = analyze_url("http://somebank.com")
        self.assertGreater(result["score"], 0)

    def test_suspicious_keywords(self):
        result = analyze_url("http://verify-your-account.com/login")
        self.assertGreater(result["score"], 30)

    def test_long_url(self):
        long_url = "https://secure-bank-account-update-verify-login-portal-customer.com/" + "a" * 50
        result = analyze_url(long_url)
        self.assertGreater(result["score"], 15)

    # ── High Risk URLs ────────────────────────────────────────
    def test_at_symbol(self):
        result = analyze_url("http://paypal.com@evil.com/login")
        self.assertGreater(result["score"], 45)

    def test_suspicious_tld(self):
        result = analyze_url("http://paytm-login-verify.xyz/account")
        self.assertGreaterEqual(result["score"], 45)
        self.assertEqual(result["verdict"], "HIGH RISK — PHISHING LIKELY")

    def test_multiple_hyphens(self):
        result = analyze_url("http://secure-bank-login.com/verify")
        self.assertGreater(result["score"], 30)

    # ── Edge Cases ────────────────────────────────────────────
    def test_url_without_protocol(self):
        result = analyze_url("example.com")
        self.assertIn("score", result)

    def test_score_max_100(self):
        result = analyze_url("http://login-verify-secure-bank-account-update.xyz/@user?confirm=1" + "x"*60)
        self.assertLessEqual(result["score"], 100)

    def test_score_min_0(self):
        result = analyze_url("https://google.com")
        self.assertGreaterEqual(result["score"], 0)


if __name__ == "__main__":
    print("\n🧪 Running Phishing Detector Tests...\n")
    unittest.main(verbosity=2)
