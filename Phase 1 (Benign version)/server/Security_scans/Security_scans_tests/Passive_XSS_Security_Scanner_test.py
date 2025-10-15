"""
Tests for Passive_XSS_Security_Scanner.py
=========================================

Run with:
    python -m unittest \
        Security_scans.Security_scans_tests.Passive_XSS_Security_Scanner_test \
        -v
"""
import requests
from types import SimpleNamespace
from unittest import TestCase, mock

from Security_scans import Passive_XSS_Security_Scanner as scanner


class PassiveXSSScannerTests(TestCase):
    """Fetch helper, heuristic helpers, and full-path integration tests."""

    # ------------------------------------------------------------------ #
    # fetch_page helper
    # ------------------------------------------------------------------ #
    @mock.patch("Security_scans.Passive_XSS_Security_Scanner.requests.get")
    def test_fetch_page_success(self, fake_get):
        fake_get.return_value = SimpleNamespace(
            text="<html/>",
            headers={"Content-Security-Policy": "default-src 'self'"},
            raise_for_status=lambda: None,
        )
        html, hdrs = scanner.fetch_page("https://good.example")
        self.assertEqual(html, "<html/>")
        self.assertIn("Content-Security-Policy", hdrs)
        fake_get.assert_called_once_with("https://good.example", timeout=10)

    @mock.patch(
        "Security_scans.Passive_XSS_Security_Scanner.requests.get",
        side_effect=requests.RequestException("timeout")
    )
    def test_fetch_page_failure(self, _fake_get):
        self.assertEqual(scanner.fetch_page("https://down.example"), (None, None))

    # ------------------------------------------------------------------ #
    # Individual heuristics
    # ------------------------------------------------------------------ #
    def test_find_risky_functions_detects_eval(self):
        self.assertIn(
            "eval(",
            scanner.find_risky_functions("<script>eval('x')</script>")
        )

    def test_missing_security_headers_detects_both(self):
        missing = scanner.missing_security_headers({})
        self.assertEqual(
            set(missing),
            {"Content-Security-Policy", "X-XSS-Protection"}
        )

    def test_find_reflected_parameters(self):
        url = "https://ex.com/?q=hello"
        html = "<p>You searched for hello</p>"
        self.assertEqual(
            scanner.find_reflected_parameters(url, html),
            ["q"]
        )

    def test_find_inline_scripts_counts_blocks(self):
        html = "<script>alert(1)</script><script src='app.js'></script>"
        self.assertEqual(len(scanner.find_inline_scripts(html)), 1)

    # ------------------------------------------------------------------ #
    # analyze_xss_security – perfect & worst paths
    # ------------------------------------------------------------------ #
    @mock.patch("Security_scans.Passive_XSS_Security_Scanner.fetch_page")
    def test_analyze_xss_security_perfect(self, fake_fetch):
        html = "<html><body>safe</body></html>"
        hdrs = {
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1; mode=block",
        }
        fake_fetch.return_value = (html, hdrs)

        score, notes = scanner.analyze_xss_security("https://safe.example")

        self.assertEqual(score, 10)
        self.assertIn("No significant XSS risks", notes)

    @mock.patch("Security_scans.Passive_XSS_Security_Scanner.fetch_page")
    def test_analyze_xss_security_worst(self, fake_fetch):
        html = (
            "<script>eval('bad')</script>"
            "<p>term</p>"
            "<script>alert('x')</script>"
        )
        hdrs = {}  # missing CSP & X-XSS-Protection
        url = "https://hack.example?term=term"
        fake_fetch.return_value = (html, hdrs)

        score, notes = scanner.analyze_xss_security(url)

        self.assertEqual(score, 1)
        txt = notes.lower()
        for phrase in (
            "insecure js calls",
            "missing headers",
            "reflected params",
            "inline scripts"
        ):
            self.assertIn(phrase, txt)
        self.assertIn("high xss risk", txt)
