"""
Tests for Passive_Outdated_Plugin_Security_Scanner.py

Run via:
    python -m unittest Security_scans.Security_scans_tests.Passive_Outdated_Plugin_Security_Scanner_test -v
"""
from types import SimpleNamespace
from unittest import TestCase, mock

# Local import – mirrors the package layout in the repository
from Security_scans import Passive_Outdated_Plugin_Security_Scanner as scanner


class OutdatedPluginScannerTest(TestCase):
    """Covers fetch, detection, scoring, and the public wrapper."""

    # ------------------------------------------------------------------ #
    # Sample data shared by several tests
    # ------------------------------------------------------------------ #
    def setUp(self) -> None:
        # A minimal page that deliberately triggers multiple patterns
        self._html = """
          <!doctype html>
          <html lang="en">
            <head>
              <!-- JS libs -->
              <script src="/static/js/jquery-3.6.0.min.js"></script>
              <script src="/static/js/bootstrap-5.2.3.min.js"></script>

              <!-- CMS hint -->
              <meta name="generator" content="WordPress 6.2.1" />
            </head>
            <body>Hello 🚀</body>
          </html>
        """
        self._url = "https://demo.example"

    # ------------------------------------------------------------------ #
    # get_page_content
    # ------------------------------------------------------------------ #
    @mock.patch("Security_scans.Passive_Outdated_Plugin_Security_Scanner.requests.get")
    def test_get_page_content_returns_text_when_ok(self, fake_get):
        """Happy‑path HTTP GET returns response.text unchanged."""
        fake_get.return_value = SimpleNamespace(
            text="<html/>",          # pretend HTML
            status_code=200,
            raise_for_status=lambda: None,
        )
        html = scanner.get_page_content("https://good.example")
        self.assertEqual(html, "<html/>")
        fake_get.assert_called_once_with("https://good.example", timeout=8)

    @mock.patch("Security_scans.Passive_Outdated_Plugin_Security_Scanner.requests.get",
                side_effect=Exception("network down"))
    def test_get_page_content_gracefully_handles_errors(self, _fake_get):
        """Any network/HTTP issue should bubble up as None (not an exception)."""
        self.assertIsNone(scanner.get_page_content("https://bad.example"))

    # ------------------------------------------------------------------ #
    # detect_libraries
    # ------------------------------------------------------------------ #
    def test_detect_libraries_finds_every_expected_pattern(self):
        """The crafted HTML should match jQuery, Bootstrap and WordPress."""
        libs = dict(scanner.detect_libraries(self._html))  # convert to dict for lookup
        self.assertIn("jQuery", libs)
        self.assertEqual(libs["jQuery"], "3.6.0")

        self.assertIn("Bootstrap", libs)
        self.assertEqual(libs["Bootstrap"], "5.2.3")

        self.assertIn("WordPress", libs)
        self.assertEqual(libs["WordPress"], "6.2.1")

        # Exactly 3 hits, nothing more, nothing less
        self.assertEqual(len(libs), 3)

    # ------------------------------------------------------------------ #
    # check_vulnerabilities
    # ------------------------------------------------------------------ #
    def test_check_vulnerabilities_deducts_penalty_per_library(self):
        """Score math: MAX – (count * PENALTY), floored at MIN."""
        sample_libs = [("FooJS", "1.0.0"), ("BarCMS", "9.9.9")]
        expected = max(
            scanner._MIN_SCORE,
            scanner._MAX_SCORE - len(sample_libs) * scanner._PENALTY,
        )
        score, details = scanner.check_vulnerabilities(sample_libs)

        self.assertEqual(score, expected)
        self.assertEqual(len(details), len(sample_libs) + 1)  # +1 for summary line

    # ------------------------------------------------------------------ #
    # analyze_outdated_plugins  (integration smoke‑test)
    # ------------------------------------------------------------------ #
    @mock.patch("Security_scans.Passive_Outdated_Plugin_Security_Scanner.get_page_content")
    def test_analyze_outdated_plugins_end_to_end(self, fake_fetch):
        """Wrapper should stitch helpers together and downgrade score."""
        fake_fetch.return_value = self._html

        score, details = scanner.analyze_outdated_plugins(self._url)

        # With 3 libs, expect at least one deduction
        self.assertLess(score, scanner._MAX_SCORE)
        self.assertTrue(any("Bootstrap" in line for line in details))
        fake_fetch.assert_called_once_with(self._url)
