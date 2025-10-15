"""
Tests for Passive_Security_Headers_Scanner.py
=============================================

Place this file next to the other *_test.py modules and run with:

    python -m unittest Security_scans.Security_scans_tests.Passive_Security_Headers_Scanner_test -v
"""
from types import SimpleNamespace
from unittest import TestCase, mock

# Local import of the module under scrutiny
from Security_scans import Passive_Security_Headers_Scanner as scanner


# --------------------------------------------------------------------------- #
# Tiny helper: craft a faux requests.Response that only exposes .headers
# --------------------------------------------------------------------------- #
def _response_with(headers: dict) -> SimpleNamespace:
    """Return a stub object with the minimum surface area the scanner needs."""
    return SimpleNamespace(headers=headers)


class SecurityHeaderScannerTests(TestCase):
    """Smoke‑, edge‑ and sad‑path tests for the security‑headers scanner."""

    # ------------------------------------------------------------------ #
    # _clamp behaves for in‑, sub‑ and super‑range inputs
    # ------------------------------------------------------------------ #
    def test_clamp_respects_bounds(self):
        self.assertEqual(scanner._clamp(11), 10)   # upper bound
        self.assertEqual(scanner._clamp(0), 1)     # lower bound
        self.assertEqual(scanner._clamp(7), 7)     # in range

    # ------------------------------------------------------------------ #
    # Perfect configuration – score should stay at 10
    # ------------------------------------------------------------------ #
    @mock.patch("Security_scans.Passive_Security_Headers_Scanner.requests.get")
    def test_analyze_security_headers_all_present(self, fake_get):
        good = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "X-XSS-Protection": "1; mode=block",
            "Permissions-Policy": "geolocation=(), microphone=()",
        }
        fake_get.return_value = _response_with(good)

        score, notes = scanner.analyze_security_headers("https://good.example")

        self.assertEqual(score, 10)
        self.assertIn("All essential security headers are in place.", notes)
        self.assertGreaterEqual(len(notes), 7)  # six header lines + summary
        fake_get.assert_called_once_with("https://good.example", timeout=10)

    # ------------------------------------------------------------------ #
    # Worst‑case – no headers → score drops to the floor (1)
    # ------------------------------------------------------------------ #
    @mock.patch("Security_scans.Passive_Security_Headers_Scanner.requests.get")
    def test_analyze_security_headers_none_present(self, fake_get):
        fake_get.return_value = _response_with({})  # bare response

        score, notes = scanner.analyze_security_headers("https://bad.example")

        self.assertEqual(score, 1)
        # A representative missing‑header message should be present
        self.assertTrue(any("Missing Strict-Transport-Security" in n for n in notes))
        self.assertIn("fix ASAP", " ".join(notes).lower())
        fake_get.assert_called_once_with("https://bad.example", timeout=10)

    # ------------------------------------------------------------------ #
    # Network / DNS error path – should not raise, just degrade gracefully
    # ------------------------------------------------------------------ #
    @mock.patch(
        "Security_scans.Passive_Security_Headers_Scanner.requests.get",
        side_effect=Exception("network unreachable"),
    )
    def test_analyze_security_headers_network_failure(self, _fake_get):
        score, notes = scanner.analyze_security_headers("https://offline.local")

        self.assertEqual(score, 1)
        self.assertEqual(len(notes), 1)
        self.assertTrue(notes[0].startswith("Error fetching page:"))
