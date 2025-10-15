"""
Tests for Passive_SQL_Injection_Security_Scanner.py
---------------------------------------------------

Run with:
    python -m unittest Security_scans.Security_scans_tests.Passive_SQL_Injection_Security_Scanner_test -v
"""
from types import SimpleNamespace
from unittest import TestCase, mock

# Local import – mirrors the project’s package layout
from Security_scans import Passive_SQL_Injection_Security_Scanner as scanner


# --------------------------------------------------------------------------- #
# Helper – fabricate a bare‑bones “requests.Response” stand‑in
# --------------------------------------------------------------------------- #
def _fake_response(html: str = "", headers: dict | None = None) -> SimpleNamespace:
    """
    Return a stub object exposing only the attributes the scanner touches.
    """
    return SimpleNamespace(text=html, headers=headers or {})


class PassiveSQLScannerTests(TestCase):
    """Smoke‑, edge‑ and worst‑case tests for the SQL‑injection scanner."""

    # ------------------------------------------------------------------ #
    # Happy path: no red flags ⇒ score should stay at 10
    # ------------------------------------------------------------------ #
    @mock.patch("Security_scans.Passive_SQL_Injection_Security_Scanner.requests.get")
    def test_analyze_sql_security_perfect(self, fake_get):
        headers_ok = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "SAMEORIGIN",
        }
        fake_get.return_value = _fake_response(
            "<html><body>all good</body></html>",
            headers_ok,
        )

        score, notes = scanner.analyze_sql_security("https://safe.example")

        self.assertEqual(score, scanner._MAX_SCORE)
        self.assertIn("No SQL-injection red flags", " ".join(notes))
        fake_get.assert_called_once_with("https://safe.example", timeout=10)

    # ------------------------------------------------------------------ #
    # Worst‑case: every deduction vector is triggered ⇒ score clamped to 1
    # ------------------------------------------------------------------ #
    @mock.patch("Security_scans.Passive_SQL_Injection_Security_Scanner.requests.get")
    def test_analyze_sql_security_worst(self, fake_get):
        html = "You have an error in your SQL syntax near 'SELECT *'"  # leaks error
        fake_get.return_value = _fake_response(html, {})               # no headers
        url = "https://hack.example?id=7&search=test"                  # shady params

        score, notes = scanner.analyze_sql_security(url)

        self.assertEqual(score, scanner._MIN_SCORE)          # floor enforced
        self.assertTrue(any("SQL errors exposed" in n for n in notes))
        self.assertTrue(any("Suspicious params" in n for n in notes))
        self.assertTrue(any("Missing headers" in n for n in notes))
        self.assertIn("High risk", " ".join(notes))

    # ------------------------------------------------------------------ #
    # Network / DNS error – should not raise; returns (1, [msg])
    # ------------------------------------------------------------------ #
    @mock.patch(
        "Security_scans.Passive_SQL_Injection_Security_Scanner.requests.get",
        side_effect=Exception("timeout"),
    )
    def test_analyze_sql_security_network_failure(self, _fake_get):
        score, notes = scanner.analyze_sql_security("https://offline.local")

        self.assertEqual(score, scanner._MIN_SCORE)
        self.assertEqual(len(notes), 1)
        self.assertTrue(notes[0].startswith("Failed to retrieve URL:"))
