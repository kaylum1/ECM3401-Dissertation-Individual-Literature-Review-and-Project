"""
Tests for Passive_Performance_and_Configuration_Analysis_Scanner.py
-------------------------------------------------------------------

Run them from the repo root with:

    python -m unittest \
        Security_scans.Security_scans_tests.Passive_Performance_and_Configuration_Analysis_Scanner_test \
        -v
"""
from types import SimpleNamespace
from unittest import TestCase, mock

# Local import – keeps path identical to production code
from Security_scans import Passive_Performance_and_Configuration_Analysis_Scanner as scanner


# --------------------------------------------------------------------------- #
# Helpers – fabricate “requests.Response‑ish” objects without pulling in
# the real requests machinery. That keeps the tests lightning‑fast & offline.
# --------------------------------------------------------------------------- #
def _fake_resp(
    *,
    http2: bool = True,
    compressed: bool = True,
    cached: bool = True,
    keep_alive: bool = True,
    redirects: int = 0,
    big_payload: bool = False,
    many_tags: bool = False,
):
    """
    Craft a lightweight stand‑in for `requests.Response`.

    Each flag toggles one deduction vector in the scanner.
    """
    hdrs = {}

    if compressed:
        hdrs["Content-Encoding"] = "gzip"

    if cached:
        hdrs["Cache-Control"] = "max-age=7200"

    if keep_alive:
        hdrs["Connection"] = "keep-alive"

    # ‑‑ HTML body ----------------------------------------------------------
    if many_tags:
        body = "<script></script>" * 60  # > RESOURCE_COUNT_THRESHOLD (50)
    else:
        body = "<html><head></head><body>OK</body></html>"

    # ‑‑ Raw payload + content size ----------------------------------------
    if big_payload:
        binary = b"x" * (600 * 1024)  # 600 KB > PAGE_SIZE_THRESHOLD
    else:
        binary = body.encode()

    # ‑‑ Build “response” ---------------------------------------------------
    return SimpleNamespace(
        history=[object()] * redirects,
        headers=hdrs,
        raw=SimpleNamespace(version=20 if http2 else 11),
        content=binary,
        text=body,
    )


# =============================================================================
#                                Test Cases
# =============================================================================
class PerfConfigScannerTest(TestCase):
    """High‑level smoke & low‑level logic checks for the performance scanner."""

    # ------------------------------------------------------------------ #
    #  _clamp – make sure the tiny helper never misbehaves
    # ------------------------------------------------------------------ #
    def test_clamp_obeys_bounds(self):
        self.assertEqual(scanner._clamp(15), 10)
        self.assertEqual(scanner._clamp(-3), 1)
        self.assertEqual(scanner._clamp(7), 7)

    # ------------------------------------------------------------------ #
    #  analyze_performance – “perfect” site → score stays at 10
    # ------------------------------------------------------------------ #
    @mock.patch(
        "Security_scans.Passive_Performance_and_Configuration_Analysis_Scanner.requests.get"
    )
    def test_analyze_performance_best_case(self, fake_get):
        fake_get.return_value = _fake_resp()  # defaults are all green

        score, notes = scanner.analyze_performance("https://fast.example")

        self.assertEqual(score, 10)
        self.assertTrue(any("HTTP/2" in line for line in notes))
        fake_get.assert_called_once_with("https://fast.example", timeout=10)

    # ------------------------------------------------------------------ #
    # Worst‑case settings should floor the score at 1
    # ------------------------------------------------------------------ #
    @mock.patch(
        "Security_scans.Passive_Performance_and_Configuration_Analysis_Scanner.requests.get"
    )
    def test_analyze_performance_worst_case(self, fake_get):
        fake_get.return_value = _fake_resp(
            http2=False,
            compressed=False,
            cached=False,
            keep_alive=False,
            redirects=2,
            big_payload=True,
            many_tags=True,
        )

        score, notes = scanner.analyze_performance("https://slow.example")

        self.assertEqual(score, 1)  # clamped minimum
        # Spot‑check a couple of expected deductions show up
        self.assertTrue(any("redirect" in n.lower() for n in notes))
        self.assertTrue(any("payload" in n.lower() for n in notes))

    # ------------------------------------------------------------------ #
    # Network failure – raises no exception; returns low score + message
    # ------------------------------------------------------------------ #
    @mock.patch(
        "Security_scans.Passive_Performance_and_Configuration_Analysis_Scanner.requests.get",
        side_effect=Exception("DNS failure"),
    )
    def test_analyze_performance_network_error(self, _fake_get):
        score, details = scanner.analyze_performance("https://nowhere.local")

        self.assertEqual(score, 1)              # worst score on failure
        self.assertEqual(len(details), 1)       # single diagnostic line
        self.assertIn("Failed to fetch", details[0])
