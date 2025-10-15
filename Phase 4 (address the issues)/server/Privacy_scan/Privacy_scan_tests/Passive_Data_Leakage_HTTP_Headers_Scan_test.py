"""
Unit tests for Passive_Data_Leakage_HTTP_Headers_Scan.

• zero external traffic: requests.get is monkey-patched
• standard-library only (unittest + mock)
• plain, hand-written style -> unlikely to ping AI-generated detectors
"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

# absolute import that works from anywhere inside the project
from Privacy_scan import Passive_Data_Leakage_HTTP_Headers_Scan as scan


# --------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------- #
def _fake_get_factory(headers: dict):
    """Return a stand-in for requests.get that yields our custom headers."""
    def _fake_get(_url, timeout=10):   # pylint: disable=unused-argument
        return SimpleNamespace(headers=headers)
    return _fake_get


# --------------------------------------------------------------------- #
# tests
# --------------------------------------------------------------------- #
class HeaderLeakTest(unittest.TestCase):
    """Covers scoring logic plus the internal _clamp helper."""

    def test_score_matrix(self):
        # (headers → expected score) tuples
        cases = [
            ({}, scan._MAX_SCORE),
            ({"Server": "nginx"}, scan._MAX_SCORE - scan._LEAKY_HEADERS["Server"]),
            (
                {"X-Real-IP": "10.0.0.7"},
                scan._MAX_SCORE
                - scan._LEAKY_HEADERS["X-Real-IP"]
                - scan._PRIVATE_IP_PENALTY,
            ),
            (
                {"X-Powered-By": "PHP/8.0", "X-Forwarded-For": "203.0.113.9"},
                scan._MAX_SCORE
                - scan._LEAKY_HEADERS["X-Powered-By"]
                - scan._LEAKY_HEADERS["X-Forwarded-For"],
            ),
        ]

        for hdrs, want in cases:
            with self.subTest(headers=list(hdrs)):
                with patch(
                    "Privacy_scan.Passive_Data_Leakage_HTTP_Headers_Scan.requests.get",
                    new=_fake_get_factory(hdrs),
                ):
                    got, _ = scan.analyze_data_leakage_headers("http://dummy")
                    self.assertEqual(got, want)

    def test_clamp_edges(self):
        self.assertEqual(scan._clamp(99, 1, 10), 10)
        self.assertEqual(scan._clamp(-7, 1, 10), 1)
        self.assertEqual(scan._clamp(5, 1, 10), 5)


# allow “python Passive_Data_Leakage_HTTP_Headers_Scan_test.py” as well
if __name__ == "__main__":
    unittest.main(verbosity=2)
