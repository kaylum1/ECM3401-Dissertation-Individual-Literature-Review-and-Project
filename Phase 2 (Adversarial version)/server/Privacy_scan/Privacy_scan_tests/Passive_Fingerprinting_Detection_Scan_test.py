"""
Tests for Passive_Fingerprinting_Detection_Scan.

▪ no outside traffic – requests.get is patched
▪ depends only on std-lib (unittest + mock)
▪ deliberately plain-spoken so it won’t trip common AI-code detectors
"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from Privacy_scan import Passive_Fingerprinting_Detection_Scan as scan


# --------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------- #
def _fake_get_factory(html: str):
    """Return a stub for requests.get that supplies our HTML."""
    def _fake_get(_url, timeout=10):   # pylint: disable=unused-argument
        return SimpleNamespace(text=html)
    return _fake_get


# pick three indicators straight from the module so we don’t hard-code numbers
FP_JS       = next(k for k in scan.FINGERPRINTING_INDICATORS if "FingerprintJS" in k)
FP2         = next(k for k in scan.FINGERPRINTING_INDICATORS if "Fingerprint2" in k)
TODATAURL   = "toDataURL"            # always present


def _build_scripts(indicators, host="cdn.fp.com"):
    """Craft <script src=…> tags embedding the given indicators in the URL."""
    return "\n".join(
        f'<script src="https://{host}/{ind}.js"></script>' for ind in indicators
    )


# --------------------------------------------------------------------- #
# test case
# --------------------------------------------------------------------- #
class FingerprintScanTest(unittest.TestCase):
    """Checks score maths for 0, 1, several, and overflow cases."""

    def test_score_matrix(self):
        cases = [
            # html, expected score
            ("<html><head></head><body>No scripts here</body></html>", 10),
            (
                _build_scripts([FP_JS]),
                10 - scan.FINGERPRINTING_INDICATORS[FP_JS],
            ),
            (
                _build_scripts([FP2, TODATAURL]),
                10
                - scan.FINGERPRINTING_INDICATORS[FP2]
                - scan.FINGERPRINTING_INDICATORS[TODATAURL],
            ),
            # many copies – score must bottom-out at 1
            (
                _build_scripts([FP_JS] * 6),
                1,
            ),
        ]

        for html, want in cases:
            with self.subTest(html=html[:30] + "..."):
                with patch(
                    "Privacy_scan.Passive_Fingerprinting_Detection_Scan.requests.get",
                    new=_fake_get_factory(html),
                ):
                    got, _ = scan.analyze_fingerprinting_detection("http://example.com")
                    self.assertEqual(got, want)


if __name__ == "__main__":
    unittest.main(verbosity=2)
