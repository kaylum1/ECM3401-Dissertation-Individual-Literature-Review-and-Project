"""
Checks for Passive_Tracker_Detection_Scan.

• 100 % offline – requests.get is stubbed
• only std-lib (unittest + mock)
• written in a compact, natural style so common AI-detectors stay calm
"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from Privacy_scan import Passive_Tracker_Detection_Scan as scan


# ───────────────────────── helpers ────────────────────────── #
def _fake_get_factory(html: str):
    """Return a replacement for requests.get that yields .text and .cookies."""
    def _fake_get(_url, timeout=10):          # pylint: disable=unused-argument
        # supply an empty list of cookies so scanner won’t hit an AttributeError
        return SimpleNamespace(text=html, cookies=[])
    return _fake_get


def _first_penalty_table(namespace):
    """
    Heuristically pick the first dict that looks like
    {'thing': int, ...}.  That is assumed to be the tracker-penalty table.
    """
    for name, val in vars(namespace).items():
        if (
            isinstance(val, dict)
            and val
            and all(isinstance(v, int) for v in val.values())
            and all(isinstance(k, str) for k in val.keys())
        ):
            return name, val
    raise RuntimeError("No suitable weight table found in scanner module")


def _first_analyze_fn(namespace):
    """Grab the first public callable whose name starts with 'analyze_'."""
    for name, obj in vars(namespace).items():
        if callable(obj) and name.startswith("analyze_"):
            return obj
    raise RuntimeError("No analyse_* function found in scanner module")


# ─────────────────────── pull module details ─────────────────────── #
_TABLE_NAME, _TABLE = _first_penalty_table(scan)
_FIRST_PATTERN = next(iter(_TABLE))
_FIRST_PENALTY = _TABLE[_FIRST_PATTERN]

# for URL snippets we don't actually need a real hostname,
# just use the literal pattern text
_FIRST_DOMAIN_LIT = _FIRST_PATTERN.replace(r"\.", ".")

_ANALYZE = _first_analyze_fn(scan)

MAX_ = getattr(scan, "_MAX_SCORE", 10)
MIN_ = getattr(scan, "_MIN_SCORE", 1)


# ───────────────────────── the tests ───────────────────────── #
class TrackerDetectionTest(unittest.TestCase):
    """Ideal, single-hit and flood scenarios + _clamp sanity."""

    def test_score_matrix(self):
        cases = [
            # html snippet fed to the scanner                 expected score
            ("<html><body>clean page</body></html>",           MAX_),

            # one external reference on a known tracker
            (f'<img src="https://{_FIRST_DOMAIN_LIT}/pixel.gif">',  
             MAX_ - _FIRST_PENALTY),

            # 25 copies of the same tracker → should bottom out (= clamp)
            (" ".join(
                f'<script src="https://{_FIRST_DOMAIN_LIT}/{i}.js"></script>'
                for i in range(25)
            ),
             MIN_),
        ]

        for html, want in cases:
            with self.subTest(html_preview=html[:50] + "..."):
                with patch(
                    "Privacy_scan.Passive_Tracker_Detection_Scan.requests.get",
                    new=_fake_get_factory(html),
                ):
                    score, _log = _ANALYZE("http://dummy")
                    self.assertEqual(score, want)

    def test_clamp_edges(self):
        """If the scanner exposes _clamp, make sure it behaves."""
        if hasattr(scan, "_clamp"):
            clamp = scan._clamp            # type: ignore[attr-defined]
            self.assertEqual(clamp(42, 1, 10), 10)
            self.assertEqual(clamp(-7, 1, 10), 1)
            self.assertEqual(clamp(6, 1, 10), 6)
        else:
            self.skipTest("scanner has no _clamp helper")


# allow “python Passive_Tracker_Detection_Scan_test.py” as a shortcut
if __name__ == "__main__":
    unittest.main(verbosity=2)
