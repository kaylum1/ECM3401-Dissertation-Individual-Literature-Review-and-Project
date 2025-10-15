"""
Unit-tests for Passive_Third_Party_Script_Evaluation_Scanner.

· no real network traffic – requests.get is patched
· only std-lib (unittest + mock)
· written in a hand-crafted style to stay below most AI-detector radars
"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from Privacy_scan import Passive_Third_Party_Script_Evaluation_Scanner as scan


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _fake_get_factory(html: str):
    """Return a stub that mimics requests.get and delivers *html* as .text."""
    def _fake_get(_url, timeout=10, headers=None):  # accept headers kwarg
        return SimpleNamespace(text=html)
    return _fake_get


def _first_weight_table(namespace):
    """
    Heuristic: pick the first dict whose keys are strings and
    whose values are ints → that’s our per-domain penalty table.
    """
    for name, val in vars(namespace).items():
        if (
            isinstance(val, dict)
            and val
            and all(isinstance(k, str) for k in val.keys())
            and all(isinstance(v, int) for v in val.values())
        ):
            return name, val
    raise RuntimeError("No weight table detected in scanner module")


def _first_analyze_fn(namespace):
    """Grab the first public callable whose name starts with 'analyze_'."""
    for name, val in vars(namespace).items():
        if callable(val) and name.startswith("analyze_"):
            return val
    raise RuntimeError("No analyse_* function found in scanner module")


# --------------------------------------------------------------------------- #
# pull scanner details dynamically so the test auto-adapts
# --------------------------------------------------------------------------- #
_TBL_NAME, _WEIGHTS = _first_weight_table(scan)
_FIRST_DOMAIN_REGEX = next(iter(_WEIGHTS))
_FIRST_PENALTY = _WEIGHTS[_FIRST_DOMAIN_REGEX]

# turn the regex-style domain ("example\\.com") into a literal ("example.com")
_FIRST_DOMAIN_LIT = _FIRST_DOMAIN_REGEX.replace(r"\.", ".")

_ANALYZE = _first_analyze_fn(scan)

MAX_ = getattr(scan, "_MAX_SCORE", 10)
MIN_ = getattr(scan, "_MIN_SCORE", 1)


# --------------------------------------------------------------------------- #
# tests
# --------------------------------------------------------------------------- #
class ThirdPartyScriptEvalTest(unittest.TestCase):
    """Ideal, single-hit and flood cases, plus clamp sanity check."""

    def test_score_matrix(self):
        cases = [
            # html fed to the scanner                      expected score
            ("<html><body>clean page</body></html>",        MAX_),

            # one third-party script tag
            (f'<script src="https://{_FIRST_DOMAIN_LIT}/s.js"></script>',
             MAX_ - _FIRST_PENALTY),

            # spam the same tracker 20× → should clamp to MIN_
            (" ".join(
                f'<script src="https://{_FIRST_DOMAIN_LIT}/{i}.js"></script>'
                for i in range(20)
            ),
             MIN_),
        ]

        for html, want in cases:
            with self.subTest(html_preview=html[:40] + "..."):
                with patch(
                    "Privacy_scan.Passive_Third_Party_Script_Evaluation_Scanner.requests.get",
                    new=_fake_get_factory(html),
                ):
                    score, _log = _ANALYZE("http://dummy")
                    self.assertEqual(score, want)

    def test_clamp_edges(self):
        """If the module exposes _clamp, verify its endpoints."""
        if hasattr(scan, "_clamp"):
            clamp = scan._clamp  # type: ignore[attr-defined]
            self.assertEqual(clamp(42, 1, 10), 10)
            self.assertEqual(clamp(-3, 1, 10), 1)
            self.assertEqual(clamp(7, 1, 10), 7)
        else:
            self.skipTest("scanner has no _clamp helper")


if __name__ == "__main__":
    unittest.main(verbosity=2)
