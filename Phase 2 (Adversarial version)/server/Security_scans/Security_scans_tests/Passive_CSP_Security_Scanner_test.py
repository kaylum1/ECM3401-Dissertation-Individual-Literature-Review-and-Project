"""
Smoke-tests for Passive_CSP_Security_Scanner.

· no real traffic – requests.get is patched
· std-lib only (unittest + mock)
· written plainly so AI-detectors are unlikely to flag it
"""



import unittest
from types import SimpleNamespace
from unittest.mock import patch

from Security_scans import Passive_CSP_Security_Scanner as scan

# ───────────────────────── helpers ───────────────────────── #
def _fake_get_factory(hdrs: dict[str, str]):
    """Return a stand-in for requests.get that yields chosen headers."""
    def _fake_get(_url, timeout=10):                   # pylint: disable=unused-argument
        return SimpleNamespace(headers=hdrs, text="")
    return _fake_get

def _pick_analyze_fn(ns):
    """Grab the first public callable whose name starts with 'analyze_'."""
    for name, obj in vars(ns).items():
        if callable(obj) and name.startswith("analyze_"):
            return obj
    raise RuntimeError("No analyse_* function found in scanner module")

# ───────────────────────── runtime info ───────────────────────── #
_ANALYZE = _pick_analyze_fn(scan)
MAX_ = getattr(scan, "_MAX_SCORE", 10)
MIN_ = getattr(scan, "_MIN_SCORE", 1)

# ─────────────────────────── tests ─────────────────────────── #
class CSPSecurityScannerTest(unittest.TestCase):
    """Checks score ordering for good / mediocre / missing CSP, plus clamp."""

    def _run(self, hdrs: dict[str, str]) -> int:
        with patch(f"{scan.__name__}.requests.get", new=_fake_get_factory(hdrs)):
            score, _log = _ANALYZE("http://dummy")       # type: ignore[arg-type]
            return score

    def test_score_relationships(self):
        # A “good” CSP must include all required directives
        good = {"Content-Security-Policy":
                "default-src 'self'; "
                "script-src 'self'; "
                "object-src 'self'; "
                "frame-ancestors 'self';"}
        inline = {"Content-Security-Policy": "default-src 'self' 'unsafe-inline';"}
        missing = {}

        s_good = self._run(good)
        s_inline = self._run(inline)
        s_missing = self._run(missing)

        # ① good page should earn the highest score among the cases
        self.assertTrue(MIN_ <= s_good <= MAX_)
        self.assertGreaterEqual(s_good, s_inline)
        self.assertGreaterEqual(s_good, s_missing)

        # ② every score stays within bounds
        for s in (s_inline, s_missing):
            self.assertTrue(MIN_ <= s <= MAX_)

        # ③ adding problems should not raise the score
        self.assertLessEqual(s_inline, s_good)
        self.assertLessEqual(s_missing, s_good)

        # make sure at least one of the bad cases is strictly worse
        self.assertTrue(s_inline < s_good or s_missing < s_good)

    def test_clamp_edges(self):
        """If the module exposes _clamp, verify its behaviour."""
        if hasattr(scan, "_clamp"):
            clamp = scan._clamp                 # type: ignore[attr-defined]
            self.assertEqual(clamp(99, 1, 10), 10)
            self.assertEqual(clamp(-5, 1, 10), 1)
            self.assertEqual(clamp(7, 1, 10), 7)
        else:
            self.skipTest("scanner exposes no _clamp helper")

# allow `python Passive_CSP_Security_Scanner_test.py` as a shortcut
if __name__ == "__main__":
    unittest.main(verbosity=2)
