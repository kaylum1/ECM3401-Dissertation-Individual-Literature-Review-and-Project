"""
Smoke-tests for Passive_CSRF_Security_Scanner.

– offline (requests.get is patched)
– std-lib only
– hand-written style
"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from Security_scans import Passive_CSRF_Security_Scanner as scan


# ───────────────────────── helpers ───────────────────────── #
def _fake_get_factory(html: str,
                      *,
                      headers: dict[str, str] | None = None,
                      cookies: list | None = None):
    """Return a stub that mimics requests.get and adds .cookies."""
    if cookies is None:
        cookies = []                      # ensure attribute exists
    if headers is None:
        headers = {}

    def _fake_get(_url, timeout=10):      # pylint: disable=unused-argument
        return SimpleNamespace(text=html,
                               headers=headers,
                               cookies=cookies)
    return _fake_get


def _pick_analyze_fn(ns):
    for name, obj in vars(ns).items():
        if callable(obj) and name.startswith("analyze_"):
            return obj
    raise RuntimeError("no analyse_* function in CSRF scanner")


# ─────────────────────────── runtime info ─────────────────────────── #
_ANALYZE = _pick_analyze_fn(scan)
MAX_ = getattr(scan, "_MAX_SCORE", 10)
MIN_ = getattr(scan, "_MIN_SCORE", 1)


# ──────────────────────────── tests ──────────────────────────── #
class CSRFSecurityScannerTest(unittest.TestCase):
    """Checks score ordering for token vs no-token cases."""

    def _score(self, html: str, *, cookies: list | None = None) -> int:
        with patch(f"{scan.__name__}.requests.get",
                   new=_fake_get_factory(html, cookies=cookies)):
            score, _ = _ANALYZE("http://dummy")          # type: ignore[arg-type]
            return score

    # -------------------------------------------------------- #
    def test_score_relationships(self):
        # good: hidden token + matching cookie with flags
        good_html = (
            "<form method='post'>"
            "<input type='hidden' name='csrf_token' value='abc123'>"
            "</form>"
        )
        # stub cookie must have .secure and ._rest["SameSite"]
        good_cookie = SimpleNamespace(
            name="csrf_token",
            secure=True,
            _rest={"SameSite": "Lax"}
        )
        good_cookies = [good_cookie]

        # mediocre: form without token
        bare_html = "<form method='post'></form>"

        # worst: many token-less forms
        flood_html = " ".join("<form method='post'></form>" for _ in range(40))

        s_good  = self._score(good_html, cookies=good_cookies)
        s_bare  = self._score(bare_html)
        s_flood = self._score(flood_html)

        # within bounds
        for s in (s_good, s_bare, s_flood):
            self.assertTrue(MIN_ <= s <= MAX_)

        # ordering expected
        self.assertTrue(s_good >= s_bare >= s_flood)
        self.assertTrue(s_good > s_bare or s_good > s_flood)

    # -------------------------------------------------------- #
    def test_clamp_helper_if_present(self):
        if hasattr(scan, "_clamp"):
            c = scan._clamp            # type: ignore[attr-defined]
            self.assertEqual(c(99, 1, 10), 10)
            self.assertEqual(c(-4, 1, 10), 1)
            self.assertEqual(c(6, 1, 10), 6)
        else:
            self.skipTest("no _clamp helper")


if __name__ == "__main__":
    unittest.main(verbosity=2)
