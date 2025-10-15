"""
Tests for Passive_Cookie_Privacy_Scan (unittest flavour).

They run entirely offline: requests.get is swapped out with a stub
that returns a minimal response carrying whatever cookie list we pass
in.  No external traffic, no frameworks beyond std-lib.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import Passive_Cookie_Privacy_Scan as scan


# --------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------- #
def _mk_cookie(name, *, secure=True, httponly=True):
    """Craft the smallest object the scanner needs."""
    rest = {"HttpOnly": True} if httponly else {}
    return SimpleNamespace(name=name, secure=secure, _rest=rest)


def _fake_get_factory(cookie_list):
    """Return a stand-in for requests.get that carries our cookies."""
    def _fake_get(_url, timeout=10):   # pylint: disable=unused-argument
        return SimpleNamespace(cookies=cookie_list)
    return _fake_get


# --------------------------------------------------------------------- #
# test case
# --------------------------------------------------------------------- #
class CookieScanTest(unittest.TestCase):
    """Coverage for scoring logic plus the private clamp helper."""

    def test_score_variations(self):
        combos = [
            ([], scan._MAX_SCORE),
            ([_mk_cookie("ideal")], scan._MAX_SCORE),
            ([_mk_cookie("no_secure", secure=False)], 8),
            ([_mk_cookie("no_http", httponly=False)], 8),
            ([_mk_cookie("both_bad", secure=False, httponly=False)], 6),
        ]

        for cookies, expected in combos:
            with self.subTest(cookies=[c.name for c in cookies]):
                with patch(
                    "Passive_Cookie_Privacy_Scan.requests.get",
                    new=_fake_get_factory(cookies),
                ):
                    score, _ = scan.analyze_cookie_privacy("http://dummy")
                    self.assertEqual(score, expected)

    def test_clamp_edges(self):
        self.assertEqual(scan._clamp(50, 1, 10), 10)
        self.assertEqual(scan._clamp(-5, 1, 10), 1)
        self.assertEqual(scan._clamp(7, 1, 10), 7)


# --------------------------------------------------------------------- #
# “python Passive_Cookie_Privacy_Scan_test.py” fallback
# --------------------------------------------------------------------- #
if __name__ == "__main__":
    unittest.main(verbosity=2)
