

import unittest
from types import SimpleNamespace
from unittest.mock import patch

# absolute import from the parent package
from Privacy_scan import Passive_Cookie_Privacy_Scan as scan


# --------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------- #
def _mk_cookie(name, *, secure=True, httponly=True):
    rest = {"HttpOnly": True} if httponly else {}
    return SimpleNamespace(name=name, secure=secure, _rest=rest)


def _fake_get_factory(cookie_list):
    def _fake_get(_url, timeout=10):        # pylint: disable=unused-argument
        return SimpleNamespace(cookies=cookie_list)
    return _fake_get


# --------------------------------------------------------------------- #
# tests
# --------------------------------------------------------------------- #
class CookieScanTest(unittest.TestCase):
    """Exercise scoring logic + the private _clamp helper."""

    def test_score_variations(self):
        scenarios = [
            ([], scan._MAX_SCORE),
            ([_mk_cookie("ideal")], scan._MAX_SCORE),
            ([_mk_cookie("no_secure", secure=False)], 8),
            ([_mk_cookie("no_http", httponly=False)], 8),
            ([_mk_cookie("both_bad", secure=False, httponly=False)], 6),
        ]

        for cookies, expected in scenarios:
            with self.subTest(cookies=[c.name for c in cookies]):
                with patch(
                    "Privacy_scan.Passive_Cookie_Privacy_Scan.requests.get",
                    new=_fake_get_factory(cookies),
                ):
                    score, _ = scan.analyze_cookie_privacy("http://dummy")
                    self.assertEqual(score, expected)

    def test_clamp_edges(self):
        self.assertEqual(scan._clamp(50, 1, 10), 10)
        self.assertEqual(scan._clamp(-5, 1, 10), 1)
        self.assertEqual(scan._clamp(7, 1, 10), 7)


# allow `python Passive_Cookie_Privacy_Scan_test.py` as well
if __name__ == "__main__":
    unittest.main(verbosity=2)
