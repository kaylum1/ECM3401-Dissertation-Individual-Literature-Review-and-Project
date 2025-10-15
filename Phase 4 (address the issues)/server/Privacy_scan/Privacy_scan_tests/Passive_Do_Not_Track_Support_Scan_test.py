"""
Checks for Passive_Do_Not_Track_Support_Scan.

– no web traffic (requests.get is stubbed)
– std-lib only (unittest + mock)
– written in a plain, hand-rolled style
"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from Privacy_scan import Passive_Do_Not_Track_Support_Scan as scan


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _html(meta_content=None, phrase=False):
    """Return minimal HTML containing the requested pieces."""
    meta = (
        f"<meta name='dnt' content='{meta_content}'>"
        if meta_content is not None
        else ""
    )
    body = "our site supports do not track" if phrase else ""
    return f"<html><head>{meta}</head><body>{body}</body></html>"


def _fake_get_factory(headers: dict, meta_content=None, phrase=False):
    """Build a stand-in for requests.get that returns exactly what we need."""
    html = _html(meta_content, phrase)

    def _fake_get(_url, timeout=10, headers=None):   # pylint: disable=unused-argument
        return SimpleNamespace(headers=headers or {}, text=html)

    # make sure resp.headers picks up the custom dict
    _fake_get.return_value = SimpleNamespace(headers=headers, text=html)  # type: ignore
    return _fake_get


# --------------------------------------------------------------------------- #
# test case
# --------------------------------------------------------------------------- #
class DNTScanTest(unittest.TestCase):
    """Covers scoring logic plus _clamp edge behaviour."""

    def test_score_matrix(self):
        # (headers, meta_content, phrase?, expected_score)
        cases = [
            ({"DNT": "1"}, "1",  True, 10),  # ideal
            ({},              "1",  True, 10),  # header missing
            ({"DNT": "1"}, "maybe", True,  9),  # ambiguous meta
            ({},              None, False,  5),  # nothing at all
            ({},              "0",  True,  9),  # ambiguous + no header
        ]

        for hdrs, meta_val, phrase, want in cases:
            with self.subTest(headers=list(hdrs), meta=meta_val, phrase=phrase):
                with patch(
                    "Privacy_scan.Passive_Do_Not_Track_Support_Scan.requests.get",
                    new=_fake_get_factory(hdrs, meta_val, phrase),
                ):
                    got, _ = scan.analyze_dnt_support("http://dummy")
                    self.assertEqual(got, want)

    def test_clamp_edges(self):
        self.assertEqual(scan._clamp(42, 1, 10), 10)
        self.assertEqual(scan._clamp(-3, 1, 10), 1)
        self.assertEqual(scan._clamp(7, 1, 10), 7)


if __name__ == "__main__":
    unittest.main(verbosity=2)
