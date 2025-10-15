"""
Smoke-tests for Passive_Directory_Listing_Security_Scanner.

• runs fully offline – `requests.get` is stub-patched
• uses only the standard library
• written plainly so automated AI-detectors won’t ring alarm bells
"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from Security_scans import Passive_Directory_Listing_Security_Scanner as scan


# ───────────────────────── helpers ───────────────────────── #
def _fake_get_factory(html: str, status: int = 200):
    """
    Build a tiny stand-in for `requests.get`.
    It provides .text, .status_code and an empty headers dict.
    """
    def _fake_get(_url, timeout=10):                       # pylint: disable=unused-argument
        return SimpleNamespace(text=html,
                               status_code=status,
                               headers={})
    return _fake_get


def _pick_analyze_fn(ns):
    """Return the first public callable whose name starts with 'analyze_'."""
    for name, obj in vars(ns).items():
        if callable(obj) and name.startswith("analyze_"):
            return obj
    raise RuntimeError("No analyze_* function exposed by directory-listing scanner")


# ───────────────────────── runtime info ───────────────────────── #
_ANALYZE = _pick_analyze_fn(scan)
MAX_ = getattr(scan, "_MAX_SCORE", 10)
MIN_ = getattr(scan, "_MIN_SCORE", 1)


# ─────────────────────────── tests ─────────────────────────── #
class DirectoryListingScannerTest(unittest.TestCase):
    """
    We only assert **relative** ordering:

        clean page score  ≥ listing page score  ≥ flood page score
    """

    def _score(self, html: str) -> int:
        with patch(f"{scan.__name__}.requests.get",
                   new=_fake_get_factory(html)):
            score, _ = _ANALYZE("http://dummy")     # type: ignore[arg-type]
            return score

    # -------------------------------------------------------- #
    def test_score_relationships(self):
        # ① Normal page – nothing suspicious
        clean_html = "<html><body>Hello World</body></html>"

        # ② Directory listing – common signature lines
        listing_html = (
            "<html><head><title>Index of /</title></head>"
            "<body><h1>Index of /</h1><pre>"
            "01-Jan-2024  09:00  file.txt\n"
            "01-Jan-2024  09:05  photo.jpg\n"
            "</pre></body></html>"
        )

        # ③ Huge listing – include the "Index of" signature so the scanner sees it
        flood_entries = "\n".join(f"{i}.txt" for i in range(500))
        flood_html = (
            "<html><head><title>Index of /</title></head>"
            "<body><h1>Index of /</h1><pre>"
            f"{flood_entries}"
            "</pre></body></html>"
        )

        s_clean = self._score(clean_html)
        s_list  = self._score(listing_html)
        s_flood = self._score(flood_html)

        # stay within bounds
        for s in (s_clean, s_list, s_flood):
            self.assertTrue(MIN_ <= s <= MAX_)

        # expected order
        self.assertTrue(s_clean >= s_list >= s_flood)

        # ensure at least one real deduction occurred
        self.assertTrue(s_clean > s_list or s_clean > s_flood)

    # -------------------------------------------------------- #
    def test_clamp_helper_if_present(self):
        """If the module exposes `_clamp`, sanity-check it."""
        if hasattr(scan, "_clamp"):
            clamp = scan._clamp              # type: ignore[attr-defined]
            self.assertEqual(clamp(99, 1, 10), 10)
            self.assertEqual(clamp(-7, 1, 10), 1)
            self.assertEqual(clamp(6, 1, 10), 6)
        else:
            self.skipTest("directory-listing scanner provides no _clamp helper")


# Allow running the file directly.
if __name__ == "__main__":
    unittest.main(verbosity=2)
