"""
Tests for Passive_Privacy_and_Tracker_Audit_Scanner.

• Offline – requests.get is patched
• Std-lib only
• Written plainly so AI-detectors are unlikely to flag it
"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from Privacy_scan import Passive_Privacy_and_Tracker_Audit_Scanner as scan


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _fake_get_factory(html: str):
    def _fake_get(_url, timeout=10, headers=None):      # pylint: disable=unused-argument
        return SimpleNamespace(text=html)
    return _fake_get


# quick references so we don’t hard-code numbers
H_COST = next(iter(scan._HEAVY_TRACKERS.values()))
L_COST = next(iter(scan._LIGHT_TRACKERS.values()))
MAX_, MIN_ = scan._MAX_SCORE, scan._MIN_SCORE

# pick one regex pattern from each table
H_TRACK = next(iter(scan._HEAVY_TRACKERS))
L_TRACK = next(iter(scan._LIGHT_TRACKERS))

# turn the regex-style domain into a literal one (e.g. "doubleclick\.net" → "doubleclick.net")
H_DOMAIN = H_TRACK.replace(r'\.', '.')
L_DOMAIN = L_TRACK.replace(r'\.', '.')


# --------------------------------------------------------------------------- #
# tests
# --------------------------------------------------------------------------- #
class AuditScanTest(unittest.TestCase):
    """Covers ideal, mixed, and repeated-pattern paths, plus _clamp edges."""

    def test_score_matrix(self):
        cases = [
            # html, expected score, summary fragment
            ("<html><body>clean page</body></html>",
             MAX_,
             "No obvious"),

            (f'<script src="https://{H_DOMAIN}/file.js"></script>',
             MAX_ - H_COST,
             "Some tracking present"),

            # heavy + light => deduction = H_COST + L_COST
            (f'<script src="https://{H_DOMAIN}/a.js"></script>'
             f'<script src="https://{L_DOMAIN}/b.js"></script>',
             MAX_ - H_COST - L_COST,
             "Some tracking present"),

            # many occurrences of the same two patterns → still only counts once each
            # deduction = H_COST + L_COST, same summary branch
            (" ".join(
                f'<script src="https://{H_DOMAIN}/{i}.js"></script> '
                f'<script src="https://{L_DOMAIN}/{i}.js"></script>'
                for i in range(6)
            ),
             MAX_ - H_COST - L_COST,
             "Some tracking present"),
        ]

        for html, want_score, want_msg in cases:
            with self.subTest(html_preview=html[:40] + "..."):
                with patch(
                    "Privacy_scan.Passive_Privacy_and_Tracker_Audit_Scanner.requests.get",
                    new=_fake_get_factory(html),
                ):
                    score, log = scan.analyze_privacy("http://dummy")
                    self.assertEqual(score, want_score)
                    # last summary line contains our fragment
                    self.assertIn(want_msg, " ".join(log))

    def test_clamp_edges(self):
        self.assertEqual(scan._clamp(42, 1, 10), 10)
        self.assertEqual(scan._clamp(-3, 1, 10), 1)
        self.assertEqual(scan._clamp(7, 1, 10), 7)


if __name__ == "__main__":
    unittest.main(verbosity=2)
