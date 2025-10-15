
"""
Passive Privacy-&-Tracker Audit Scan
====================================

Brutally simple:

1. Fetch *url* once.
2. Scan the HTML + inline scripts for strings that usually indicate a
   third-party tracker or aggressive analytics platform.
3. Start with 10 points; subtract a little for every hit we find.

Scoring Rules (tweakable constants below)
-----------------------------------------
    • -2  for each “heavy-weight” tracker (e.g. Facebook, Google Analytics)
    • -1  for “lighter” marketing pixels or generic ad networks
    • cap the total deduction so the score never drops below 1

Things this DOESN’T do (yet — see TODO):
    • run the JS -- we’re only matching text
    • detect trackers that load dynamically after initial HTML
    • parse CSP/report-to for leaks
"""

import re
from typing import List, Tuple
import requests

# --------------------------------------------------------------------------- #
# Tunables — move these around to your taste
# --------------------------------------------------------------------------- #
_HEAVY_TRACKERS = {
    r"connect\.facebook\.net":       2,
    r"www\.google\-analytics\.com":  2,
    r"www\.googletagmanager\.com":   2,
    r"static\.doubleclick\.net":     2,
    r"bat\.bing\.com":               2,
}

_LIGHT_TRACKERS = {
    r"stats\.wp\.com":               1,
    r"pixel\.quantserve\.com":       1,
    r"cdn\.taboola\.com":            1,
    r"cdn\.segment\.com":            1,
    r"hotjar\.com":                  1,
}

_MAX_SCORE = 10
_MIN_SCORE = 1

def _clamp(val: int, low: int, high: int) -> int:
    """Return *val* bounded to [low, high]."""
    return max(low, min(high, val))


def analyze_privacy(url: str, timeout: int = 10) -> Tuple[int, List[str]]:
    """
    Quick-n-dirty sweep for common tracker strings.

    Returns
    -------
    final_score : int
        10  → no trackers spotted (or at least none we recognise)
        1-9 → progressively worse as more trackers show up
    details : list[str]
        Human-readable log lines.
    """
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "PrivacyAudit/0.1"})
        html = resp.text
    except Exception as exc:  # pragma: no cover
        return _MIN_SCORE, [f"Request failed: {exc}"]

    details: List[str] = []
    deduction = 0

    # Heavy-weight trackers
    for pattern, cost in _HEAVY_TRACKERS.items():
        if re.search(pattern, html, re.I):
            host = pattern.split("\\")[0].replace(r"\.", ".")
            details.append(f"⚠️ Found heavy tracker: {host}  (-{cost})")
            deduction += cost

    # Light / marketing trackers
    for pattern, cost in _LIGHT_TRACKERS.items():
        if re.search(pattern, html, re.I):
            host = pattern.split("\\")[0].replace(r"\.", ".")
            details.append(f"• Found tracker: {host}  (-{cost})")
            deduction += cost

    final_score = _clamp(_MAX_SCORE - deduction, _MIN_SCORE, _MAX_SCORE)

    # Summary line
    if final_score == _MAX_SCORE:
        details.append("No obvious third-party trackers recognised — good news.")
    elif final_score < 5:
        details.append("High tracker load detected — privacy looks weak.")
    else:
        details.append("Some tracking present; worth reviewing.")

    # TODO: parse inline JSON configs, honour CSP/permissions-policy headers,
    #       maybe run playwright & watch network calls.

    return final_score, details


if __name__ == "__main__":  # pragma: no cover
    import argparse

    parser = argparse.ArgumentParser(
        description="Passive sweep for common third-party trackers"
    )
    parser.add_argument("-u", "--url", required=True, help="Target site (http/https)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (s)")

    opts = parser.parse_args()
    score, log_lines = analyze_privacy(opts.url, timeout=opts.timeout)

    print(f"\nFinal score: {score}/10\n" + "-" * 40)
    for line in log_lines:
        print(line)
