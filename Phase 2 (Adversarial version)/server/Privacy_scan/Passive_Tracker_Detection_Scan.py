
"""
Passive Tracker Detection Scan
===============================

Does a one-shot GET of the page at *url* and looks for telltale tracker
markers in:

  • External resource URLs (<script>, <img>, <iframe>, <link>)  
  • Inline <script> blocks  
  • Cookie names

We start at 10 points and subtract whenever we spot something in our
TRACKER_PATTERNS list.  Score is clamped to [1, 10].

TODO:
  * Maybe follow up with a headless browser run to catch dynamic loads
  * Log which domain each tracker came from (could use urlparse)
"""

import re
import requests
from bs4 import BeautifulSoup
from typing import List, Tuple

# --------------------------------------------------------------------------- #
# Patterns → penalty points
# --------------------------------------------------------------------------- #
_TRACKER_PATTERNS = {
    "ga(": 1,            # Google Analytics calls
    "gtag(": 1,          # Global site tag
    "fbq(": 2,           # Facebook Pixel
    "mixpanel": 2,
    "segment": 2,
    "hotjar": 2,
    "clicky": 1,
    "chartbeat": 1,
    "scorecardresearch": 2,
    "quantserve": 2,
    "criteo": 1,
    "doubleclick": 2,
    "twitter": 1,
    "piwik": 1,
    "matomo": 1,
    "cookiebot": 1,
    "pixel": 1,          # generic pixel
    "tracking": 1        # catch-all
}

_MAX_SCORE = 10
_MIN_SCORE = 1

def _clamp(val: int, low: int, high: int) -> int:
    """Keep *val* inside the [low, high] range."""
    return max(low, min(high, val))

def analyze_tracker_detection(url: str, timeout: int = 10) -> Tuple[int, List[str]]:
    """
    Scan the page for tracker hints and return (final_score, details_lines).

    final_score: 1–10, higher means fewer trackers.
    details_lines: human-readable notes on what was spotted.
    """
    try:
        resp = requests.get(url, timeout=timeout)
        html = resp.text
        cookies = resp.cookies
    except Exception as err:  # pragma: no cover
        return _MIN_SCORE, [f"Fetch error: {err}"]

    details: List[str] = []
    total_deduction = 0

    # ----- 1) external resources -----
    soup = BeautifulSoup(html, "html.parser")
    resource_tags = soup.find_all(["script", "img", "iframe", "link"])
    for tag in resource_tags:
        attr = "href" if tag.name == "link" else "src"
        src = tag.get(attr)
        if not src:
            continue
        low_src = src.lower()
        for pattern, cost in _TRACKER_PATTERNS.items():
            if pattern in low_src:
                details.append(f"Resource '{src}' matched '{pattern}' (−{cost})")
                total_deduction += cost
                break

    # ----- 2) inline scripts -----
    for script in soup.find_all("script"):
        if not script.string:
            continue
        txt = script.string.lower()
        for pattern, cost in _TRACKER_PATTERNS.items():
            if pattern in txt:
                details.append(f"Inline script found '{pattern}' (−{cost})")
                total_deduction += cost
                break

    # ----- 3) cookies -----
    for ck in cookies:
        name = ck.name.lower()
        for pattern, cost in _TRACKER_PATTERNS.items():
            if pattern in name:
                details.append(f"Cookie '{ck.name}' suggests tracking (−{cost})")
                total_deduction += cost
                break

    # ----- finalize score -----
    score = _clamp(_MAX_SCORE - total_deduction, _MIN_SCORE, _MAX_SCORE)

    if score == _MAX_SCORE:
        details.append("✅ No obvious tracker indicators found.")
    elif score < 5:
        details.append("⚠️ Many tracker hints detected; privacy may be at risk.")
    else:
        details.append("ℹ️ Some trackers spotted; review recommended.")

    return score, details


# --------------------------------------------------------------------------- #
# CLI driver for ad-hoc tests
# --------------------------------------------------------------------------- #
if __name__ == "__main__":  # pragma: no cover
    import argparse

    parser = argparse.ArgumentParser(
        description="Passive Tracker Detection Scan"
    )
    parser.add_argument(
        "-u", "--url", required=True,
        help="URL to scan (include http/https)"
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="Request timeout in seconds (default: 10)"
    )
    args = parser.parse_args()

    final_score, report = analyze_tracker_detection(args.url, timeout=args.timeout)
    print(f"\nFinal Score: {final_score}/10\n" + "-" * 40)
    for line in report:
        print(line)
