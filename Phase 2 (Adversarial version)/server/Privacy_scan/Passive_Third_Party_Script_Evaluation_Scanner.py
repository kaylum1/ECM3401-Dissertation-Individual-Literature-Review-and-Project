

"""
Passive Third-Party Script Evaluation Scan
==========================================

Grabs the page at *url* and inspects every <script> tag.  
We look for scripts loaded from domains often tied to analytics or ads,
knock points off a simple 10-point score whenever we spot one.

Scoring setup (tweak constants below):
    • -2 for “heavy” scripts (Google Analytics, Facebook, DoubleClick, etc.)
    • -1 for “lighter” embeds (Hotjar, Twitter widgets, etc.)
    • never drop below 1 point

This does not execute any JavaScript—just parses the HTML.  
TODO: consider running a headless browser to catch dynamically injected scripts.
"""

import re
from typing import List, Tuple

import requests
from bs4 import BeautifulSoup

# --------------------------------------------------------------------------- #
# Which script sources to flag and how severely
# --------------------------------------------------------------------------- #
_HEAVY_SCRIPTS = {
    r"connect\.facebook\.net":       2,
    r"www\.google\-analytics\.com":  2,
    r"www\.googletagmanager\.com":   2,
    r"static\.doubleclick\.net":     2,
}

_LIGHT_SCRIPTS = {
    r"hotjar\.com":                  1,
    r"platform\.twitter\.com":       1,
    r"cdn\.instagram\.com":          1,
}

_MAX_SCORE = 10
_MIN_SCORE = 1

def _clamp(value: int, minimum: int, maximum: int) -> int:
    """Keep *value* within the [minimum, maximum] bounds."""
    return max(minimum, min(maximum, value))


def analyze_third_party_script_evaluation(url: str, timeout: int = 10) -> Tuple[int, List[str]]:
    """
    Scan <script> tags on the page at *url*.
    
    Returns:
        final_score (int): 1–10, higher means fewer flagged scripts.
        details    (List[str]): log lines explaining each deduction.
    """
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "ScriptEval/1.0"})
        html = resp.text
    except Exception as exc:  # pragma: no cover
        return _MIN_SCORE, [f"Fetch error: {exc}"]

    soup = BeautifulSoup(html, "html.parser")
    scripts = soup.find_all("script", src=True)

    details: List[str] = []
    deduction = 0

    # Check each external script URL
    for tag in scripts:
        src = tag["src"]
        # Heavy hitters
        for pattern, penalty in _HEAVY_SCRIPTS.items():
            if re.search(pattern, src, re.I):
                details.append(f"⚠️ Heavy script: {src} (−{penalty})")
                deduction += penalty
        # Lighter embeds
        for pattern, penalty in _LIGHT_SCRIPTS.items():
            if re.search(pattern, src, re.I):
                details.append(f"• Light embed: {src} (−{penalty})")
                deduction += penalty

    # Clamp and summarize
    final_score = _clamp(_MAX_SCORE - deduction, _MIN_SCORE, _MAX_SCORE)
    if final_score == _MAX_SCORE:
        details.append("No known third-party scripts found — nice and clean.")
    elif final_score < 5:
        details.append("Lots of third-party scripts—privacy could be at risk.")
    else:
        details.append("Some third-party scripts detected; review advised.")

    return final_score, details


# --------------------------------------------------------------------------- #
# CLI entry-point for quick runs
# --------------------------------------------------------------------------- #
if __name__ == "__main__":  # pragma: no cover
    import argparse

    parser = argparse.ArgumentParser(
        description="Passive scan of <script> tags for third-party trackers"
    )
    parser.add_argument("-u", "--url", required=True, help="Page URL (http/https)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")

    args = parser.parse_args()
    score, log_items = analyze_third_party_script_evaluation(args.url, timeout=args.timeout)

    print(f"\nFinal score: {score}/10\n" + "-" * 40)
    for item in log_items:
        print(item)
