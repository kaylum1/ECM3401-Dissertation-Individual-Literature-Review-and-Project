
"""
Passive Third-Party Data Collection Scan
=======================================

Fetches the given URL once, then looks through the HTML and inline scripts
for URLs or domains commonly associated with third-party data collectors
(adnetworks, analytics, social widgets, etc.).  We start with 10 points and
subtract per hit:

    • -2 for known analytics/CDP domains (Google Analytics, Segment, Mixpanel)  
    • -1 for ad networks and minor trackers (Taboola, Outbrain)  
    • never drop below 1  

This is a quick-and-dirty check—no JS execution, no network tracing, just
regex matches in the raw HTML.

TODO:
  * consider scanning JSON config blobs for data-collection endpoints  
  * integrate with CSP/report-to headers in the future  
"""

import re
from typing import List, Tuple
import requests

# --------------------------------------------------------------------------- #
# tweakable lists of patterns and their penalties
# --------------------------------------------------------------------------- #
_HEAVY_DOMAINS = {
    r"www\.google\-analytics\.com": 2,
    r"cdn\.segment\.com":           2,
    r"api\.mixpanel\.com":          2,
    r"analytics\.hubspot\.com":     2,
}

_LIGHT_DOMAINS = {
    r"cdn\.taboola\.com":     1,
    r"widgets\.outbrain\.com": 1,
    r"pixel\.quantserve\.com": 1,
}

_MAX_SCORE = 10
_MIN_SCORE = 1

def _clamp(score: int, lo: int, hi: int) -> int:
    """Keep score within [lo, hi]."""
    return max(lo, min(hi, score))

def analyze_third_party_data_collection(url: str, timeout: int = 10) -> Tuple[int, List[str]]:
    """
    Scan the HTML of *url* for third-party data collection endpoints.
    Returns (score, detail_lines).
    """
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "DataAudit/1.0"})
        html = resp.text
    except Exception as exc:  # pragma: no cover
        return _MIN_SCORE, [f"Could not fetch page: {exc}"]

    details: List[str] = []
    deduction = 0

    # Heavy hitters first
    for pattern, penalty in _HEAVY_DOMAINS.items():
        if re.search(pattern, html, re.IGNORECASE):
            domain = pattern.replace(r"\.", ".").split(".")[1:]
            domain = ".".join(domain)
            details.append(f"⚠️ Detected heavy collector: {domain}  (-{penalty})")
            deduction += penalty

    # Lighter trackers
    for pattern, penalty in _LIGHT_DOMAINS.items():
        if re.search(pattern, html, re.IGNORECASE):
            domain = pattern.replace(r"\.", ".").split(".")[1:]
            domain = ".".join(domain)
            details.append(f"• Found lightweight tracker: {domain}  (-{penalty})")
            deduction += penalty

    final_score = _clamp(_MAX_SCORE - deduction, _MIN_SCORE, _MAX_SCORE)

    # Summary line
    if final_score == _MAX_SCORE:
        details.append("No obvious third-party data collectors found.")
    elif final_score < 5:
        details.append("High volume of data collection endpoints detected.")
    else:
        details.append("Some data-collection references spotted; review advised.")

    return final_score, details

# --------------------------------------------------------------------------- #
# CLI entry-point for quick testing
# --------------------------------------------------------------------------- #
if __name__ == "__main__":  # pragma: no cover
    import argparse

    parser = argparse.ArgumentParser(
        description="Passive scan for third-party data collectors"
    )
    parser.add_argument("-u", "--url", required=True,
                        help="Target URL (include http/https)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default 10)")

    args = parser.parse_args()
    score, lines = analyze_third_party_data_collection(args.url, timeout=args.timeout)

    print(f"\nFinal score: {score}/10\n" + "-" * 40)
    for line in lines:
        print(line)

