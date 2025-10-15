

import re
from typing import List, Tuple

import requests
from bs4 import BeautifulSoup

# --------------------------------------------------------------------------- #
# Policy categories and their penalty weights
# --------------------------------------------------------------------------- #
_GOOD_POLICIES = {
    "no-referrer",
    "strict-origin",
    "same-origin",
    "strict-origin-when-cross-origin",
}
_ACCEPTABLE_POLICIES = {
    "origin",
    "origin-when-cross-origin",
}
_POOR_POLICIES = {
    "no-referrer-when-downgrade",
    "unsafe-url",
}

# Penalty constants
_PENALTY_MISSING_POLICY   = 4
_PENALTY_ACCEPTABLE       = 1
_PENALTY_POOR             = 3
_PENALTY_UNKNOWN_POLICY   = 2
_PENALTY_NO_META          = 2
_PENALTY_META_AMBIGUOUS   = 1

_MAX_SCORE = 10
_MIN_SCORE = 1

def _clamp(score: int, lo: int, hi: int) -> int:
    """Ensure score stays within [lo, hi]."""
    return max(lo, min(hi, score))


def analyze_referrer_dnt(url: str, timeout: int = 10) -> Tuple[int, List[str]]:
    """
    Returns (final_score, details) for the given URL.
    """
    try:
        # simulate a privacy-conscious GET
        resp = requests.get(url, headers={"DNT": "1"}, timeout=timeout)
        headers = resp.headers
        html = resp.text
    except Exception as err:  # pragma: no cover
        return _MIN_SCORE, [f"Request error: {err}"]

    details: List[str] = []
    deduction = 0

    # --- Referrer-Policy header check ---
    ref_pol = headers.get("Referrer-Policy")
    if ref_pol:
        val = ref_pol.strip().lower()
        details.append(f"Referrer-Policy: {val}")
        if val in _GOOD_POLICIES:
            details.append("  * Looks solid for privacy.")
        elif val in _ACCEPTABLE_POLICIES:
            details.append("  * Acceptable, but could be stricter.")
            deduction += _PENALTY_ACCEPTABLE
        elif val in _POOR_POLICIES:
            details.append("  * Poor choice; may leak URLs.")
            deduction += _PENALTY_POOR
        else:
            details.append("  * Unrecognized policy value.")
            deduction += _PENALTY_UNKNOWN_POLICY
    else:
        details.append("No Referrer-Policy header found.")
        deduction += _PENALTY_MISSING_POLICY

    # --- DNT meta tag in HTML ---
    soup = BeautifulSoup(html, "html.parser")
    meta = soup.find("meta", attrs={"name": re.compile(r"^dnt$", re.I)})
    if meta:
        content = (meta.get("content") or "").strip().lower()
        details.append(f"DNT meta tag content: '{content}'")
        if content not in {"1", "true"}:
            details.append("  * Meta is ambiguous, not a clear opt-out flag.")
            deduction += _PENALTY_META_AMBIGUOUS
    else:
        details.append("No <meta name=\"dnt\"> tag detected.")
        deduction += _PENALTY_NO_META

    # --- Final score ---
    score = _clamp(_MAX_SCORE - deduction, _MIN_SCORE, _MAX_SCORE)

    if score == _MAX_SCORE:
        details.append("All good – referrer and DNT look configured for privacy.")
    elif score < 5:
        details.append("Privacy is weak here – too many defaults or missing headers.")
    else:
        details.append("Some settings OK, but a few tweaks recommended.")

    # debug print if you need it:
    # print(f"[DEBUG] deduction={deduction}, score={score}")

    return score, details


# --------------------------------------------------------------------------- #
# Simple CLI entry-point
# --------------------------------------------------------------------------- #
if __name__ == "__main__":  # pragma: no cover
    import argparse

    parser = argparse.ArgumentParser(
        description="Passive Referrer-Policy & DNT scan")
    parser.add_argument("-u", "--url", required=True,
                        help="Website to test (include http/https)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Seconds to wait for response (default 10)")
    args = parser.parse_args()

    final_score, log = analyze_referrer_dnt(args.url, timeout=args.timeout)
    print(f"\nFinal Score: {final_score}/10\n" + "-"*30)
    for entry in log:
        print(entry)
