
"""
Passive Tracker Script Security Scan
====================================

This one’s all about making sure your <script> tags aren’t opening
security holes. We grab the page once and look for:

  • Scripts loaded over plain HTTP (that’s a no-no)  
  • Missing Subresource Integrity (SRI) `integrity` attributes  
  • Inline `<script>` blocks (harder to manage securely)  
  • Scripts with an `integrity` but no `crossorigin` (you’ll need both)

Start at 10 and knock off points for each issue. The score never dips
below 1.  
"""

import requests
from bs4 import BeautifulSoup
from typing import List, Tuple

# --------------------------------------------------------------------------- #
# tweak these penalties if you like
# --------------------------------------------------------------------------- #
_PENALTY_INLINE          = 2  # inline <script> tags
_PENALTY_HTTP            = 3  # scripts not served over HTTPS
_PENALTY_NO_SRI          = 1  # missing integrity attribute
_PENALTY_NO_CROSSORIGIN  = 1  # integrity without crossorigin
_MAX_SCORE               = 10
_MIN_SCORE               = 1

def _clamp(val: int, lo: int, hi: int) -> int:
    """Keep val in the [lo, hi] range."""
    return max(lo, min(hi, val))

def analyze_tracker_security(url: str, timeout: int = 10) -> Tuple[int, List[str]]:
    """
    Scan a page’s <script> tags for basic security best practices.

    Returns:
        final_score (int): 1–10, higher is better.
        details     (List[str]): notes on each deduction or finding.
    """
    try:
        resp = requests.get(url, timeout=timeout)
        html = resp.text
    except Exception as exc:  # pragma: no cover
        return _MIN_SCORE, [f"Couldn’t fetch page: {exc}"]

    details: List[str] = []
    deduction = 0
    soup = BeautifulSoup(html, "html.parser")
    scripts = soup.find_all("script")

    for idx, tag in enumerate(scripts, start=1):
        src = tag.get("src")
        if src:
            details.append(f"Script #{idx}: src={src}")
            # 1) HTTP vs HTTPS
            if not src.lower().startswith("https://"):
                deduction += _PENALTY_HTTP
                details.append(f"    • insecure protocol (-{_PENALTY_HTTP})")
            # 2) SRI integrity
            if not tag.has_attr("integrity"):
                deduction += _PENALTY_NO_SRI
                details.append(f"    • missing integrity attribute (-{_PENALTY_NO_SRI})")
            # 3) crossorigin when using integrity
            if tag.has_attr("integrity") and not tag.has_attr("crossorigin"):
                deduction += _PENALTY_NO_CROSSORIGIN
                details.append(f"    • missing crossorigin (-{_PENALTY_NO_CROSSORIGIN})")
        else:
            # Inline scripts are tougher to audit
            details.append(f"Inline script #{idx}")
            deduction += _PENALTY_INLINE
            details.append(f"    • inline script detected (-{_PENALTY_INLINE})")

    final_score = _clamp(_MAX_SCORE - deduction, _MIN_SCORE, _MAX_SCORE)

    # Wrap-up message
    if final_score == _MAX_SCORE:
        details.append("All scripts use HTTPS and have proper SRI/crossorigin.")
    elif final_score < 5:
        details.append("Major security gaps: review script tags for SRI and HTTPS.")
    else:
        details.append("Some scripts need SRI/HTTPS adjustments; see above.")

    return final_score, details

# --------------------------------------------------------------------------- #
# CLI interface for quick checks
# --------------------------------------------------------------------------- #
if __name__ == "__main__":  # pragma: no cover
    import argparse

    parser = argparse.ArgumentParser(
        description="Passive scan of <script> tag security"
    )
    parser.add_argument("-u", "--url", required=True, help="Page URL (http/https)")
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="Request timeout in seconds (default 10)"
    )
    args = parser.parse_args()

    score, notes = analyze_tracker_security(args.url, timeout=args.timeout)
    print(f"\nFinal score: {score}/10\n" + "-" * 40)
    for line in notes:
        print(line)
