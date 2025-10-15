

"""
Passive Outdated Plugin Security Scanner
----------------------------------------

Quick-and-dirty pass over the page HTML to spot common JS libraries
and CMS frameworks, grab their version strings (if present), and treat
any hit as “potentially outdated.”

Scoring:
  • Start at 10
  • −2 points per library found
  • Never drop below 1

No live vulnerability lookup here—just pattern matching.  
TODO:
  • Wire up real CVE data  
  • Distinguish truly outdated vs. current versions  
"""

import requests
import re
from typing import List, Tuple

# Patterns to regex-match known libraries/CMS and capture a version string
LIBRARY_PATTERNS = {
    "jQuery":     r"jquery[-.](\d+\.\d+\.\d+)\.min\.js",
    "Bootstrap":  r"bootstrap[-.](\d+\.\d+\.\d+)\.min\.js",
    "Angular":    r"angular(?:\.min)?\.js(?:\?v=)?(\d+\.\d+\.\d+)",
    "Vue.js":     r"vue@(\d+\.\d+\.\d+)/vue(?:\.global)?\.js",
    "React":      r"react@(\d+\.\d+\.\d+)/react(?:\.production)?\.min\.js",
    "WordPress":  r"content=\"WordPress (\d+\.\d+\.\d+)\"",
    "Joomla":     r"mootools-core\.js\?(\d+\.\d+\.\d+)",
    "Drupal":     r"Drupal\.settings\s*=\s*\{[^}]*version:\s*'(\d+\.\d+\.\d+)'",
}

_MAX_SCORE = 10
_PENALTY   = 2
_MIN_SCORE = 1

def get_page_content(url: str, timeout: int = 8) -> str | None:
    """Fetch the page HTML, or return None if something goes wrong."""
    try:
        resp = requests.get(url, timeout=timeout)
        # resp.raise_for_status()  # uncomment if you want HTTP error bubbling
        return resp.text
    except Exception as e:
        # print(f"[debug] fetch failed: {e}")  # debug log
        return None

def detect_libraries(html: str) -> List[Tuple[str, str]]:
    """
    Scan the raw HTML for our library patterns.
    Returns a list of (library_name, version) tuples.
    """
    found: List[Tuple[str, str]] = []
    for name, pattern in LIBRARY_PATTERNS.items():
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            version = m.group(1)
            found.append((name, version))
    return found

def check_vulnerabilities(detected: List[Tuple[str, str]]) -> Tuple[int, List[str]]:
    """
    Given a list of detected libraries, compute a score and assemble details.
    """
    if not detected:
        return _MAX_SCORE, ["No known libraries detected (10/10)."]

    details: List[str] = []
    deduction = 0

    for lib, ver in detected:
        details.append(f"Found {lib} v{ver}")
        deduction += _PENALTY
        # Optionally, note that we assume it's outdated:
        # details.append(f"  (treating as outdated, −{_PENALTY})")

    score = _MAX_SCORE - deduction
    if score < _MIN_SCORE:
        score = _MIN_SCORE

    details.append(f"{len(detected)} library(ies) spotted, final score {score}/10")
    return score, details

def analyze_outdated_plugins(url: str) -> Tuple[int, List[str]]:
    """
    Main entry point. Fetches the page, detects libs, and returns
    (score, list_of_detail_strings).
    """
    html = get_page_content(url)
    if html is None:
        return _MIN_SCORE, ["Could not retrieve page content."]

    libs = detect_libraries(html)
    return check_vulnerabilities(libs)

# --------------------------------------------------------------------------- #
# Command-line interface for standalone testing
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Passive scan for outdated JS/CMS libraries"
    )
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL (include http:// or https://)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=8,
        help="Fetch timeout in seconds (default: 8)"
    )
    args = parser.parse_args()

    score, report = analyze_outdated_plugins(args.url)
    print("\n--- Outdated Plugin Scan ---")
    for line in report:
        print(" *", line)
    print(f"\nFinal score: {score}/10")
