


"""
Passive CSRF Security Scanner
-----------------------------

A quick, non-intrusive check for common CSRF protections:

  1. Look for hidden CSRF tokens in all <form> tags
  2. Verify presence of key security headers (e.g. X-Frame-Options)
  3. Ensure cookies have Secure & SameSite flags set
  4. Inspect CORS policy via Access-Control-Allow-Origin

Scoring starts at 10 and subtracts points for each issue found:

  • Missing CSRF token in any form      → −4  
  • Missing security headers            → −3  
  • Cookies lacking Secure/SameSite     → −2  
  • Open CORS (wildcard or different origin) → −3  

Final score is clamped between 1 and 10.  
"""

import requests
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from typing import List, Tuple

# ————— tweak these as needed —————
REQUIRED_HEADERS = ["X-Frame-Options"]
SCORE_PENALTIES = {
    "missing_csrf_token": 4,
    "missing_headers":    3,
    "weak_cookies":       2,
    "open_cors":          3,
}
_MAX_SCORE = 10
_MIN_SCORE = 1


def _clamp(value: int, floor: int, ceiling: int) -> int:
    """Keep *value* within [floor, ceiling]."""
    return max(floor, min(ceiling, value))


def analyze_csrf_security(url: str, timeout: int = 10) -> Tuple[int, List[str]]:
    """
    Perform passive CSRF checks on the given URL.

    Returns:
        final_score (int): 1–10, higher is better.
        details     (List[str]): notes on each check.
    """
    details: List[str] = []
    deduction = 0

    try:
        resp = requests.get(url, timeout=timeout)
    except Exception as exc:  # pragma: no cover
        return _MIN_SCORE, [f"Request failed: {exc}"]

    # 1) Hidden CSRF tokens in forms
    soup = BeautifulSoup(resp.text, "html.parser")
    forms = soup.find_all("form")
    missing_tokens = 0
    for form in forms:
        hidden = form.find_all("input", type="hidden")
        has_token = any(
            ("csrf" in (inp.get("name") or "").lower()
             or "authenticity" in (inp.get("name") or "").lower())
            for inp in hidden
        )
        if not has_token:
            missing_tokens += 1
    if missing_tokens:
        details.append(f"{missing_tokens} form(s) missing CSRF token")
        deduction += SCORE_PENALTIES["missing_csrf_token"]
    else:
        details.append("All forms include a hidden CSRF token")

    # 2) Security headers
    missing = [h for h in REQUIRED_HEADERS if h not in resp.headers]
    if missing:
        details.append("Missing headers: " + ", ".join(missing))
        deduction += SCORE_PENALTIES["missing_headers"]
    else:
        details.append("Required security headers are present")

    # 3) Cookie flags
    bad_cookies = 0
    for ck in resp.cookies:
        # note: requests stores Secure flag, and SameSite in ck._rest
        if not ck.secure or ck._rest.get("SameSite", "").lower() not in ("lax", "strict"):
            bad_cookies += 1
    if bad_cookies:
        details.append(f"{bad_cookies} cookie(s) lack Secure/SameSite")
        deduction += SCORE_PENALTIES["weak_cookies"]
    else:
        details.append("Cookies have Secure & SameSite flags")

    # 4) CORS policy
    aco = resp.headers.get("Access-Control-Allow-Origin")
    if aco:
        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        if aco == "*" or aco != origin:
            details.append(f"CORS allows {aco}")
            deduction += SCORE_PENALTIES["open_cors"]
        else:
            details.append("CORS restricted to same origin")
    else:
        details.append("No CORS header found (same-origin only by default)")

    # Final score
    final_score = _clamp(_MAX_SCORE - deduction, _MIN_SCORE, _MAX_SCORE)
    details.append(f"Final deduction: {deduction}")

    return final_score, details


def main() -> None:
    """CLI entry-point for quick, stand-alone checks."""
    parser = argparse.ArgumentParser(
        description="Passive scan for CSRF protections"
    )
    parser.add_argument(
        "-u", "--url", required=True,
        help="Website URL to scan (include http/https)"
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="Request timeout seconds (default 10)"
    )
    args = parser.parse_args()

    score, report = analyze_csrf_security(args.url, timeout=args.timeout)
    print("\n--- CSRF Security Report ---")
    for line in report:
        print(" •", line)
    print(f"\nSecurity Score: {score} / 10")


if __name__ == "__main__":
    main()
