
import requests
from typing import List, Tuple

# “Magic numbers” pulled into constants for quick tweaking
_PENALTY_SECURE   = 2
_PENALTY_HTTPONLY = 2
_MAX_SCORE        = 10
_MIN_SCORE        = 1


def _clamp(val: int, low: int, high: int) -> int:
    """Tiny helper: keep *val* inside [low, high]."""
    return max(low, min(high, val))


def analyze_cookie_privacy(url: str, timeout: int = 10) -> Tuple[int, List[str]]:
    """Run the scan and return *(final_score, details_lines)*."""
    try:
        resp = requests.get(url, timeout=timeout)
    except Exception as exc:                     # pragma: no cover
        # A fetch failure doesn’t tell us anything about cookies.
        return _MIN_SCORE, [f"Request failed: {exc}"]

    details: List[str] = []
    deduction = 0

    if not resp.cookies:
        details.append("No cookies set – nothing to check.")
        return _MAX_SCORE, details

    for ck in resp.cookies:
        name = ck.name
        is_secure   = ck.secure
        is_httponly = ck._rest.get("HttpOnly") is True  # some libs store it as a string

        # Raw dump (handy when we eyeball logs)
        details.append(f"{name}: Secure={is_secure}, HttpOnly={is_httponly}")

        # Apply penalties
        if not is_secure:
            deduction += _PENALTY_SECURE
            details.append(f"    • missing Secure flag (-{_PENALTY_SECURE})")
        if not is_httponly:
            deduction += _PENALTY_HTTPONLY
            details.append(f"    • missing HttpOnly flag (-{_PENALTY_HTTPONLY})")

        # Uncomment if you want noisy inline debugging
        # print(f"[dbg] {name=} {is_secure=} {is_httponly=} {deduction=}")

    final_score = _clamp(_MAX_SCORE - deduction, _MIN_SCORE, _MAX_SCORE)

    # A bit of colour in the report text
    if final_score == _MAX_SCORE:
        details.append("All good – every cookie carries Secure+HttpOnly.")
    elif final_score < 5:
        details.append("Danger zone: lots of cookies missing basic protections.")
    else:
        details.append("Some cookies need attention – see above for which ones.")

    # TODO: check SameSite and SameParty once the backend supports it
    return final_score, details


# --------------------------------------------------------------------------- #
# CLI entry-point – makes the module runnable as a tiny standalone tool
# --------------------------------------------------------------------------- #
if __name__ == "__main__":                       # pragma: no cover
    import argparse

    parser = argparse.ArgumentParser(
        description="Quick passive scan of cookie privacy flags.")
    parser.add_argument("-u", "--url", required=True,
                        help="Target site (include http/https)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default 10)")

    opts = parser.parse_args()
    score, log_lines = analyze_cookie_privacy(opts.url, timeout=opts.timeout)

    print(f"\nFinal score: {score}/10\n" + "-" * 40)
    for line in log_lines:
        print(line)
