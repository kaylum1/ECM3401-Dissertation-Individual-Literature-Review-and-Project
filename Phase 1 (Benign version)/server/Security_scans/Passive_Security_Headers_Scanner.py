
import requests
from typing import List, Tuple

# Penalties for each header if absent or bogus
_PENALTIES = {
    'hsts':               3,
    'frame_options':      2,
    'content_type':       2,
    'referrer_policy':    1,
    'xss_protection':     1,
    'permissions_policy': 1,
}


def _clamp(score: int) -> int:
    """Keep score in the range [1, 10]."""
    return max(1, min(10, score))


def analyze_security_headers(url: str, timeout: int = 10) -> Tuple[int, List[str]]:
    """
    Return (final_score, notes) after checking key security headers.
    """
    notes: List[str] = []
    score = 10

    try:
        resp = requests.get(url, timeout=timeout)
    except Exception as exc:  # network or DNS problem
        return 1, [f"Error fetching page: {exc}"]

    hdrs = resp.headers

    # 1) HSTS
    hsts = hdrs.get('Strict-Transport-Security')
    if hsts:
        notes.append(f"HSTS: {hsts}")
    else:
        score -= _PENALTIES['hsts']
        notes.append(f"Missing Strict-Transport-Security (−{_PENALTIES['hsts']})")

    # 2) X-Frame-Options
    xfo = hdrs.get('X-Frame-Options')
    if xfo:
        notes.append(f"X-Frame-Options: {xfo}")
    else:
        score -= _PENALTIES['frame_options']
        notes.append(f"Missing X-Frame-Options (−{_PENALTIES['frame_options']})")

    # 3) X-Content-Type-Options
    xcto = hdrs.get('X-Content-Type-Options')
    if xcto:
        notes.append(f"X-Content-Type-Options: {xcto}")
    else:
        score -= _PENALTIES['content_type']
        notes.append(f"Missing X-Content-Type-Options (−{_PENALTIES['content_type']})")

    # 4) Referrer-Policy
    rp = hdrs.get('Referrer-Policy')
    if rp:
        notes.append(f"Referrer-Policy: {rp}")
    else:
        score -= _PENALTIES['referrer_policy']
        notes.append(f"Missing Referrer-Policy (−{_PENALTIES['referrer_policy']})")

    # 5) X-XSS-Protection
    xxp = hdrs.get('X-XSS-Protection')
    if xxp:
        notes.append(f"X-XSS-Protection: {xxp}")
    else:
        score -= _PENALTIES['xss_protection']
        notes.append(f"Missing X-XSS-Protection (−{_PENALTIES['xss_protection']})")

    # 6) Permissions-Policy
    pp = hdrs.get('Permissions-Policy')
    if pp:
        notes.append(f"Permissions-Policy: {pp}")
    else:
        score -= _PENALTIES['permissions_policy']
        notes.append(f"Missing Permissions-Policy (−{_PENALTIES['permissions_policy']})")

    # Clamp and summarise
    score = _clamp(score)
    if score == 10:
        notes.append("All essential security headers are in place.")
    elif score >= 7:
        notes.append("Minor header gaps; review recommended.")
    elif score >= 4:
        notes.append("Several headers missing; urgent review needed.")
    else:
        notes.append("Few to no security headers detected; fix ASAP.")

    return score, notes


# --------------------------------------------------------------------------- #
# CLI for standalone testing
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Check basic HTTP security headers and score them"
    )
    parser.add_argument(
        "-u", "--url", required=True,
        help="Target URL (include http:// or https://)"
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="Seconds to wait for the response (default: 10)"
    )
    args = parser.parse_args()

    final_score, report = analyze_security_headers(args.url, timeout=args.timeout)
    print(f"\nSecurity Headers Scan for {args.url}")
    print(f"Score: {final_score}/10\n")
    for line in report:
        print(" -", line)
