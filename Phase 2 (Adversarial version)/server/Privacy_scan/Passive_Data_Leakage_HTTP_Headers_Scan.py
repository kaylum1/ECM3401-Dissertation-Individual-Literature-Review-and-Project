
"""
Passive check for HTTP-header data leakage
-----------------------------------------

Very small helper that grabs a page once and looks at the response headers.
If we spot headers that routinely expose internal information (e.g. “Server”,
“X-Powered-By”, private IPs in forwarding headers, etc.) we knock points off
a simple 10-point score.

Penalties (tweak these constants if you ever feel like it):

    * -2  for most “loud” disclosure headers
    * -1  for softer hints (“Via”, “X-Real-IP”)
    * extra -2 if the value itself leaks a private IP address

Score never drops below 1; if you see a 10 the response looked squeaky-clean.

TODO:
    • maybe check for build numbers in headers?
    • SameSite / security headers could be part of a separate scan
"""



import re
from typing import List, Tuple

import requests

# --------------------------------------------------------------------------- #
# Tunables – adjust as needed
# --------------------------------------------------------------------------- #

# Headers that usually shouldn’t be public and their penalty weights
_LEAKY_HEADERS = {
    "Server": 2,
    "X-Powered-By": 2,
    "X-AspNet-Version": 2,
    "X-AspNetMvc-Version": 2,
    "X-Backend-Server": 2,
    "Via": 1,
    "Forwarded": 2,
    "X-Forwarded-For": 2,
    "X-Real-IP": 1,
}

# regex to catch private IPv4 ranges inside any header value
_PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b"
)

_MAX_SCORE = 10
_MIN_SCORE = 1
_PRIVATE_IP_PENALTY = 2


# --------------------------------------------------------------------------- #
# Helper(s)
# --------------------------------------------------------------------------- #
def _clamp(val: int, low: int, high: int) -> int:
    """Keep *val* inside [low, high]."""
    return max(low, min(high, val))


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def analyze_data_leakage_headers(url: str, timeout: int = 10) -> Tuple[int, List[str]]:
    """
    Grab *url* once, look at its response headers, and return (score, log lines).
    A higher score means less information is leaking.
    """
    try:
        resp = requests.get(url, timeout=timeout)
    except Exception as exc:  # pragma: no cover
        return _MIN_SCORE, [f"Request failed: {exc}"]

    details: List[str] = []
    deduction = 0

    for header, points in _LEAKY_HEADERS.items():
        if header in resp.headers:
            raw_val = resp.headers[header]
            details.append(f"{header}: {raw_val}")

            deduction += points

            # Extra hit if the value itself shouts a private IP
            if _PRIVATE_IP_RE.search(raw_val):
                details.append("    • contains private IP address (-2)")
                deduction += _PRIVATE_IP_PENALTY

    final_score = _clamp(_MAX_SCORE - deduction, _MIN_SCORE, _MAX_SCORE)

    # Human-friendly summary line (feel free to localise / re-word)
    if final_score == _MAX_SCORE:
        details.append("All clear – no obvious data leakage headers present.")
    elif final_score < 5:
        details.append("High risk: several headers expose internal details.")
    else:
        details.append("Some headers could leak information – review recommended.")

    return final_score, details


# --------------------------------------------------------------------------- #
# CLI driver – lets us run “python Passive_Data_Leakage_HTTP_Headers_Scan.py -u https://…”
# --------------------------------------------------------------------------- #
if __name__ == "__main__":  # pragma: no cover
    import argparse

    p = argparse.ArgumentParser(
        description="Quick passive scan for data-leaking HTTP headers"
    )
    p.add_argument("-u", "--url", required=True, help="Target site (include http/https)")
    p.add_argument("--timeout", type=int, default=10, help="Timeout (sec), default 10")

    opt = p.parse_args()

    score, lines = analyze_data_leakage_headers(opt.url, timeout=opt.timeout)

    print(f"\nFinal score: {score}/10\n" + "-" * 40)
    for ln in lines:
        print(ln)
