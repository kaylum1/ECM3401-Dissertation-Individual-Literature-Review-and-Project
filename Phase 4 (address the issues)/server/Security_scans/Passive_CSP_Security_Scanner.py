

"""
Passive CSP Security Scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Grab the Content-Security-Policy header from a site and flag any
missing or weak bits.  We also look inside the `script-src` directive
for external hosts that aren’t 'self'.

Scoring starts at 10 and knocks off points for:

  • missing essential directives  
  • wildcard '*' usage  
  • unsafe-inline or unsafe-eval  
  • external script hosts in the CSP  

Score is kept between 1 and 10.
"""

import re
import requests
from urllib.parse import urlparse

# ——— what we expect in a decent CSP ———
_REQUIRED_DIRECTIVES = [
    "default-src",
    "script-src",
    "object-src",
    "frame-ancestors",
]

# ——— patterns that weaken CSP ———
_WEAK_PATTERNS = {
    "wildcard":        r"\*",
    "unsafe_inline":   r"unsafe-inline",
    "unsafe_eval":     r"unsafe-eval",
}

# ——— how many points to lose for each issue ———
_PENALTIES = {
    "missing_directive": 3,
    "wildcard":          3,
    "unsafe_inline":     4,
    "unsafe_eval":       4,
    "external_scripts":  2,
}


def _clamp(score: int, lo: int = 1, hi: int = 10) -> int:
    """Keep score in the [lo, hi] range."""
    return max(lo, min(hi, score))


def _get_csp_header(headers: dict) -> str | None:
    """Return the CSP header value if present (case-insensitive)."""
    for name, val in headers.items():
        if name.lower() == "content-security-policy":
            return val
    return None


def _missing_directives(csp: str) -> list[str]:
    """List any required directives that are absent from the CSP string."""
    return [d for d in _REQUIRED_DIRECTIVES if d not in csp]


def _find_weak_patterns(csp: str) -> list[str]:
    """Detect any of our known risky patterns in the policy."""
    found = []
    for key, pat in _WEAK_PATTERNS.items():
        if re.search(pat, csp):
            found.append(key)
    return found


def _external_sources(csp: str) -> list[str]:
    """
    Look into the 'script-src' part and pull out any hosts that start with http
    and aren’t 'self'.
    """
    m = re.search(r"script-src\s+([^;]+)", csp)
    if not m:
        return []
    hosts = m.group(1).split()
    return [h for h in hosts if h.startswith("http") and "self" not in h]


def analyze_csp_security(url: str) -> tuple[int, list[str]]:
    """
    Fetch the page headers, parse the CSP, and return (score, notes).
    """
    score = 10
    notes: list[str] = []

    try:
        resp = requests.get(url, timeout=10)
        hdrs = resp.headers
    except Exception as e:
        return 1, [f"Failed to retrieve headers: {e}"]

    csp = _get_csp_header(hdrs)
    if not csp:
        return 1, ["No CSP header found. Major security risk!"]

    # 1) missing directives?
    miss = _missing_directives(csp)
    if miss:
        pen = _PENALTIES["missing_directive"]
        score -= pen
        notes.append(f"Missing directives: {', '.join(miss)} (−{pen})")

    # 2) weak patterns like '*' or 'unsafe-inline'
    weak = _find_weak_patterns(csp)
    for w in weak:
        pen = _PENALTIES.get(w, 0)
        label = w.replace("_", "-")
        score -= pen
        notes.append(f"Found '{label}' in policy (−{pen})")

    # 3) external script hosts listed in CSP
    extern = _external_sources(csp)
    if extern:
        pen = _PENALTIES["external_scripts"]
        score -= pen
        sample = extern[:3]
        trail = "..." if len(extern) > 3 else ""
        notes.append(f"External script hosts: {', '.join(sample)}{trail} (−{pen})")

    final = _clamp(score)

    # summary line
    if final == 10:
        notes.append("CSP looks solid; no glaring issues.")
    elif final < 5:
        notes.append("High risk: CSP misconfigurations need fixing.")
    else:
        notes.append("Some weaknesses in CSP; consider tightening it.")

    return final, notes


def _normalize_url(u: str) -> str:
    """
    Ensure there's an HTTP scheme and strip everything except origin.
    """
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    p = urlparse(u)
    return f"{p.scheme}://{p.netloc}"


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="Passive CSP Security Scanner"
    )
    parser.add_argument("-u", "--url", required=True,
                        help="Website to scan (scheme optional)")
    args = parser.parse_args()

    origin = _normalize_url(args.url)
    print(f"\nScanning CSP for: {origin}\n" + "-"*30)
    score, details = analyze_csp_security(origin)

    for line in details:
        print(" -", line)
    print(f"\nFinal Score: {score}/10\n")


if __name__ == "__main__":
    main()
