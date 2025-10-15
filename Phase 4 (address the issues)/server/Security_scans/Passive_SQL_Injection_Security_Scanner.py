

"""
Passive SQL Injection Security Scan
-----------------------------------

Grab a page, peek for telltale SQL error messages, sniff out sketchy URL
parameters (id, login, search, etc.), and verify a couple of headers (CSP,
X-Frame-Options) that help lock things down.  We start at 10 points and knock
off for each red flag we spot.  Score is clamped between 1 and 10.
"""

import requests
import re
from urllib.parse import urlparse, parse_qs
from typing import List, Tuple

# Patterns that usually show up in database error dumps
_SQL_ERROR_PATTERNS = [
    r"You have an error in your SQL syntax",
    r"Warning: mysql_fetch_array\(",
    r"Warning: mysql_fetch_assoc\(",
    r"Unclosed quotation mark",
    r"Microsoft OLE DB Provider for SQL Server",
    r"ORA-01756",
    r"SQLSTATE\[[0-9]{5}\]"
]

# Param names that often map straight to database fields
_SUSPICIOUS_PARAM_RE = re.compile(
    r'^(?:id|user|login|name|page|search|query|q)$', re.IGNORECASE
)

# Headers whose absence makes injections easier
_REQUIRED_HEADERS = ["Content-Security-Policy", "X-Frame-Options"]

# Penalties per finding type
_PENALTIES = {
    "errors": 5,         # SQL error messages in page body
    "params": 3,         # suspicious URL params present
    "headers": 2         # missing CSP or frame-options
}

_MAX_SCORE = 10
_MIN_SCORE = 1


def analyze_sql_security(url: str, timeout: int = 10) -> Tuple[int, List[str]]:
    """
    Return (score, findings) after a passive SQL-injection check.
    """
    findings: List[str] = []
    deduction = 0

    # 1) Fetch the page
    try:
        resp = requests.get(url, timeout=timeout)
        text = resp.text or ""
        hdrs = resp.headers
    except Exception as exc:
        return _MIN_SCORE, [f"Failed to retrieve URL: {exc}"]

    # 2) Look for SQL error snippets
    errors = [pat for pat in _SQL_ERROR_PATTERNS if re.search(pat, text, re.IGNORECASE)]
    if errors:
        deduction += _PENALTIES["errors"]
        sample = errors[:3]
        findings.append(f"SQL errors exposed: {', '.join(sample)}" + ("..." if len(errors) > 3 else ""))

    # 3) Spot sketchy query parameters
    qs = parse_qs(urlparse(url).query)
    suspects = [name for name in qs if _SUSPICIOUS_PARAM_RE.match(name)]
    if suspects:
        deduction += _PENALTIES["params"]
        findings.append(f"Suspicious params: {', '.join(suspects)}")

    # 4) Check for essential security headers
    missing = [h for h in _REQUIRED_HEADERS if h not in hdrs]
    if missing:
        deduction += _PENALTIES["headers"]
        findings.append(f"Missing headers: {', '.join(missing)}")

    # 5) Tally up the final score
    score = _MAX_SCORE - deduction
    if score < _MIN_SCORE:
        score = _MIN_SCORE

    # 6) Summary line
    if score == _MAX_SCORE:
        findings.append("No SQL-injection red flags detected.")
    elif score == _MIN_SCORE:
        findings.append("High risk: SQL injection likely possible.")
    else:
        findings.append("Potential SQL-injection issues found.")

    return score, findings


# --------------------------------------------------------------------------
# CLI entry-point for ad-hoc testing
# --------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Passive SQL Injection Security Scanner"
    )
    parser.add_argument(
        "-u", "--url", required=True,
        help="Target URL (include http:// or https://)"
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="Seconds to wait for response (default: 10)"
    )
    args = parser.parse_args()

    final_score, report = analyze_sql_security(args.url, timeout=args.timeout)
    print(f"\nFinal Score: {final_score}/10\n" + "-" * 30)
    for line in report:
        print("•", line)
