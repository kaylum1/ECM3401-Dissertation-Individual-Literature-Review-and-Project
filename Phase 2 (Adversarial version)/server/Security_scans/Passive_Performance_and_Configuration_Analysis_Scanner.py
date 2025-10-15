

"""
Passive Performance & Configuration Analysis
--------------------------------------------

A one-shot check of a site’s core performance headers and settings.
We fetch the homepage once and look for:

  • HTTP/2 vs HTTP/1.1
  • Response compression (gzip/br)
  • Cache-Control max-age values
  • Connection keep-alive
  • Number of HTTP redirects
  • Page payload size
  • Rough count of static resources (scripts, images, CSS, etc.)

Start from 10 points; knock off per issue based on SCORE_DEDUCTIONS.
Never go below 1. Results come back as (score, list_of_notes).

Constants and logic are split into small, tweakable chunks below.
"""

import requests
import argparse
import time
import re
from urllib.parse import urlparse
from typing import List, Tuple

# -----------------------------------------------------------------------------
# Penalties for each misconfiguration or potential slowdown (invert for bonuses)
# -----------------------------------------------------------------------------
SCORE_DEDUCTIONS = {
    "no_http2":            2,   # not negotiating HTTP/2
    "no_compression":      2,   # missing gzip or brotli
    "weak_cache":          1,   # no or low max-age
    "no_keep_alive":       2,   # missing Connection: keep-alive
    "redirects":           2,   # any HTTP redirects happened
    "large_page":          3,   # payload over threshold
    "excessive_requests":  2    # too many resource tags found
}

# Thresholds (tweak to taste)
PAGE_SIZE_THRESHOLD      = 500 * 1024   # 500 KB
RESOURCE_COUNT_THRESHOLD = 50           # tags before we call it “excessive”

def _clamp(score: int, lo: int = 1, hi: int = 10) -> int:
    """Keep score inside the [lo, hi] range."""
    return max(lo, min(hi, score))


def analyze_performance(base_url: str, timeout: int = 10) -> Tuple[int, List[str]]:
    """
    Perform the scan on base_url and return (final_score, notes).
    """
    notes: List[str] = []
    score = 10

    # Time the request for potential latency insights (not used in score here)
    start = time.time()
    try:
        resp = requests.get(base_url, timeout=timeout)
    except Exception as exc:
        # If we can’t reach the site, give up and flag as worst score
        return 1, [f"Failed to fetch {base_url}: {exc}"]
    elapsed = time.time() - start

    # --- Redirects check ---
    num_redirects = len(resp.history)
    if num_redirects:
        score -= SCORE_DEDUCTIONS["redirects"]
        notes.append(f"{num_redirects} redirect(s) followed (−{SCORE_DEDUCTIONS['redirects']})")
    else:
        notes.append("No HTTP redirects")

    # --- HTTP version (requests uses raw.version: 11=1.1, 20=2) ---
    http_ver = getattr(resp.raw, "version", None)
    if http_ver == 20:
        notes.append("Connection used HTTP/2")
    else:
        score -= SCORE_DEDUCTIONS["no_http2"]
        notes.append(f"Not HTTP/2 (raw.version={http_ver}) (−{SCORE_DEDUCTIONS['no_http2']})")

    # --- Compression check ---
    enc = resp.headers.get("Content-Encoding", "")
    if "gzip" in enc or "br" in enc:
        notes.append(f"Content-Encoding: {enc}")
    else:
        score -= SCORE_DEDUCTIONS["no_compression"]
        notes.append(f"No response compression (−{SCORE_DEDUCTIONS['no_compression']})")

    # --- Cache-Control check ---
    cc = resp.headers.get("Cache-Control", "")
    m = re.search(r"max-age=(\d+)", cc)
    if m and int(m.group(1)) >= 3600:
        notes.append(f"Cache-Control max-age={m.group(1)}s")
    else:
        score -= SCORE_DEDUCTIONS["weak_cache"]
        notes.append(f"Weak or missing cache header (−{SCORE_DEDUCTIONS['weak_cache']})")

    # --- Keep-Alive header ---
    conn_hdr = resp.headers.get("Connection", "").lower()
    if "keep-alive" in conn_hdr:
        notes.append("Connection: keep-alive present")
    else:
        score -= SCORE_DEDUCTIONS["no_keep_alive"]
        notes.append(f"No keep-alive (−{SCORE_DEDUCTIONS['no_keep_alive']})")

    # --- Page size check ---
    size = len(resp.content)
    if size > PAGE_SIZE_THRESHOLD:
        score -= SCORE_DEDUCTIONS["large_page"]
        notes.append(f"Large payload: {size//1024} KB (−{SCORE_DEDUCTIONS['large_page']})")
    else:
        notes.append(f"Payload size: {size//1024} KB")

    # --- Rough resource-count check ---
    html = resp.text or ""
    found = re.findall(r"<(?:script|img|link|iframe)\b", html, re.IGNORECASE)
    count = len(found)
    if count > RESOURCE_COUNT_THRESHOLD:
        score -= SCORE_DEDUCTIONS["excessive_requests"]
        notes.append(f"{count} resource tags (−{SCORE_DEDUCTIONS['excessive_requests']})")
    else:
        notes.append(f"{count} resource tags found")

    # Clamp the final score and return
    final_score = _clamp(score)
    return final_score, notes


def main() -> None:
    """
    CLI entrypoint: parse args, normalize URL, run scanner, and print results.
    """
    parser = argparse.ArgumentParser(
        description="Assess basic performance and HTTP config issues"
    )
    parser.add_argument(
        "-u", "--url", required=True,
        help="Base URL to scan (include http:// or https://)"
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="Request timeout in seconds (default: 10)"
    )
    args = parser.parse_args()

    # Strip path, query, fragment: just keep scheme://host
    p = urlparse(args.url)
    base = f"{p.scheme}://{p.netloc}"

    print(f"🔍 Scanning performance & configuration for: {base}\n")
    score, details = analyze_performance(base, timeout=args.timeout)

    print("\n--- Performance & Configuration Report ---")
    for note in details:
        print(f" - {note}")
    print(f"\n--- Security Score ---\nSecurity Score: {score} / 10")

    # Quick interpretation
    if score < 5:
        print("Serious performance/security misconfigurations!")
    elif score < 8:
        print("Some optimization/security risks exist.")
    else:
        print("Strong performance and configuration.")


if __name__ == "__main__":
    main()
