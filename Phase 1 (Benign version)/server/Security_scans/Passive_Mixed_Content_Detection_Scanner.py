

"""
Passive Mixed Content Detection Scanner
---------------------------------------

Fetches a page over HTTPS and looks for any resources loaded over HTTP.
Checks <script>, <link rel="stylesheet">, <img>, <iframe>, plus any tags
with src or href attributes. Deducts points per resource type:

    - scripts       : -3 points each
    - stylesheets   : -2 points each
    - iframes       : -3 points each
    - images        : -1 point  each
    - other         : -1 point  each

Score starts at 10 and never drops below 1.  
Returns (final_score, details_list).
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from typing import List, Tuple
import argparse

# How many points to deduct per mixed-content resource
PENALTIES = {
    'script':     3,
    'stylesheet': 2,
    'iframe':     3,
    'image':      1,
    'other':      1,
}

MAX_SCORE = 10
MIN_SCORE = 1

def fetch_html(url: str, timeout: int = 10) -> str | None:
    """Return the page HTML, or None on error."""
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"[!] Failed to fetch {url}: {e}")
        return None

def find_mixed_content(base_url: str, html: str) -> dict[str, List[str]]:
    """
    Scan the HTML for insecure URLs (http://) in various tags.
    Returns a dict mapping category -> list of URLs.
    """
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    soup = BeautifulSoup(html, 'html.parser')

    found = {key: [] for key in PENALTIES}

    # Check known tags
    tag_map = {
        'script':     ('src', 'script'),
        'link':       ('href', 'stylesheet'),
        'img':        ('src', 'image'),
        'iframe':     ('src', 'iframe'),
    }
    for tag, (attr, cat) in tag_map.items():
        for node in soup.find_all(tag):
            link = node.get(attr)
            if not link:
                continue
            full = urljoin(origin, link)
            if full.startswith('http://'):
                found[cat].append(full)

    # Look for any other http:// in src or href
    for node in soup.find_all(src=True):
        link = node['src']
        full = urljoin(origin, link)
        if full.startswith('http://') and node.name not in tag_map:
            found['other'].append(full)
    for node in soup.find_all(href=True):
        link = node['href']
        full = urljoin(origin, link)
        if full.startswith('http://') and node.name not in tag_map:
            found['other'].append(full)

    return found

def score_mixed_content(found: dict[str, List[str]]) -> Tuple[int, List[str]]:
    """
    Given the mixed-content dict, compute a score and assemble detail lines.
    """
    score = MAX_SCORE
    details: List[str] = []
    total_deduction = 0

    for category, urls in found.items():
        if not urls:
            continue
        penalty = PENALTIES.get(category, PENALTIES['other'])
        count = len(urls)
        deduction = penalty * count
        total_deduction += deduction
        details.append(f"{count} insecure {category}(s) detected (-{deduction})")
        # show up to 3 examples
        for example in urls[:3]:
            details.append(f"  • {example}")
        if count > 3:
            details.append("  • ...")

    final = max(MIN_SCORE, score - total_deduction)
    if total_deduction == 0:
        details.append("No mixed content found.")
    elif final < 5:
        details.append("High mixed content risk detected.")
    else:
        details.append("Some mixed content found; consider updating links.")
    return final, details

def analyze_mixed_content(url: str) -> Tuple[int, List[str]]:
    """
    Integration entry-point. Returns (score, details_list).
    """
    html = fetch_html(url)
    if not html:
        return 1, [f"Could not retrieve content from {url}"]
    found = find_mixed_content(url, html)
    return score_mixed_content(found)

def main():
    parser = argparse.ArgumentParser(
        description="Passive Mixed Content Detection Scanner"
    )
    parser.add_argument(
        "-u", "--url", required=True,
        help="Target page URL (must start with https://)"
    )
    args = parser.parse_args()
    score, details = analyze_mixed_content(args.url)
    print(f"\nScanning {args.url}")
    print(f"Final Score: {score}/10\n")
    for line in details:
        print(line)

if __name__ == "__main__":
    main()
