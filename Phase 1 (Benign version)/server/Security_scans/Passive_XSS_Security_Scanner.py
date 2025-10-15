


# server/Security_scans/Passive_XSS_Security_Scanner.py

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
import argparse

# Functions often abused in XSS attacks
RISKY_FUNCTIONS = [
    'eval(',
    'document.write(',
    'innerHTML',
    'setTimeout(',
    'setInterval(',
    'unescape(',
    'location.href',
    'location.assign(',
    'localStorage.setItem(',
    'sessionStorage.setItem(',
    'Function(',
]

# How many points we knock off for each issue
DEDUCTIONS = {
    'risky_js':              3,
    'missing_csp':           3,
    'missing_xss_protection':2,
    'reflected_params':      2,
    'inline_scripts':        2,
}

def fetch_page(url: str, timeout: int = 10) -> tuple[str | None, dict | None]:
    """GET the page, return (html, headers) or (None, None) on error."""
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.text, resp.headers
    except requests.RequestException:
        return None, None

def find_risky_functions(html: str) -> list[str]:
    """Scan the raw HTML/JS for known dangerous calls."""
    found = []
    for fn in RISKY_FUNCTIONS:
        if fn in html:
            found.append(fn)
    return found

def missing_security_headers(headers: dict) -> list[str]:
    """Check for CSP and X-XSS-Protection headers."""
    missing = []
    if 'Content-Security-Policy' not in headers:
        missing.append('Content-Security-Policy')
    if 'X-XSS-Protection' not in headers:
        missing.append('X-XSS-Protection')
    return missing

def find_reflected_parameters(url: str, html: str) -> list[str]:
    """
    Look at URL query parameters and see if any value shows up in the HTML.
    """
    params = parse_qs(urlparse(url).query)
    reflected = [k for k, vals in params.items() if any(val in html for val in vals)]
    return reflected

def find_inline_scripts(html: str) -> list[str]:
    """Return any <script> blocks without a src attribute."""
    soup = BeautifulSoup(html, 'html.parser')
    return [script.string or '' for script in soup.find_all('script') if not script.get('src')]

def analyze_xss_security(url: str) -> tuple[int, str]:
    """
    Run all passive XSS checks and return (score, detail_string).
    detail_string contains semicolon-separated findings.
    """
    score = 10
    notes: list[str] = []

    html, headers = fetch_page(url)
    if html is None or headers is None:
        return 1, 'Could not fetch page or headers.'

    # 1) risky JS usage
    bad_funcs = find_risky_functions(html)
    if bad_funcs:
        score -= DEDUCTIONS['risky_js']
        notes.append(f'Insecure JS calls: {", ".join(bad_funcs)} (-{DEDUCTIONS["risky_js"]})')

    # 2) missing security headers
    missing = missing_security_headers(headers)
    if missing:
        for hdr in missing:
            key = 'missing_' + hdr.lower().replace('-', '_')
            ded = DEDUCTIONS.get(key, 1)
            score -= ded
        notes.append(f'Missing headers: {", ".join(missing)}')

    # 3) reflected URL parameters
    reflected = find_reflected_parameters(url, html)
    if reflected:
        score -= DEDUCTIONS['reflected_params']
        notes.append(f'Reflected params: {", ".join(reflected)} (-{DEDUCTIONS["reflected_params"]})')

    # 4) inline scripts
    inline = find_inline_scripts(html)
    if inline:
        score -= DEDUCTIONS['inline_scripts']
        notes.append(f'Inline scripts found: {len(inline)} block(s) (-{DEDUCTIONS["inline_scripts"]})')

    # clamp and summary
    score = max(1, min(10, score))
    if score == 10:
        notes.append('No significant XSS risks detected.')
    elif score < 5:
        notes.append('High XSS risk: multiple red flags.')
    else:
        notes.append('Moderate XSS risk: some improvements needed.')

    return score, '; '.join(notes)

def get_base_url(raw: str) -> str:
    """Ensure URL has a scheme and return scheme://host."""
    if '://' not in raw:
        raw = 'https://' + raw
    p = urlparse(raw)
    return f'{p.scheme}://{p.netloc}'

def main():
    parser = argparse.ArgumentParser(description='Passive XSS Security Scanner')
    parser.add_argument('-u', '--url', required=True, help='Full page URL to scan')
    args = parser.parse_args()

    target = get_base_url(args.url)
    print(f'\nScanning XSS risks for: {target}\n')

    score, details = analyze_xss_security(target)
    print('--- XSS Security Report ---')
    for entry in details.split('; '):
        print('-', entry)
    print(f'\nSecurity Score: {score}/10')
    if score < 5:
        print('⚠️ Serious XSS vulnerabilities detected.')
    elif score < 8:
        print('⚠️ Some XSS issues found; recommendations apply.')
    else:
        print('✅ Looks good against common XSS vectors.')

if __name__ == '__main__':
    main()
