

import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse

FINGERPRINTING_INDICATORS = {
    "toDataURL": 2,
    "getContext('2d')": 1,
    'getContext("2d")': 1,
    "getContext('webgl')": 2,
    'getContext("webgl")': 2,
    "FingerprintJS": 3,
    "Fingerprint2": 3,
    "clientjs": 2,
    "canvas fingerprint": 2,
    "audioContext": 2,
    "navigator.plugins": 1,
    "devicePixelRatio": 1,
    "screen.width": 1,
    "screen.height": 1,
    "screen.colorDepth": 1,
    "timezone": 1,
    "navigator.languages": 1,
    "hardwareConcurrency": 1
}

def analyze_fingerprinting_detection(url):
    try:
        response = requests.get(url, timeout=10)
        html = response.text
    except Exception as e:
        return 1, [f"Error fetching page: {str(e)}"]

    details = []
    total_deduction = 0

    soup = BeautifulSoup(html, "html.parser")
    page_domain = urlparse(url).netloc.lower()

    # Inline script analysis
    for script in soup.find_all("script"):
        if not script.has_attr("src"):
            content = script.get_text()
            for indicator, deduction in FINGERPRINTING_INDICATORS.items():
                if re.search(re.escape(indicator), content, re.IGNORECASE):
                    details.append(f"Inline script contains fingerprinting indicator '{indicator}' (deduction {deduction})")
                    total_deduction += deduction

    # External scripts
    for script in soup.find_all("script", src=True):
        src = script["src"]
        parsed = urlparse(src)
        if parsed.netloc and parsed.netloc.lower() != page_domain:
            for indicator, deduction in FINGERPRINTING_INDICATORS.items():
                if re.search(re.escape(indicator), src, re.IGNORECASE):
                    details.append(f"External script URL '{src}' contains fingerprinting indicator '{indicator}' (deduction {deduction})")
                    total_deduction += deduction
                    break

    final_score = max(1, min(10, 10 - total_deduction))
    if final_score == 10:
        details.append("✅ No significant fingerprinting methods detected.")
    elif final_score < 5:
        details.append("⚠️ High risk: Numerous fingerprinting techniques detected!")
    else:
        details.append("⚠️ Moderate risk: Some fingerprinting techniques detected.")

    return final_score, details

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Passive Fingerprinting Detection Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()
    score, details = analyze_fingerprinting_detection(args.url)
    print(f"Final Score: {score}/10")
    for detail in details:
        print(detail)
