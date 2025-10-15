import re
from typing import List, Tuple

import requests
from bs4 import BeautifulSoup

# --------------------------------------------------------------------------- #
# tweak-me constants
# --------------------------------------------------------------------------- #
_PENALTY_NO_HEADER        = 1
_PENALTY_NO_META          = 2
_PENALTY_META_AMBIGUOUS   = 1
_PENALTY_NO_PHRASE        = 3

_MAX_SCORE = 10
_MIN_SCORE = 1

# phrases that *might* appear in a site that genuinely cares about DNT
_DNT_PHRASES = [
    r"honou?r do not track",
    r"respect(s)? do not track",
    r"support(s)? do not track",
    r"do not track policy",
    r"dnt is honoured",
]

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _clamp(val: int, low: int, high: int) -> int:
    return max(low, min(high, val))


# --------------------------------------------------------------------------- #
# public API – keep name & signature stable for the rest of the code-base
# --------------------------------------------------------------------------- #
def analyze_dnt_support(url: str, timeout: int = 10) -> Tuple[int, List[str]]:
    """
    Return *(final_score, details_lines)* for *url*.

    A high score ⇒ strong indication the site honours DNT.
    """
    try:
        resp = requests.get(url, timeout=timeout, headers={"DNT": "1"})
    except Exception as exc:                      # pragma: no cover
        return _MIN_SCORE, [f"Request failed: {exc}"]

    details: List[str] = []
    deduction = 0

    # ---- 1. did the server echo a DNT header back? -------------------------
    if "DNT" in resp.headers:
        details.append("Server replies with a 'DNT' header – good sign.")
    else:
        details.append("No 'DNT' header echoed in the response.")
        deduction += _PENALTY_NO_HEADER

    # ---- 2. is there a <meta name="dnt">… ? --------------------------------
    soup = BeautifulSoup(resp.text, "html.parser")
    meta_tag = soup.find("meta", attrs={"name": re.compile(r"^dnt$", re.I)})

    if meta_tag:
        meta_val = (meta_tag.get("content") or "").strip().lower()
        details.append(f"Found <meta name='dnt' content='{meta_val}'>.")

        if meta_val not in {"1", "true"}:
            details.append("Meta tag present but value is ambiguous.")
            deduction += _PENALTY_META_AMBIGUOUS
    else:
        details.append("No <meta name='dnt'> tag spotted.")
        deduction += _PENALTY_NO_META

    # ---- 3. scan HTML for friendly wording ---------------------------------
    html_lower = resp.text.lower()
    if any(re.search(pat, html_lower) for pat in _DNT_PHRASES):
        details.append("Page text contains a phrase that promises DNT support.")
    else:
        details.append("Couldn’t find a phrase explicitly mentioning DNT.")
        deduction += _PENALTY_NO_PHRASE

    # ---- wrap-up -----------------------------------------------------------
    final_score = _clamp(_MAX_SCORE - deduction, _MIN_SCORE, _MAX_SCORE)

    if final_score == _MAX_SCORE:
        details.append("Looks like the site takes Do-Not-Track seriously.")
    elif final_score < 5:
        details.append("Plenty of room for improvement – DNT support unclear.")
    else:
        details.append("Some hints of DNT support, but not definitive.")

    return final_score, details


# --------------------------------------------------------------------------- #
# CLI harness – handy for ad-hoc testing
# --------------------------------------------------------------------------- #
if __name__ == "__main__":                       # pragma: no cover
    import argparse

    cli = argparse.ArgumentParser(
        description="Quick passive probe for Do-Not-Track support")
    cli.add_argument("-u", "--url", required=True,
                     help="Target site (include http/https)")
    cli.add_argument("--timeout", type=int, default=10,
                     help="Request timeout in seconds (default 10)")

    opts = cli.parse_args()
    score, lines = analyze_dnt_support(opts.url, timeout=opts.timeout)

    print(f"\nFinal score: {score}/10\n" + "-" * 40)
    for ln in lines:
        print(ln)





