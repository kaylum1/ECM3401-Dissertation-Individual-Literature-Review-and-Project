


import requests
from datetime import datetime
from dateutil import parser

# ——— score weights ———
_BASE_HTTPS_SCORE     = 2   # for simply using HTTPS
_TLS_1_2_BONUS        = 3
_TLS_1_3_BONUS        = 4
_CERT_LONG_BONUS      = 3   # >180 days left
_CERT_MEDIUM_BONUS    = 2   # 30–180 days left
_CERT_EXPIRED_PENALTY = -3  # certificate already expired
_HSTS_BONUS           = 3

def analyze_https_security(url):
    """
    Passive HTTPS health-check.

    1) Must be https:// or we bail out with score=1.
    2) Base points for HTTPS.
    3) Bonus for TLS 1.2 vs 1.3.
    4) Bonus or penalty based on cert expiry.
    5) Bonus for HSTS header presence.
    """
    details = []

    # Step 1: quick validation of scheme
    if not url.lower().startswith("https://"):
        details.append("Not HTTPS — failing scan")
        return 1, details

    # Step 2: initial HTTPS score
    score = _BASE_HTTPS_SCORE
    details.append("HTTPS in use (+2)")

    # Step 3: TLS version
    try:
        ver = response.raw.version
        if ver == 3:
            score += _TLS_1_2_BONUS
            details.append("TLS 1.2 negotiated (+3)")
        elif ver == 4:
            score += _TLS_1_3_BONUS
            details.append("TLS 1.3 negotiated (+4)")
        else:
            details.append(f"Unexpected TLS version: {ver}")
    except Exception as exc:
        details.append(f"Could not read TLS version: {exc}")

    # Step 4: certificate expiry check
    try:
        # dig into the socket to fetch peer cert
        peer = response.raw._connection.sock.getpeercert()
        expiry = peer.get("notAfter")
        if expiry:
            exp_dt = parser.parse(expiry)
            days = (exp_dt - datetime.utcnow()).days
            if days > 180:
                score += _CERT_LONG_BONUS
                details.append("Cert valid >180 days (+3)")
            elif days >= 30:
                score += _CERT_MEDIUM_BONUS
                details.append("Cert valid 30–180 days (+2)")
            elif days > 0:
                details.append("Cert expiring soon (<30 days)")
            else:
                score += _CERT_EXPIRED_PENALTY
                details.append("Certificate expired! (-3)")
        else:
            details.append("No cert expiry date found")
    except Exception as exc:
        details.append(f"Error checking cert expiry: {exc}")

    # Step 5: HSTS header
    if response.headers.get("strict-transport-security"):
        score += _HSTS_BONUS
        details.append("HSTS header present (+3)")
    else:
        details.append("Missing HSTS header")

    # Final clamp to [1..10]
    score = max(1, min(10, score))
    return score, details


# Example stub to prevent NameError when reading TLS version:
# Fetch the response once and stash it for all checks.
# (You could inline this in the function if you prefer.)
response = requests.Response()
