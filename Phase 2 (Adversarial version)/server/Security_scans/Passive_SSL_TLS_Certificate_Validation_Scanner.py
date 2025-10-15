

"""
Passive SSL/TLS Certificate Validation Scan
============================================

A simple, one-shot check of a server’s TLS certificate:

  • Extract host and port from a URL  
  • Connect (without verifying) to grab cert details and TLS version  
  • Check for outdated TLS (anything below 1.2)  
  • Look at expiration date (expired, expiring soon)  
  • Detect self-signed certs  
  • Try a second, *verified* connection to catch untrusted issuers  
  • Inspect public key size (warn if <2048 bits)

Score starts at 10 and we subtract per issue (see SCORE_DEDUCTIONS).  
Score is always clamped to [1, 10].

Note: this is purely passive—no certs are modified or revoked.
"""

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from typing import Tuple, List

# tweak these penalties if you like
SCORE_DEDUCTIONS = {
    "expired":         5,
    "expiring_soon":   3,
    "tls_old":         3,
    "tls_outdated":    5,
    "self_signed":     3,
    "untrusted_issuer":3,
    "weak_key":        2,
}

# --------------------------------------------------------------------------- #
def get_hostname(url: str) -> str:
    """
    Pull host (and port) out of a URL.  
    Defaults to port 443 for HTTPS, 80 for HTTP.
    """
    parsed = urlparse(url)
    host = parsed.hostname or url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{host}:{port}"

# --------------------------------------------------------------------------- #
def analyze_certificate(host: str) -> Tuple[int, List[str]]:
    """
    Connects to host (as 'name:port'), inspects TLS cert and returns
    (score out of 10, list of detail messages).
    """
    details: List[str] = []
    score = 10

    # split host:port
    try:
        hostname, port_str = host.split(":", 1)
        port = int(port_str)
    except (ValueError, TypeError):
        hostname = host
        port = 443

    # 1) grab cert and TLS version (unverified)
    unverified_ctx = ssl._create_unverified_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with unverified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_ver = ssock.version() or "unknown"
                cert_der = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
    except Exception as e:
        return 1, [f"Connection/handshake failed: {e}"]

    details.append(f"TLS version negotiated: {tls_ver}")
    # TLS version penalties
    if tls_ver == "TLSv1.3":
        pass
    elif tls_ver == "TLSv1.2":
        score -= SCORE_DEDUCTIONS["tls_old"]
        details.append(f"Using TLS1.2 (−{SCORE_DEDUCTIONS['tls_old']})")
    else:
        score -= SCORE_DEDUCTIONS["tls_outdated"]
        details.append(f"Old TLS version (−{SCORE_DEDUCTIONS['tls_outdated']})")

    # 2) certificate expiration
    not_after = cert.get("notAfter")
    if not_after:
        try:
            exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_dt - datetime.utcnow()).days
            details.append(f"Certificate expires in {days_left} day(s)")
            if days_left < 0:
                score -= SCORE_DEDUCTIONS["expired"]
                details.append(f"Expired certificate (−{SCORE_DEDUCTIONS['expired']})")
            elif days_left < 30:
                score -= SCORE_DEDUCTIONS["expiring_soon"]
                details.append(f"Certificate expiring soon (−{SCORE_DEDUCTIONS['expiring_soon']})")
        except Exception:
            details.append("Could not parse expiry date")
    else:
        details.append("No expiry info found in certificate")

    # 3) self-signed check
    subj = cert.get("subject", ())
    issuer = cert.get("issuer", ())
    if subj == issuer:
        score -= SCORE_DEDUCTIONS["self_signed"]
        details.append(f"Self-signed certificate (−{SCORE_DEDUCTIONS['self_signed']})")
    else:
        details.append("Certificate is not self-signed")

    # 4) untrusted issuer check (verified context)
    verified_ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock2:
            with verified_ctx.wrap_socket(sock2, server_hostname=hostname):
                pass
    except ssl.SSLCertVerificationError as verr:
        score -= SCORE_DEDUCTIONS["untrusted_issuer"]
        details.append(f"Untrusted issuer (−{SCORE_DEDUCTIONS['untrusted_issuer']})")
    except Exception as e:
        details.append(f"Issue during trust check: {e}")
    else:
        details.append("Certificate chain is trusted")

    # 5) public key size detection (optional, requires cryptography)
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
        key_size = cert_obj.public_key().key_size
        details.append(f"Public key size: {key_size} bits")
        if key_size < 2048:
            score -= SCORE_DEDUCTIONS["weak_key"]
            details.append(f"Weak key (−{SCORE_DEDUCTIONS['weak_key']})")
    except ImportError:
        details.append("cryptography lib missing; skipped key-size check")
    except Exception:
        details.append("Could not determine key strength")

    # clamp final score
    final_score = max(1, min(10, score))
    return final_score, details

# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Passive SSL/TLS Certificate Validation Scanner"
    )
    parser.add_argument(
        "-u", "--url", required=True,
        help="Full URL to inspect (e.g. https://example.com)"
    )
    args = parser.parse_args()

    host = get_hostname(args.url)
    ssl_score, ssl_details = analyze_certificate(host)

    print(f"\nSSL/TLS Certificate Score: {ssl_score}/10\n" + "-"*40)
    for note in ssl_details:
        print(" *", note)
