"""
Tests for Passive_SSL_TLS_Certificate_Validation_Scanner.py
-----------------------------------------------------------

Run from the repo root with:

    python -m unittest Security_scans.Security_scans_tests.Passive_SSL_TLS_Certificate_Validation_Scanner_test -v
"""
from types import SimpleNamespace
from unittest import TestCase, mock
import sys

# Local import – mirrors the package layout
from Security_scans import Passive_SSL_TLS_Certificate_Validation_Scanner as scanner


# --------------------------------------------------------------------------- #
# Minimal stubs used by several tests
# --------------------------------------------------------------------------- #
class _DummySock:
    """Socket stand‑in that works inside a with‑statement."""
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False


class _FakeSSock(_DummySock):
    """Fake SSL socket exposing only what the scanner touches."""
    def __init__(self, *, tls_ver="TLSv1.3", cert=None, der=b"der"):
        self._tls_ver = tls_ver
        self._cert = cert or {}
        self._der = der

    def version(self):
        return self._tls_ver

    def getpeercert(self, binary_form=False):
        return self._der if binary_form else self._cert


class _DummyUnverifiedContext:
    """Stand‑in for ssl._create_unverified_context()."""
    def __init__(self, ssl_sock):
        self._ssl_sock = ssl_sock

    def wrap_socket(self, sock, server_hostname=None):  # noqa: D401
        return self._ssl_sock


class _DummyVerifiedContext:
    """For ssl.create_default_context()."""
    def __init__(self, raise_verification_error=False):
        self._raise = raise_verification_error

    def wrap_socket(self, sock, server_hostname=None):  # noqa: D401
        if self._raise:
            raise scanner.ssl.SSLCertVerificationError("untrusted")
        return _DummySock()


# =============================================================================
#                                   Test cases
# =============================================================================
class SSLCertificateScannerTests(TestCase):
    """Smoke‑, edge‑ and worst‑case tests for the TLS‑scanner."""

    # ------------------------------------------------------------------ #
    # get_hostname helper
    # ------------------------------------------------------------------ #
    def test_get_hostname_variants(self):
        self.assertEqual(scanner.get_hostname("https://example.com"), "example.com:443")
        self.assertEqual(scanner.get_hostname("http://plain.com"), "plain.com:80")
        self.assertEqual(scanner.get_hostname("https://sec.org:8443"), "sec.org:8443")

    # ------------------------------------------------------------------ #
    # Perfect path – score should remain 10
    # ------------------------------------------------------------------ #
    @mock.patch("Security_scans.Passive_SSL_TLS_Certificate_Validation_Scanner.ssl._create_unverified_context")
    @mock.patch("Security_scans.Passive_SSL_TLS_Certificate_Validation_Scanner.socket.create_connection")
    @mock.patch("Security_scans.Passive_SSL_TLS_Certificate_Validation_Scanner.ssl.create_default_context")
    def test_analyze_certificate_best_case(self, fake_def_ctx, fake_conn, fake_unverified_ctx):
        good_cert = {
            "notAfter": "Dec 31 23:59:59 2030 GMT",
            "subject": ((('CN', 'good.example'),),),
            "issuer":  ((('CN', 'CA Root'),),),
        }
        fake_ssl_sock = _FakeSSock(tls_ver="TLSv1.3", cert=good_cert)

        fake_unverified_ctx.return_value = _DummyUnverifiedContext(fake_ssl_sock)
        fake_conn.return_value = _DummySock()
        fake_def_ctx.return_value = _DummyVerifiedContext(raise_verification_error=False)

        score, notes = scanner.analyze_certificate("good.example:443")

        self.assertEqual(score, 10)
        self.assertTrue(any("TLS version" in n for n in notes))
        self.assertTrue(any("trusted" in n.lower() for n in notes))

    # ------------------------------------------------------------------ #
    # Worst‑case – every deduction fires ⇒ score floors at 1
    # ------------------------------------------------------------------ #
    @mock.patch("Security_scans.Passive_SSL_TLS_Certificate_Validation_Scanner.ssl._create_unverified_context")
    @mock.patch("Security_scans.Passive_SSL_TLS_Certificate_Validation_Scanner.socket.create_connection")
    @mock.patch("Security_scans.Passive_SSL_TLS_Certificate_Validation_Scanner.ssl.create_default_context")
    def test_analyze_certificate_worst_case(self, fake_def_ctx, fake_conn, fake_unverified_ctx):
        bad_cert = {
            "notAfter": "Jan 01 00:00:00 2020 GMT",            # expired
            "subject": ((('CN', 'bad.example'),),),
            "issuer":  ((('CN', 'bad.example'),),),            # self‑signed
        }
        bad_ssl_sock = _FakeSSock(tls_ver="TLSv1.0", cert=bad_cert)

        fake_unverified_ctx.return_value = _DummyUnverifiedContext(bad_ssl_sock)
        fake_conn.return_value = _DummySock()
        fake_def_ctx.return_value = _DummyVerifiedContext(raise_verification_error=True)

        # Stub‑in a mini “cryptography” so key‑size deduction works
        class _Key: key_size = 1024
        class _Cert:                                # noqa: D101
            def public_key(self): return _Key()
        fake_x509 = SimpleNamespace(load_der_x509_certificate=lambda *_, **__: _Cert())
        fake_crypto = SimpleNamespace(x509=fake_x509)
        sys.modules["cryptography"] = fake_crypto
        sys.modules["cryptography.x509"] = fake_x509

        score, notes = scanner.analyze_certificate("bad.example:443")

        self.assertEqual(score, 1)
        joined = " ".join(notes).lower()
        for needle in ("old tls", "expired", "self-signed", "untrusted", "weak key"):
            self.assertIn(needle, joined)

    # ------------------------------------------------------------------ #
    # Connection / handshake failure – graceful (1, [msg]) tuple
    # ------------------------------------------------------------------ #
    @mock.patch(
        "Security_scans.Passive_SSL_TLS_Certificate_Validation_Scanner.socket.create_connection",
        side_effect=OSError("timeout"),
    )
    def test_analyze_certificate_network_failure(self, _fake_conn):
        score, notes = scanner.analyze_certificate("offline.local:443")

        self.assertEqual(score, 1)
        self.assertEqual(len(notes), 1)
        self.assertTrue(notes[0].startswith("Connection/handshake failed"))
