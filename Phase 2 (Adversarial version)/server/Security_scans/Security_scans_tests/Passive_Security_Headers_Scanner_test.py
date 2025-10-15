import unittest
from unittest.mock import patch, Mock
import requests

# Import functions and constants from your module using the full package path.
from Security_scans.Passive_Security_Headers_Scanner import (
    get_headers,
    analyze_headers,
    get_base_url,
    analyze_security_headers,
    SECURITY_HEADERS,
    SCORE_DEDUCTIONS,
)

# Helper class to simulate a response object from requests.head
class DummyResponse:
    def __init__(self, headers):
        self.headers = headers

class TestPassiveSecurityHeadersScanner(unittest.TestCase):

    def test_get_base_url_with_scheme(self):
        # Test when the URL has a scheme.
        self.assertEqual(get_base_url("https://example.com/page"), "https://example.com")
        self.assertEqual(get_base_url("http://example.com/path"), "http://example.com")

    def test_get_base_url_without_scheme(self):
        # Test when the URL is missing a scheme.
        self.assertEqual(get_base_url("example.com/page"), "https://example.com")

    @patch("Security_scans.Passive_Security_Headers_Scanner.requests.head")
    def test_get_headers_success(self, mock_head):
        # Simulate a successful HEAD request that returns some headers.
        expected_headers = {"X-Test": "value"}
        dummy_resp = DummyResponse(expected_headers)
        mock_head.return_value = dummy_resp
        result = get_headers("https://example.com")
        self.assertEqual(result, expected_headers)

    @patch("Security_scans.Passive_Security_Headers_Scanner.requests.head")
    def test_get_headers_failure(self, mock_head):
        # Simulate a RequestException when trying to retrieve headers.
        mock_head.side_effect = requests.RequestException("Error")
        result = get_headers("https://example.com")
        self.assertEqual(result, {})

    def test_analyze_headers_all_secure(self):
        # Create a headers dictionary where all expected security headers are correctly set.
        secure_headers = {
            "Strict-Transport-Security": SECURITY_HEADERS["Strict-Transport-Security"],
            "Content-Security-Policy": SECURITY_HEADERS["Content-Security-Policy"],
            "X-Frame-Options": "DENY",  # Allowed values: DENY or SAMEORIGIN
            "X-XSS-Protection": SECURITY_HEADERS["X-XSS-Protection"],
            "X-Content-Type-Options": SECURITY_HEADERS["X-Content-Type-Options"],
            "Referrer-Policy": "no-referrer",  # One of the acceptable values
            "Permissions-Policy": SECURITY_HEADERS["Permissions-Policy"],
        }
        score, details = analyze_headers(secure_headers)
        # Expect a perfect score of 10.
        self.assertEqual(score, 10)
        for line in details:
            self.assertIn("✅", line)

    def test_analyze_headers_missing_and_weak(self):
        # Create a headers dictionary with some missing and weak values.
        # - "Strict-Transport-Security" is missing.
        # - "Content-Security-Policy" is present but weak (does not include "default-src 'self'").
        # - "X-Frame-Options" is present with a value not in the accepted list.
        headers = {
            "Content-Security-Policy": "default-src 'none'",
            # "Strict-Transport-Security" is missing.
            "X-Frame-Options": "ALLOW",  # Not acceptable (should be DENY or SAMEORIGIN)
            "X-XSS-Protection": "1; mode=block",  # Secure
            "X-Content-Type-Options": "nosniff",   # Secure
            "Referrer-Policy": "strict-origin",    # Acceptable (in the list)
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",  # Secure
        }
        score, details = analyze_headers(headers)
        # Expected deductions:
        # - Strict-Transport-Security missing: -2
        # - Weak Content-Security-Policy: -1
        # - Weak X-Frame-Options: -1
        # Total deduction: 4 points → Expected score: 10 - 4 = 6
        self.assertEqual(score, 6)
        self.assertTrue(any("Missing: Strict-Transport-Security" in d for d in details))
        self.assertTrue(any("Weak: Content-Security-Policy" in d for d in details))
        self.assertTrue(any("Weak: X-Frame-Options" in d for d in details))

    @patch("Security_scans.Passive_Security_Headers_Scanner.requests.head")
    def test_analyze_security_headers_success(self, mock_head):
        # Simulate a successful HEAD request with secure header values.
        secure_headers = {
            "Strict-Transport-Security": SECURITY_HEADERS["Strict-Transport-Security"],
            "Content-Security-Policy": SECURITY_HEADERS["Content-Security-Policy"],
            "X-Frame-Options": "SAMEORIGIN",
            "X-XSS-Protection": SECURITY_HEADERS["X-XSS-Protection"],
            "X-Content-Type-Options": SECURITY_HEADERS["X-Content-Type-Options"],
            "Referrer-Policy": "same-origin",  # Acceptable value from the list
            "Permissions-Policy": SECURITY_HEADERS["Permissions-Policy"],
        }
        dummy_resp = DummyResponse(secure_headers)
        mock_head.return_value = dummy_resp

        score, details = analyze_security_headers("example.com")
        self.assertEqual(score, 10)
        self.assertTrue(any("✅" in d for d in details))

    @patch("Security_scans.Passive_Security_Headers_Scanner.requests.head")
    def test_analyze_security_headers_failure(self, mock_head):
        # Simulate a failure to retrieve headers (raise an exception).
        mock_head.side_effect = requests.RequestException("Error")
        score, details = analyze_security_headers("example.com")
        self.assertEqual(score, 1)
        self.assertEqual(details, ["❌ Failed to retrieve headers."])

if __name__ == "__main__":
    unittest.main()
