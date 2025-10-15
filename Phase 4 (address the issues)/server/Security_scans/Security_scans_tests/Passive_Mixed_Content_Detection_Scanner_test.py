"""
Unit-tests for Passive_Mixed_Content_Detection_Scanner.py

Run from the repository root with:
    python -m unittest Security_scans.Security_scans_tests.Passive_Mixed_Content_Detection_Scanner_test -v
"""
from types import SimpleNamespace
from unittest import TestCase, mock

# Local import of the scanner under test
from Security_scans import Passive_Mixed_Content_Detection_Scanner as scanner


class MixedContentScannerTestCase(TestCase):
    """Smoke-, logic- and integration-tests for the mixed-content scanner."""

    # ------------------------------------------------------------------
    # Shared fixtures
    # ------------------------------------------------------------------
    def setUp(self) -> None:
        # A deliberately small page that still hits every category
        self._html = """
        <!doctype html>
        <html>
          <head>
            <script src="http://example.com/app.js"></script>
            <link rel="stylesheet" href="http://example.com/app.css">
          </head>
          <body>
            <img    src="http://example.com/img.png">
            <iframe src="http://example.com/frame.html"></iframe>
            <a href="http://example.com/page.html">insecure link</a>
          </body>
        </html>
        """
        self._url = "https://secure.example.com"

    # ------------------------------------------------------------------
    # fetch_html
    # ------------------------------------------------------------------
    @mock.patch("Security_scans.Passive_Mixed_Content_Detection_Scanner.requests.get")
    def test_fetch_html_happy_path(self, mock_get):
        """Successful HTTP GET returns the response.text."""
        mock_get.return_value = SimpleNamespace(
            status_code=200,
            text="<ok/>",
            raise_for_status=lambda: None
        )
        html = scanner.fetch_html("https://good.com")
        self.assertEqual(html, "<ok/>")
        mock_get.assert_called_once_with("https://good.com", timeout=10)

    @mock.patch(
        "Security_scans.Passive_Mixed_Content_Detection_Scanner.requests.get",
        side_effect=Exception("boom")
    )
    def test_fetch_html_returns_none_on_failure(self, mock_get):
        """Any exception bubbles down as a graceful None."""
        html = scanner.fetch_html("https://good.com")
        self.assertIsNone(html)

    # ------------------------------------------------------------------
    # find_mixed_content
    # ------------------------------------------------------------------
    def test_find_mixed_content_classifies_everything_correctly(self):
        """The HTML snippet above should hit every bucket exactly once."""
        found = scanner.find_mixed_content(self._url, self._html)

        self.assertEqual(len(found["script"]),     1)
        self.assertEqual(len(found["stylesheet"]), 1)
        self.assertEqual(len(found["image"]),      1)
        self.assertEqual(len(found["iframe"]),     1)
        self.assertEqual(len(found["other"]),      1)

        # Sanity-check that all captured URLs are indeed insecure
        for cat, urls in found.items():
            for insecure_url in urls:
                self.assertTrue(
                    insecure_url.startswith("http://"),
                    f"{cat}: {insecure_url}"
                )

    # ------------------------------------------------------------------
    # score_mixed_content
    # ------------------------------------------------------------------
    def test_score_mixed_content_deduction_math(self):
        """Scoring logic must deduct exactly penalty*count for every bucket."""
        found = {
            "script":     ["http://a", "http://b"],          # -6
            "stylesheet": ["http://c"],                      # -2
            "image":      [],                                #  0
            "iframe":     ["http://d"],                      # -3
            "other":      ["http://e", "http://f"]           # -2
        }

        score, details = scanner.score_mixed_content(found)

        # Verify the numeric score calculation
        total_deduction = (
            3 * 2  # scripts
            + 2 * 1  # stylesheet
            + 3 * 1  # iframe
            + 1 * 2  # other
        )
        expected_score = max(scanner.MIN_SCORE, scanner.MAX_SCORE - total_deduction)
        self.assertEqual(score, expected_score)

        # Compute expected number of detail lines:
        #  • one header per non-empty bucket
        #  • one line per example URL (up to 3 each)
        #  • one final summary line
        header_lines = sum(1 for urls in found.values() if urls)
        example_lines = sum(len(urls[:3]) for urls in found.values() if urls)
        expected_lines = header_lines + example_lines + 1
        self.assertEqual(len(details), expected_lines)

    # ------------------------------------------------------------------
    # analyze_mixed_content (integration)
    # ------------------------------------------------------------------
    @mock.patch("Security_scans.Passive_Mixed_Content_Detection_Scanner.fetch_html")
    def test_analyze_mixed_content_end_to_end(self, mock_fetch):
        """High-level wrapper should orchestrate sub-calls as expected."""
        mock_fetch.return_value = self._html

        score, details = scanner.analyze_mixed_content(self._url)

        self.assertLess(score, scanner.MAX_SCORE)        # score got reduced
        self.assertTrue(any("script" in d for d in details))
        mock_fetch.assert_called_once_with(self._url)
