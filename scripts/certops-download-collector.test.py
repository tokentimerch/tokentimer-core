"""Controlled urllib transport adversaries; no network or native action runs.

Exercise the actual collector download function, including Request headers and
bounded reads. Synthetic bodies demonstrate transport rules, never qualification.
"""
import importlib.util
import io
from pathlib import Path
import unittest
import urllib.error
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("download_boundary_collector", Path(__file__).with_name("certops-release-collector.py"))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
API = "https://api.github.com/repos/tokentimerch/tokentimer-core/actions/artifacts/123/zip"
BLOB = "https://productionresultssa0.blob.core.windows.net/controlled?sig=fixture"


class DownloadBoundaryTests(unittest.TestCase):
    def transport(self, outcomes):
        calls = []
        opener = Mock()

        def open_request(request, timeout):
            calls.append((request, timeout))
            outcome = outcomes[len(calls) - 1]
            if isinstance(outcome, Exception):
                raise outcome
            return io.BytesIO(outcome)

        opener.open.side_effect = open_request
        return calls, patch.object(collector.urllib.request, "build_opener", return_value=opener)

    def redirect(self, location=BLOB, status=302):
        return urllib.error.HTTPError(API, status, "controlled redirect", {"Location": location}, None)

    def test_api_token_never_reaches_single_signed_blob_redirect(self):
        for location in (BLOB, "https://objects.githubusercontent.com/controlled", "https://results.actions.githubusercontent.com/controlled", "https://fixture.blob.core.windows.net:443/controlled"):
            calls, transport = self.transport([self.redirect(location), b"bounded public fixture"])
            with transport:
                self.assertEqual(collector.download(API, "controlled-token", redirect=True), b"bounded public fixture")
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0][0].get_header("Authorization"), "Bearer controlled-token")
            self.assertIsNone(calls[1][0].get_header("Authorization"))
            self.assertIsNone(calls[1][0].get_header("X-github-api-version"))
            self.assertEqual([timeout for _, timeout in calls], [60, 60])

    def test_initial_api_authority_and_url_shape_are_closed_before_transport(self):
        for url in (None, "http://api.github.com/x", "https://api.github.com:444/x", "https://api.github.com:invalid/x", "https://user:secret@api.github.com/x", "https://@api.github.com/x", "https://api.github.com/x#fragment", "https://api.github.com/x#", "https://api.github.com/x\n", "https://api.github.com.attacker.test/x", BLOB, "https://127.0.0.1/x", "https://169.254.169.254/x"):
            with self.subTest(url=url), patch.object(collector.urllib.request, "build_opener") as opener:
                with self.assertRaises(ValueError):
                    collector.download(url, "controlled-token", redirect=True)
                opener.assert_not_called()

    def test_redirect_rejects_local_foreign_credentialed_and_fragmented_destinations(self):
        for url in ("https://127.0.0.1/x", "https://169.254.169.254/x", "https://blob.core.windows.net.attacker.test/x", "https://api.github.com/x", "https://fixture.blob.core.windows.net:444/x", "http://fixture.blob.core.windows.net/x", "https://user:secret@fixture.blob.core.windows.net/x", "https://@fixture.blob.core.windows.net/x", "https://fixture.blob.core.windows.net/x#secret", "https://.blob.core.windows.net/x", "https://a..blob.core.windows.net/x", None):
            calls, transport = self.transport([self.redirect(url)])
            with self.subTest(url=url), transport, self.assertRaises(ValueError):
                collector.download(API, "controlled-token", redirect=True)
            self.assertEqual(len(calls), 1)

    def test_second_redirect_or_unapproved_status_never_follows(self):
        for outcomes, enabled, count in (([self.redirect(), self.redirect("https://foreign.example/x")], True, 2), ([self.redirect()], False, 1), ([self.redirect(status=301)], True, 1), ([self.redirect(status=307)], True, 1)):
            calls, transport = self.transport(outcomes)
            with transport, self.assertRaises(ValueError):
                collector.download(API, "controlled-token", redirect=enabled)
            self.assertEqual(len(calls), count)

    def test_existing_api_and_blob_response_byte_bounds_remain_effective(self):
        for outcomes, redirect in (([b"12345"], False), ([self.redirect(), b"12345"], True)):
            _, transport = self.transport(outcomes)
            with transport, patch.object(collector, "MAX_ARCHIVE", 4), self.assertRaises(ValueError):
                collector.download(API, "controlled-token", redirect=redirect)
        calls, transport = self.transport([b"{}"])
        with transport:
            self.assertEqual(collector.download("https://api.github.com:443/repos/tokentimerch/tokentimer-core"), b"{}")
        self.assertIsNone(calls[0][0].get_header("Authorization"))


if __name__ == "__main__":
    unittest.main()
