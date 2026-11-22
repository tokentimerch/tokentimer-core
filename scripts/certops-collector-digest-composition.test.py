"""Exercise the ordinary workflow collection path with offline fixture metadata."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("collector_composition", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class DigestBeforeExtraction(unittest.TestCase):
    def test_ordinary_workflow_rejects_missing_or_wrong_digest_before_extraction(self):
        candidate = "a" * 40
        fixture_matrix = {"slots": [{"id": "fixture", "kind": "host", "suite": "fixture"}]}
        env = {"CERTOPS_RELEASE_CANDIDATE": candidate, "CERTOPS_RELEASE_RUN_IDS": "[1]",
               "GITHUB_REPOSITORY": "owner/repo", "GITHUB_TOKEN": "fixture-only"}
        for metadata in ({}, {"digest": "sha256:" + "0" * 64}):
            with self.subTest(metadata=metadata), tempfile.TemporaryDirectory(prefix="tt-digest-collector-") as directory:
                root = Path(directory)
                (root / ".github/maintainers/certops").mkdir(parents=True)
                (root / ".github/maintainers/certops/qualification-suites.json").write_text(json.dumps(fixture_matrix))
                artifact = {"id": 7, "size_in_bytes": 12, **metadata}
                def fake_download(url, token=None, redirect=False):
                    if url.endswith("/zip"):
                        return b"fixture-zip"
                    if "/artifacts?" in url:
                        return json.dumps({"total_count": 1, "artifacts": [artifact]}).encode()
                    return json.dumps({"path": ".github/workflows/ci.yml"}).encode()
                with patch.object(collector, "ROOT", root), patch.dict(collector.os.environ, env), \
                     patch.object(collector, "download", side_effect=fake_download), \
                     patch.object(collector, "validate_run"), patch.object(collector, "collectable_artifact", return_value=True), \
                     patch.object(collector, "catalog_coverage", return_value={}), \
                     patch.object(collector, "extract_reports") as extract:
                    with self.assertRaisesRegex(ValueError, "digest"):
                        collector.main()
                    extract.assert_not_called()


if __name__ == "__main__":
    unittest.main()
