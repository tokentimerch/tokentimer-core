import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("snapshot", Path(__file__).with_name("windows-release-snapshot.py"))
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


class SnapshotTests(unittest.TestCase):
    def test_snapshot_remains_exact_after_source_changes(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "archive.tgz"
            original = b"qualified staged bytes"
            path.write_bytes(original)
            assets = snapshot.snapshot_assets(d, {path.name: hashlib.sha256(original).hexdigest()})
            path.write_bytes(b"replaced after verification")
            self.assertEqual(assets[path.name], original)
            with self.assertRaises(TypeError): assets[path.name] = b"replacement"

    def test_changed_missing_unsafe_or_oversized_asset_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "archive.tgz"
            path.write_bytes(b"data")
            for entries in ({"../archive.tgz": "a" * 64}, {"CON.txt": "a" * 64}, {"lpt1": "a" * 64}, {"file.": "a" * 64}, {path.name: "a" * 64}, {"missing": "a" * 64}, {}, {path.name: "invalid"}):
                with self.assertRaises((ValueError, FileNotFoundError)):
                    snapshot.snapshot_assets(d, entries)
            snapshot.MAX_FILE = 3
            try:
                with self.assertRaises(ValueError): snapshot.snapshot_assets(d, {path.name: hashlib.sha256(b"data").hexdigest()})
            finally:
                snapshot.MAX_FILE = 128 * 1024 * 1024


if __name__ == "__main__":
    unittest.main()
