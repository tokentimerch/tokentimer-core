import hashlib
import base64
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("enrich", Path(__file__).with_name("agent-sbom-enrich.py"))
enrich = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enrich)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as tar:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            if kind == tarfile.SYMTYPE:
                info.linkname = "../../escape"
            tar.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return output.getvalue()


class EnrichmentTests(unittest.TestCase):
    def setUp(self):
        self.node = b"fixture-node"
        self.license = b"fixture license"
        self.entries = [("package/runtime/LICENSE", self.license, tarfile.REGTYPE),
                        ("package/runtime/amd64/node.exe", self.node, tarfile.REGTYPE),
                        ("package/bin/agent.exe", b"fixture-host", tarfile.REGTYPE)]
        self.archive = archive(self.entries)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("node-v1.2.3-win-x64/LICENSE", self.license)
            z.writestr("node-v1.2.3-win-x64/node.exe", self.node)
        self.upstream = buf.getvalue()
        self.policy = {"amd64": ("x64", digest(self.upstream), digest(self.node))}
        self.bom = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                               "metadata": {"component": {"type": "file", "version": "sha256:" + digest(self.archive)}},
                               "components": [{"type": "library", "name": "existing"}]}).encode()

    def run_enrich(self, **changes):
        args = {"archive": self.archive, "expected_archive_sha": digest(self.archive), "upstream": self.upstream,
                "sbom": self.bom, "architecture": "amd64", "policy": self.policy, "version": "1.2.3"}
        args.update(changes)
        return enrich.enrich(**args)

    def test_binds_runtime_license_and_every_executable(self):
        result = json.loads(self.run_enrich())
        components = result["components"]
        self.assertEqual(len(components), 3)
        by_name = {c["name"]: c for c in components}
        self.assertEqual(by_name["node.exe"]["hashes"][0]["content"], digest(self.node))
        notice = by_name["node.exe"]["licenses"][0]["license"]
        self.assertEqual(base64.b64decode(notice["text"]["content"]), self.license)
        self.assertEqual(by_name["agent.exe"]["hashes"][0]["content"], digest(b"fixture-host"))
        self.assertEqual(self.run_enrich(), self.run_enrich())

    def test_rejects_untrusted_inputs_and_source_mismatch(self):
        for changes in ({"expected_archive_sha": "0" * 64}, {"upstream": self.upstream + b"changed"},
                        {"sbom": self.bom.replace(digest(self.archive).encode(), b"0" * 64)},
                        {"sbom": self.bom.replace(b'"version": 1', b'"version": 1, "version": 1')},
                        {"sbom": self.bom.replace(b'"version": 1', b'"version": NaN')}):
            with self.assertRaises(ValueError): self.run_enrich(**changes)

        source = json.loads(self.bom)
        source["components"] = [{"type": "library", "name": "a", "bom-ref": "same"},
                                {"type": "library", "name": "b", "bom-ref": "same"}]
        with self.assertRaises(ValueError): self.run_enrich(sbom=json.dumps(source).encode())

    def test_rejects_modified_runtime_or_license_and_unsafe_tar(self):
        for entries in (self.entries[:-1] + [("../escape", b"x", tarfile.REGTYPE)],
                        self.entries + [self.entries[0]],
                        self.entries + [("package/RUNTIME/license", b"collision", tarfile.REGTYPE)],
                        self.entries + [("package/AUX.txt", b"reserved", tarfile.REGTYPE)],
                        self.entries + [("package/bin", b"parent-file", tarfile.REGTYPE)],
                        self.entries + [("package/link", b"", tarfile.SYMTYPE)],
                        [(self.entries[0][0], b"changed", tarfile.REGTYPE)] + self.entries[1:],
                        [self.entries[0], (self.entries[1][0], b"changed", tarfile.REGTYPE), self.entries[2]]):
            altered = archive(entries)
            bom = self.bom.replace(digest(self.archive).encode(), digest(altered).encode())
            with self.assertRaises(ValueError): self.run_enrich(archive=altered, expected_archive_sha=digest(altered), sbom=bom)

    def test_runtime_policy_matches_packager_pins(self):
        packager = (Path(__file__).resolve().parent.parent / "packages/agent/scripts/windows-runtime-package.js").read_text(encoding="utf8")
        self.assertIn('const VERSION = "' + enrich.NODE_VERSION + '";', packager)
        for _, zip_digest, runtime_digest in enrich.POLICY.values():
            self.assertIn(zip_digest, packager)
            self.assertIn(runtime_digest, packager)


if __name__ == "__main__":
    unittest.main()
