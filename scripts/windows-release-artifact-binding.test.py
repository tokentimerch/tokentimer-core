import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("binding", Path(__file__).with_name("windows-release-artifact-binding.py"))
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def make_archive(items):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as tar:
        for name, value, kind in items:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            entry.size = len(value) if kind == tarfile.REGTYPE else 0
            tar.addfile(entry, io.BytesIO(value) if kind == tarfile.REGTYPE else None)
    return output.getvalue()


class CandidateBindingTests(unittest.TestCase):
    def setUp(self):
        self.params = {"archive_name": "tokentimer-agent-1.2.3-windows-amd64.tgz", "sbom_name": "agent.spdx.json",
                       "version": "1.2.3", "architecture": "amd64", "source_commit": "a" * 40}
        self.archive = make_archive([("package/a.exe", b"signed fixture", tarfile.REGTYPE), ("package/lib/x.js", b"script", tarfile.REGTYPE)])
        self.sbom = b'{"spdxVersion":"SPDX-2.3"}'
        self.doc = {"schemaVersion": 1, "sourceCommit": "a" * 40, "version": "1.2.3", "architecture": "amd64",
                    "archive": {"name": self.params["archive_name"], "sha256": sha(self.archive)},
                    "sbom": {"name": self.params["sbom_name"], "sha256": sha(self.sbom)},
                    "files": [{"path": "package/a.exe", "size": 14, "sha256": sha(b"signed fixture")},
                              {"path": "package/lib/x.js", "size": 6, "sha256": sha(b"script")}]}

    def check(self, archive=None, sbom=None, doc=None, params=None):
        binding.validate_binding(self.archive if archive is None else archive, self.sbom if sbom is None else sbom,
                                 json.dumps(self.doc if doc is None else doc).encode(), **(self.params if params is None else params))

    def test_valid_candidate_and_tampered_inputs(self):
        self.check()
        for changes in ({"archive": self.archive + b"x"}, {"sbom": b"different"},
                        {"params": {**self.params, "source_commit": "b" * 40}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.check(**changes)

    def test_inventory_cannot_omit_or_alter_packaged_files(self):
        for mutation in (lambda x: x["files"].pop(), lambda x: x["files"][0].update(size=15),
                         lambda x: x["files"][1].update(sha256="0" * 64),
                         lambda x: x["files"].append(copy.deepcopy(x["files"][0]))):
            doc = copy.deepcopy(self.doc)
            mutation(doc)
            with self.assertRaises(ValueError):
                self.check(doc=doc)

    def test_unsafe_archive_is_rejected_even_with_matching_archive_digest(self):
        for items in ([('package/../x', b'x', tarfile.REGTYPE)],
                      [('package/a', b'x', tarfile.SYMTYPE)],
                      [('package/a', b'x', tarfile.REGTYPE), ('package/A', b'x', tarfile.REGTYPE)],
                      [('package/CON.txt', b'x', tarfile.REGTYPE)]):
            archive = make_archive(items)
            doc = copy.deepcopy(self.doc)
            doc['archive']['sha256'] = sha(archive)
            with self.subTest(items=items), self.assertRaises(ValueError):
                self.check(archive=archive, doc=doc)

    def test_duplicate_json_keys_are_rejected(self):
        raw = json.dumps(self.doc).encode().replace(b'"schemaVersion": 1', b'"schemaVersion": 1, "schemaVersion": 1')
        with self.assertRaises(ValueError):
            binding.validate_binding(self.archive, self.sbom, raw, **self.params)

    def test_inventory_generator_and_independent_binding_agree(self):
        archive = make_archive([("package/runtime/amd64/node.exe", b"node-fixture", tarfile.REGTYPE),
                                ("package/bin/tokentimer-agent-host-amd64.exe", b"host-fixture", tarfile.REGTYPE)])
        sbom = json.dumps({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
                           "documentNamespace": "https://example.invalid/fixture", "packages": [
                               {"name": "nodejs", "SPDXID": "SPDXRef-node", "licenseDeclared": "MIT",
                                "checksums": [{"algorithm": "SHA256", "checksumValue": sha(b"node-fixture")}]},
                               {"name": "tokentimer-agent-host", "SPDXID": "SPDXRef-host",
                                "checksums": [{"algorithm": "SHA256", "checksumValue": sha(b"host-fixture")}]}
                           ]}).encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_file = root / self.params["archive_name"]
            sbom_file = root / self.params["sbom_name"]
            output = root / "inventory.json"
            archive_file.write_bytes(archive)
            sbom_file.write_bytes(sbom)
            subprocess.run(["go", "run", ".", "--archive", str(archive_file), "--sbom", str(sbom_file),
                            "--version", self.params["version"], "--architecture", "amd64", "--source-commit", "a" * 40,
                            "--out", str(output)], cwd=Path(__file__).parent / "agent-release-inventory", check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            binding.validate_binding(archive, sbom, output.read_bytes(), **self.params)


if __name__ == '__main__':
    unittest.main()
