import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
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

    def test_rejects_data_hidden_after_tar_end_or_in_another_gzip_member(self):
        for archive in (gzip.compress(gzip.decompress(self.archive) + b"hidden"),
                        self.archive + gzip.compress(b"hidden")):
            doc = copy.deepcopy(self.doc)
            doc["archive"]["sha256"] = sha(archive)
            with self.subTest(length=len(archive)), self.assertRaises(ValueError):
                self.check(archive=archive, doc=doc)

    def test_duplicate_json_keys_are_rejected(self):
        raw = json.dumps(self.doc).encode().replace(b'"schemaVersion": 1', b'"schemaVersion": 1, "schemaVersion": 1')
        with self.assertRaises(ValueError):
            binding.validate_binding(self.archive, self.sbom, raw, **self.params)

    def test_cli_emits_only_digest_of_the_validated_inventory_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_file = root / self.params["archive_name"]
            sbom_file = root / self.params["sbom_name"]
            inventory_file = root / "inventory.json"
            inventory = json.dumps(self.doc).encode()
            archive_file.write_bytes(self.archive)
            sbom_file.write_bytes(self.sbom)
            inventory_file.write_bytes(inventory)
            command = [sys.executable, str(Path(__file__).with_name("windows-release-artifact-binding.py")),
                       "--archive", str(archive_file), "--sbom", str(sbom_file), "--inventory", str(inventory_file),
                       "--version", "1.2.3", "--architecture", "amd64", "--source-commit", "a" * 40]
            good = subprocess.run(command + ["--archive-sha256", sha(self.archive)], capture_output=True, text=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertEqual(good.stdout, sha(inventory) + "\n")
            bad = subprocess.run(command + ["--archive-sha256", "0" * 64], capture_output=True, text=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertEqual(bad.stdout, "")

    def test_inventory_generator_and_independent_binding_agree(self):
        names = ["package/package.json", "package/LICENSE", "package/README.md",
                 "package/bin/tokentimer-agent.js", "package/src/index.js",
                 "package/scripts/install-agent.ps1", "package/src/acme/windows-command.ps1",
                 "package/src/windows-material/connector.ps1", "package/runtime/LICENSE",
                 "package/runtime/manifest.json", "package/runtime/amd64/node.exe"]
        names += [f"package/bin/{family}-{arch}.exe" for arch in ("amd64", "arm64")
                  for family in ("tokentimer-agent-host", "tokentimer-adcs-chain", "tokentimer-adcs-cmc")]
        files = [(name, name.encode(), tarfile.REGTYPE) for name in names]
        archive = make_archive(files)
        packages = []
        for index, (name, data, _) in enumerate(files):
            if not name.endswith(".exe"):
                continue
            item = {"name": name.rsplit("/", 1)[-1], "SPDXID": f"SPDXRef-exe-{index}",
                    "checksums": [{"algorithm": "SHA256", "checksumValue": sha(data)}]}
            if name.endswith("/node.exe"):
                item["licenseDeclared"] = "MIT"
            packages.append(item)
        sbom = json.dumps({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
                           "documentNamespace": "https://example.invalid/fixture", "packages": packages}).encode()
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
