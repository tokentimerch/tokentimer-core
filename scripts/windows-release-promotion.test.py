import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("promotion", Path(__file__).with_name("windows-release-promotion.py"))
promotion = importlib.util.module_from_spec(spec)
spec.loader.exec_module(promotion)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def make_archive(arch):
    data = ("candidate " + arch).encode()
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        info = tarfile.TarInfo("package/file.js")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return out.getvalue(), data


class PromotionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.candidate = {"sourceCommit": "a" * 40, "version": "1.2.3", "architectures": {},
                          "editionCommits": {"core": "a" * 40, "cloud": "b" * 40, "enterprise": "c" * 40},
                          "editionCoreCommits": {name: "a" * 40 for name in promotion.evidence.EDITION_REPOS}}
        self.names = {}
        for arch in promotion.ARCHES:
            archive_name = f"tokentimer-agent-1.2.3-windows-{arch}.tgz"
            names = {"archive": archive_name, "checksum": archive_name + ".sha256", "sbom": arch + ".sbom.json",
                     "inventory": arch + ".inventory.json", "signature": arch + ".p7", "launcher": arch + ".exe"}
            archive, content = make_archive(arch)
            sbom = b'{"fixture":"experimental SBOM"}'
            inventory = json.dumps({"schemaVersion": 1, "sourceCommit": "a" * 40, "version": "1.2.3", "architecture": arch,
                                    "archive": {"name": archive_name, "sha256": sha(archive)},
                                    "sbom": {"name": names["sbom"], "sha256": sha(sbom)},
                                    "files": [{"path": "package/file.js", "sha256": sha(content), "size": len(content)}]}).encode()
            contents = {"archive": archive, "checksum": f'{sha(archive)}  {archive_name}\n'.encode(), "sbom": sbom,
                        "inventory": inventory, "signature": b"synthetic signature", "launcher": b"synthetic launcher"}
            self.names[arch] = names
            self.candidate["architectures"][arch] = {role: sha(data) for role, data in contents.items()}
            for role, data in contents.items():
                (self.root / names[role]).write_bytes(data)

    def stage(self):
        return promotion.stage_candidate(self.root, self.candidate, self.names)

    def test_successful_snapshot_is_exact_and_independent_of_later_changes(self):
        metadata, names, assets = self.stage()
        original = assets[names["amd64"]["archive"]]
        (self.root / names["amd64"]["archive"]).write_bytes(b"changed")
        self.candidate["version"] = "8.8.8"
        self.names["amd64"]["archive"] = "replaced"
        self.assertEqual(assets[names["amd64"]["archive"]], original)
        self.assertEqual(json.loads(metadata)["version"], "1.2.3")
        with self.assertRaises(TypeError): assets["replacement"] = b"x"
        with self.assertRaises(TypeError): names["amd64"]["archive"] = "x"

    def test_refuses_changed_file_missing_role_and_alias(self):
        (self.root / self.names["amd64"]["signature"]).write_bytes(b"changed")
        with self.assertRaises(ValueError): self.stage()
        (self.root / self.names["amd64"]["signature"]).write_bytes(b"synthetic signature")
        names = copy.deepcopy(self.names)
        names["arm64"].pop("launcher")
        with self.assertRaises(ValueError): promotion.stage_candidate(self.root, self.candidate, names)
        names = copy.deepcopy(self.names)
        names["arm64"]["launcher"] = names["amd64"]["launcher"].upper()
        with self.assertRaises(ValueError): promotion.stage_candidate(self.root, self.candidate, names)

    def test_refuses_consistent_digest_for_incorrect_sidecar_or_inventory(self):
        arch = "amd64"
        for role, content in (("checksum", b"wrong"), ("inventory", b"{}")):
            path = self.root / self.names[arch][role]
            original = path.read_bytes()
            original_hash = self.candidate["architectures"][arch][role]
            path.write_bytes(content)
            self.candidate["architectures"][arch][role] = sha(content)
            with self.assertRaises(ValueError): self.stage()
            path.write_bytes(original)
            self.candidate["architectures"][arch][role] = original_hash

    def test_release_refuses_even_with_synthetic_successful_evidence(self):
        staged = self.stage()
        slots = set(promotion.evidence.EDITION_REPOS) | set(promotion.evidence.NATIVE_SYSTEMS) | {"download-command"}
        runs = {arch: {slot: 1 for slot in slots} for arch in promotion.ARCHES}
        tokens = {edition: "test-token" for edition in promotion.evidence.EDITION_REPOS}
        with patch.object(promotion.evidence, "fetch_trusted_edition_pin", return_value="a" * 40), \
             patch.object(promotion.evidence, "fetch_trusted_qualification_report", return_value={}) as fetch, \
             patch.object(promotion.evidence, "validate_binding", return_value=None) as validate:
            with self.assertRaisesRegex(NotImplementedError, "not qualified"):
                promotion.verify_qualification(staged, runs, tokens)
            self.assertEqual(fetch.call_count, len(slots) * 2)
            validate.assert_called_once()

    def test_forged_staged_bytes_are_rejected_before_network(self):
        metadata, names, assets = self.stage()
        slots = set(promotion.evidence.EDITION_REPOS) | set(promotion.evidence.NATIVE_SYSTEMS) | {"download-command"}
        runs = {arch: {slot: 1 for slot in slots} for arch in promotion.ARCHES}
        tokens = {edition: "test-token" for edition in promotion.evidence.EDITION_REPOS}
        with patch.object(promotion.evidence, "fetch_trusted_edition_pin") as fetch:
            for arch in promotion.ARCHES:
                for role in promotion.evidence.ROLES:
                    altered = dict(assets)
                    altered[names[arch][role]] = b"substituted"
                    with self.subTest(arch=arch, role=role), self.assertRaises(ValueError):
                        promotion.verify_qualification((metadata, names, altered), runs, tokens)
            extra = dict(assets)
            extra["unexpected"] = b"extra"
            with self.assertRaises(ValueError):
                promotion.verify_qualification((metadata, names, extra), runs, tokens)
            with self.assertRaises(ValueError):
                promotion.verify_qualification((metadata + b" ", names, assets), runs, tokens)
            fetch.assert_not_called()

    def test_mismatched_edition_and_missing_runs_fail_closed(self):
        staged = self.stage()
        slots = set(promotion.evidence.EDITION_REPOS) | set(promotion.evidence.NATIVE_SYSTEMS) | {"download-command"}
        runs = {arch: {slot: 1 for slot in slots} for arch in promotion.ARCHES}
        tokens = {edition: "test-token" for edition in promotion.evidence.EDITION_REPOS}
        bad_runs = copy.deepcopy(runs)
        bad_runs["amd64"].pop("download-command")
        with self.assertRaises(ValueError): promotion.verify_qualification(staged, bad_runs, tokens)
        with patch.object(promotion.evidence, "fetch_trusted_edition_pin", return_value="d" * 40), \
             patch.object(promotion.evidence, "fetch_trusted_qualification_report") as fetch:
            with self.assertRaises(ValueError): promotion.verify_qualification(staged, runs, tokens)
            fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
