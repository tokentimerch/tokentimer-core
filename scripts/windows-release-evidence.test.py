import base64
import copy
import json
import hashlib
import io
import zipfile
import importlib.util
from pathlib import Path
import unittest
import urllib.error
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("binding", Path(__file__).with_name("windows-release-evidence.py"))
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)


class BindingTests(unittest.TestCase):
    def fixture(self):
        source = "a" * 40
        edition = {"core": source, "cloud": "b" * 40, "enterprise": "c" * 40}
        c = {"sourceCommit": source, "version": "1.2.3", "editionCommits": edition,
             "editionCoreCommits": {name: source for name in edition},
             "architectures": {arch: {role: str(n) * 64 for n, role in enumerate(sorted(binding.ROLES), 1)} for arch in ("amd64", "arm64")}}
        reports = []
        for arch in c["architectures"]:
            for slot in list(binding.EDITION_REPOS) + sorted(binding.NATIVE_SYSTEMS) + ["download-command"]:
                owner = slot if slot in edition else "core"
                repo, branch, workflow = binding.EDITION_REPOS[owner]
                run = {"status": "completed", "conclusion": "success", "event": "workflow_dispatch", "path": workflow,
                       "head_branch": branch, "head_sha": edition[owner], "repository": {"full_name": repo}, "head_repository": {"full_name": repo}}
                report = {"slot": slot, "architecture": arch, "sourceCommit": source, "version": c["version"],
                          "artifactDigests": copy.deepcopy(c["architectures"][arch]), "editionCommit": edition[owner], "editionCoreCommit": source, "status": "passed"}
                records = {name: json.dumps({"caseId": name, "status": "passed", **{field: report[field] for field in ("sourceCommit", "version", "architecture", "artifactDigests", "editionCommit", "editionCoreCommit")}}).encode() for name in binding.required_cases(slot)}
                report["cases"] = [{"id": name, "status": "passed", "evidenceSha256": hashlib.sha256(raw).hexdigest()} for name, raw in sorted(records.items())]
                reports.append({"report": report, "run": run, "records": records})
        return c, reports

    def test_edition_manifests_require_the_actual_composition_field(self):
        cloud = b'{"manifestVersion":1,"repo":"tokentimer-cloud","core":{"testedCommit":"' + b'a' * 40 + b'"}}'
        enterprise = b'{"manifestVersion":1,"repo":"tokentimer-enterprise","core":{"lastSyncedCoreCommit":"' + b'b' * 40 + b'"}}'
        self.assertEqual(binding.edition_pin_from_manifest(cloud, "cloud"), "a" * 40)
        self.assertEqual(binding.edition_pin_from_manifest(enterprise, "enterprise"), "b" * 40)
        for raw, edition in ((cloud, "enterprise"), (cloud.replace(b'"core":', b'"core":{},"core":'), "cloud"), (cloud.replace(b'"testedCommit"', b'"lastSyncedCoreCommit"'), "cloud"), (b'{}', "cloud")):
            with self.assertRaises(ValueError): binding.edition_pin_from_manifest(raw, edition)

    def test_manifest_fetch_uses_fixed_repository_and_exact_commit(self):
        raw = b'{"manifestVersion":1,"repo":"tokentimer-cloud","core":{"testedCommit":"' + b'a' * 40 + b'"}}'
        calls = []
        def download(url, token):
            calls.append((url, token))
            return json.dumps({"type": "file", "path": "compatibility.manifest.json", "encoding": "base64", "content": base64.b64encode(raw).decode()}).encode()
        self.assertEqual(binding.fetch_edition_pin("cloud", "b" * 40, "fixture-token", download), "a" * 40)
        self.assertEqual(calls, [("https://api.github.com/repos/tokentimerch/tokentimer-cloud/contents/compatibility.manifest.json?ref=" + "b" * 40, "fixture-token")])
        for edition, commit in (("other", "b" * 40), ("cloud", "main"), ("cloud", "../")):
            with self.assertRaises(ValueError): binding.fetch_edition_pin(edition, commit, "fixture-token", download)

    def test_report_fetch_binds_run_artifact_and_downloaded_zip(self):
        c, items = self.fixture()
        original = next(item for item in items if item["report"]["slot"] == "cloud")
        run = {**original["run"], "id": 5}
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as z:
            z.writestr("qualification.json", json.dumps(original["report"]))
            for name, raw in original["records"].items(): z.writestr("evidence/" + name + ".json", raw)
        archive = buffer.getvalue()
        artifact = {"id": 7, "name": "windows-final-package-qualification", "expired": False,
                    "size_in_bytes": len(archive), "digest": "sha256:" + hashlib.sha256(archive).hexdigest()}
        def download(url, token, redirect=False):
            if url.endswith("/zip"): return archive
            if "/artifacts?" in url: return json.dumps({"total_count": 1, "artifacts": [artifact]}).encode()
            return json.dumps(run).encode()
        item = binding.fetch_qualification_report("cloud", c["editionCommits"]["cloud"], 5, "fixture", download)
        self.assertEqual(item["report"], original["report"])
        artifact["digest"] = "sha256:" + "f" * 64
        with self.assertRaises(ValueError): binding.fetch_qualification_report("cloud", c["editionCommits"]["cloud"], 5, "fixture", download)
        artifact["digest"] = "sha256:" + hashlib.sha256(archive).hexdigest()
        run["head_sha"] = "f" * 40
        with self.assertRaises(ValueError): binding.fetch_qualification_report("cloud", c["editionCommits"]["cloud"], 5, "fixture", download)

    def test_trusted_report_fetch_does_not_send_token_to_blob(self):
        c, items = self.fixture()
        original = next(item for item in items if item["report"]["slot"] == "cloud")
        run = {**original["run"], "id": 5}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("qualification.json", json.dumps(original["report"]))
            for name, raw in original["records"].items(): z.writestr("evidence/" + name + ".json", raw)
        data = buf.getvalue()
        artifact = {"id": 7, "name": "windows-final-package-qualification", "expired": False, "size_in_bytes": len(data), "digest": "sha256:" + hashlib.sha256(data).hexdigest()}
        redirect = urllib.error.HTTPError("https://api.github.com/zip", 302, "redirect", {"Location": "https://fixture.blob.core.windows.net/evidence"}, None)
        outcomes = [json.dumps(run).encode(), json.dumps({"total_count": 1, "artifacts": [artifact]}).encode(), redirect, data]
        calls = []
        opener = Mock()
        def open_request(request, timeout):
            calls.append(request)
            outcome = outcomes[len(calls) - 1]
            if isinstance(outcome, Exception): raise outcome
            return io.BytesIO(outcome)
        opener.open.side_effect = open_request
        with patch("urllib.request.build_opener", return_value=opener):
            item = binding.fetch_trusted_qualification_report("cloud", c["editionCommits"]["cloud"], 5, "fixture-token")
        self.assertEqual(item["report"], original["report"])
        self.assertTrue(all(req.get_header("Authorization") == "Bearer fixture-token" for req in calls[:3]))
        self.assertIsNone(calls[3].get_header("Authorization"))

    def test_report_fetch_rejects_duplicate_names_and_case_tampering(self):
        c, items = self.fixture()
        original = next(item for item in items if item["report"]["slot"] == "cloud")
        run = {**original["run"], "id": 5}
        for variant in ("duplicate", "tamper", "traversal"):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                z.writestr("qualification.json", json.dumps(original["report"]))
                for name, raw in original["records"].items():
                    z.writestr("evidence/" + name + ".json", b"altered" if variant == "tamper" else raw)
                if variant == "duplicate":
                    with self.assertWarns(UserWarning): z.writestr("qualification.json", "{}")
                if variant == "traversal": z.writestr("../outside.json", "{}")
            data = buf.getvalue()
            artifact = {"id": 7, "name": "windows-final-package-qualification", "expired": False,
                        "size_in_bytes": len(data), "digest": "sha256:" + hashlib.sha256(data).hexdigest()}
            def download(url, token, redirect=False):
                if url.endswith("/zip"): return data
                if "/artifacts?" in url: return json.dumps({"total_count": 1, "artifacts": [artifact]}).encode()
                return json.dumps(run).encode()
            with self.assertRaises(ValueError):
                binding.fetch_qualification_report("cloud", c["editionCommits"]["cloud"], 5, "fixture", download)

    def test_complete_matrix_is_only_a_binding_not_publication_approval(self):
        c, e = self.fixture()
        with self.assertRaises(NotImplementedError): binding.validate_binding(c, e)

    def test_missing_duplicate_or_stale_evidence_is_rejected(self):
        c, e = self.fixture()
        for bad in (e[:-1], [e[0]] + e[1:-1] + [e[0]]):
            with self.assertRaises(ValueError): binding.validate_binding(c, bad)
        for key in ("archive", "checksum", "signature", "sbom", "inventory", "launcher"):
            bad = copy.deepcopy(e)
            bad[0]["report"]["artifactDigests"][key] = "0" * 64
            with self.assertRaises(ValueError): binding.validate_binding(c, bad)
        bad = copy.deepcopy(e)
        bad[0]["report"]["sourceCommit"] = "f" * 40
        with self.assertRaises(ValueError): binding.validate_binding(c, bad)

    def test_case_records_require_real_bound_bytes_and_all_required_cases(self):
        c, e = self.fixture()
        for mutate in (
            lambda item: item["report"]["cases"].pop(),
            lambda item: item["report"]["cases"][0].update(status="skipped"),
            lambda item: item["report"]["cases"][0].update(evidenceSha256="0" * 64),
            lambda item: item["records"].pop(next(iter(item["records"]))),
            lambda item: item["records"].update({"unexpected": b"extra"}),
            lambda item: item["records"].update({next(iter(item["records"])): b"changed"}),
        ):
            bad = copy.deepcopy(e)
            mutate(bad[0])
            with self.assertRaises(ValueError): binding.validate_binding(c, bad)
        bad = copy.deepcopy(e)
        case = bad[0]["report"]["cases"][0]
        raw = bad[0]["records"][case["id"]].replace(b'"passed"', b'"failed"')
        bad[0]["records"][case["id"]] = raw
        case["evidenceSha256"] = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(ValueError): binding.validate_binding(c, bad)

    def test_fork_wrong_workflow_or_edition_composition_is_rejected(self):
        c, e = self.fixture()
        for key, value in (("path", ".github/workflows/other.yml"), ("head_branch", "feature"), ("conclusion", "failure"), ("head_sha", "f" * 40), ("head_repository", {"full_name": "fork/repo"})):
            bad = copy.deepcopy(e)
            bad[0]["run"][key] = value
            with self.assertRaises(ValueError): binding.validate_binding(c, bad)
        c["editionCoreCommits"]["cloud"] = "f" * 40
        with self.assertRaises(ValueError): binding.validate_binding(c, e)


if __name__ == "__main__":
    unittest.main()
