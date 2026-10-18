"""Offline immutable-owner adversaries; synthetic data is never native evidence."""
import base64
import copy
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
import zipfile
from unittest.mock import patch

import certops_adcs_ttl24h_collection as auth

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("adcs_ttl_main_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def fixture(native):
    p, proof = copy.deepcopy(native["prepared"]), copy.deepcopy(native["proof"])
    lease, repository, head = p["lease"], "tokentimerch/tokentimer-core", "e" * 40
    candidate, owner_id, attempt = lease["candidateSha"], lease["runId"], lease["runAttempt"]
    base = f"https://api.github.com/repos/{repository}"
    run = {"id": 456, "run_attempt": 1, "path": auth.FINALIZER, "head_branch": "main", "event": "schedule", "head_sha": head,
           "status": "completed", "conclusion": "success", "repository": {"full_name": repository}, "head_repository": {"full_name": repository}}
    owner = {**copy.deepcopy(run), "id": int(owner_id), "run_attempt": int(attempt), "path": auth.PREPARE, "event": "workflow_dispatch", "head_sha": candidate,
             "created_at": "2026-10-10T00:00:00Z", "updated_at": "2026-10-15T15:00:00Z"}
    job = {"id": 789, "name": "prepare", "run_id": int(owner_id), "run_attempt": int(attempt), "head_sha": candidate,
           "status": "completed", "conclusion": "success", "started_at": lease["createdAt"], "completed_at": owner["updated_at"]}
    observed = {key: lease[key] for key in auth.IDENTITIES}
    observed.update({key: proof[key] for key in ("preparedSha256", "taskXmlSha256", "processId", "processCreatedAt", "bootTime")})
    observed.update(principalSid="S-1-5-18", taskState="Running", nativeVerificationStartedAt="2026-10-15T12:00:31.000Z",
                    nativeVerificationFinishedAt="2026-10-15T12:00:32.000Z", monotonicElapsedMs=1000)
    observed.update({key: True for key in auth.OBSERVED_FLAGS})
    infra = [{"name": name, "resourceId": lease["vmResourceId"].rsplit("/", 1)[0] + "/" + name,
              "vmId": digit * 8 + "-" + digit * 4 + "-" + digit * 4 + "-" + digit * 4 + "-" + digit * 12,
              "createdAt": lease["createdAt"]} for name, digit in (("domain-ca", "a"), ("control-plane", "b"))]
    control = {key: infra[1][key] for key in ("resourceId", "vmId")}
    control.update(candidateSha=candidate, observedAt="2026-10-15T12:00:30.000Z", composeServices=["api", "mailhog", "postgres"], noStandaloneCertOpsWorker=True)
    control["containerIds"] = [{"service": service, "id": digit * 64} for service, digit in (("api", "1"), ("mailhog", "2"), ("postgres", "3"))]
    original = dict(schemaVersion=1, kind=auth.KIND, lease=lease, publicPreparation=p, taskObserved=observed, controlPlaneObserved=control, infrastructureOwnership=infra)
    handoff = {**copy.deepcopy(original), "lease": {**lease, "phase": "resident-owned", "expiresAt": lease["hardExpiresAt"]}, "handoffObserved": {**observed,
               "nativeVerificationStartedAt": "2026-10-15T12:02:00.000Z", "nativeVerificationFinishedAt": "2026-10-15T12:02:01.000Z"}}
    urls, sources = {}, []
    for file in sorted(auth.CONTROLLER_SOURCES):
        raw = ("Synthetic controller: " + file).encode()
        sources.append({"file": file, "sha256": hashlib.sha256(raw).hexdigest()})
        urls[f"{base}/contents/{file}?ref={head}"] = dict(type="file", path=file, encoding="base64", size=len(raw), content=base64.b64encode(raw).decode())
    report = dict(suite=auth.SUITE, candidateSha=candidate, nativeAdcsTtl24h=proof, fixtureSources=p["sources"],
                  fixtureSource=next(row for row in p["sources"] if row["file"] == "scripts/certops-adcs-ttl24h-resident.js"))
    provenance = dict(finalizerProvenance=dict(repository=repository, runId="456", runAttempt="1", headSha=head, event="schedule", headBranch="main", workflowPath=auth.FINALIZER, controllerSources=sources))
    report["adcsTtl24hProvenance"] = provenance
    urls[f"{base}/actions/runs/{owner_id}/attempts/{attempt}"] = owner
    urls[f"{base}/actions/runs/{owner_id}/attempts/{attempt}/jobs?per_page=100"] = {"total_count": 1, "jobs": [job]}
    value = dict(report=report, run=run, candidate=candidate, repository=repository, urls=urls, original=original, handoff=handoff, base=base, owner=owner, job=job)
    reseal(value)
    return value


def reseal(value):
    p, artifacts = value["report"]["adcsTtl24hProvenance"], []
    lease = value["original"]["lease"]
    for field, kind, artifact_id, when in (("originalArtifact", "original", 1001, "2026-10-15T12:01:00Z"), ("handoffArtifact", "ownership", 1002, "2026-10-15T12:03:00Z")):
        if kind == "ownership":
            value["handoff"]["originalArtifact"] = copy.deepcopy(p["originalArtifact"])
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(f"adcs-ttl24h-{kind}.json", encode(value["original" if kind == "original" else "handoff"]))
        raw = stream.getvalue()
        digest = hashlib.sha256(raw).hexdigest()
        name = f"adcs-ttl24h-{kind}-{lease['runAttempt']}-{lease['nonce']}"
        p[field] = dict(id=str(artifact_id), name=name, archiveSha256=digest)
        value["urls"][f"{value['base']}/actions/artifacts/{artifact_id}/zip"] = raw
        artifacts.append(dict(id=artifact_id, name=name, expired=False, size_in_bytes=len(raw), digest="sha256:" + digest, created_at=when,
                              workflow_run=dict(id=int(lease["runId"]), head_sha=lease["candidateSha"], head_branch="main")))
    value["urls"][f"{value['base']}/actions/runs/{lease['runId']}/artifacts?per_page=100"] = {"total_count": 2, "artifacts": artifacts}


def verify(value):
    def fetch(url, redirect=False):
        item = value["urls"][url]
        if isinstance(item, bytes):
            assert redirect, "Only reviewed artifact requests permit signed redirects"
            return item
        assert not redirect, "API credentials cannot follow redirects"
        return encode(item)
    return auth.authenticate(value["report"], value["run"], value["run"]["id"], value["candidate"], value["repository"], fetch)


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = "const f=require('./scripts/fixtures/certops-adcs-ttl24h-proof.cjs').fixture();f.prepared.sources.push({file:'scripts/certops-adcs-ttl24h-resident.js',sha256:'9'.repeat(64)});f.proof.preparedSha256=require('./scripts/certops-adcs-ttl24h-contract').preparedDigest(f.prepared);require('./scripts/certops-adcs-ttl24h-proof').verifyAgainstPrepared(f.proof,f.prepared,f.observed);process.stdout.write(JSON.stringify(f));"
        cls.native = json.loads(subprocess.check_output(["node", "-e", source], cwd=ROOT, timeout=10))

    def test_authenticated_later_controller_preserves_original_candidate(self):
        value = fixture(self.native)
        self.assertNotEqual(value["run"]["head_sha"], value["candidate"])
        self.assertTrue(verify(value))

    def test_sealed_enrollment_context_cannot_be_substituted(self):
        for field in ("workspaceId", "agentRowId", "issuerId", "installedEnrollmentId", "deferredEnrollmentId", "snapshotSha256", "deadlineAt"):
            with self.subTest(field=field):
                value = fixture(self.native)
                value["report"]["nativeAdcsTtl24h"][field] = "0" * 64
                with self.assertRaises(ValueError):
                    verify(value)
        for field in ("requestIds", "fingerprints", "spkiFingerprints", "caRequestCounts"):
            for index in (0, 1):
                value = fixture(self.native)
                value["report"]["nativeAdcsTtl24h"][field][index] = 999 if field == "caRequestCounts" else "0" * 64
                with self.assertRaises(ValueError):
                    verify(value)

    def test_workflow_attempt_success_and_source_are_authenticated(self):
        for target, field, wrong in (("run", "path", auth.PREPARE), ("run", "conclusion", "failure"), ("run", "head_branch", "feature"),
                                      ("owner", "run_attempt", 3), ("owner", "head_sha", "f" * 40), ("job", "name", "other"), ("job", "conclusion", "cancelled")):
            value = fixture(self.native)
            value[target][field] = wrong
            with self.subTest(target=target, field=field), self.assertRaises(ValueError):
                verify(value)
        value = fixture(self.native)
        value["report"]["adcsTtl24hProvenance"]["finalizerProvenance"]["controllerSources"][0]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            verify(value)

    def test_original_vm_task_and_purpose_cannot_be_replaced(self):
        for field, wrong in (("kind", "certops-native-retention24h"), ("taskName", "TokenTimer-Retention24h-" + "b" * 64), ("vmId", "f" * 36)):
            value = fixture(self.native)
            value["original"]["lease"][field] = wrong
            reseal(value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify(value)
        value = fixture(self.native)
        value["handoff"]["handoffObserved"]["processId"] += 1
        reseal(value)
        with self.assertRaises(ValueError):
            verify(value)

    def test_day_timing_and_both_cache_ages_are_bound(self):
        for field, wrong in (("monotonicElapsedMs", 1000), ("maximumObservationGapMs", 4000000), ("keptObservationCount", 1), ("residentFinishedAt", "2026-10-15T13:00:00.000Z"), ("preDeadlineObservedAt", "2026-10-16T12:00:20.000Z")):
            value = fixture(self.native)
            value["report"]["nativeAdcsTtl24h"][field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify(value)

    def test_resealed_default_timeout_and_api_tls_cover_remain_mandatory(self):
        changes = (
            lambda p: p["validation"].update(configuredTimeoutSeconds=300),
            lambda p: p["validation"].update(journalUpdatedAt="2026-10-15T13:00:00.000Z"),
            lambda p: p["apiTrust"].update(notAfter="2026-10-16T12:00:00.000Z"),
        )
        for change in changes:
            value = fixture(self.native)
            prepared = value["original"]["publicPreparation"]
            change(prepared)
            value["handoff"]["publicPreparation"] = copy.deepcopy(prepared)
            digest = hashlib.sha256(encode(prepared) + b"\n").hexdigest()
            value["report"]["nativeAdcsTtl24h"]["preparedSha256"] = digest
            for observed in (value["original"]["taskObserved"], value["handoff"]["taskObserved"], value["handoff"]["handoffObserved"]):
                observed["preparedSha256"] = digest
            reseal(value)
            with self.assertRaises(ValueError):
                verify(value)

    def test_independent_control_plane_and_original_infrastructure_are_required(self):
        for change in (lambda v: v["original"]["controlPlaneObserved"].update(noStandaloneCertOpsWorker=False),
                       lambda v: v["handoff"]["infrastructureOwnership"][0].update(vmId="f" * 36),
                       lambda v: v["original"]["controlPlaneObserved"]["composeServices"].append("worker")):
            value = fixture(self.native)
            change(value)
            reseal(value)
            with self.assertRaises(ValueError):
                verify(value)

    def test_inventory_and_archive_bytes_are_independently_required(self):
        value = fixture(self.native)
        url = f"{value['base']}/actions/artifacts/1001/zip"
        value["urls"][url] += b"tampered"
        with self.assertRaises(ValueError):
            verify(value)
        value = fixture(self.native)
        url = f"{value['base']}/actions/runs/{value['owner']['id']}/artifacts?per_page=100"
        value["urls"][url]["artifacts"].append(copy.deepcopy(value["urls"][url]["artifacts"][0]))
        value["urls"][url]["total_count"] = 3
        with self.assertRaises(ValueError):
            verify(value)

    def test_authenticated_zip_still_refuses_unsafe_members_and_duplicate_json(self):
        for mode in ("traversal", "symlink", "extra", "duplicate-json"):
            value = fixture(self.native)
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
                member = zipfile.ZipInfo("../adcs-ttl24h-original.json" if mode == "traversal" else "adcs-ttl24h-original.json")
                if mode == "symlink":
                    member.create_system = 3
                    member.external_attr = 0o120777 << 16
                archive.writestr(member, b'{"kind":1,"kind":2}' if mode == "duplicate-json" else encode(value["original"]))
                if mode == "extra":
                    archive.writestr("unexpected.json", b"{}")
            raw = stream.getvalue()
            digest = hashlib.sha256(raw).hexdigest()
            value["urls"][f"{value['base']}/actions/artifacts/1001/zip"] = raw
            value["report"]["adcsTtl24hProvenance"]["originalArtifact"]["archiveSha256"] = digest
            inventory = value["urls"][f"{value['base']}/actions/runs/{value['owner']['id']}/artifacts?per_page=100"]
            inventory["artifacts"][0].update(digest="sha256:" + digest, size_in_bytes=len(raw))
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                verify(value)

    def test_extra_authentication_reads_remain_within_collection_bounds(self):
        with patch.object(auth, "MAX_AUTH_BYTES", 1), self.assertRaises(ValueError):
            verify(fixture(self.native))
        with patch.object(auth, "MAX_ZIP", 100), self.assertRaises(ValueError):
            verify(fixture(self.native))

    def test_strict_json_and_source_bounds(self):
        for raw in (b'{"kind":1,"kind":2}', b'{"time":NaN}'):
            with self.assertRaises(ValueError):
                auth.json_bytes(raw)
        rows = [{"file": f"scripts/source-{i}.js", "sha256": "a" * 64} for i in range(128)]
        self.assertEqual(len(auth.source_pairs(rows)), 128)
        for extra in ({"file": "scripts/../private", "sha256": "a" * 64}, rows[0], {"file": "scripts/source-128.js", "sha256": "a" * 64}):
            with self.assertRaises(ValueError):
                auth.source_pairs(rows + [extra])
        for short in ([rows[0], rows[0]], [{"file": "scripts/../private", "sha256": "a" * 64}], [{"file": "/scripts/private.js", "sha256": "a" * 64}]):
            with self.assertRaises(ValueError):
                auth.source_pairs(short)

    def test_main_authenticates_before_persisting_and_preserves_original_candidate(self):
        for failure in (None, "owner", "enrollment"):
            value = fixture(self.native)
            if failure == "owner":
                value["owner"]["head_sha"] = "f" * 40
            if failure == "enrollment":
                value["report"]["nativeAdcsTtl24h"]["issuerId"] = "00000000-0000-0000-0000-000000000000"
            report = value["report"]
            report.update(schemaVersion=1, strict=True, status="passed", evidenceLevel="e2e", platform="win32", architecture="x64",
                          startedAt=report["nativeAdcsTtl24h"]["residentStartedAt"], finishedAt=report["nativeAdcsTtl24h"]["residentFinishedAt"],
                          cleanup={"status": "passed"}, qualificationEnvironment=dict(osFamily="windows", osVersion="2022", nativeLanguage="en-US", identity="LocalSystem", measurement="native", architecture="x64"),
                          requiredScenarios=[], requiredCapabilities=[], missingScenarios=[], missingCapabilities=[], capabilities={}, scenarios=[])
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("another-campaign.json", encode({"suite": auth.SUITE, "candidateSha": "f" * 40, "nativeAdcsTtl24h": {"notAnExecutionProof": True}}))
                archive.writestr("qualified.json", encode(report))
            raw = stream.getvalue()
            endpoint = f"{value['base']}/actions/runs/456"
            value["urls"][endpoint] = value["run"]
            value["urls"][endpoint + "/artifacts?per_page=100"] = {"total_count": 1, "artifacts": [dict(id=3001, expired=False, size_in_bytes=len(raw), digest="sha256:" + hashlib.sha256(raw).hexdigest())]}
            value["urls"][f"{value['base']}/actions/artifacts/3001/zip"] = raw
            def download(url, token=None, redirect=False):
                item = value["urls"][url]
                self.assertEqual(redirect, isinstance(item, bytes))
                return item if isinstance(item, bytes) else encode(item)
            with tempfile.TemporaryDirectory(prefix="ttl-owner-main-") as directory:
                root = Path(directory)
                (root / "docs/certops").mkdir(parents=True)
                (root / "docs/certops/release-qualification-matrix.json").write_bytes(encode({"slots": [{"id": "owned-elapsed-fixture", "kind": "host", "suite": auth.SUITE, "source": report["fixtureSource"]["file"], "requiredSources": [row["file"] for row in report["fixtureSources"]]}]}))
                (root / "tests/integration").mkdir(parents=True)
                (root / "tests/integration/certops-qualification-groups.json").write_bytes((ROOT / "tests/integration/certops-qualification-groups.json").read_bytes())
                contract = json.loads((ROOT / "docs/certops/qualification-suites.json").read_text())
                contract["suites"][auth.SUITE] = []
                contract["requiredCapabilities"][auth.SUITE] = []
                (root / "docs/certops/qualification-suites.json").write_bytes(encode(contract))
                environment = dict(CERTOPS_QUALIFICATION_PROFILE="full", CERTOPS_RELEASE_CANDIDATE=value["candidate"], CERTOPS_RELEASE_RUN_IDS="[456]", GITHUB_REPOSITORY=value["repository"], GITHUB_TOKEN="synthetic-no-network", GITHUB_SHA=value["run"]["head_sha"])
                # Actual archive/parser/authentication/projection run together.
                # The final whole-matrix execution is outside this owner test.
                with patch.object(collector, "ROOT", root), patch.dict(os.environ, environment), patch.object(collector, "download", side_effect=download), patch.object(collector, "catalog_coverage", return_value={}), patch.object(collector, "validate_matrix_summary"), patch.object(collector.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="{}")) as verifier:
                    if failure:
                        with self.assertRaises(ValueError):
                            collector.main()
                        verifier.assert_not_called()
                    else:
                        collector.main()
                        self.assertEqual(verifier.call_args.kwargs["env"]["GITHUB_SHA"], value["candidate"])
                output = root / "qualification-results/release-collection"
                reports = list(output.glob("report-*.json"))
                self.assertEqual(len(reports), 0 if failure else 1)
                self.assertEqual(json.loads((output / "summary.json").read_text())["status"], "failed" if failure else "passed")
                if not failure:
                    collected = json.loads(reports[0].read_text())
                    self.assertEqual(collected["candidateSha"], value["candidate"])
                    self.assertEqual(collected["nativeAdcsTtl24h"], self.native["proof"])
                    self.assertNotIn("adcsTtl24hProvenance", collected)


if __name__ == "__main__":
    unittest.main()
