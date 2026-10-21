"""Controlled owner-chain adversaries, never native qualification fixtures.

The production native-proof sanitizer/verifier has separate full-proof tests.
These tests authenticate API identities, sealed archives and source hashes;
no GitHub, Azure, service, certificate or key action is performed.
"""
import base64
import copy
import hashlib
import io
import importlib.util
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import subprocess
from types import SimpleNamespace
import unittest
import zipfile
from unittest.mock import patch
import certops_retention24h_collection as auth

spec = importlib.util.spec_from_file_location("retention_main_collector", Path(__file__).with_name("certops-release-collector.py"))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def fixture(native=None):
    candidate, head, repository = "a" * 40, "b" * 40, "tokentimerch/tokentimer-core"
    base = f"https://api.github.com/repos/{repository}"
    run = {"id": 200, "run_attempt": 2, "status": "completed", "conclusion": "success",
           "path": auth.FINALIZER, "head_branch": "main", "event": "schedule", "head_sha": head,
           "repository": {"full_name": repository}, "head_repository": {"full_name": repository}}
    owner = {**copy.deepcopy(run), "id": 100, "run_attempt": 1, "path": auth.PREPARE,
             "event": "workflow_dispatch", "head_sha": candidate}
    lease = {"candidateSha": candidate, "phase": "preparing", "runId": "100", "runAttempt": "1", "nonce": "c" * 64,
             "vmId": "11111111-1111-1111-1111-111111111111", "nodeSha256": "3" * 64, "keeperSha256": "4" * 64,
             "createdAt": "2026-10-14T00:00:00.000Z", "expiresAt": "2026-10-14T04:00:00.000Z", "hardExpiresAt": "2026-10-15T08:00:00.000Z",
             "schemaVersion": 1, "kind": "certops-native-retention24h", "vmResourceId": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/tt-certops-100-1/providers/Microsoft.Compute/virtualMachines/windows-agent",
             "taskName": "TokenTimer-Retention24h-" + "c" * 64}
    pairs = [{"file": "scripts/certops-retention24h-runtime.js", "sha256": "d" * 64}]
    preparation = {"lease": lease, "configSha256": "e" * 64, "fixtureSources": pairs,
                   "actualRequestIds": ["17", "18"], "fingerprints": ["1" * 64, "2" * 64]}
    generations = [{"requestId": str(17 + index), "enrollmentId": str(index + 1) * 36, "jobId": str(index + 3) * 36,
                    "thumbprint": str(index + 1) * 40, "containerName": "controlled-" + str(index),
                    "spkiSha256": str(index + 5) * 64, "serial": "a" + str(index)} for index in range(2)]
    preparation.update(generations=generations, collectorHelper={"sha256": "5" * 64}, ledgerIdentitySha256="6" * 64,
                       verifiedCutoverAt="2026-10-14T00:30:00.000Z", oldNotAfter="2026-10-18T00:00:00.000Z", cleanupDeadline="2026-10-15T00:30:00.000Z")
    observed = {"processId": 1234, "processCreatedAt": "2026-10-14T00:31:00.000Z", "bootTime": lease["createdAt"], "taskXmlSha256": "7" * 64}
    if native:
        composite = native["composite"]
        candidate = composite["candidateSha"]; lease = composite["preparedLease"]
        preparation = composite["publicPreparation"]; observed = composite["handoffObserved"]
        generations = preparation["generations"]; pairs = preparation["fixtureSources"]
    owner_id, attempt = lease["runId"], lease["runAttempt"]
    owner.update(id=int(owner_id), run_attempt=int(attempt), head_sha=candidate)
    created = datetime.fromisoformat(lease["createdAt"].replace("Z", "+00:00"))
    api_time = lambda value: value.isoformat(timespec="seconds").replace("+00:00", "Z")
    # Protected approval can wait days. The authenticated prepare job start,
    # rather than workflow creation, anchors the four-hour resource window.
    owner.update(created_at=api_time(created - timedelta(days=3)), updated_at=api_time(created + timedelta(hours=3)))
    prepare_job = {"id": 901, "name": "prepare", "run_id": int(owner_id), "head_sha": candidate,
                   "status": "completed", "conclusion": "success", "started_at": api_time(created),
                   "completed_at": api_time(created + timedelta(hours=3))}
    observed_at = preparation.get("finishedAt", "2026-10-14T01:00:00.000Z")
    original = {"schemaVersion": 1, "scope": "host-verified-original-four-hour-retention24h-not-elapsed-qualified",
                "preparedLease": lease, "configSha256": preparation["configSha256"], "observed": observed,
                "observedAt": observed_at, "publicPreparation": preparation}
    urls, artifacts = {}, []
    def archive(value, name, member, artifact_id):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as packed:
            packed.writestr(member, json.dumps(value))
        raw = stream.getvalue()
        digest = hashlib.sha256(raw).hexdigest()
        urls[f"{base}/actions/artifacts/{artifact_id}/zip"] = raw
        artifacts.append({"id": artifact_id, "name": name, "expired": False, "size_in_bytes": len(raw), "created_at": observed_at,
                          "digest": "sha256:" + digest, "workflow_run": {"id": int(owner_id), "head_sha": candidate, "head_branch": "main"}})
        return {"id": str(artifact_id), "name": name, "archiveSha256": digest}
    original_artifact = archive(original, f"retention24h-original-{attempt}-" + lease["nonce"], "retention24h-original.json", 1001)
    extended = {**lease, "phase": "keeper-owned", "expiresAt": lease["hardExpiresAt"]}
    handoff = {"schemaVersion": 1, "scope": "host-verified-retention24h-handoff-not-elapsed-qualified",
               "preparedLease": lease, "lease": extended, "configSha256": preparation["configSha256"],
               "observed": observed, "observedAt": original["observedAt"], "originalArtifact": original_artifact,
               "publicPreparation": preparation, "actualRequestIds": preparation["actualRequestIds"],
               "fingerprints": preparation["fingerprints"]}
    handoff_artifact = archive(handoff, f"retention24h-prepare-ownership-{attempt}-" + lease["nonce"], "retention24h-ownership.json", 1002)
    sources = []
    for file in sorted(auth.CONTROLLER_SOURCES):
        raw = ("Controlled source fixture: " + file).encode()
        sources.append({"file": file, "sha256": hashlib.sha256(raw).hexdigest()})
        urls[f"{base}/contents/{file}?ref={head}"] = {"type": "file", "path": file, "encoding": "base64",
                                                    "size": len(raw), "content": base64.b64encode(raw).decode()}
    provenance = {"originalArtifact": original_artifact, "handoffArtifact": handoff_artifact,
                  "finalizerProvenance": {"repository": repository, "runId": "200", "runAttempt": "2", "headSha": head,
                                          "event": "schedule", "headBranch": "main", "workflowPath": auth.FINALIZER, "controllerSources": sources}}
    proof = {"candidateSha": candidate, "prepareRunId": owner_id, "prepareRunAttempt": attempt,
             "requestIds": preparation["actualRequestIds"], "fingerprints": preparation["fingerprints"],
             **{key: lease[key] for key in ("nonce", "vmId", "nodeSha256", "keeperSha256")},
             **{key: preparation[key] for key in ("configSha256", "verifiedCutoverAt", "oldNotAfter", "cleanupDeadline", "ledgerIdentitySha256")},
             **observed, "originalCreatedAt": lease["createdAt"], "collectorHelperSha256": preparation["collectorHelper"]["sha256"],
             "serialNumbers": [row["serial"].lower() for row in generations]}
    for target, key in (("enrollmentIds", "enrollmentId"), ("jobIds", "jobId"), ("thumbprints", "thumbprint"), ("containerNames", "containerName"), ("spkiSha256", "spkiSha256")):
        proof[target] = [row[key] for row in generations]
    report = {"suite": auth.SUITE, "candidateSha": candidate, "nativeRetention24h": proof,
              "retention24hProvenance": provenance, "fixtureSources": pairs, "fixtureSource": pairs[0]}
    if native:
        report = native["report"]; report["retention24hProvenance"] = provenance
    owner_url = f"{base}/actions/runs/{owner_id}/attempts/{attempt}"
    urls[owner_url] = owner
    urls[owner_url + "/jobs?per_page=100"] = {"total_count": 1, "jobs": [prepare_job]}
    urls[f"{base}/actions/runs/{owner_id}/artifacts?per_page=100"] = {"total_count": 2, "artifacts": artifacts}
    return {"report": report, "run": run, "candidate": candidate, "repository": repository, "urls": urls, "base": base, "owner_url": owner_url}


def verify(value):
    def fetch(url, redirect=False):
        if url not in value["urls"]:
            raise AssertionError("Unexpected API request")
        item = value["urls"][url]
        if isinstance(item, bytes):
            if not redirect:
                raise AssertionError("Archive must use credential-safe redirect policy")
            return item
        return json.dumps(item).encode()
    return auth.authenticate(value["report"], value["run"], 200, value["candidate"], value["repository"], fetch)


def reseal_prepared_lease(value, mutate):
    """Preserve real ZIP/digest/link checks while testing embedded lease facts.

    Controlled API archive metadata is re-sealed to match the mutated original
    and handoff. A rejection must therefore come from the ownership/schema
    contract, rather than an unrelated stale archive hash or preparation copy.
    """
    owner = value["report"]["nativeRetention24h"]
    base = value["base"]
    def unpack(artifact_id):
        with zipfile.ZipFile(io.BytesIO(value["urls"][f"{base}/actions/artifacts/{artifact_id}/zip"])) as archive:
            return json.loads(archive.read(archive.namelist()[0]))
    original, handoff = unpack(1001), unpack(1002)
    mutate(original["preparedLease"])
    lease = original["preparedLease"]
    original["publicPreparation"]["lease"] = copy.deepcopy(lease)
    handoff["preparedLease"] = copy.deepcopy(lease)
    handoff["lease"] = {**lease, "phase": "keeper-owned", "expiresAt": lease.get("hardExpiresAt")}
    handoff["publicPreparation"] = copy.deepcopy(original["publicPreparation"])
    inventory = value["urls"][f"{base}/actions/runs/{owner['prepareRunId']}/artifacts?per_page=100"]["artifacts"]
    def seal(artifact_id, member, document, field):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(member, json.dumps(document))
        raw = output.getvalue()
        digest = hashlib.sha256(raw).hexdigest()
        value["urls"][f"{base}/actions/artifacts/{artifact_id}/zip"] = raw
        value["report"]["retention24hProvenance"][field]["archiveSha256"] = digest
        metadata = next(item for item in inventory if item["id"] == artifact_id)
        metadata.update(digest="sha256:" + digest, size_in_bytes=len(raw))
    seal(1001, "retention24h-original.json", original, "originalArtifact")
    handoff["originalArtifact"] = copy.deepcopy(value["report"]["retention24hProvenance"]["originalArtifact"])
    seal(1002, "retention24h-ownership.json", handoff, "handoffArtifact")
    return value


class RetentionOwnerTests(unittest.TestCase):
    def test_prepare_job_identity_lifecycle_and_optional_attempt_are_authenticated(self):
        value = fixture()
        self.assertTrue(verify(value))
        value["urls"][value["owner_url"] + "/jobs?per_page=100"]["jobs"][0]["run_attempt"] = 1
        self.assertTrue(verify(value))
        for field, bad in (("id", True), ("id", 0), ("name", "other-job"), ("run_id", 101),
                           ("head_sha", "f" * 40), ("run_attempt", 2), ("run_attempt", True),
                           ("started_at", None), ("completed_at", None), ("status", "in_progress"),
                           ("conclusion", "cancelled"), ("started_at", "2026-10-10T00:00:00Z"),
                           ("completed_at", "2026-10-13T23:59:59Z"), ("completed_at", "2026-10-14T03:00:06Z")):
            value = fixture()
            value["urls"][value["owner_url"] + "/jobs?per_page=100"]["jobs"][0][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                verify(value)
        for response in ({"total_count": True, "jobs": []}, {"total_count": 0, "jobs": []},
                         {"total_count": 101, "jobs": []}):
            value = fixture(); value["urls"][value["owner_url"] + "/jobs?per_page=100"] = response
            with self.subTest(response=response), self.assertRaises(ValueError):
                verify(value)
        value = fixture(); jobs = value["urls"][value["owner_url"] + "/jobs?per_page=100"]
        jobs["jobs"].append(copy.deepcopy(jobs["jobs"][0])); jobs["total_count"] = 2
        with self.assertRaises(ValueError):
            verify(value)

    def test_creation_uses_authenticated_job_after_approval_with_five_second_precision(self):
        # The owner fixture was created three days before the actual job. These
        # real parser calls ensure approval delay is not mistaken for lease age.
        for start, passes in (("2026-10-14T00:00:05Z", True), ("2026-10-14T00:00:06Z", False),
                              ("2026-10-13T20:00:00Z", True), ("2026-10-13T19:59:56Z", True),
                              ("2026-10-13T19:59:55Z", False)):
            value = fixture()
            value["urls"][value["owner_url"] + "/jobs?per_page=100"]["jobs"][0]["started_at"] = start
            with self.subTest(start=start):
                if passes:
                    self.assertTrue(verify(value))
                else:
                    with self.assertRaises(ValueError):
                        verify(value)
        for field, bad in (("created_at", "2026-10-14T00:00:06Z"), ("updated_at", "2026-10-13T23:59:59Z"),
                           ("created_at", None), ("updated_at", None)):
            value = fixture(); value["urls"][value["owner_url"]][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                verify(value)
        # The last artifact must be sealed before job completion plus API
        # precision, even if its preparation remains otherwise self-consistent.
        for completed, passes in (("2026-10-14T00:59:55Z", True), ("2026-10-14T00:59:54Z", False)):
            value = fixture()
            value["urls"][value["owner_url"] + "/jobs?per_page=100"]["jobs"][0]["completed_at"] = completed
            with self.subTest(completed=completed):
                if passes:
                    self.assertTrue(verify(value))
                else:
                    with self.assertRaises(ValueError):
                        verify(value)

    def test_resealed_original_and_handoff_refuse_lease_schema_identity_and_ttl_changes(self):
        value = fixture()
        self.assertTrue(verify(reseal_prepared_lease(value, lambda lease: None)))
        changes = (
            ("schemaVersion", True), ("schemaVersion", 2), ("kind", "supporting-timer"),
            ("phase", "keeper-owned"), ("repository", "other/repository"),
            ("workflowPath", ".github/workflows/wrong.yml"), ("headBranch", "feature"),
            ("event", "pull_request"), ("privateCredential", "controlled-never-persist"),
            ("candidateSha", "f" * 40), ("runId", "101"), ("runAttempt", "2"),
            ("nonce", "f" * 64), ("vmId", "invalid-vm"), ("nodeSha256", "f" * 64),
            ("keeperSha256", "f" * 64), ("taskName", "TokenTimer-Retention24h-" + "f" * 64),
            ("vmResourceId", "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/tt-certops-101-1/providers/Microsoft.Compute/virtualMachines/windows-agent"),
            ("expiresAt", "2026-10-14T04:00:00.001Z"),
            ("expiresAt", "2026-10-14T03:59:59.999Z"),
            ("hardExpiresAt", "2026-10-15T08:00:00.001Z"),
            ("hardExpiresAt", "2026-10-15T07:59:59.999Z"),
            ("createdAt", "2026-10-14T00:00:00Z"),
            ("createdAt", "2026-10-14T00:00:00.000+00:00"),
            ("createdAt", "2026-02-30T00:00:00.000Z"),
        )
        for field, bad in changes:
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                verify(reseal_prepared_lease(fixture(), lambda lease: lease.update({field: bad})))
        for field in ("schemaVersion", "taskName", "vmResourceId", "expiresAt", "hardExpiresAt"):
            with self.subTest(missing=field), self.assertRaises(ValueError):
                verify(reseal_prepared_lease(fixture(), lambda lease: lease.pop(field)))

    def test_main_authenticates_before_writing_and_keeps_original_candidate(self):
        # Use the actual JS report producer and actual Python archive/parser;
        # only remote APIs and final matrix execution are controlled fixtures.
        script = "const fs=require('node:fs'),crypto=require('node:crypto');const c=require('./scripts/certops-retention24h-test-fixture.cjs')();for(const p of c.publicPreparation.fixtureSources)p.sha256=crypto.createHash('sha256').update(fs.readFileSync(p.file)).digest('hex');const report=require('./scripts/certops-retention24h-proof').createQualificationReport(c);process.stdout.write(JSON.stringify({composite:c,report}));"
        produced = subprocess.run(["node", "-e", script], cwd=Path(__file__).resolve().parent.parent, capture_output=True, text=True, timeout=30)
        self.assertEqual(produced.returncode, 0, "Actual pure report factory failed")
        native = json.loads(produced.stdout)
        for wrong_owner in (False, True):
            value = fixture(copy.deepcopy(native))
            if wrong_owner:
                value["urls"][value["owner_url"]]["head_sha"] = "f" * 40
            packed = io.BytesIO()
            with zipfile.ZipFile(packed, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("another-campaign.json", json.dumps({"suite": auth.SUITE, "candidateSha": "f" * 40, "nativeRetention24h": {"deliberatelyNotANativeProof": True}}))
                archive.writestr("qualification.json", json.dumps(value["report"]))
            raw = packed.getvalue()
            value["urls"][value["base"] + "/actions/runs/200"] = value["run"]
            value["urls"][value["base"] + "/actions/runs/200/artifacts?per_page=100"] = {"total_count": 1, "artifacts": [{"id": 3001, "name": "controlled-finalizer", "expired": False, "size_in_bytes": len(raw), "digest": "sha256:" + hashlib.sha256(raw).hexdigest()}]}
            value["urls"][value["base"] + "/actions/artifacts/3001/zip"] = raw
            def download(url, token="", redirect=False):
                item = value["urls"][url]
                return item if isinstance(item, bytes) else json.dumps(item).encode()
            with tempfile.TemporaryDirectory(prefix="certops-retention-owner-") as directory:
                root = Path(directory)
                (root / "docs/certops").mkdir(parents=True)
                (root / "docs/certops/qualification-suites.json").write_text(json.dumps({"slots": [{"id": "owned-elapsed-fixture", "kind": "host", "suite": auth.SUITE}]}))
                environment = {"CERTOPS_QUALIFICATION_PROFILE": "full", "CERTOPS_RELEASE_CANDIDATE": value["candidate"], "CERTOPS_RELEASE_RUN_IDS": "[200]", "GITHUB_REPOSITORY": value["repository"], "GITHUB_TOKEN": "controlled-no-network", "GITHUB_SHA": value["run"]["head_sha"]}
                collector_extract = collector.extract_reports
                # The temporary output root need not duplicate repository
                # metadata; parsing reads the real committed suite contract.
                real_root = collector.ROOT
                def parse(*args, **kwargs):
                    with patch.object(collector, "ROOT", real_root):
                        return collector_extract(*args, **kwargs)
                with patch.object(collector, "ROOT", root), patch.dict(os.environ, environment), patch.object(collector, "download", side_effect=download), patch.object(collector, "extract_reports", side_effect=parse), patch.object(collector, "catalog_coverage", return_value={}), patch.object(collector, "validate_matrix_summary"), patch.object(collector.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="{}")) as verifier:
                    if wrong_owner:
                        with self.assertRaises(ValueError):
                            collector.main()
                        verifier.assert_not_called()
                    else:
                        collector.main()
                        self.assertEqual(verifier.call_args.kwargs["env"]["GITHUB_SHA"], value["candidate"])
                    destination = root / "qualification-results/release-collection"
                    self.assertEqual(len(list(destination.glob("report-*.json"))), 0 if wrong_owner else 1)
                    self.assertEqual(json.loads((destination / "summary.json").read_text())["status"], "failed" if wrong_owner else "passed")
                    if not wrong_owner:
                        collected = json.loads(next(destination.glob("report-*.json")).read_text())
                        self.assertNotIn("retention24hProvenance", collected)
                        self.assertNotIn("publicPreparation", collected["nativeRetention24h"])

    def test_original_prepare_source_seal_covers_every_new_interruption_dependency(self):
        script = "const c=require('./scripts/certops-retention24h-test-fixture.cjs')(),report=require('./scripts/certops-retention24h-proof').createQualificationReport(c);process.stdout.write(JSON.stringify({composite:c,report}));"
        produced = subprocess.run(["node", "-e", script], cwd=Path(__file__).resolve().parent.parent, capture_output=True, text=True, timeout=30)
        self.assertEqual(produced.returncode, 0)
        native = json.loads(produced.stdout)
        paths = ("tests/e2e/helpers/certops-retention24h-interrupted.js", "packages/agent/scripts/host/retention-interrupted-child.js", "packages/agent/src/platform/index.js", "tests/e2e/helpers/certops-windows-contained-process.js", "tests/e2e/helpers/certops-windows-contained-process.ps1")
        self.assertTrue(verify(fixture(copy.deepcopy(native))))
        for path in paths:
            value = fixture(copy.deepcopy(native)); value["report"]["fixtureSources"] = [row for row in value["report"]["fixtureSources"] if row["file"] != path]
            with self.subTest(missing=path), self.assertRaises(ValueError): verify(value)
            value = fixture(copy.deepcopy(native)); next(row for row in value["report"]["fixtureSources"] if row["file"] == path)["sha256"] = "0" * 64
            with self.subTest(stale=path), self.assertRaises(ValueError): verify(value)

    def test_later_trusted_main_authenticates_only_original_native_candidate(self):
        value = fixture()
        self.assertNotEqual(value["run"]["head_sha"], value["candidate"])
        self.assertTrue(verify(value))
        value["candidate"] = value["run"]["head_sha"]
        with self.assertRaises(ValueError):
            verify(value)

    def test_finalizer_and_original_owner_are_independently_authenticated(self):
        for target, field, bad in (("run", "head_branch", "feature"), ("run", "event", "pull_request"),
                                   ("run", "conclusion", "cancelled"), ("run", "run_attempt", True),
                                   ("owner", "head_sha", "f" * 40), ("owner", "run_attempt", 2),
                                   ("owner", "event", "push"), ("owner", "path", auth.FINALIZER),
                                   ("owner", "conclusion", "failure")):
            value = fixture()
            selected = value["run"] if target == "run" else value["urls"][value["base"] + "/actions/runs/100/attempts/1"]
            selected[field] = bad
            with self.subTest(target=target, field=field), self.assertRaises(ValueError):
                verify(value)

    def test_archives_require_exact_owner_name_digest_context_and_single_member(self):
        for mutate in (
            lambda row: row.update(expired=True), lambda row: row.update(digest="sha256:" + "0" * 64),
            lambda row: row.update(id=1009), lambda row: row["workflow_run"].update(head_sha="f" * 40),
            lambda row: row.update(size_in_bytes=auth.MAX_ZIP + 1),
        ):
            value = fixture()
            mutate(value["urls"][value["base"] + "/actions/runs/100/artifacts?per_page=100"]["artifacts"][0])
            with self.assertRaises(ValueError):
                verify(value)
        value = fixture()
        inventory = value["urls"][value["base"] + "/actions/runs/100/artifacts?per_page=100"]
        inventory["artifacts"].append(copy.deepcopy(inventory["artifacts"][0])); inventory["total_count"] = 3
        with self.assertRaises(ValueError):
            verify(value)
        for member in ("../retention24h-original.json", "retention24h-original.json"):
            value = fixture(); output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as packed:
                packed.writestr(member, "{}")
                if member == "retention24h-original.json":
                    packed.writestr("extra-private.json", "{}")
            raw = output.getvalue(); digest = hashlib.sha256(raw).hexdigest()
            value["urls"][value["base"] + "/actions/artifacts/1001/zip"] = raw
            value["report"]["retention24hProvenance"]["originalArtifact"]["archiveSha256"] = digest
            inventory = value["urls"][value["base"] + "/actions/runs/100/artifacts?per_page=100"]
            inventory["artifacts"][0].update(digest="sha256:" + digest, size_in_bytes=len(raw))
            with self.assertRaises(ValueError):
                verify(value)

    def test_native_and_controller_sources_cannot_be_relabelled_or_replaced(self):
        for change in ("native-source", "controller-source", "configuration", "handoff", "request", "private-provenance"):
            value = fixture(); report = value["report"]
            if change == "native-source":
                report["fixtureSources"] = [{"file": report["fixtureSource"]["file"], "sha256": "f" * 64}]
            elif change == "controller-source":
                report["retention24hProvenance"]["finalizerProvenance"]["controllerSources"][0]["sha256"] = "f" * 64
            elif change == "configuration":
                report["nativeRetention24h"]["configSha256"] = "f" * 64
            elif change == "handoff":
                report["nativeRetention24h"]["processId"] = 9999
            elif change == "request":
                report["nativeRetention24h"]["requestIds"] = ["19", "20"]
            else:
                report["retention24hProvenance"]["private"] = "forbidden"
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify(value)

    def test_owner_downloads_and_json_are_bounded_without_disk_extraction(self):
        with patch.object(auth, "MAX_AUTH_BYTES", 8), self.assertRaises(ValueError):
            verify(fixture())
        for raw in (b'{"id":1,"id":2}', b'{"elapsed":NaN}', b'{"elapsed":Infinity}'):
            with self.assertRaises(ValueError):
                auth.json_bytes(raw)

    def test_github_sealing_chronology_cannot_be_inverted(self):
        for index, when in ((0, "2026-10-14T02:00:00Z"), (0, "2026-10-14T00:00:00Z"), (1, "2026-10-14T00:00:00Z")):
            value = fixture()
            inventory = value["urls"][value["base"] + "/actions/runs/100/artifacts?per_page=100"]
            inventory["artifacts"][index]["created_at"] = when
            with self.subTest(index=index, when=when), self.assertRaises(ValueError):
                verify(value)


if __name__ == "__main__":
    unittest.main()
