# Exercise release collection trust, archive bounds and sanitized evidence retention offline.
# Synthetic API/artifact fixtures verify refusal paths; no workflow is dispatched and no
# native environment is qualified by these collector regression tests.
import importlib.util
import io
import json
import stat
import sys
from pathlib import Path
import unittest
import zipfile
import tempfile
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("collector", Path(__file__).with_name("certops-release-collector.py"))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class CollectorTests(unittest.TestCase):
    def test_second_rename_proof_retains_scope_and_refuses_incomplete_restoration(self):
        fields = ("childIdentityVerifiedBeforeActivation", "actualProductionFunctions", "nativeOrderedRestoreEvents", "originalDirectoryIdentityRestored", "heldStagingIdentityUnchanged", "explicitStagingCleanupFailure", "candidateNeverActivated", "predecessorFilesUnchanged", "sameRunningServicePid", "configurationAndCredentialUnchanged", "cngCustodyUnchanged", "bindingAndTrustedTlsUnchanged", "freshAuthenticatedHeartbeat", "nativeHandleReleased", "ownedStagingRemoved", "ownedChildDrained")
        proof = {**dict.fromkeys(fields, True), "scope": "production-activation-functions-not-installer-cli"}
        suite = "windows-activation-second-rename"
        result = collector.sanitized_report({"suite": suite, "nativeSecondRename": {**proof, "rawConfig": "sentinel", "rawNativeEvents": "sentinel"}}, {suite}, set())
        self.assertEqual(result["nativeSecondRename"], proof)
        self.assertNotIn("sentinel", json.dumps(result))
        for field in fields:
            with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite, "nativeSecondRename": {**proof, field: False}}, {suite}, set())
        for invalid in (None, {**proof, "scope": "complete-installer-rollback"}):
            with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite, "nativeSecondRename": invalid}, {suite}, set())

    def test_retention_atomic_proof_strips_native_paths_and_requires_all_facts(self):
        fields = ("nativeFileHandleHeld", "nativeFileIdentityMatched", "actualAtomicReplaceRefused", "priorRowBytesPreserved", "priorRowIdentityPreserved", "failedTemporaryFileRemoved", "nativeHandleReleased", "ownedChildDrained", "actualReplacementSucceeded", "freshProcessReadExactReplacement", "restrictivePermissionsVerified", "ownedTemporaryFixtureRemoved")
        proof = dict.fromkeys(fields, True)
        suite = "windows-host"
        custody_fields = ("exportableControlSucceeded", "controlBytesZeroed", "protectedBytesZeroed", "protectedExportDenied", "publicNonceSignatureVerified", "originalCustodyUnchanged", "controlKeyRemoved")
        custody = {"privateExportBytesWritten": False, "privateExportBytesReported": False, "workDirectoryUnchanged": True,
                   "cases": [{"caseId": profile + "/" + store, **dict.fromkeys(custody_fields, True), "privateExportHResult": -2146893813} for store in ("My", "WebHosting") for profile in ("rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384")]}
        result = collector.sanitized_report({"suite": suite, "cngCustody": custody, "nativeRetentionAtomicReplace": {**proof, "rawLedger": "sentinel", "nativePath": "sentinel"}}, {suite}, set())
        self.assertEqual(result["nativeRetentionAtomicReplace"], proof)
        self.assertNotIn("sentinel", json.dumps(result))
        for field in fields:
            with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite, "nativeRetentionAtomicReplace": {**proof, field: False}}, {suite}, set())
        with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite}, {suite}, set())
    def test_browser_retirement_retains_declared_sources_without_browser_private_state(self):
        suite = "browser-retirement-visibility"
        sources = [{"file": file, "sha256": "a" * 64} for file in (
            "scripts/certops-browser-retirement.js",
            "tests/e2e/helpers/certops-browser-retirement-fixture.js",
            "tests/e2e/helpers/certops-api-fixture.js")]
        report = {"suite": suite, "fixtureSource": sources[0], "fixtureSources": sources,
                  "cookies": [{"value": "sentinel"}], "screenshot": "sentinel", "tlsPrivateKey": "sentinel"}
        result = collector.sanitized_report(report, {suite}, set())
        self.assertEqual(result["fixtureSource"], sources[0])
        self.assertEqual(result["fixtureSources"], sources)
        self.assertNotIn("sentinel", json.dumps(result))

    def test_main_collects_more_than_old_run_and_report_limits_without_network(self):
        candidate = "a" * 40
        run_ids = list(range(1, 202))
        coverage = {"implementationStatus": "incomplete"}
        summary = {"schemaVersion": 1, "status": "passed", "candidateSha": candidate,
                   "mandatoryEnvironments": 201, "qualificationScope": "committed-mandatory-matrix",
                   "allFeaturesQualified": False, "catalogCoverage": coverage}
        calls = []
        def download(url, token=None, redirect=False):
            calls.append(url)
            if url.endswith("/zip"): return b"owned-fixture-archive"
            if "/artifacts?" in url:
                run_id = int(url.split("/runs/")[1].split("/")[0])
                return json.dumps({"total_count": 1, "artifacts": [{"id": run_id, "size_in_bytes": 21}]}).encode()
            return b"{}"
        with tempfile.TemporaryDirectory(prefix="certops-collector-budget-") as directory:
            root = Path(directory)
            (root / "docs/certops").mkdir(parents=True)
            (root / "docs/certops/release-qualification-matrix.json").write_text(json.dumps({"slots": [{"kind": "host", "suite": "fixture"}] * 201}))
            with patch.object(collector, "ROOT", root), patch.dict(collector.os.environ, {"CERTOPS_RELEASE_CANDIDATE": candidate, "CERTOPS_RELEASE_RUN_IDS": json.dumps(run_ids), "GITHUB_REPOSITORY": "owner/repo", "GITHUB_TOKEN": "offline-fixture"}), patch.object(collector, "download", side_effect=download), patch.object(collector, "validate_run"), patch.object(collector, "catalog_coverage", return_value=coverage), patch.object(collector, "extract_reports", return_value=[(".json", {"suite": "fixture"})]), patch.object(collector.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps(summary))) as verifier:
                output = io.StringIO()
                with redirect_stdout(output):
                    collector.main()
                self.assertEqual(output.getvalue().strip(), "Committed mandatory matrix passed; full feature specifications remain separately tracked")
                self.assertEqual(len(verifier.call_args.args[0][3:]), 201)
                result = json.loads((root / "qualification-results/release-collection/summary.json").read_text())
                self.assertEqual(result["collectedReports"], 201)
                self.assertEqual(result["status"], "passed")
                self.assertEqual(len([url for url in calls if url.endswith("/zip")]), 201)

    def test_collection_budgets_follow_committed_growth_with_absolute_caps(self):
        self.assertEqual(collector.collection_limits(1), {"runs": 100, "archives": 200, "reports": 200})
        for slots in (201, 256, 512):
            limits = collector.collection_limits(slots)
            for budget in limits.values():
                self.assertGreaterEqual(budget, slots * 2)
                self.assertLessEqual(budget, collector.MAX_COLLECTION_ITEMS)
            collector.validate_run_ids(list(range(1, slots + 1)), limits)
        for invalid in (0, -1, 513, 1024, True, 201.0, "201", None):
            with self.assertRaises(ValueError): collector.collection_limits(invalid)
        matrix = json.loads((collector.ROOT / "docs/certops/release-qualification-matrix.json").read_text())
        self.assertGreaterEqual(collector.collection_limits(len(matrix["slots"]))["reports"], len(matrix["slots"]))

    def test_growth_preserves_run_identity_and_independent_download_bounds(self):
        limits = collector.collection_limits(201)
        for invalid in ([], [1, 1], [True], [-1], [0], [1.0], ["1"], list(range(1, limits["runs"] + 2))):
            with self.assertRaises(ValueError): collector.validate_run_ids(invalid, limits)
        self.assertEqual(collector.MAX_ARCHIVE, 20 * 1024 * 1024)
        self.assertEqual(collector.MAX_REPORT, 2 * 1024 * 1024)
        self.assertEqual(collector.MAX_TOTAL_DOWNLOAD, 512 * 1024 * 1024)
        self.assertEqual(collector.MAX_ARTIFACTS_PER_RUN, 100)

    def test_windows_wrong_spki_only_retains_required_custody_booleans(self):
        fields = ("actualSignedRenewalFailed", "actualCsrDiffersFromReturnedLeaf", "genuineCaIssuedLeafReused", "rejectedUnacceptedKeyRemoved", "predecessorCustodyUnchanged", "bindingAndTrustedTlsUnchanged", "storedProfileUnchanged", "configurationRestored")
        proof = {**dict.fromkeys(fields, True), "rawCsr": "sentinel", "rawKeyReceipt": {"secret": "sentinel"}}
        suite = "windows-acme-wrong-spki"
        value = {"suite": suite, "nativeWrongSpki": proof}
        result = collector.sanitized_report(value, {suite}, set())
        self.assertNotIn("sentinel", json.dumps(result))
        self.assertEqual(result["nativeWrongSpki"], dict.fromkeys(fields, True))
        for field in fields:
            proof[field] = False
            with self.assertRaises(ValueError): collector.sanitized_report(value, {suite}, set())
            proof[field] = True

    def test_windows_public_admission_preserves_only_bounded_measured_facts(self):
        fields = ("anonymousAdmissionRefused", "viewerAdmissionRefused", "authorizedAdmissionCreated", "idempotentSameJob", "publicRequesterPreserved", "serverDerivedOsStoreKeyMode", "publicPayloadPreserved", "nativeJobSucceeded", "nativeCngIisTrustedTlsVerified", "ownedActorCleanup")
        facts = {**dict.fromkeys(fields, True), "anonymousStatus": 401, "viewerStatus": 403, "createStatus": 201, "replayStatus": 201, "source": "api", "mode": "real", "authorizedRole": "workspace_manager", "rawSession": {"password": "sentinel"}}
        scope = "real-agent-windows-acme-iis/rsa-2048"
        event = {"scope": scope, "name": "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence", "type": "test:pass", "windowsPublicIssuance": facts}
        output = collector.sanitized_report([event], set(), {scope})
        self.assertEqual(output[0]["windowsPublicIssuance"]["source"], "api")
        self.assertNotIn("sentinel", json.dumps(output))
        for field in fields:
            facts[field] = False
            with self.assertRaises(ValueError):
                collector.sanitized_report([event], set(), {scope})
            facts[field] = True
        facts["viewerStatus"] = {"secret": "sentinel"}
        with self.assertRaises(ValueError):
            collector.sanitized_report([event], set(), {scope})

    def test_generic_top_fields_cannot_carry_nested_private_metadata(self):
        keys = ("status", "strict", "schemaVersion", "startedAt", "finishedAt", "evidenceLevel", "artifactQualification", "qualificationStatus", "experimental", "candidateSha")
        for key in keys:
            with self.assertRaises(ValueError):
                collector.sanitized_report({"suite": "job-decisions-api", key: {"secret": "sentinel"}}, {"job-decisions-api"}, set())
        for shape in ({"suite": "job-decisions-api"}, {"scope": "fixture-database"}, [{"scope": "fixture-stack", "name": "unknown", "type": "test:fail"}]):
            report = shape[0] if isinstance(shape, list) else shape
            report.update({"candidateSha": "sentinel", "artifactQualification": "sentinel", "experimental": False})
            output = collector.sanitized_report(shape, {"job-decisions-api"}, {"fixture-stack"}, {"fixture-database"})
            self.assertNotIn("sentinel", json.dumps(output))
        output = collector.sanitized_report({"suite": "job-decisions-api", "status": "failed", "strict": False, "schemaVersion": 1, "candidateSha": None, "startedAt": "2026-02-30T12:00:00Z"}, {"job-decisions-api"}, set())
        self.assertEqual(output["status"], "failed")
        self.assertIs(output["strict"], False)
        self.assertIsNone(output["candidateSha"])
        self.assertEqual(output["startedAt"], "invalid")

    def test_event_names_project_committed_cases_and_keep_unrecognized_failures(self):
        scope = "agent-protocol-api-worker"
        manifest = json.loads((collector.ROOT / "tests/e2e/agent-protocol-required-tests.json").read_text())
        events = [{"scope": scope, "name": manifest["requiredTests"][0], "type": "test:pass"},
                  {"scope": scope, "name": "password=sentinel", "type": "test:fail"},
                  {"scope": scope, "name": {"secret": "sentinel"}, "type": "test:pass"}]
        result = collector.sanitized_report(events, set(), {scope})
        self.assertEqual(result[0]["name"], events[0]["name"])
        self.assertEqual(result[1]["type"], "test:fail")
        self.assertEqual(result[2]["type"], "invalid")
        self.assertEqual(len(result), 3)
        self.assertNotIn("sentinel", json.dumps(result))
        parent = collector.sanitized_report([{"scope": scope, "name": "CertOps agent surface E2E", "type": "test:pass"}], set(), {scope})
        self.assertEqual(parent[0]["type"], "test:pass")
        group = json.loads((collector.ROOT / "tests/integration/certops-qualification-groups.json").read_text())["adcs"]
        case = group["requiredTests"][0]
        report = {"scope": "adcs-database-integration", "tests": [
            {**case, "status": "pass"},
            {"file": "private/sentinel", "name": "sentinel", "status": "fail"},
            {"file": case["file"], "name": "sentinel", "status": "pass"}]}
        result = collector.sanitized_report(report, set(), set(), {report["scope"]})
        self.assertEqual(result["tests"][0], {**case, "status": "pass"})
        self.assertEqual([row["status"] for row in result["tests"]], ["pass", "fail", "invalid"])
        self.assertNotIn("sentinel", json.dumps(result))

    def test_source_upgrade_cannot_claim_published_archive_or_drop_preservation(self):
        fields = ("werPolicyPreserved", "schedulerHistoryPreserved", "distinctVersionObserved", "configurationPreserved", "credentialPreserved", "signingKeyPinPreserved", "sameAgentIdentity", "authenticatedCandidateHeartbeat", "candidateHelperActivated", "nonExportableCngKeyPreserved", "iisBindingPreserved", "trustedTlsPreserved", "serviceIdentityPreserved", "ownedFixtureRemoved")
        facts = {**dict.fromkeys(fields, True), "provenance": "historical-source-build", "publishedArchiveUsedForInstallation": False,
                 "historicalCommit": "a" * 40, "historicalArchiveSha256": "a" * 64, "historicalVersion": "0.17.2", "candidateVersion": "0.17.3",
                 "historicalHelpers": {"amd64": "a" * 64, "arm64": "b" * 64, "secret": "sentinel"}, "rawCredential": "sentinel"}
        suite = "windows-historical-source-upgrade"
        value = {"suite": suite, "sourceUpgrade": facts, "cleanup": {"status": "passed", "rawError": "sentinel"}}
        self.assertNotIn("sentinel", json.dumps(collector.sanitized_report(value, {suite}, set())))
        for field in fields:
            facts[field] = False
            with self.assertRaises(ValueError):
                collector.sanitized_report(value, {suite}, set())
            facts[field] = True
        facts["publishedArchiveUsedForInstallation"] = True
        with self.assertRaises(ValueError):
            collector.sanitized_report(value, {suite}, set())

    def test_common_metadata_is_projected_for_every_report_kind(self):
        source = {"file": "tests/e2e/certops-job-decisions-e2e.test.js", "sha256": "a" * 64, "rawSecret": "sentinel"}
        environment = {"osFamily": "linux", "measurement": "native", "credential": {"password": "sentinel"}}
        variants = [
            {"suite": "job-decisions-api", "fixtureSource": source, "qualificationEnvironment": environment},
            [{"scope": "fixture-scope", "fixtureSource": source, "qualificationEnvironment": environment}],
            {"scope": "fixture-database", "fixtureSources": [source], "qualificationEnvironment": environment},
        ]
        for value in variants:
            result = collector.sanitized_report(value, {"job-decisions-api"}, {"fixture-scope"}, {"fixture-database"})
            self.assertNotIn("sentinel", json.dumps(result))
            item = result[0] if isinstance(result, list) else result
            self.assertEqual(item["qualificationEnvironment"], {"osFamily": "linux", "measurement": "native"})
        for invalid in (["linux"], {"osFamily": ["linux"]}, {"keySize": True}, {"build": "password=sentinel"}):
            with self.assertRaises(ValueError):
                collector.sanitized_report({"suite": "job-decisions-api", "qualificationEnvironment": invalid}, {"job-decisions-api"}, set())
        with self.assertRaises(ValueError):
            collector.sanitized_report({"suite": "job-decisions-api", "fixtureSource": {**source, "sha256": []}}, {"job-decisions-api"}, set())

    def test_cng_custody_has_ten_bounded_profiles_and_no_exported_bytes(self):
        suite = "windows-host"
        atomic = dict.fromkeys(("nativeFileHandleHeld", "nativeFileIdentityMatched", "actualAtomicReplaceRefused", "priorRowBytesPreserved", "priorRowIdentityPreserved", "failedTemporaryFileRemoved", "nativeHandleReleased", "ownedChildDrained", "actualReplacementSucceeded", "freshProcessReadExactReplacement", "restrictivePermissionsVerified", "ownedTemporaryFixtureRemoved"), True)
        fields = ("exportableControlSucceeded", "controlBytesZeroed", "protectedBytesZeroed", "protectedExportDenied", "publicNonceSignatureVerified", "originalCustodyUnchanged", "controlKeyRemoved")
        cases = [{"caseId": profile + "/" + store, **dict.fromkeys(fields, True), "privateExportHResult": -2146893813, "rawPrivateBlob": "sentinel"} for store in ("My", "WebHosting") for profile in ("rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384")]
        custody = {"privateExportBytesWritten": False, "privateExportBytesReported": False, "workDirectoryUnchanged": True, "cases": cases, "signature": "sentinel"}
        sni = {"siteCount": 2, "hostnameCount": 2, "certificateStore": "My", **dict.fromkeys(("twoSitesSamePort", "distinctHostnameSelectors", "primaryCutoverPeerUnchanged", "primaryRollbackPeerUnchanged", "peerCutoverPrimaryUnchanged", "peerRollbackPrimaryUnchanged", "sameCertificateReplayVerified", "independentAuthenticatedTls", "ownedCleanupVerified"), True), "privateConfig": "sentinel"}
        result = collector.sanitized_report({"suite": suite, "nativeRetentionAtomicReplace": atomic, "cngCustody": custody, "nativeSamePortSni": sni}, {suite}, set())
        self.assertEqual(result["nativeSamePortSni"]["siteCount"], 2)
        self.assertTrue(result["nativeSamePortSni"]["peerRollbackPrimaryUnchanged"])
        for change in ({"siteCount": True}, {"hostnameCount": 1}, {"certificateStore": "Other"}):
            with self.assertRaises(ValueError):
                collector.sanitized_report({"suite": suite, "cngCustody": custody, "nativeSamePortSni": {**sni, **change}}, {suite}, set())
        missing = collector.sanitized_report({"suite": suite, "nativeRetentionAtomicReplace": atomic, "cngCustody": custody, "nativeSamePortSni": {**sni, "ownedCleanupVerified": False}}, {suite}, set())
        self.assertFalse(missing["nativeSamePortSni"]["ownedCleanupVerified"])
        contention = {**dict.fromkeys(("winnerGeneratedRealCsr", "loserLockedBeforeNativeExecution", "retryAcquiredEnrollmentLock", "retryExistingContainerRefused", "sameCsrAndSpki", "sameNonExportableKey", "winnerSignatureVerified", "ownedChildrenStopped", "ownedKeyRemoved"), True), "loserNativeCalls": 0, "loserCertreqCalls": 0, "retryCertreqCalls": 0, "winnerCertreqCalls": 1, "retryNativeCalls": 1, "privateRaw": "sentinel"}
        projected = collector.sanitized_report({"suite": suite, "nativeRetentionAtomicReplace": atomic, "cngCustody": custody, "nativeEnrollmentContention": contention}, {suite}, set())
        self.assertEqual(projected["nativeEnrollmentContention"]["loserNativeCalls"], 0)
        self.assertNotIn("sentinel", json.dumps(projected))
        for bad in (True, "0", -1, 33):
            with self.assertRaises(ValueError):
                collector.sanitized_report({"suite": suite, "cngCustody": custody, "nativeEnrollmentContention": {**contention, "loserNativeCalls": bad}}, {suite}, set())
        self.assertEqual(len(result["cngCustody"]["cases"]), 10)
        self.assertNotIn("sentinel", json.dumps(result))
        for field in ("privateExportBytesWritten", "privateExportBytesReported"):
            with self.assertRaises(ValueError):
                collector.sanitized_report({"suite": suite, "cngCustody": {**custody, field: True}}, {suite}, set())
        for change in ({"caseId": "foreign/My"}, {"privateExportHResult": 0}, {"privateExportHResult": "denied"}):
            with self.assertRaises(ValueError):
                collector.sanitized_report({"suite": suite, "cngCustody": {**custody, "cases": [{**cases[0], **change}, *cases[1:]]}}, {suite}, set())

    def test_published_linux_archive_provenance_is_exact_and_private_state_excluded(self):
        suite = "linux-systemd-published-upgrade"
        facts = {"baselineVersion": "0.17.2", "publishedAssetId": 612562598, "publishedArchiveSize": 410054,
                 "publishedArchiveSha256": "c602fe36825c74d423c2c9b89680df3b1ac76542f71804de14dc5e2ec5aa85bf",
                 "candidateVersion": "0.17.3", "candidateArchiveSha256": "a" * 64,
                 "beforePid": 100, "afterPid": 101, "rollbackClaimed": False,
                 "rawCredential": "sentinel", "rawConfig": {"private": "sentinel"}}
        result = collector.sanitized_report({"suite": suite, "nativePublishedLinuxUpgrade": facts}, {suite}, set())
        self.assertEqual(result["nativePublishedLinuxUpgrade"]["publishedAssetId"], 612562598)
        self.assertNotIn("sentinel", json.dumps(result))
        for field, replacement in (("publishedAssetId", 1), ("publishedArchiveSha256", "a" * 64), ("candidateArchiveSha256", "bad"), ("beforePid", "100"), ("rollbackClaimed", True)):
            with self.assertRaises(ValueError):
                collector.sanitized_report({"suite": suite, "nativePublishedLinuxUpgrade": {**facts, field: replacement}}, {suite}, set())

    def test_native_reapplication_and_worker_maintenance_are_bounded(self):
        suite = "linux-systemd-reapply"
        value = {"suite": suite, "nativeInstallerReapply": {
            "installation": "same-candidate-reapplication", "beforePid": 100,
            "reappliedPid": 101, "freshRestartPid": 102, "nativeUid": 1001,
            "credentialBytesPreserved": True, "rawCredential": "sentinel"}}
        result = collector.sanitized_report(value, {suite}, set())
        self.assertEqual(result["nativeInstallerReapply"]["nativeUid"], 1001)
        self.assertNotIn("sentinel", json.dumps(result))
        value["nativeInstallerReapply"]["nativeUid"] = "1001"
        with self.assertRaises(ValueError):
            collector.sanitized_report(value, {suite}, set())
        suite = "agent-log-maintenance-worker"
        facts = {"scope": "actual-default-five-minute-grace-and-supported-retention-zero",
                 "timestampsRewritten": False, "defaultGraceMs": 300000,
                 "observedMonotonicMs": 300100, "abandonedStreams": 1,
                 "purgedLines": 2, "repeatedPurgeDeleted": 0, "retentionDays": 0,
                 "rawLine": "sentinel"}
        value = {"suite": suite, "maintenance": facts}
        result = collector.sanitized_report(value, {suite}, set())
        self.assertEqual(result["maintenance"]["observedMonotonicMs"], 300100)
        self.assertNotIn("sentinel", json.dumps(result))
        facts["timestampsRewritten"] = True
        with self.assertRaises(ValueError):
            collector.sanitized_report(value, {suite}, set())

    def test_windows_privacy_preserves_only_bounded_proof(self):
        suite = "windows-native-child-output-privacy"
        value = {"suite": suite, "actualNativeIdentity": "LocalSystem",
                 "childOutputPolicy": "captured-and-withheld-not-live-forwarded",
                 "nativeCertificateOutcome": "parent-independent-CNG-IIS-trusted-TLS",
                 "actualStdoutAndStderrEmission": True, "actualDelegatedSuccess": True,
                 "actualAcmeSuccessLogObserved": True, "actualHttpUploadsSecretFree": True,
                 "persistedLogsEvidenceResultsSecretFree": True, "scmConsoleSecretFree": True,
                 "receiptCount": 2, "jobLogCount": 3, "evidenceCount": 4,
                 "httpUploadCount": 5, "rawOutput": "sentinel"}
        result = collector.sanitized_report(value, {suite}, set())
        self.assertEqual(result["receiptCount"], 2)
        self.assertTrue(result["actualHttpUploadsSecretFree"])
        self.assertNotIn("sentinel", json.dumps(result))
        for count in (33, "2", True):
            value["receiptCount"] = count
            with self.assertRaises(ValueError):
                collector.sanitized_report(value, {suite}, set())

    def test_elapsed_pending_preserves_only_bounded_native_facts(self):
        facts = {"pendingTimeoutSeconds": 3600, "pollIntervalSeconds": 60,
                 "monotonicWaitSeconds": 3601, "databaseElapsedSeconds": 3602,
                 "pendingSince": "2026-10-14T12:00:00.000Z", "requestId": "17",
                 "snapshotSha256": "a" * 64, "clocks": "actual-host-and-database",
                 "schedulerClock": "default-real-now", "databaseDatesRewritten": False,
                 "journalRewritten": False,
                 "qualificationScope": "configured-one-hour-not-default-fourteen-days",
                 "private": "sentinel"}
        value = {"suite": "enterprise-adcs-elapsed-pending-real", "nativePendingElapsed": facts}
        result = collector.sanitized_report(value, {value["suite"]}, set())
        self.assertEqual(result["nativePendingElapsed"]["monotonicWaitSeconds"], 3601)
        self.assertNotIn("sentinel", json.dumps(result))
        facts["journalRewritten"] = True
        with self.assertRaises(ValueError):
            collector.sanitized_report(value, {value["suite"]}, set())
        facts["journalRewritten"] = False
        facts["monotonicWaitSeconds"] = "3601"
        with self.assertRaises(ValueError):
            collector.sanitized_report(value, {value["suite"]}, set())

    def test_native_compaction_evidence_keeps_only_bounded_public_facts(self):
        evidence = {"expiredStatus": 410, "originalResourceVersion": "10", "compactedRevision": "20", "observedResourceVersion": "21", "certificateUid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "productionClient": True, "productionObserver": True, "controlPlaneRestarted": True, "ownedSingleNodeCluster": True, "private": "sentinel"}
        value = {"suite": "kubernetes-host", "nativeCompaction": evidence}
        result = collector.extract_reports(self.archive("kube.json", value), {"kubernetes-host"}, set())
        self.assertEqual(result[0][1]["nativeCompaction"]["expiredStatus"], 410)
        self.assertNotIn("sentinel", json.dumps(result))
        evidence["certificateUid"] = "-" * 36
        with self.assertRaises(ValueError):
            collector.extract_reports(self.archive("kube.json", value), {"kubernetes-host"}, set())
        evidence["certificateUid"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        evidence["compactedRevision"] = "sentinel"
        with self.assertRaises(ValueError):
            collector.extract_reports(self.archive("kube.json", value), {"kubernetes-host"}, set())

    def test_native_console_evidence_cannot_copy_raw_lines(self):
        row = {"scenario": "native-agent-log-transient-retry", "actualNativeConsole": True, "jobSucceeded": True, "attempts": 1, "persistedLines": 3, "agentGapLines": 0, "serverDroppedLines": 0, "finalAcknowledged": True, "lines": ["sentinel"]}
        value = {"suite": "native-agent-api", "nativeLogFaults": [row], "nativeChildOutputPrivacy": {"executedChildren": 2, "stdoutEmitted": True, "stderrEmitted": True, "rawChildOutputWithheld": True, "genericExecutionMarkerPersisted": True, "jobSucceeded": True, "private": "sentinel"}}
        value["nativeDispatchTiming"] = {"fixtureLifetimeSeconds": 2, "localToleranceMs": 1, "heldMonotonicMs": 5001, "originalDispatchLifetimeSeconds": 3600, "issuedAt": "2026-10-14T12:00:00.000Z", "expiresAt": "2026-10-14T12:00:02.000Z", "releasedAt": "2026-10-14T12:00:05.001Z", "clocks": "actual-host-monotonic-and-database", "fixture": "production-signer-short-lifetime-and-delayed-HTTP-delivery", "databaseDatesRewritten": False, "journalRewritten": False, "nativeClockRefusalObserved": True, "executionSuccessAbsent": True, "nonceUnconsumed": True, "freshClaimRecoverySucceeded": True, "credentialAndPinUnchanged": True, "leaseCallsBeforeRefusal": 0, "expiredNonceResultStatus": 409, "expiredNonceResultCode": "CERTOPS_AGENT_RESULT_NONCE_REJECTED", "actualServerJobState": "claimed", "actualRejectedOutbox": "dead-letter", "qualificationScope": "native-Linux-shortened-dispatch-fixture-not-stock-TTL-or-Windows-SCM", "private": "sentinel"}
        result = collector.extract_reports(self.archive("native.json", value), {"native-agent-api"}, set())
        self.assertEqual(result[0][1]["nativeLogFaults"][0]["persistedLines"], 3)
        self.assertNotIn("sentinel", json.dumps(result))

    def test_uncommitted_execution_names_and_values_are_never_artifacts(self):
        sentinel = "private-sentinel"
        value = {"suite": "job-decisions-api", "requiredScenarios": [sentinel], "missingScenarios": [sentinel], "requiredCapabilities": [sentinel], "capabilities": {sentinel: {"available": {"private": sentinel}}}, "scenarios": [{"id": sentinel, "status": sentinel, "evidenceLevel": sentinel, "startedAt": sentinel}]}
        result = collector.extract_reports(self.archive("failed.json", value), {"job-decisions-api"}, set())
        self.assertNotIn(sentinel, json.dumps(result))
        self.assertEqual(result[0][1]["scenarios"][0]["id"], "[unrecognized]")

    def test_native_cohort_budgets_are_bounded_without_private_fields(self):
        cohort = {"workspaceId": "a" * 36, "agentId": "b" * 36, "dispatchCount": 18, "dispatchLimit": 18, "nativeIdentity": "LocalSystem", "runtime": "candidate-cli", "privateState": "sentinel"}
        value = {"suite": "enterprise-adcs-real", "primaryNativePreflightDispatchCount": 18, "nativePreflightCohorts": [cohort], "nativeTemplateMutations": [], "nativeValidationExpiry": {"configuredTimeoutSeconds": 300, "defaultTimeoutSeconds": 86400, "storedWindowSeconds": 299, "monotonicObservedWaitSeconds": 301, "actualDeadline": "2026-10-14T12:00:00.000Z", "requestId": "17", "snapshotSha256": "a" * 64, "nativeAndCaClocks": "actual", "qualificationScope": "configured-five-minute-window-not-default-24-hour-elapsed"}}
        value["nativeIssuedCancellation"] = {"requestId": "17", "snapshotSha256": "a" * 64, "pollIntervalSeconds": 900, "schedulerClock": "default-real-now", "databaseDatesRewritten": False, "journalRewritten": False, "private": "sentinel"}
        result = collector.extract_reports(self.archive("adcs.json", value), {"enterprise-adcs-real"}, set())
        self.assertEqual(result[0][1]["nativePreflightCohorts"][0]["dispatchCount"], 18)
        self.assertNotIn("sentinel", json.dumps(result))
        cohort["dispatchCount"] = 19
        with self.assertRaises(ValueError):
            collector.extract_reports(self.archive("adcs.json", value), {"enterprise-adcs-real"}, set())

    def test_dns_cases_keep_only_committed_names_and_fixed_statuses(self):
        inventory = json.loads((collector.ROOT / "docs/certops/dns-provider-errors.json").read_text())
        provider = inventory["providers"][0]
        row = {"file": provider["file"], "name": provider["requiredTests"][0], "status": "secret-sentinel", "body": "secret-sentinel"}
        value = {"suite": "dns-provider-errors", "dnsAdapterCases": [row, {"file": "private", "name": "secret-sentinel"}]}
        result = collector.extract_reports(self.archive("dns.json", value), {"dns-provider-errors"}, set())
        self.assertEqual(result[0][1]["dnsAdapterCases"], [{"file": row["file"], "name": row["name"], "status": "invalid"}])
        self.assertNotIn("secret-sentinel", json.dumps(result))

    def test_supporting_sources_are_bounded_to_committed_public_files(self):
        file = "tests/e2e/helpers/certops-windows-reregistration.js"
        value = [{"file": file, "sha256": "a" * 64, "privateConfig": "sentinel"}, {"file": "private/sentinel.json", "sha256": "b" * 64}]
        self.assertEqual(collector.supporting_sources(value), [{"file": file, "sha256": "a" * 64}])
        with self.assertRaises(ValueError):
            collector.supporting_sources([{"file": file, "sha256": "private-value"}])
        with self.assertRaises(ValueError):
            collector.supporting_sources(value * 17)

    def migration(self):
        return {
            "suite": "core-api-migration-upgrade",
            "sourceProvenance": "historical-source-build-to-candidate-source",
            "sourceIdentity": {kind: {"sha": letter * 40, "version": "0.17.3", "lockfileSha256": letter * 64, "privateConfig": "sentinel"} for kind, letter in (("baseline", "a"), ("candidate", "b"))},
            "databaseRuntime": {"imageId": "sha256:" + "c" * 64, "serverVersion": "16.6", "password": "sentinel"},
            "baselineSchema": {"tables": 5, "columns": 30, "migrations": [{"version": 1, "name": "core_schema", "secret": "sentinel"}]},
            "candidateSchema": {"tables": 6, "columns": 35, "migrations": [{"version": 1, "name": "core_schema"}, {"version": 2, "name": "new_schema"}]},
            "actualTlsObservedPromotion": True, "repeatMigrationSchemaUnchanged": True,
        }

    def test_migration_public_identity_and_schema_survive_collection(self):
        value = self.migration()
        result = collector.sanitized_report(value, {value["suite"]}, set())
        self.assertEqual(result["sourceIdentity"]["candidate"]["sha"], "b" * 40)
        self.assertEqual(result["candidateSchema"]["migrations"][1]["name"], "new_schema")
        self.assertNotIn("sentinel", json.dumps(result))

    def test_migration_identity_and_schema_are_bounded(self):
        for field, replacement in (("sourceProvenance", "untrusted"), ("databaseRuntime", {"imageId": "private-value", "serverVersion": "16.6"}), ("candidateSchema", {"tables": 1, "columns": 2, "migrations": [{"version": 1, "name": "secret\nvalue"}]})):
            value = self.migration(); value[field] = replacement
            with self.assertRaises(ValueError):
                collector.sanitized_report(value, {value["suite"]}, set())

    def test_matrix_success_cannot_declare_all_features_qualified(self):
        coverage = {"total": 2, "planned": 1, "partial": 1, "implemented": 0, "implementationStatus": "incomplete", "executionEvidence": "reported-separately"}
        value = {"schemaVersion": 1, "status": "passed", "candidateSha": "a" * 40, "mandatoryEnvironments": 1, "qualificationScope": "committed-mandatory-matrix", "allFeaturesQualified": False, "catalogCoverage": coverage}
        collector.validate_matrix_summary(value, "a" * 40, 1, coverage)
        for changes in ({"allFeaturesQualified": True}, {"qualificationScope": "all-features"}, {"catalogCoverage": {**coverage, "implementationStatus": "all-specifications-implemented"}}, {"candidateSha": "b" * 40}):
            with self.assertRaises(ValueError):
                collector.validate_matrix_summary({**value, **changes}, "a" * 40, 1, coverage)

    def archive(self, name, value):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr(name, json.dumps(value))
        return output.getvalue()

    def test_trusted_run_identity(self):
        run = {"status": "completed", "conclusion": "success", "head_sha": "a" * 40, "head_branch": "main", "repository": {"full_name": "owner/repo"}, "head_repository": {"full_name": "owner/repo"}, "path": ".github/workflows/certops-qualification.yml", "event": "workflow_dispatch"}
        collector.validate_run(run, "a" * 40, "owner/repo")
        for field, value in (("head_sha", "b" * 40), ("head_branch", "other"), ("conclusion", "failure"), ("path", ".github/workflows/ci.yml"), ("event", "pull_request")):
            with self.assertRaises(ValueError):
                collector.validate_run({**run, field: value}, "a" * 40, "owner/repo")

    def test_archive_cannot_escape_output_or_use_drive_path(self):
        for name in ("../report.json", "/report.json", "C:/report.json", "folder/../../report.json", "folder\\..\\..\\report.json"):
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive(name, {}), {"fixture"}, set())

    def test_only_report_evidence_is_retained_without_probe_secrets(self):
        value = {"suite": "fixture", "status": "failed", "capabilities": {"api": {"available": True, "evidence": "password=secret"}}, "scenarios": [], "privateDebug": "never-copy"}
        reports = collector.extract_reports(self.archive("nested/report.json", value), {"fixture"}, set())
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0][1]["status"], "failed")
        self.assertNotIn("secret", json.dumps(reports))
        self.assertNotIn("never-copy", json.dumps(reports))
        self.assertEqual(collector.extract_reports(self.archive("other.json", {"suite": "unknown"}), {"fixture"}, set()), [])

    def test_first_rename_refusal_projection_requires_fault_and_preservation(self):
        suite = "windows-installer-first-rename-refusal"
        fields = ("nativeDirectoryHandleHeld", "nativeHandleIdentityMatched", "actualFirstRenameRefused", "stagingRemoved", "previousDirectoryAbsent", "installedFilesUnchanged", "configurationAndCredentialUnchanged", "sameRunningServicePid", "freshAuthenticatedHeartbeat", "trustedTlsUnchanged", "nativeHandleReleased", "ownedChildDrained")
        facts = dict.fromkeys(fields, True)
        result = collector.sanitized_report({"suite": suite, "nativeRenameRefusal": {**facts, "private": {"secret": "never-copy"}}}, {suite}, set())
        self.assertEqual(result["nativeRenameRefusal"], facts)
        self.assertNotIn("never-copy", json.dumps(result))
        for field in fields:
            for replacement in (False, {"secret": "never-copy"}):
                with self.assertRaises(ValueError):
                    collector.sanitized_report({"suite": suite, "nativeRenameRefusal": {**facts, field: replacement}}, {suite}, set())
        with self.assertRaises(ValueError):
            collector.sanitized_report({"suite": suite}, {suite}, set())

    def test_download_limits(self):
        with self.assertRaises(ValueError):
            collector.extract_reports(b"x" * (collector.MAX_ARCHIVE + 1), set(), set())
        with self.assertRaises(ValueError):
            collector.extract_reports(self.archive("oversized.json", "x" * collector.MAX_REPORT), set(), set())

    def test_symlinks_and_malformed_json_fail_closed(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            entry = zipfile.ZipInfo("linked.json")
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, "../../outside")
        with self.assertRaises(ValueError):
            collector.extract_reports(output.getvalue(), set(), set())
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("failed.json", "{malformed")
        with self.assertRaises(ValueError):
            collector.extract_reports(output.getvalue(), set(), set())

    def test_database_report_keeps_failure_status_and_source_identity_without_error_payloads(self):
        report = {"scope": "adcs-database-integration", "evidenceLevel": "integration", "fixtureSources": [{"file": "tests/integration/certops-adcs-enrollments.test.js", "sha256": "a" * 64}], "tests": [{"file": "fixture.js", "name": "fixture", "status": "fail", "error": "password=never-copy"}]}
        result = collector.extract_reports(self.archive("adcs.json", report), set(), set(), {"adcs-database-integration"})
        self.assertEqual(result[0][1]["tests"][0]["status"], "fail")
        self.assertEqual(result[0][1]["fixtureSources"], report["fixtureSources"])
        self.assertNotIn("never-copy", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
