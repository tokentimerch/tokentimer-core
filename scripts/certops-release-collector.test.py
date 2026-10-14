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

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("collector", Path(__file__).with_name("certops-release-collector.py"))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class CollectorTests(unittest.TestCase):
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
        value = {"suite": "native-agent-api", "nativeLogFaults": [row]}
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
        report = {"scope": "adcs-database-integration", "evidenceLevel": "integration", "fixtureSources": [{"file": "tests/integration/fixture.js", "sha256": "a" * 64}], "tests": [{"file": "fixture.js", "name": "fixture", "status": "fail", "error": "password=never-copy"}]}
        result = collector.extract_reports(self.archive("adcs.json", report), set(), set(), {"adcs-database-integration"})
        self.assertEqual(result[0][1]["tests"][0]["status"], "fail")
        self.assertEqual(result[0][1]["fixtureSources"], report["fixtureSources"])
        self.assertNotIn("never-copy", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
