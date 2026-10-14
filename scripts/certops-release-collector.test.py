# Exercise release collection trust, archive bounds and sanitized evidence retention offline.
# Synthetic API/artifact fixtures verify refusal paths; no workflow is dispatched and no
# native environment is qualified by these collector regression tests.
import importlib.util
import hashlib
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


def retention_reference_proof():
    fields = ("twoOpenReferencesPersistedAcrossProcess", "bothOpenNativeSweepPreservedCustody", "oneClosedStillProtected", "unknownReferenceDoesNotCloseOwnedReferences", "allClosedStillDeferredByRealDeadline", "nativeCustodyAndTrustedTlsUnchanged")
    return {**dict.fromkeys(fields, True), "scope": "native-collector-supporting-ledger-reference-lifecycle", "elapsed24HourQualified": False}


def state_read_proof():
    fields = ("threeReadablePositiveControls", "threeActualNativeReadDenials", "productionReadersRefused", "exactFileIdentityAndBytesPreserved", "exactAclRestored", "allReadersRecovered", "ownedTemporaryStateRemoved")
    return {**dict.fromkeys(fields, True), "scope": "native-temporary-state-read-denials-production-readers", "installedServiceStartupQualified": False}


def survivor_proof():
    return dict.fromkeys(("differentCertificateCrossStoreProtected", "sameCertificateCrossStoreProtected", "originalKeyPreserved", "replacementTrustedTlsPreserved", "ownedCrossStoreCopiesRemoved"), True)


def key_usage_proof():
    profiles = {"rsa-2048": 160, "rsa-3072": 160, "rsa-4096": 160, "ec-p256": 128, "ec-p384": 128}
    return {"scope": "native-copied-csr-x509-usage-and-cng-signing-permission", "copiedActualCsrExtensions": True, "privateKeyUsageClaim": "signing-permitted-not-exact-default-ncrypt-mask",
            "cases": [{"caseId": f"{profile}/{store}", "certificateUsageFlags": usage, "cngAllowedOperations": 0x00ffffff} for store in ("My", "WebHosting") for profile, usage in profiles.items()]}


def installed_handoff_proof():
    flags = ("retiredPredecessorCredentialFenced", "publicConflictBootstrapUnconsumed", "unusedConflictBootstrapRevoked", "publicReplacementBootstrapConsumed", "unmodifiedCliRegisteredReplacement", "registrationChildDrained", "sameInstalledServicePathAndSystemIdentity", "freshReplacementScmHeartbeat", "sourceStateBytesPreserved", "protectedCustodyAndJournalCopiesPreserved", "signingPinPreserved", "nativeCngBindingAndTrustedTlsPreserved", "predecessorJobsNotReplayed", "noBootstrapInServiceRegistry", "replacementRetiredAndServiceStopped", "originalRegistryRestored", "ownedStateRemoved")
    return {"scope": "explicit-operator-protected-state-installed-scm-handoff-not-automatic-reregistration", **dict.fromkeys(flags, True)}


def foreign_spki_proof():
    flags = ("sameRequesterNativeRetrieveSucceeded", "nativeCaIdentityMatched", "differentEnrollmentSpkiProved", "explicitCandidateRefused", "boundedSearchUnresolved", "originalJournalWatermarkPreserved", "originalNativeCustodyAndTlsPreserved", "noAdditionalCaRequest")
    return {"scope": "read-only-native-foreign-spki-candidate-not-public-uncertain-recovery", **dict.fromkeys(flags, True), "requestIds": ["17", "18"], "spkiFingerprints": ["a" * 64, "b" * 64]}


def local_pairs_proof():
    fields = ("actualSignedJobRefused", "claimBoundOutcome", "noCaRequestAllocated", "noKeyGenerated", "noAcceptedLeafOrJournal", "originalNativeCustodyPreserved", "outgoingTrustedTlsPreserved", "configurationAndCredentialRestored")
    return [{"caseId": case, **dict.fromkeys(fields, True)} for case in ("ca-host-mismatch", "ca-authority-mismatch", "template-pair-mismatch")]


def browser_adcs_proof():
    flags = ("browserIssuerCreation", "nativeSafePreflight", "browserCaConfirmation", "postConfirmationNativePreflight", "browserProfileCreation", "browserProfileAttachment", "actualDueSelection", "defaultSweepCreatedEnrollment", "automaticSourceAndRealMode", "claimBoundEvidence", "installedEnrollment", "freshLeafAndSpki", "nativeCaRequestMatched", "nonexportableMachineCng", "nativeIisSniMatched", "independentTrustedTls", "browserInstalledStateVisible", "noSyntheticResponses", "noDateOrJournalOverrides", "ownedEnrollmentRegistered", "browserAndTrustCleaned", "otherProfilePoliciesRestored")
    def uuid(value):
        return f"{value * 8}-{value * 4}-4{value * 3}-8{value * 3}-{value * 12}"
    return {**dict.fromkeys(flags, True), "scope": "browser-issuer-profile-default-scheduler-native-adcs", "lifecycle": "renew-existing-inventory-not-first-issue-or-manual-job", "scheduler": "production-default-sweep-not-background-worker-loop", "browserEngine": "chromium", "browserMutationCount": 6, "successfulEnrollments": 1,
            "fingerprints": ["a" * 64, "b" * 64], "spkiFingerprints": ["c" * 64, "d" * 64], "requestId": "17", "enrollmentId": uuid("a"), "jobId": uuid("b"), "profileId": uuid("c"), "issuerId": uuid("d")}


def certificate_dry_run_proof():
    flags = ("deployDryRunComplete", "renewDryRunComplete", "authenticPlanEvidence", "deployedFilesUnchangedDuringDryRun", "custodyFilesUnchangedDuringDryRun", "servedLeafUnchangedDuringDryRun", "noCommandsOrGatewayCallsDuringDryRun", "realDeployChangedFileAndTrustedTls", "realValidateAndReloadObserved", "realRenewCommandReachedCaAndDnsSentinels", "renewControlFailedBeforeIssuance", "identityAndConfigRestored", "ownedResourcesCleaned")
    return {**dict.fromkeys(flags, True), "scope": "native-linux-signed-certificate-dry-run-with-local-command-controls", "admission": "production-service-explicit-mode", "dryRunOperations": 2, "deployPlanSteps": 3, "renewPlanSteps": 6, "validateCalls": 1, "reloadCalls": 1, "caSentinelCalls": 1, "dnsSentinelCalls": 1}


def uncertain_abandon_proof():
    result = dict.fromkeys(("ownedObserverDrained", "ownedTransportBlock", "observedSubmittingTermination", "actualLeaseExpiry", "acknowledgedPublicRecovery", "sameCsrAndKey", "noAutomaticResubmit", "publicAbandonAudited", "unacceptedKeyRemoved", "originalOrphanPreserved", "recoveryPolicyUnchanged"), True)
    return {**result, "leaseRemainingAtFaultMs": 60000, "recoveryWaitBudgetMs": 150000, "actualLeaseWaitMs": 61000, "scope": "native-zero-request-uncertain-abandon", "resolvedIssuingCaAddress": "10.64.0.4", "caRequestsAtFault": 0, "caRequestsAfterRecovery": 0, "caRequestsAfterAbandon": 0}


def operator_ambiguity_proof():
    flags = ("ownedObserverDrained", "ownedTransportBlock", "observedSubmittingTermination", "actualLeaseExpiry", "acknowledgedPublicRecovery", "sameCsrAndKey", "noAutomaticResubmit", "originalOrphanPreserved", "recoveryPolicyUnchanged", "operatorCreatedSameCsrAmbiguity", "nativeCaOwnershipVerified", "automaticAttachmentRefused", "unacceptedKeyPreserved", "unrelatedTrustedTlsPreserved", "publicExplicitReconcileAudited", "exactSelectedRequestInstalled", "claimBoundVerification", "sameProtectedMachineKeyInstalled", "unusedOwnedRequestRevoked", "unusedLeafNeverAccepted")
    enrollment = "11111111-1111-1111-1111-111111111111"
    return {**dict.fromkeys(flags, True), "scope": "native-zero-request-uncertainty-with-operator-created-same-csr-ambiguity", "fixtureOrigin": "operator-created-two-real-system-submissions-of-the-same-public-csr", "resolvedIssuingCaAddress": "10.64.0.4", "leaseRemainingAtFaultMs": 60000, "recoveryWaitBudgetMs": 150000, "actualLeaseWaitMs": 120000, "caRequestsAtFault": 0, "caRequestsAfterOperatorSubmissions": 2, "caRequestsAfterAmbiguousRecovery": 2, "caRequestsAfterExplicitRecovery": 2, "requestIds": ["101", "102"], "fingerprints": ["1" * 64, "2" * 64], "serialNumbers": ["aa", "bb"], "csrSpkiSha256": "3" * 64, "csrSha256": "4" * 64, "selectedRequestId": "101", "unusedRequestId": "102", "enrollmentId": enrollment, "containerName": "tokentimer-enr-" + enrollment, "jobIds": [value * 8 + "-" + value * 4 + "-" + value * 4 + "-" + value * 4 + "-" + value * 12 for value in ("2", "3", "4")], "reconcileSearchFrom": 100, "scanWindowSize": 16}


def two_adcs_renewals_proof():
    flags = ("defaultSqlNowSelection", "automaticSourceAndRealMode", "distinctExpiryGenerations", "independentCaRequests", "freshLeafSerialAndSpki", "protectedUniqueMachineKeys", "nativeIisAndSniCutovers", "independentTrustedTls", "claimBoundVerificationEvidence", "unchangedStoredProfile", "sameManagementPeriod", "predecessorCustodyPreserved", "actualInventoryMatchesLatest", "ownedEnrollmentCleanupRegistered", "noDateOrJournalOverrides")
    return {**dict.fromkeys(flags, True), "scope": "two-native-adcs-default-scheduler-cycles-not-expiry-cleanup", "renewalProtocol": "fresh-enrollment-with-new-key-and-csr", "schedulerInvocation": "qualification-invoked-production-default-sweep", "workerIntervalQualified": False, "successfulAutomationCycles": 2, "expiryCleanupQualified": False,
            "requestIds": ["17", "18", "19"], "caRequestCounts": [7, 8, 9], "fingerprints": [value * 64 for value in ("a", "b", "c")], "spkiFingerprints": [value * 64 for value in ("d", "e", "f")], "serialNumbers": ["a1", "b2", "c3"],
            "containerNames": [f"tokentimer-enr-{value * 8}-{value * 4}-4{value * 3}-8{value * 3}-{value * 12}" for value in ("a", "b", "c")], "expiryEpochs": [1792497600000, 1792497601000, 1792497602000]}


def elapsed_proof():
    return {"mode": "real-clock-two-cutover-expiry-grace", "successfulCutovers": 2,
            "predecessorCertificatesRemoved": 2, "predecessorKeysRemoved": 2, "lineageRowsFinalized": 2,
            "immediateDeferralPreservedCustody": True, "immutableHistoryPreserved": True,
            "replacementTrustedBoundCustodyUnchanged": True, "interruptedNativeDeleteRecovered": True,
            "configuredRetentionHours": 24, "fullRetentionWindowQualified": False, "waitedMonotonicMs": 420000}


class CollectorTests(unittest.TestCase):
    def test_windows_certificate_dry_run_keeps_only_complete_bounded_observations(self):
        flags = ("priorRealIssuanceVerified", "authenticatedPlansPersisted", "nativeCertificateInventoryUnchanged", "machineKeyMetadataUnchanged", "exactCngCustodyUnchanged", "httpSysBindingUnchanged", "trustedTlsUnchanged", "configurationCredentialPinUnchanged", "dnsProxyRequestsUnchanged")
        proof = {**dict.fromkeys(flags, True), "scope": "installed-windows-signed-certificate-plans-native-state-and-dns-observation", "admission": "production-service-explicit-mode", "deployPlanSteps": 3, "renewPlanSteps": 6}
        report = {"suite": "windows-certificate-dry-run", "nativeCertificateDryRun": {**proof, "machineKeyNames": "sentinel", "credential": "sentinel"}}
        result = collector.sanitized_report(report, {report["suite"]}, set())
        self.assertEqual(result["nativeCertificateDryRun"], proof)
        self.assertNotIn("sentinel", json.dumps(result))
        for key, expected in proof.items():
            with self.subTest(field=key):
                invalid = json.loads(json.dumps(report)); del invalid["nativeCertificateDryRun"][key]
                with self.assertRaises(ValueError):
                    collector.sanitized_report(invalid, {report["suite"]}, set())
                invalid = json.loads(json.dumps(report)); invalid["nativeCertificateDryRun"][key] = False if expected is True else (0 if type(expected) is int else "incorrect")
                with self.assertRaises(ValueError):
                    collector.sanitized_report(invalid, {report["suite"]}, set())

    def test_canonical_installer_and_completed_console_keep_only_bounded_facts(self):
        cases = [
            ("windows-canonical-root-lifecycle", "nativeCanonicalRoot", ("initialRootAbsent", "initialServiceAbsent", "ownershipRecordedBeforeInstall", "originalInstallerBytesUnchanged", "canonicalInstalledHostVerified", "localSystemServiceVerified", "authenticatedRegistration", "bootstrapRegistryScrubbed", "restartChangedServicePid", "freshHeartbeatAfterRestart", "candidateReapplicationSucceeded", "configurationCredentialAndPinPreserved", "freshHeartbeatAfterReapplication", "unmodifiedUninstallerSucceeded", "serviceAndAppRemoved", "uninstallPreservedState", "exactOwnedRootRemoved"), {"scope": "unmodified-candidate-cli-canonical-root-same-version-reapplication"}),
            ("browser-agent-console", "completedConsolePrivacy", ("finalStreamDoesNotCompleteJob", "claimBoundResultCompletesNoop", "completedViewerTextWithdrawn", "restoredHistoryWithoutDuplicates", "removedMemberTextWithdrawn", "sameConsoleRemainedMounted", "authoritativeTerminalStatePreserved", "foregroundRevalidationWithinThirtySeconds", "noNativeExecutionClaim"), {}),
        ]
        for suite, key, fields, extra in cases:
            proof = {**dict.fromkeys(fields, True), **extra}
            report = {"suite": suite, key: {**proof, "privatePath": "sentinel", "credential": "sentinel", "consoleText": "sentinel"}}
            result = collector.sanitized_report(report, {suite}, set())
            self.assertEqual(result[key], proof)
            self.assertNotIn("sentinel", json.dumps(result))
            for field in fields:
                for invalid in (False, 1, None, "true"):
                    with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite, key: {**proof, field: invalid}}, {suite}, set())
                missing = {**proof}
                del missing[field]
                with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite, key: missing}, {suite}, set())
            with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite}, {suite}, set())
            if extra:
                with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite, key: {**proof, "scope": "published-upgrade"}}, {suite}, set())


    def test_renewal_key_facts_keep_only_committed_sources_not_public_leaf_or_claim_bodies(self):
        suite = "renewal-key-facts-api"
        matrix = json.loads((collector.ROOT / "docs/certops/release-qualification-matrix.json").read_text())
        slot = next(row for row in matrix["slots"] if row["suite"] == suite)
        sources = [{"file": file, "sha256": "a" * 64} for file in slot["requiredSources"]]
        report = {"suite": suite, "fixtureSource": sources[0], "fixtureSources": sources,
                  "certificatePem": "sentinel", "spki": "sentinel", "claimBody": {"credential": "sentinel"}}
        result = collector.sanitized_report(report, {suite}, set())
        self.assertEqual(result["fixtureSources"], sources)
        self.assertNotIn("sentinel", json.dumps(result))
        report["fixtureSources"].append({"file": "uncommitted/secret.json", "sha256": "a" * 64})
        self.assertEqual(collector.sanitized_report(report, {suite}, set())["fixtureSources"], sources[:6])

    def test_two_unattended_renewals_retains_exact_scope_not_raw_key_or_ledger_state(self):
        fields = ("automaticSourceAndRealMode", "naturallyDueGenerations", "distinctIdempotencyKeys", "leafAndSpkiChangedTwice", "nativeBindingMatchesLatest", "nativeKeyProfilesVerified", "persistedEvidenceBothCycles", "inventoryMatchesActualLeaf", "profileAndManagementLineagePreserved", "retentionLineageMatchesBothCutovers", "predecessorCustodyPreserved", "noExpiryOrClockOverrides")
        proof = {**dict.fromkeys(fields, True), "successfulAutomationCycles": 2, "expiryCleanupQualified": False,
                 "scope": "two-unattended-cycles-and-preserved-predecessors-not-expiry-cleanup"}
        suite = "windows-two-unattended-renewals"
        result = collector.sanitized_report({"suite": suite, "nativeTwoRenewals": {**proof, "rawCngMetadata": "sentinel", "rawLedger": "sentinel"}}, {suite}, set())
        self.assertEqual(result["nativeTwoRenewals"], proof)
        self.assertNotIn("sentinel", json.dumps(result))
        for field in fields:
            with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite, "nativeTwoRenewals": {**proof, field: False}}, {suite}, set())
        for change in ({"successfulAutomationCycles": 1}, {"successfulAutomationCycles": 3}, {"successfulAutomationCycles": True}, {"expiryCleanupQualified": True}, {"scope": "complete-expiry-cleanup"}):
            with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite, "nativeTwoRenewals": {**proof, **change}}, {suite}, set())
        with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite}, {suite}, set())

    def test_browser_audit_preserves_current_source_inventory_without_raw_events_or_sessions(self):
        suite = "browser-certificate-audit"
        files = ("scripts/certops-browser-audit.js", "tests/e2e/helpers/certops-browser-audit-fixture.js",
                 "tests/e2e/helpers/certops-api-fixture.js", "apps/dashboard/src/pages/Audit.jsx",
                 "apps/api/routes/usage.js", "apps/api/services/certops/certificateIdentity.js")
        sources = [{"file": file, "sha256": "a" * 64} for file in files]
        report = {"suite": suite, "fixtureSource": sources[0], "fixtureSources": sources,
                  "rawAuditRows": [{"metadata": "sentinel"}], "cookies": "sentinel", "screenshot": "sentinel"}
        result = collector.sanitized_report(report, {suite}, set())
        self.assertEqual(result["fixtureSources"], sources)
        self.assertNotIn("sentinel", json.dumps(result))
        report["fixtureSources"] = [{"file": "uncommitted/private-path.js", "sha256": "a" * 64}]
        self.assertEqual(collector.sanitized_report(report, {suite}, set())["fixtureSources"], [])

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

    def test_full_cli_second_rename_projection_requires_exact_scope_and_nineteen_facts(self):
        fields = ("sourceOplockGranted", "actualSourceOpenBrokeOplock", "stagingHeldBeforeCopyResumed", "nativeOrderedRestoration", "originalDirectoryIdentityPreserved", "installedBytesUnchanged", "explicitStagingCleanupFailure", "sourceBytesUnchanged", "nativeHandleReleased", "ownedInstallerDrained", "ownedDriverDrained", "ownedStagingRemoved", "originalInstallerCliBytes", "sameRunningLocalSystemServicePid", "configurationCredentialAndPinUnchanged", "freshAuthenticatedHeartbeat", "nonExportableMachineCngCustodyUnchanged", "nativeBindingAndTrustedTlsUnchanged", "ownedCertificateKeyAndEndpointRemoved")
        self.assertEqual(len(fields), 19)
        suite = "windows-installer-cli-second-rename"
        proof = {"scope": "unmodified-installer-cli-canonical-root-operator-cng-binding", **dict.fromkeys(fields, True)}
        def project(value):
            return collector.sanitized_report({"suite": suite, "nativeCliSecondRename": value}, {suite}, set())
        projected = project({**proof, "rawConfig": "private-sentinel", "rawNativeEvents": "private-sentinel", "agentIssuanceQualified": True})
        self.assertEqual(projected["nativeCliSecondRename"], proof)
        self.assertNotIn("private-sentinel", json.dumps(projected))
        self.assertNotIn("agentIssuanceQualified", json.dumps(projected))
        for field in fields:
            for invalid in (False, None, 1, "true"):
                with self.subTest(field=field, invalid=invalid), self.assertRaises(ValueError):
                    project({**proof, field: invalid})
            missing = dict(proof)
            del missing[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                project(missing)
        for invalid in (None, [], {}, {**proof, "scope": "production-activation-functions-not-installer-cli"}, {**proof, "scope": "temporaryfile-mechanics-only"}):
            with self.assertRaises(ValueError):
                project(invalid)
        with self.assertRaises(ValueError):
            collector.sanitized_report({"suite": suite}, {suite}, set())

    def test_linux_acme_reuse_projection_binds_clients_and_strips_broader_claims(self):
        fields = ("publicProfilePolicyChanged", "manualRenewalSucceeded", "defaultSqlNowRenewalSucceeded", "claimBoundVerification", "unchangedPrivateCustody", "privateMaterialStayedLocal", "unchangedSpki", "distinctCaLeavesAndSerials", "advancingExpiry", "trustedTlsEachGeneration", "dnsCleanEachGeneration", "stableReuseProfile")
        scopes = ("real-agent-acme-filesystem", "real-agent-acme-eab-filesystem", "real-agent-acmesh-filesystem", "real-agent-acmesh-eab-filesystem", "real-agent-alpine-acmesh")
        main = "real ACME: agent discovers public files registers claims issues renews deploys and persists independently verified certificate evidence"
        for scope in scopes:
            client = "acme.sh" if "acmesh" in scope else "certbot"
            proof = {"scope": "real-linux-manual-and-default-scheduler-csr-key-reuse", "client": client, **dict.fromkeys(fields, True), "fingerprints": [letter * 64 for letter in "abc"], "serials": ["A1", "B2", "C3"], "spkiFingerprint": "d" * 64, "jobIds": ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"], "sourceProfileId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "sourceProfileFingerprint": "e" * 64}
            def project(value):
                return collector.sanitized_report([{"scope": scope, "name": main, "type": "test:pass", "nativeAcmeKeyReuse": value}], set(), {scope})
            result = project({**proof, "rawKey": "private-sentinel", "windowsQualified": True, "workerLoopQualified": True})
            self.assertEqual(result[0]["nativeAcmeKeyReuse"], proof)
            for forbidden in ("private-sentinel", "windowsQualified", "workerLoopQualified"):
                self.assertNotIn(forbidden, json.dumps(result))
            for field in fields:
                for invalid in (False, None, 1, "true"):
                    with self.subTest(scope=scope, field=field, invalid=invalid), self.assertRaises(ValueError):
                        project({**proof, field: invalid})
                missing = dict(proof)
                del missing[field]
                with self.assertRaises(ValueError):
                    project(missing)
            for change in ({"scope": "windows-native-reuse"}, {"scope": "background-worker-loop"}, {"client": "certbot" if client == "acme.sh" else "acme.sh"}, {"fingerprints": ["a" * 64] * 3}, {"serials": ["AA"] * 3}, {"jobIds": [proof["jobIds"][0], proof["jobIds"][0].upper()]}, {"spkiFingerprint": "bad"}, {"sourceProfileId": "foreign"}, {"sourceProfileFingerprint": "bad"}):
                with self.subTest(scope=scope, change=change), self.assertRaises(ValueError):
                    project({**proof, **change})
            with self.assertRaises(ValueError):
                project(None)

    def test_installed_scm_handoff_projection_requires_explicit_operator_scope_and_cleanup(self):
        scope = "real-agent-windows-acme-iis/rsa-2048"
        proof = installed_handoff_proof()
        event = {"scope": scope, "name": "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence", "type": "test:pass"}
        def project(value):
            return collector.installed_handoff_fields({**event, "nativeInstalledStateHandoff": value})
        self.assertEqual(project({**proof, "rawCredential": "private", "automaticMigrationQualified": True})["nativeInstalledStateHandoff"], proof)
        for flag, fact in proof.items():
            if fact is not True:
                continue
            for wrong in (False, None, 1, "true"):
                with self.subTest(flag=flag, wrong=wrong), self.assertRaises(ValueError):
                    project({**proof, flag: wrong})
            missing = dict(proof)
            del missing[flag]
            with self.assertRaises(ValueError):
                project(missing)
        for wrong in (None, [], {}, {**proof, "scope": "automatic-in-place-reregistration"}):
            with self.assertRaises(ValueError):
                project(wrong)
        self.assertEqual(collector.installed_handoff_fields({**event, "type": "test:fail"}), {})
        self.assertEqual(collector.installed_handoff_fields({**event, "scope": "real-agent-acme-filesystem"}), {})

    def test_retention_atomic_proof_strips_native_paths_and_requires_all_facts(self):
        fields = ("nativeFileHandleHeld", "nativeFileIdentityMatched", "actualAtomicReplaceRefused", "priorRowBytesPreserved", "priorRowIdentityPreserved", "failedTemporaryFileRemoved", "nativeHandleReleased", "ownedChildDrained", "actualReplacementSucceeded", "freshProcessReadExactReplacement", "restrictivePermissionsVerified", "ownedTemporaryFixtureRemoved")
        proof = dict.fromkeys(fields, True)
        suite = "windows-host"
        custody_fields = ("exportableControlSucceeded", "controlBytesZeroed", "protectedBytesZeroed", "protectedExportDenied", "publicNonceSignatureVerified", "originalCustodyUnchanged", "controlKeyRemoved")
        custody = {"privateExportBytesWritten": False, "privateExportBytesReported": False, "workDirectoryUnchanged": True,
                   "cases": [{"caseId": profile + "/" + store, **dict.fromkeys(custody_fields, True), "privateExportHResult": -2146893813} for store in ("My", "WebHosting") for profile in ("rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384")]}
        result = collector.sanitized_report({"suite": suite, "cngCustody": custody, "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeKeySurvivors": survivor_proof(), "nativeElapsedRetention": elapsed_proof(), "nativeRetentionAtomicReplace": {**proof, "rawLedger": "sentinel", "nativePath": "sentinel"}}, {suite}, set())
        self.assertEqual(result["nativeRetentionAtomicReplace"], proof)
        survivor_report = {"suite": suite, "cngCustody": custody, "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeRetentionAtomicReplace": proof, "nativeElapsedRetention": elapsed_proof(), "nativeKeySurvivors": {**survivor_proof(), "rawInventory": "sentinel", "containerName": "sentinel"}}
        self.assertEqual(collector.sanitized_report(survivor_report, {suite}, set())["nativeKeySurvivors"], survivor_proof())
        self.assertNotIn("sentinel", json.dumps(collector.sanitized_report(survivor_report, {suite}, set())))
        reference_report = {**survivor_report, "nativeRetentionReferences": {**retention_reference_proof(), "rawInventory": "sentinel"}}
        projected = collector.sanitized_report(reference_report, {suite}, set())["nativeRetentionReferences"]
        self.assertEqual(projected, retention_reference_proof())
        self.assertNotIn("sentinel", json.dumps(projected))
        for field, value in retention_reference_proof().items():
            for invalid in (None, 1, "true", not value if isinstance(value, bool) else "foreign-scope"):
                bad = {**reference_report, "nativeRetentionReferences": {**retention_reference_proof(), field: invalid}}
                with self.assertRaises(ValueError): collector.sanitized_report(bad, {suite}, set())
            missing = retention_reference_proof()
            del missing[field]
            with self.assertRaises(ValueError): collector.sanitized_report({**reference_report, "nativeRetentionReferences": missing}, {suite}, set())
        state_report = {**survivor_report, "nativeStateReadRefusals": {**state_read_proof(), "rawCredential": "sentinel"}}
        projected = collector.sanitized_report(state_report, {suite}, set())["nativeStateReadRefusals"]
        self.assertEqual(projected, state_read_proof())
        self.assertNotIn("sentinel", json.dumps(projected))
        for field, value in state_read_proof().items():
            for invalid in (None, 1, "true", not value if isinstance(value, bool) else "foreign-scope"):
                bad = {**state_report, "nativeStateReadRefusals": {**state_read_proof(), field: invalid}}
                with self.assertRaises(ValueError): collector.sanitized_report(bad, {suite}, set())
            missing = state_read_proof()
            del missing[field]
            with self.assertRaises(ValueError): collector.sanitized_report({**state_report, "nativeStateReadRefusals": missing}, {suite}, set())
        for field in survivor_proof():
            for invalid in (False, None, 1, "true"):
                survivor_report["nativeKeySurvivors"] = {**survivor_proof(), field: invalid}
                with self.assertRaises(ValueError): collector.sanitized_report(survivor_report, {suite}, set())
        survivor_report.pop("nativeKeySurvivors")
        with self.assertRaises(ValueError): collector.sanitized_report(survivor_report, {suite}, set())

        elapsed = elapsed_proof()
        result = collector.sanitized_report({"suite": suite, "cngCustody": custody, "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeRetentionAtomicReplace": proof,
            "nativeKeySurvivors": survivor_proof(), "nativeElapsedRetention": {**elapsed, "rawLedger": "sentinel", "nativeKeyPath": "sentinel"}}, {suite}, set())
        self.assertEqual(result["nativeElapsedRetention"], elapsed)
        self.assertNotIn("sentinel", json.dumps(result))
        for change in ({"successfulCutovers": True}, {"predecessorCertificatesRemoved": 1}, {"predecessorKeysRemoved": 1},
                       {"lineageRowsFinalized": 1}, {"immediateDeferralPreservedCustody": False}, {"immutableHistoryPreserved": False},
                       {"replacementTrustedBoundCustodyUnchanged": False}, {"interruptedNativeDeleteRecovered": False},
                       {"configuredRetentionHours": 1}, {"fullRetentionWindowQualified": True},
                       {"waitedMonotonicMs": 299999}, {"waitedMonotonicMs": 600000}, {"waitedMonotonicMs": float("nan")},
                       {"mode": "synthetic-clock"}):
            with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite, "cngCustody": custody, "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(),
                "nativeRetentionAtomicReplace": proof, "nativeKeySurvivors": survivor_proof(), "nativeElapsedRetention": {**elapsed, **change}}, {suite}, set())
        with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite, "cngCustody": custody, "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeRetentionAtomicReplace": proof}, {suite}, set())

        self.assertNotIn("sentinel", json.dumps(result))
        for field in fields:
            with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite, "nativeKeySurvivors": survivor_proof(), "nativeElapsedRetention": elapsed_proof(), "nativeRetentionAtomicReplace": {**proof, field: False}}, {suite}, set())
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
        event = {"scope": scope, "name": "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence", "type": "test:pass", "windowsPublicIssuance": facts, "nativeInstalledStateHandoff": installed_handoff_proof()}
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
        result = collector.sanitized_report({"suite": suite, "nativeKeySurvivors": survivor_proof(), "nativeElapsedRetention": elapsed_proof(), "nativeRetentionAtomicReplace": atomic, "cngCustody": custody, "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeSamePortSni": sni}, {suite}, set())
        self.assertEqual(result["nativeSamePortSni"]["siteCount"], 2)
        self.assertTrue(result["nativeSamePortSni"]["peerRollbackPrimaryUnchanged"])
        usage_report = {"suite": suite, "nativeKeySurvivors": survivor_proof(), "nativeElapsedRetention": elapsed_proof(), "nativeRetentionAtomicReplace": atomic, "cngCustody": custody, "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof()}
        usage_report["nativeKeyUsage"]["rawKeyPath"] = "sentinel"
        usage_report["nativeKeyUsage"]["cases"][0]["privateBlob"] = "sentinel"
        projected_usage = collector.sanitized_report(usage_report, {suite}, set())
        self.assertEqual(projected_usage["nativeKeyUsage"], key_usage_proof())
        self.assertNotIn("sentinel", json.dumps(projected_usage))
        for mask in (2, 3, 6, 7, 0x00ffffff):
            valid = json.loads(json.dumps(usage_report))
            for item in valid["nativeKeyUsage"]["cases"]:
                item["cngAllowedOperations"] = mask
            self.assertEqual(collector.sanitized_report(valid, {suite}, set())["nativeKeyUsage"]["cases"][0]["cngAllowedOperations"], mask)
        for key in key_usage_proof():
            invalid = json.loads(json.dumps(usage_report))
            del invalid["nativeKeyUsage"][key]
            with self.assertRaises(ValueError):
                collector.sanitized_report(invalid, {suite}, set())
        missing_usage = json.loads(json.dumps(usage_report))
        del missing_usage["nativeKeyUsage"]
        with self.assertRaises(ValueError):
            collector.sanitized_report(missing_usage, {suite}, set())
        for index in range(10):
            for change in ({"certificateUsageFlags": 0}, {"certificateUsageFlags": 4}, {"certificateUsageFlags": True}, {"cngAllowedOperations": 2 | 8}, {"cngAllowedOperations": 0xffffffff}, {"cngAllowedOperations": 0}, {"cngAllowedOperations": -1}, {"cngAllowedOperations": 0x100000000}, {"cngAllowedOperations": True}, {"cngAllowedOperations": "Signing"}, {"caseId": []}, {"caseId": "rsa-1024/My"}):
                invalid = json.loads(json.dumps(usage_report))
                invalid["nativeKeyUsage"]["cases"][index].update(change)
                with self.assertRaises(ValueError):
                    collector.sanitized_report(invalid, {suite}, set())
            for field in ("certificateUsageFlags", "cngAllowedOperations", "caseId"):
                invalid = json.loads(json.dumps(usage_report))
                del invalid["nativeKeyUsage"]["cases"][index][field]
                with self.assertRaises(ValueError):
                    collector.sanitized_report(invalid, {suite}, set())
        for change in ({"scope": "exact-default-cng-policy-qualified"}, {"copiedActualCsrExtensions": False}, {"privateKeyUsageClaim": "ecdsa-decryption-qualified"}, {"cases": key_usage_proof()["cases"][:-1]}, {"cases": [key_usage_proof()["cases"][0]] * 10}):
            invalid = json.loads(json.dumps(usage_report))
            invalid["nativeKeyUsage"].update(change)
            with self.assertRaises(ValueError):
                collector.sanitized_report(invalid, {suite}, set())
        for change in ({"siteCount": True}, {"hostnameCount": 1}, {"certificateStore": "Other"}):
            with self.assertRaises(ValueError):
                collector.sanitized_report({"suite": suite, "cngCustody": custody, "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeSamePortSni": {**sni, **change}}, {suite}, set())
        missing = collector.sanitized_report({"suite": suite, "nativeKeySurvivors": survivor_proof(), "nativeElapsedRetention": elapsed_proof(), "nativeRetentionAtomicReplace": atomic, "cngCustody": custody, "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeSamePortSni": {**sni, "ownedCleanupVerified": False}}, {suite}, set())
        self.assertFalse(missing["nativeSamePortSni"]["ownedCleanupVerified"])
        contention = {**dict.fromkeys(("winnerGeneratedRealCsr", "loserLockedBeforeNativeExecution", "retryAcquiredEnrollmentLock", "retryExistingContainerRefused", "sameCsrAndSpki", "sameNonExportableKey", "winnerSignatureVerified", "ownedChildrenStopped", "ownedKeyRemoved"), True), "loserNativeCalls": 0, "loserCertreqCalls": 0, "retryCertreqCalls": 0, "winnerCertreqCalls": 1, "retryNativeCalls": 1, "privateRaw": "sentinel"}
        projected = collector.sanitized_report({"suite": suite, "nativeKeySurvivors": survivor_proof(), "nativeElapsedRetention": elapsed_proof(), "nativeRetentionAtomicReplace": atomic, "cngCustody": custody, "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeEnrollmentContention": contention}, {suite}, set())
        self.assertEqual(projected["nativeEnrollmentContention"]["loserNativeCalls"], 0)
        self.assertNotIn("sentinel", json.dumps(projected))
        for bad in (True, "0", -1, 33):
            with self.assertRaises(ValueError):
                collector.sanitized_report({"suite": suite, "cngCustody": custody, "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeEnrollmentContention": {**contention, "loserNativeCalls": bad}}, {suite}, set())
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
        value["primaryNativePreflightDispatchCount"] = 18
        self.assertEqual(collector.sanitized_report(value, {value["suite"]}, set())["primaryNativePreflightDispatchCount"], 18)
        for count in (19, 20, True, "18"):
            invalid = json.loads(json.dumps(value))
            invalid["primaryNativePreflightDispatchCount"] = count
            invalid["nativeBrowserAdcs"] = browser_adcs_proof()
            with self.assertRaises(ValueError):
                collector.sanitized_report(invalid, {value["suite"]}, set())
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
        value["nativeCertificateDryRun"] = {**certificate_dry_run_proof(), "private": "sentinel"}
        result = collector.extract_reports(self.archive("native.json", value), {"native-agent-api"}, set())
        self.assertEqual(result[0][1]["nativeLogFaults"][0]["persistedLines"], 3)
        self.assertEqual(result[0][1]["nativeCertificateDryRun"], certificate_dry_run_proof())
        self.assertNotIn("sentinel", json.dumps(result))
        for key, expected in certificate_dry_run_proof().items():
            with self.subTest(dry_run_field=key):
                invalid = json.loads(json.dumps(value))
                del invalid["nativeCertificateDryRun"][key]
                with self.assertRaises(ValueError):
                    collector.extract_reports(self.archive("native.json", invalid), {"native-agent-api"}, set())
                invalid = json.loads(json.dumps(value))
                invalid["nativeCertificateDryRun"][key] = False if expected is True else (0 if type(expected) is int else "incorrect")
                with self.assertRaises(ValueError):
                    collector.extract_reports(self.archive("native.json", invalid), {"native-agent-api"}, set())

    def test_uncommitted_execution_names_and_values_are_never_artifacts(self):
        sentinel = "private-sentinel"
        value = {"suite": "job-decisions-api", "requiredScenarios": [sentinel], "missingScenarios": [sentinel], "requiredCapabilities": [sentinel], "capabilities": {sentinel: {"available": {"private": sentinel}}}, "scenarios": [{"id": sentinel, "status": sentinel, "evidenceLevel": sentinel, "startedAt": sentinel}]}
        result = collector.extract_reports(self.archive("failed.json", value), {"job-decisions-api"}, set())
        self.assertNotIn(sentinel, json.dumps(result))
        self.assertEqual(result[0][1]["scenarios"][0]["id"], "[unrecognized]")

    def test_native_cohort_budgets_are_bounded_without_private_fields(self):
        cohort = {"workspaceId": "a" * 36, "agentId": "b" * 36, "dispatchCount": 18, "dispatchLimit": 18, "nativeIdentity": "LocalSystem", "runtime": "candidate-cli", "privateState": "sentinel"}
        value = {"suite": "enterprise-adcs-real", "nativeLocalRulePairs": local_pairs_proof(), "nativeForeignSpkiCandidate": foreign_spki_proof(), "primaryNativePreflightDispatchCount": 18, "nativePreflightCohorts": [cohort], "nativeTemplateMutations": [], "nativeValidationExpiry": {"configuredTimeoutSeconds": 300, "defaultTimeoutSeconds": 86400, "storedWindowSeconds": 299, "monotonicObservedWaitSeconds": 301, "actualDeadline": "2026-10-14T12:00:00.000Z", "requestId": "17", "snapshotSha256": "a" * 64, "nativeAndCaClocks": "actual", "qualificationScope": "configured-five-minute-window-not-default-24-hour-elapsed"}}
        value["nativeIssuedCancellation"] = {"requestId": "17", "snapshotSha256": "a" * 64, "pollIntervalSeconds": 900, "schedulerClock": "default-real-now", "databaseDatesRewritten": False, "journalRewritten": False, "private": "sentinel"}
        value["nativeUncertainAbandon"] = uncertain_abandon_proof()
        value["nativeUncertainOperatorAmbiguity"] = operator_ambiguity_proof()
        value["nativeUncertainOperatorAmbiguity"]["privateKey"] = "sentinel"
        value["nativeBrowserAdcs"] = browser_adcs_proof()
        value["nativeBrowserAdcs"]["privateCookie"] = "sentinel"
        value["browserNativePreflightDispatch"] = {"count": 2, "jobIds": ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"], "privateReceipt": "sentinel"}
        value["nativeAdcsTwoRenewals"] = two_adcs_renewals_proof()
        value["nativeAdcsTwoRenewals"]["privateKey"] = "sentinel"
        value["nativeUncertainAbandon"]["private"] = "sentinel"
        result = collector.extract_reports(self.archive("adcs.json", value), {"enterprise-adcs-real"}, set())
        self.assertEqual(result[0][1]["nativePreflightCohorts"][0]["dispatchCount"], 18)
        self.assertNotIn("sentinel", json.dumps(result))
        self.assertEqual(result[0][1]["nativeUncertainOperatorAmbiguity"], operator_ambiguity_proof())
        for key, expected in operator_ambiguity_proof().items():
            invalid = json.loads(json.dumps(value))
            del invalid["nativeUncertainOperatorAmbiguity"][key]
            with self.subTest(ambiguity_missing=key), self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
            bad_values = (False, None, 1, "true") if type(expected) is bool else (None, False, "invalid")
            for bad_value in bad_values:
                invalid = json.loads(json.dumps(value))
                invalid["nativeUncertainOperatorAmbiguity"][key] = bad_value
                with self.subTest(ambiguity_field=key, value=bad_value), self.assertRaises(ValueError):
                    collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for patch in ({"fixtureOrigin": "lost-submit-response"}, {"caRequestsAtFault": 1}, {"caRequestsAfterAmbiguousRecovery": 3}, {"actualLeaseWaitMs": 60000}, {"actualLeaseWaitMs": 152000}, {"reconcileSearchFrom": 102}, {"scanWindowSize": 64}, {"selectedRequestId": "103"}, {"unusedRequestId": "101"}, {"requestIds": ["101", "101"]}, {"jobIds": ["22222222-2222-2222-2222-222222222222"] * 3}):
            invalid = json.loads(json.dumps(value))
            invalid["nativeUncertainOperatorAmbiguity"].update(patch)
            with self.subTest(ambiguity_patch=patch), self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        self.assertEqual(result[0][1]["nativeBrowserAdcs"], browser_adcs_proof())
        self.assertEqual(result[0][1]["nativeLocalRulePairs"], local_pairs_proof())
        self.assertEqual(result[0][1]["nativeForeignSpkiCandidate"], foreign_spki_proof())
        for flag, fact in foreign_spki_proof().items():
            if fact is not True:
                continue
            for invalid in (False, None, 1, "true"):
                bad = json.loads(json.dumps(value))
                bad["nativeForeignSpkiCandidate"][flag] = invalid
                with self.subTest(foreign_flag=flag, invalid=invalid), self.assertRaises(ValueError):
                    collector.sanitized_report(bad, {value["suite"]}, set())
            bad = json.loads(json.dumps(value))
            del bad["nativeForeignSpkiCandidate"][flag]
            with self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value["suite"]}, set())
        for change in ({"scope": "public-uncertain-recovery"}, {"requestIds": ["17", "17"]}, {"requestIds": ["17", "4294967296"]}, {"spkiFingerprints": ["a" * 64, "a" * 64]}):
            bad = json.loads(json.dumps(value))
            bad["nativeForeignSpkiCandidate"].update(change)
            with self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value["suite"]}, set())
        private_foreign = json.loads(json.dumps(value))
        private_foreign["nativeForeignSpkiCandidate"].update({"rawKey": "foreign-private-sentinel", "publicRecoveryQualified": True})
        sanitized_foreign = collector.sanitized_report(private_foreign, {value["suite"]}, set())
        self.assertEqual(sanitized_foreign["nativeForeignSpkiCandidate"], foreign_spki_proof())
        self.assertNotIn("foreign-private-sentinel", json.dumps(sanitized_foreign))

        private_pairs = json.loads(json.dumps(value))
        private_pairs["nativeLocalRulePairs"][0]["rawKey"] = "private-pair-sentinel"
        self.assertNotIn("private-pair-sentinel", json.dumps(collector.sanitized_report(private_pairs, {value["suite"]}, set())))
        for flag in local_pairs_proof()[0]:
            if flag == "caseId":
                continue
            for invalid in (False, None, 1, "true"):
                bad = json.loads(json.dumps(value))
                bad["nativeLocalRulePairs"][0][flag] = invalid
                with self.subTest(pair_flag=flag, invalid=invalid), self.assertRaises(ValueError):
                    collector.sanitized_report(bad, {value["suite"]}, set())
            bad = json.loads(json.dumps(value))
            del bad["nativeLocalRulePairs"][0][flag]
            with self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value["suite"]}, set())
        for rows in (None, [], [local_pairs_proof()[0]] * 3, [{**row, "caseId": "unknown"} for row in local_pairs_proof()]):
            bad = json.loads(json.dumps(value))
            bad["nativeLocalRulePairs"] = rows
            with self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value["suite"]}, set())

        self.assertNotIn("privateReceipt", result[0][1]["browserNativePreflightDispatch"])
        hierarchy = json.loads(json.dumps(value))
        hierarchy["suite"] = "enterprise-adcs-hierarchy-real"
        self.assertEqual(collector.extract_reports(self.archive("hierarchy.json", hierarchy), {hierarchy["suite"]}, set())[0][1]["nativeBrowserAdcs"], browser_adcs_proof())
        del hierarchy["nativeBrowserAdcs"]
        with self.assertRaises(ValueError):
            collector.extract_reports(self.archive("hierarchy.json", hierarchy), {hierarchy["suite"]}, set())
        for key, expected in browser_adcs_proof().items():
            with self.subTest(browser_adcs_field=key):
                invalid = json.loads(json.dumps(value))
                del invalid["nativeBrowserAdcs"][key]
                with self.assertRaises(ValueError):
                    collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
                invalid = json.loads(json.dumps(value))
                invalid["nativeBrowserAdcs"][key] = [expected[0], expected[0]] if isinstance(expected, list) else False if type(expected) is bool else expected + 1 if type(expected) is int else "unqualified"
                with self.assertRaises(ValueError):
                    collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for count in (2, 18, 19, 20):
            valid = json.loads(json.dumps(value))
            valid["primaryNativePreflightDispatchCount"] = count
            self.assertEqual(collector.extract_reports(self.archive("adcs.json", valid), {"enterprise-adcs-real"}, set())[0][1]["primaryNativePreflightDispatchCount"], count)
        for key in ("nativeBrowserAdcs", "browserNativePreflightDispatch"):
            invalid = json.loads(json.dumps(value))
            invalid["primaryNativePreflightDispatchCount"] = 20
            del invalid[key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for dispatch in ({"count": 3, "jobIds": value["browserNativePreflightDispatch"]["jobIds"]}, {"count": True, "jobIds": value["browserNativePreflightDispatch"]["jobIds"]}, {"count": 2, "jobIds": ["invalid", "invalid"]}, {"count": 2, "jobIds": ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"]}, {"count": 2, "jobIds": [value["browserNativePreflightDispatch"]["jobIds"][0]]}):
            invalid = json.loads(json.dumps(value))
            invalid["browserNativePreflightDispatch"] = dispatch
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for count in (1, 21, -1, True, "20"):
            invalid = json.loads(json.dumps(value))
            invalid["primaryNativePreflightDispatchCount"] = count
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        invalid = json.loads(json.dumps(value))
        invalid["nativeBrowserAdcs"]["requestId"] = "4294967296"
        with self.assertRaises(ValueError):
            collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        self.assertEqual(result[0][1]["nativeAdcsTwoRenewals"], two_adcs_renewals_proof())
        for key, expected in two_adcs_renewals_proof().items():
            with self.subTest(two_adcs_renewals_field=key):
                invalid = json.loads(json.dumps(value))
                del invalid["nativeAdcsTwoRenewals"][key]
                with self.assertRaises(ValueError):
                    collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
                invalid = json.loads(json.dumps(value))
                invalid["nativeAdcsTwoRenewals"][key] = expected + expected[:1] if isinstance(expected, list) else not expected if type(expected) is bool else 1 if type(expected) is int else "unqualified"
                with self.assertRaises(ValueError):
                    collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for key in ("requestIds", "fingerprints", "spkiFingerprints", "serialNumbers", "containerNames", "expiryEpochs"):
            invalid = json.loads(json.dumps(value))
            invalid["nativeAdcsTwoRenewals"][key][2] = invalid["nativeAdcsTwoRenewals"][key][1]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for change in ({"requestIds": ["17", "18", "4294967296"]}, {"caRequestCounts": [999, 1000, 1001]}, {"caRequestCounts": [7, 8, 10]}, {"caRequestCounts": [True, 2, 3]}, {"expiryEpochs": [1, 2, 9007199254740992]}, {"workerIntervalQualified": True}, {"expiryCleanupQualified": True}):
            invalid = json.loads(json.dumps(value))
            invalid["nativeAdcsTwoRenewals"].update(change)
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for key, expected in uncertain_abandon_proof().items():
            with self.subTest(uncertain_abandon_field=key):
                invalid = json.loads(json.dumps(value))
                del invalid["nativeUncertainAbandon"][key]
                with self.assertRaises(ValueError):
                    collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
                invalid = json.loads(json.dumps(value))
                invalid["nativeUncertainAbandon"][key] = False if type(expected) is bool else 1 if type(expected) is int else "unqualified"
                with self.assertRaises(ValueError):
                    collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for key in ("caRequestsAtFault", "caRequestsAfterRecovery", "caRequestsAfterAbandon"):
            invalid = json.loads(json.dumps(value))
            invalid["nativeUncertainAbandon"][key] = False
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
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
        declared = sorted(collector.declared_sources())
        self.assertGreaterEqual(len(declared), 65)
        public_sources = [{"file": name, "sha256": hashlib.sha256((collector.ROOT / name).read_bytes()).hexdigest()} for name in declared[:65]]
        self.assertEqual(collector.supporting_sources(public_sources[:64]), public_sources[:64])
        with self.assertRaises(ValueError):
            collector.supporting_sources(public_sources)

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
        for workflow in ("certops-windows-fixed-root.yml", "certops-windows-arm64-cng.yml"):
            trusted = {**run, "path": ".github/workflows/" + workflow}
            collector.validate_run(trusted, "a" * 40, "owner/repo")
            for field, value in (("head_branch", "feature"), ("head_sha", "b" * 40), ("event", "pull_request"), ("conclusion", "cancelled")):
                with self.subTest(workflow=workflow, field=field), self.assertRaises(ValueError):
                    collector.validate_run({**trusted, field: value}, "a" * 40, "owner/repo")
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
