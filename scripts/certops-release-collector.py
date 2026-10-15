"""Collect bounded reports from explicitly selected trusted workflow runs.

Invoked by the manual release-collection workflow with a candidate and run IDs.
Checks run provenance and safe artifact boundaries, retains public evidence only,
and delegates qualification to the committed matrix. It neither runs native labs
nor enables AD CS, and experimental/supporting reports cannot fill native slots.
"""
import io
import hashlib
from datetime import datetime
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import certops_retention24h_collection as retention24h_collection
from certops_retention_policy_expiry import fields as retention_policy_expiry_fields, interruption_fields as retention_interruption_fields
import certops_adcs_ttl24h_collection as adcs_ttl24h_collection
import certops_linux_backup_dac_proof as linux_backup_dac_proof

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = {
    ".github/workflows/" + name for name in (
        "certops-qualification.yml", "certops-real-acme.yml",
        "certops-browser-qualification.yml", "certops-kubernetes-qualification.yml",
        "certops-kubernetes-http01-qualification.yml",
        "certops-windows-e2e.yml", "certops-linux-systemd.yml", "certops-linux-published-upgrade.yml",
        "certops-windows-arm64-cng.yml", "certops-windows-arm64-scm.yml", "certops-windows-arm64-agent.yml",
        "certops-windows-fixed-root.yml",
        "certops-native-agent-qualification.yml",
        "certops-scheduler-capacity-qualification.yml",
        "certops-renewal-alert-qualification.yml",
        "certops-log-maintenance-qualification.yml",
        "certops-alpine-acme-qualification.yml",
        "certops-signing-rotation-qualification.yml",
        "certops-enterprise-adcs-qualification.yml",
        "certops-enterprise-adcs-hierarchy-qualification.yml",
        "certops-enterprise-adcs-pending-elapsed.yml",
        "certops-integration-qualification.yml",
        "certops-linux-trust-qualification.yml",
        "certops-filesystem-qualification.yml",
        "certops-nginx-qualification.yml",
        "certops-dns-provider-qualification.yml",
        "certops-dns-routing-qualification.yml",
        "certops-dns-provider-errors.yml",
        "certops-migration-upgrade.yml",
    )
}
MAX_ARCHIVE = 20 * 1024 * 1024
MAX_REPORT = 2 * 1024 * 1024
MAX_TOTAL_DOWNLOAD = 512 * 1024 * 1024
MAX_ARTIFACTS_PER_RUN = 100
MAX_MATRIX_SLOTS = 512
MAX_COLLECTION_ITEMS = 1024


def collection_limits(slot_count):
    """Grow collection headroom with committed coverage, never with remote input.

    Absolute item/byte caps remain independent of the matrix. More than 512
    slots requires an explicit reviewed collection-policy change before labs.
    """
    if type(slot_count) is not int or not 1 <= slot_count <= MAX_MATRIX_SLOTS:
        raise ValueError("Committed matrix slot count exceeds collection policy")
    return {"runs": max(100, slot_count * 2),
            "archives": max(200, slot_count * 2),
            "reports": max(200, slot_count * 2)}


def validate_run_ids(run_ids, limits):
    if (not isinstance(run_ids, list) or not 1 <= len(run_ids) <= limits["runs"]
            or any(type(item) is not int or item < 1 for item in run_ids)
            or len(set(run_ids)) != len(run_ids)):
        raise ValueError("Run IDs must be a bounded unique JSON array of positive integers")


def catalog_coverage():
    catalog = json.loads((ROOT / "docs/certops/e2e-scenario-catalog.json").read_text())
    rows = catalog.get("scenarios")
    if catalog.get("schemaVersion") != 1 or not isinstance(rows, list) or not rows:
        raise ValueError("Invalid committed scenario catalog")
    counts = {"total": len(rows), "planned": 0, "partial": 0, "implemented": 0}
    for row in rows:
        if row.get("status") not in ("planned", "partial", "implemented"):
            raise ValueError("Invalid catalog implementation status")
        counts[row["status"]] += 1
    return {**counts, "implementationStatus": "all-specifications-implemented" if counts["implemented"] == counts["total"] else "incomplete", "executionEvidence": "reported-separately"}


def validate_matrix_summary(value, candidate, environments, coverage):
    if (not isinstance(value, dict) or value.get("schemaVersion") != 1
            or value.get("status") != "passed" or value.get("candidateSha") != candidate
            or value.get("mandatoryEnvironments") != environments
            or value.get("qualificationScope") != "committed-mandatory-matrix"
            or value.get("allFeaturesQualified") is not False
            or value.get("catalogCoverage") != coverage):
        raise ValueError("Matrix summary cannot promote incomplete feature specifications")


def validate_run(run, candidate, repository):
    if (run.get("status") != "completed" or run.get("conclusion") != "success"
            or run.get("head_sha") != candidate or run.get("head_branch") != "main"
            or run.get("repository", {}).get("full_name") != repository
            or run.get("head_repository", {}).get("full_name") != repository
            or run.get("path") not in WORKFLOWS
            or run.get("event") not in ("push", "workflow_dispatch")):
        raise ValueError("Selected run is not successful trusted-main candidate qualification")


def migration_evidence(value):
    """Retain only bounded public source/schema facts required by its verifier."""
    def text(raw, expression):
        if not isinstance(raw, str) or not re.fullmatch(expression, raw):
            raise ValueError("Invalid public migration identity")
        return raw
    identity = {}
    for kind in ("baseline", "candidate"):
        source = value.get("sourceIdentity", {}).get(kind, {})
        identity[kind] = {
            "sha": text(source.get("sha"), r"[a-f0-9]{40}"),
            "lockfileSha256": text(source.get("lockfileSha256"), r"[a-f0-9]{64}"),
            "version": text(source.get("version"), r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]{1,80})?"),
        }
    result = {"sourceIdentity": identity, "sourceProvenance": text(value.get("sourceProvenance"), r"historical-source-build-to-candidate-source")}
    runtime = value.get("databaseRuntime", {})
    result["databaseRuntime"] = {
        "imageId": text(runtime.get("imageId"), r"sha256:[a-f0-9]{64}"),
        "serverVersion": text(runtime.get("serverVersion"), r"\d+\.\d+(?:\.\d+)?"),
    }
    for name in ("baselineSchema", "candidateSchema"):
        schema = value.get(name, {})
        migrations = schema.get("migrations")
        if not isinstance(migrations, list) or not 0 < len(migrations) <= 4096:
            raise ValueError("Invalid migration inventory size")
        rows = []
        for row in migrations:
            version = row.get("version")
            if not ((type(version) is int and 0 <= version <= 100000) or
                    (isinstance(version, str) and re.fullmatch(r"\d{1,6}", version))):
                raise ValueError("Invalid migration version")
            rows.append({"version": version, "name": text(row.get("name"), r"[A-Za-z0-9_.-]{1,160}")})
        counts = {key: schema.get(key) for key in ("tables", "columns")}
        if any(type(count) is not int or not 0 < count <= 1000000 for count in counts.values()):
            raise ValueError("Invalid schema counts")
        result[name] = {**counts, "migrations": rows}
    for name in ("actualTlsObservedPromotion", "repeatMigrationSchemaUnchanged"):
        if type(value.get(name)) is not bool:
            raise ValueError("Invalid migration transition evidence")
        result[name] = value[name]
    return result


def declared_sources():
    slots = json.loads((ROOT / "docs/certops/release-qualification-matrix.json").read_text())["slots"]
    declared = {source for slot in slots for source in slot.get("requiredSources", [])}
    declared.update(slot["source"] for slot in slots if "source" in slot)
    groups = json.loads((ROOT / "tests/integration/certops-qualification-groups.json").read_text())
    declared.update("tests/integration/" + file for group in groups.values() for file in group["files"])
    return declared


def source_fingerprint(value):
    if (not isinstance(value, dict) or value.get("file") not in declared_sources()
            or not isinstance(value.get("sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", value["sha256"])):
        raise ValueError("Invalid committed source fingerprint")
    return {"file": value["file"], "sha256": value["sha256"]}


def public_environment(value):
    """Project measured, bounded facts; never retain arbitrary probe metadata."""
    if not isinstance(value, dict):
        raise ValueError("Invalid qualification environment")
    patterns = {
        "osFamily": r"windows|linux", "measurement": r"native",
        "osVersion": r"[0-9][A-Za-z0-9_.+-]{0,95}|desktop-[0-9]{1,8}|unsupported",
        "distribution": r"[A-Za-z0-9_.-]{1,40}",
        "distributionId": r"[a-z0-9_.-]{1,32}",
        "distributionVersion": r"[0-9][A-Za-z0-9_.-]{0,31}",
        "nativeLanguage": r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8}){0,3}",
        "identity": r"LocalSystem|uid:[0-9]{1,10}",
        "build": r"[0-9]{1,8}",
        "keyProfile": r"rsa-(?:2048|3072|4096)|ec-p(?:256|384)",
        "keyAlgorithm": r"rsa|ecdsa", "executionSurface": r"host|container|disposable-container|disposable-vm",
        "libc": r"glibc|musl|unknown", "architecture": r"x64|arm64|ia32",
        "dnsProvider": r"[a-z][a-z0-9-]{0,31}",
    }
    result = {}
    for key, pattern in patterns.items():
        if key not in value:
            continue
        raw = value[key]
        if not isinstance(raw, str):
            raise ValueError("Invalid qualification environment field type")
        if key == "identity" and not re.fullmatch(pattern, raw):
            continue  # Host-only administrators are not a release identity claim.
        if not re.fullmatch(pattern, raw):
            raise ValueError("Invalid qualification environment field")
        result[key] = raw
    for key, allowed in (("productType", (1, 2, 3)), ("keySize", (256, 384, 2048, 3072, 4096))):
        if key in value:
            if type(value[key]) is not int or value[key] not in allowed:
                raise ValueError("Invalid native environment numeric field")
            result[key] = value[key]
    return result


def supporting_sources(value):
    declared = declared_sources()
    # Full native AD CS journeys bind 102 reviewed dependencies including real job-decision UI.
    # Keep an explicit collection ceiling; declared-path and digest checks remain.
    if not isinstance(value, list) or len(value) > 128:
        raise ValueError("Invalid supporting source inventory")
    result, seen = [], set()
    for source in value:
        file = source.get("file") if isinstance(source, dict) else None
        if isinstance(file, str) and (file.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", file) or ".." in re.split(r"[\\/]", file)):
            raise ValueError("Supporting source escaped repository")
        if not isinstance(source, dict) or not isinstance(file, str) or file not in declared:
            continue
        if file in seen:
            raise ValueError("Duplicate supporting source identity")
        seen.add(file)
        if not isinstance(source.get("sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", source["sha256"]):
            raise ValueError("Invalid supporting source fingerprint")
        result.append({"file": source["file"], "sha256": source["sha256"]})
    return result


def windows_public_issuance(value):
    if not isinstance(value, dict):
        raise ValueError("Invalid Windows public issuance evidence")
    result = {}
    for field in ("anonymousAdmissionRefused", "viewerAdmissionRefused", "authorizedAdmissionCreated", "idempotentSameJob", "publicRequesterPreserved", "serverDerivedOsStoreKeyMode", "publicPayloadPreserved", "nativeJobSucceeded", "nativeCngIisTrustedTlsVerified", "ownedActorCleanup"):
        if value.get(field) is not True:
            raise ValueError("Incomplete Windows public issuance evidence")
        result[field] = True
    for field, allowed in (("anonymousStatus", (401, 403)), ("viewerStatus", (403,)), ("createStatus", (201,)), ("replayStatus", (201,))):
        if type(value.get(field)) is not int or value[field] not in allowed:
            raise ValueError("Invalid Windows public issuance status")
        result[field] = value[field]
    for field, expected in (("source", "api"), ("mode", "real"), ("authorizedRole", "workspace_manager")):
        if value.get(field) != expected:
            raise ValueError("Invalid Windows public issuance provenance")
        result[field] = expected
    return result


def adcs_capacity_fields(proof):
    flags = ("freshConfirmedIssuer", "actualPostConfirmationPreflight", "sixConcurrentPublicRequests", "fivePersistedPendingApprovals", "sixthTransactionRolledBack", "noCaRequestsBeforeApproval", "noNativeKeysBeforeApproval", "distinctAuthorizedApprover", "firstNativeCompletionFreesSlot", "refusedSubjectReenteredPublicly", "twoClaimBoundNativeInstallations", "twoDistinctOwnedCaRequests", "twoNonexportableMachineKeys", "twoNativeIisAndTrustedTls", "fourUnapprovedJobsPubliclyRejected", "approvalSettingRestored")
    if not isinstance(proof, dict) or proof.get("scope") != "actual-native-adcs-per-issuer-five-public-approvals-and-terminal-release" or any(proof.get(flag) is not True for flag in flags):
        raise ValueError("Incomplete native AD CS capacity evidence")
    result = {"scope": proof["scope"], **dict.fromkeys(flags, True)}
    for field, expected in (("cap", 5), ("initialAccepted", 5), ("initialRefused", 1), ("nativeCompleted", 2)):
        if type(proof.get(field)) is not int or proof[field] != expected:
            raise ValueError("Invalid native AD CS capacity count")
        result[field] = expected
    uuid = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    for field, pattern in (("requestIds", r"[1-9][0-9]{0,9}"), ("fingerprints", r"[a-f0-9]{64}"), ("enrollmentIds", uuid), ("jobIds", uuid)):
        values = proof.get(field)
        if not isinstance(values, list) or len(values) != 2 or any(not isinstance(value, str) or not re.fullmatch(pattern, value) for value in values) or len(set(values)) != 2:
            raise ValueError("Invalid distinct native AD CS capacity identities")
        result[field] = list(values)
    if any(int(value) > 0xffffffff for value in result["requestIds"]):
        raise ValueError("Invalid native AD CS capacity request bound")
    return result


def browser_cancel_fields(proof):
    flags = ['additionalSequentialPublicRenewal', 'requestedPendingApprovalObserved', 'newJobNeverClaimed', 'exactPublicCancelAcknowledged', 'browserAndTrustDrained', 'onlyNewEnrollmentAndJobCancelled', 'oldInstalledEnrollmentUnchanged', 'oldProtectedCngAndIisUnchanged', 'oldTrustedTlsUnchanged', 'newContainerAndJournalAbsent', 'subjectCaRequestsUnchanged', 'exactHumanCancelAudit', 'capacitySlotReleased', 'cleanupOwnershipRegistered']
    if not isinstance(proof, dict) or proof.get("scope") != 'browser-cancel-requested-approval-gated-renewal-preserves-issued-native-custody' or any(proof.get(flag) is not True for flag in flags):
        raise ValueError("Missing native browser requested cancellation evidence")
    result = {"scope": proof["scope"], **dict.fromkeys(flags, True)}
    for key in ("enrollmentId", "jobId", "priorEnrollmentId", "priorJobId", "priorRequestId", "fingerprint"):
        pattern = r"[a-f0-9]{64}" if key == "fingerprint" else r"[1-9][0-9]{0,9}" if key == "priorRequestId" else r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
        if not isinstance(proof.get(key), str) or not re.fullmatch(pattern, proof[key]):
            raise ValueError("Invalid browser requested cancellation identity")
        result[key] = proof[key]
    if int(result["priorRequestId"]) > 0xffffffff or len({result[key] for key in ("enrollmentId", "jobId", "priorEnrollmentId", "priorJobId")}) != 4:
        raise ValueError("Invalid browser cancellation request/UUID bounds")
    for key, expected in (("cancelPosts", 1), ("otherMutations", 0), ("capacityBeforeCancel", 5), ("capacityAfterCancel", 4)):
        if type(proof.get(key)) is not int or proof[key] != expected:
            raise ValueError("Invalid browser cancellation mutation/capacity count")
        result[key] = expected
    for key in ("initialSixConcurrencyQualified", "caSubmissionCancellationQualified"):
        if proof.get(key) is not False:
            raise ValueError("Browser cancellation scope cannot be promoted")
        result[key] = False
    return result


def issued_revocation_fields(proof):
    flags = ["matchingNativePositiveControl","actualOwnedPendingRequest","actualCaSignatureAndOnlineRevoked","sameRequestCsrSpkiAndTemplate","actualOnlineChainValidBeforeRevocation","nativePendingIdentityBeforeManualDispatch","realRevokedLeafReachedProductionValidation","productionSignedContinuationRefused","rejectedBeforeCertificateAccept","predecessorBindingTlsAndCngUnchanged","unacceptedKeyRemovedAndJournalPreserved","noCaResubmission","ownedCaRequestRevoked","cleanupOwnershipRegistered"]
    if not isinstance(proof, dict) or proof.get("scope") != "actual-ca-issued-owned-revoked-leaf-refused-before-accept" or proof.get("errorCode") != "ADCS_CERTIFICATE_INVALID" or proof.get("schedulerDefaultClockQualified") is not False or any(proof.get(flag) is not True for flag in flags):
        raise ValueError("Incomplete native issued revocation refusal")
    result = {"scope": proof["scope"], "errorCode": proof["errorCode"], "schedulerDefaultClockQualified": False, **dict.fromkeys(flags, True)}
    for key in ("requestId", "enrollmentId", "continuationJobId"):
        value = proof.get(key)
        pattern = r"[1-9][0-9]{0,9}" if key == "requestId" else r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError("Invalid native issued revocation identity")
        result[key] = value
    if int(result["requestId"]) > 0xffffffff:
        raise ValueError("Invalid native revocation request bound")
    return result


def issued_san_fields(proof):
    flags = ["matchingNativePositiveControl","actualOwnedPendingCaMutation","actualCaSignature","sameRequestCsrSpkiAndTemplate","exactUnauthorizedDnsSan","productionSignedContinuationRefused","rejectedBeforeCertificateAccept","predecessorBindingTlsAndCngUnchanged","unacceptedKeyRemovedAndJournalPreserved","noCaResubmission","ownedCaRequestRevoked","cleanupOwnershipRegistered"]
    if not isinstance(proof, dict) or proof.get("scope") != "actual-ca-issued-owned-wrong-san-refused-before-accept" or proof.get("errorCode") != "ADCS_CERTIFICATE_INVALID" or any(proof.get(flag) is not True for flag in flags):
        raise ValueError("Incomplete native issued SAN refusal")
    result = {"scope": proof["scope"], "errorCode": proof["errorCode"], **dict.fromkeys(flags, True)}
    for key in ("requestId", "enrollmentId", "continuationJobId"):
        value = proof.get(key)
        pattern = r"[1-9][0-9]{0,9}" if key == "requestId" else r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError("Invalid native issued SAN identity")
        result[key] = value
    if int(result["requestId"]) > 0xffffffff:
        raise ValueError("Invalid native SAN request bound")
    return result


def browser_reconcile_fields(proof):
    flags = ["actualUncertainRequestIdForm","invalidRequestIdDidNotMutate","exactOwnedRequestIdPosted","exactPublicReconcileAcknowledged","browserAndTrustDrained","nativeSelectedRequestInstalled","nativeSameProtectedMachineKey","nativeClaimBoundVerification","nativeExactReconcileAudit","unusedOwnedRequestRevoked","unusedLeafNeverAccepted","originalOrphanPreserved"]
    if not isinstance(proof, dict) or proof.get("scope") != "browser-requestid-reconcile-real-operator-created-same-csr-ambiguity" or proof.get("fixtureOrigin") != "operator-created-two-real-system-submissions-of-the-same-public-csr" or any(proof.get(flag) is not True for flag in flags):
        raise ValueError("Incomplete native browser reconciliation evidence")
    result = {"scope": proof["scope"], "fixtureOrigin": proof["fixtureOrigin"], **dict.fromkeys(flags, True)}
    for key in ("enrollmentId", "continuationJobId", "selectedFingerprint", "selectedRequestId", "unusedRequestId"):
        pattern = r"[a-f0-9]{64}" if key == "selectedFingerprint" else r"[1-9][0-9]{0,9}" if key.endswith("RequestId") else r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError("Invalid native browser reconciliation identity")
        result[key] = value
    if any(int(result[key]) > 0xffffffff for key in ("selectedRequestId", "unusedRequestId")) or result["selectedRequestId"] == result["unusedRequestId"]:
        raise ValueError("Invalid native browser reconciliation requests")
    for key, expected in (("reconcilePosts", 1), ("invalidRequestPosts", 0)):
        if type(proof.get(key)) is not int or proof[key] != expected:
            raise ValueError("Invalid browser reconciliation mutation count")
        result[key] = expected
    return result


def browser_admin_boundary_fields(proof):
    flags = ["distinctOwnedNonownerActors","noGlobalAdminBypassAssumed","publicManagerViewerManagerTransitions","managerAndViewerUiDenied","bothRolesReconcileAndAbandonForbidden","publicOwnerAdminPatchDemotionRefused","exactOwnerAdminUnchanged","actualUncertainEnrollmentAndJobsUnchanged","nativeCaAndUnacceptedKeyUnchanged","servingNativeCustodyAndTrustedTlsUnchanged","targetCertOpsAuditUnchanged","exactMembershipAudits","managerMembershipRestored","browserAndTrustDrained"]
    if not isinstance(proof, dict) or proof.get("scope") != "public-manager-viewer-adcs-admin-boundary-not-mounted-admin-withdrawal" or proof.get("mountedAdminWithdrawalQualified") is not False or any(proof.get(flag) is not True for flag in flags):
        raise ValueError("Incomplete supported browser role-boundary evidence")
    enrollment = proof.get("enrollmentId")
    if not isinstance(enrollment, str) or not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", enrollment):
        raise ValueError("Invalid browser role-boundary enrollment")
    result = {"scope": proof["scope"], "enrollmentId": enrollment, "mountedAdminWithdrawalQualified": False, **dict.fromkeys(flags, True)}
    for key, expected in (("forbiddenMutations", 4), ("roleChanges", 2), ("adminDemotions", 0)):
        if type(proof.get(key)) is not int or proof[key] != expected:
            raise ValueError("Invalid browser role-boundary counts")
        result[key] = expected
    return result


def browser_job_approval_fields(proof):
    flags = ["twoDistinctOwnedPendingJobs","distinctManagerApprover","exactJobVisibleInActualDashboard","cancelDidNotMutate","twoExactPublicApprovalPosts","appendOnlyDecisionsBoundToActor","payloadAndCanonicalIntentHashesVerified","browserAndTrustDrained","sameApprovedJobsInstalledNatively","capacityGenerationsCrossBound","oneExactPublicRejectionPost","rejectedJobNeverClaimedOrSubmitted","rejectedIntentAndNativeAbsencePreserved"]
    if not isinstance(proof, dict) or proof.get("scope") != "browser-control-plane-job-approval-for-two-real-adcs-capacity-installations" or proof.get("caOfficerApprovalQualified") is not False or any(proof.get(flag) is not True for flag in flags):
        raise ValueError("Incomplete actual browser job decision evidence")
    result = {"scope": proof["scope"], "caOfficerApprovalQualified": False, **dict.fromkeys(flags, True)}
    for key, expected in (("approvePosts", 2), ("rejectPosts", 1), ("cancelPosts", 0)):
        if type(proof.get(key)) is not int or proof[key] != expected: raise ValueError("Invalid browser job decision count")
        result[key] = expected
    for key, pattern in (("jobIds", r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"), ("enrollmentIds", r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"), ("payloadHashes", r"[a-f0-9]{64}"), ("requestIds", r"[1-9][0-9]{0,9}"), ("fingerprints", r"[a-f0-9]{64}")):
        values = proof.get(key)
        if not isinstance(values, list) or len(values) != 2 or any(not isinstance(value, str) or not re.fullmatch(pattern, value) for value in values) or len(set(values)) != 2: raise ValueError("Invalid browser job decision identities")
        result[key] = list(values)
    if any(int(value) > 0xffffffff for value in result["requestIds"]): raise ValueError("Invalid browser job CA request bound")
    for key in ("rejectedJobId", "rejectedEnrollmentId", "rejectedPayloadHash", "rejectedCanonicalIntentHash"):
        value = proof.get(key)
        pattern = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}" if key.endswith("Id") else r"[a-f0-9]{64}"
        if not isinstance(value, str) or not re.fullmatch(pattern, value): raise ValueError("Invalid browser rejection identity")
        result[key] = value
    if result["rejectedJobId"] in result["jobIds"] or result["rejectedEnrollmentId"] in result["enrollmentIds"]: raise ValueError("Rejected job cannot be an installed approved generation")
    return result


def ipv6_wildcard_fields(proof):
    """Native IPv6 wildcard only; no concrete-only or IPv4 wildcard substitution."""
    flags = ['actualIpv6LoopbackAvailable', 'borrowedCertificatesVerified', 'actualIpv6ShadowObserved', 'productionPrecedenceWarning', 'actualProductionVerifyFailed', 'actualProductionRollback', 'nativeHostnameEndpointRestored', 'trustedIpv6ShadowObserved', 'trustedIpv6BaselineRecovered', 'ipv4SiblingUnchanged', 'ownedSitesAndEndpointsRemoved']
    if (not isinstance(proof, dict) or proof.get("scope") != 'native-ipv6-wildcard-sni-shadow-rollback-with-ipv4-sibling'
            or proof.get("installedAgentQualified") is not False or proof.get("caQualified") is not False
            or any(proof.get(key) is not True for key in flags)):
        raise ValueError("Incomplete native IPv6 wildcard rollback evidence")
    return {"scope": proof["scope"], "installedAgentQualified": False, "caQualified": False, **dict.fromkeys(flags, True)}


def ipv6_shadow_fields(proof):
    """Concrete IPv6 native rollback only; no installed-agent or CA promotion."""
    flags = ['actualIpv6LoopbackAvailable', 'borrowedCertificatesVerified', 'actualIpv6ShadowObserved', 'productionPrecedenceWarning', 'actualProductionVerifyFailed', 'actualProductionRollback', 'nativeHostnameEndpointRestored', 'trustedIpv6ShadowObserved', 'trustedIpv6BaselineRecovered', 'ipv4SiblingUnchanged', 'ownedSitesAndEndpointsRemoved']
    if (not isinstance(proof, dict) or proof.get("scope") != 'native-ipv6-sni-shadow-rollback-with-ipv4-sibling'
            or proof.get("installedAgentQualified") is not False or proof.get("caQualified") is not False
            or any(proof.get(key) is not True for key in flags)):
        raise ValueError("Incomplete native IPv6 shadow rollback evidence")
    return {"scope": proof["scope"], "installedAgentQualified": False, "caQualified": False, **dict.fromkeys(flags, True)}


def orphan_journal_fields(proof):
    """Native local prerequisites only; never installed/CA/age qualification."""
    flags = ['actualPreparedCngCsr', 'actualUnresolvedJobPrerequisites', 'unprotectedNativeOrphanRemoved', 'openJournalKeyPreserved', 'corruptJournalFailsClosed', 'exactJournalBytesRestored', 'untrackedNativeKeyPreserved', 'independentPrivateKeyPossession', 'actualGlobalStoreInventory', 'terminalFixtureClosureAllowsCleanup', 'ownedNativeKeysAndStateRemoved']
    unsupported = ("installedServiceQualified", "caEnrollmentQualified", "orphanAgePolicyQualified")
    if (not isinstance(proof, dict) or proof.get("scope") != 'native-cng-supporting-prepared-journal-orphan-protection'
            or any(proof.get(key) is not False for key in unsupported)
            or any(proof.get(key) is not True for key in flags)):
        raise ValueError("Incomplete native orphan journal protection evidence")
    return {"scope": proof["scope"], **dict.fromkeys(unsupported, False), **dict.fromkeys(flags, True)}


def journal_acl_fields(proof):
    fields = ["genuinePreparedPublicCsr","twoActualNativeAccessDenials","journalUnreadableNotAbsent","globalProtectionScanDeferred","exactFileIdentitiesAndBytesPreserved","exactNativeAclsRestored","productionReadersRecovered","ownedTemporaryStateRemoved"]
    if (not isinstance(proof, dict) or proof.get("scope") != "native-temporary-adcs-journal-acl-refusals-not-installed-enrollment"
            or proof.get("installedServiceQualified") is not False or proof.get("nativeCngQualified") is not False
            or any(proof.get(field) is not True for field in fields)):
        raise ValueError("Incomplete native temporary journal ACL refusal evidence")
    return {"scope": proof["scope"], "installedServiceQualified": False, "nativeCngQualified": False, **dict.fromkeys(fields, True)}


def required_template_attribute_fields(proof):
    """Only actual zero/missing required LDAP attribute observations qualify."""
    flags = ('knownSafeNativeControlBefore', 'restorationRegisteredBeforeMutation', 'actualLdapMutationObserved', 'actualNativePreflightUnreadable', 'publicConfirmationRefused', 'signedInstalledJobRefused', 'noCaRequestOrCngAllocation', 'installedPredecessorPreserved', 'exactOriginalAttributesRestored', 'freshNativeSafeControlAfter', 'originalConfigCredentialPreserved')
    if not isinstance(proof, dict) or proof.get("scope") != 'actual-ldap-required-template-attribute-refusal-and-exact-native-restoration':
        raise ValueError("Invalid required template attribute scope")
    fingerprint, oid, cases = proof.get("predecessorFingerprint"), proof.get("templateOid"), proof.get("cases")
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", fingerprint) or not isinstance(oid, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", oid) or not isinstance(cases, list) or len(cases) != 2:
        raise ValueError("Invalid required template attribute identities")
    result = {"scope": proof["scope"], "predecessorFingerprint": fingerprint, "templateOid": oid, "cases": []}
    ids = set()
    for item, expected in zip(cases, (("minimum-key-zero", "minimalKeySize", 0), ("subject-name-flag-absent", "enrolleeSuppliesSubject", None))):
        if not isinstance(item, dict) or any(item.get(key) is not True for key in flags) or item.get("caseId") != expected[0] or item.get("observedField") != expected[1] or item.get("preflightVerdict") != "unreadable" or item.get("reason") != "template_unreadable":
            raise ValueError("Incomplete live required template refusal/restoration")
        observed = item.get("observedValue")
        if "observedValue" not in item or (expected[2] is None and observed is not None) or (expected[2] == 0 and expected[2] is not None and (type(observed) is not int or observed != 0)):
            raise ValueError("Wrong actual zero/null template observation")
        bounded = {"caseId": expected[0], "observedField": expected[1], "observedValue": expected[2], "preflightVerdict": "unreadable", "reason": "template_unreadable", **dict.fromkeys(flags, True)}
        for key in ("enrollmentId", "jobId"):
            value = item.get(key)
            if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value) or value in ids:
                raise ValueError("Invalid or reused required template job identity")
            ids.add(value); bounded[key] = value
        result["cases"].append(bounded)
    return result


def public_foreign_spki_fields(proof):
    """Bounded public projection of actual signed foreign-key candidate refusal."""
    flags = ('ownedRequestRegisteredBeforeSubmit', 'softwarePrivateKeyRemovedBeforeSubmit', 'sameActualCaAndSystemRequester', 'sameAuthorizedSanAndTemplate', 'differentOwnedCnAndSpki', 'actualPublicProposalAccepted', 'actualSignedSpkiMismatchRefusal', 'originalUncertainJournalAndWatermarkPreserved', 'originalCngPossessionPreserved', 'noForeignCertificateAccepted', 'servingSiblingTrustedTlsPreserved', 'noAdditionalCaSubmissionOnRefusal', 'exactUnusedForeignRequestRevoked', 'matchingCandidatePositiveRecovery', 'cleanupOwnershipResolved')
    if not isinstance(proof, dict) or proof.get("scope") != 'public-uncertain-request-rejects-owned-same-san-foreign-spki-before-positive-recovery' or any(proof.get(key) is not True for key in flags):
        raise ValueError("Incomplete public foreign SPKI evidence")
    result = {"scope": proof["scope"], **dict.fromkeys(flags, True)}
    for key in ("enrollmentId", "failedJobId"):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value):
            raise ValueError("Invalid public foreign SPKI identity")
        result[key] = value
    if result["enrollmentId"] == result["failedJobId"]:
        raise ValueError("Repeated public foreign SPKI identity")
    for key in ("foreignRequestId", "selectedRequestId"):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,9}", value) or int(value) > 0xffffffff:
            raise ValueError("Invalid public foreign SPKI request")
        result[key] = value
    if result["foreignRequestId"] == result["selectedRequestId"]:
        raise ValueError("Foreign request cannot be installed")
    for key in ("foreignFingerprint", "selectedFingerprint", "foreignSpkiSha256", "originalSpkiSha256", "foreignCsrSha256"):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("Invalid public foreign SPKI digest")
        result[key] = value
    if result["foreignFingerprint"] == result["selectedFingerprint"] or result["foreignSpkiSha256"] == result["originalSpkiSha256"]:
        raise ValueError("Foreign and original native identities must differ")
    floor = proof.get("reconcileSearchFrom")
    if type(floor) is not int or not 1 <= floor <= 0xffffffff or int(result["foreignRequestId"]) < floor:
        raise ValueError("Invalid original reconciliation floor")
    if type(proof.get("foreignSubjectRequestCount")) is not int or proof["foreignSubjectRequestCount"] != 1 or type(proof.get("originalSubjectRequestCount")) is not int or proof["originalSubjectRequestCount"] != 2:
        raise ValueError("Invalid actual foreign/original request counts")
    result.update(reconcileSearchFrom=floor, foreignSubjectRequestCount=1, originalSubjectRequestCount=2)
    return result


def pending_ca_key_change_fields(proof):
    """Actual pending refusal after CA rekey plus fresh same-issuer recovery; public projection only."""
    flags = ('actualPendingBeforeRekey', 'pendingNativeSignatureVerified', 'actualSingleNewKeyRekey', 'originalSnapshotNeverRepinned', 'signedContinuationRefusedChangedKey', 'oldUnacceptedKeyRemoved', 'oldRequestDeniedByOwnedOfficer', 'oldRequestNeverResubmitted', 'predecessorCustodyAndTlsPreserved', 'sameIssuerPublicReconfirmed', 'freshSnapshotAndCngKey', 'freshActualPendingApproved', 'freshSignedNativeInstallation', 'claimBoundNativeEvidence', 'nativeIisAndTrustedTls', 'registeredCleanupResolved')
    if not isinstance(proof, dict) or proof.get("scope") != 'real-pending-request-refused-across-ca-new-key-and-fresh-reconfirmation' or proof.get("schedulerClock") != "supported-scheduler-now-input" or proof.get("backgroundWorkerIntervalQualified") is not False or any(proof.get(key) is not True for key in flags):
        raise ValueError("Incomplete pending CA new-key evidence")
    result = {"scope": proof["scope"], "schedulerClock": proof["schedulerClock"], "backgroundWorkerIntervalQualified": False, **dict.fromkeys(flags, True)}
    ids = ('issuerId', 'oldEnrollmentId', 'oldOriginalJobId', 'oldContinuationJobId', 'freshEnrollmentId', 'freshOriginalJobId', 'freshContinuationJobId', 'preflightJobId')
    for key in ids:
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value):
            raise ValueError("Invalid pending CA new-key identity")
        result[key] = value
    if len({result[key] for key in ids}) != len(ids):
        raise ValueError("Repeated pending CA new-key identity")
    for key in ("oldRequestId", "freshRequestId"):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,9}", value) or int(value) > 0xffffffff:
            raise ValueError("Invalid pending CA new-key request")
        result[key] = value
    if result["oldRequestId"] == result["freshRequestId"]:
        raise ValueError("Fresh recovery must use a new request")
    for key in ('oldCaKeySha256', 'newCaKeySha256', 'oldSnapshotSha256', 'freshSnapshotSha256', 'oldSpkiSha256', 'freshSpkiSha256', 'predecessorFingerprint', 'freshFingerprint'):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("Invalid pending CA new-key digest")
        result[key] = value
    for left, right in (("oldCaKeySha256", "newCaKeySha256"), ("oldSnapshotSha256", "freshSnapshotSha256"), ("oldSpkiSha256", "freshSpkiSha256"), ("predecessorFingerprint", "freshFingerprint")):
        if result[left] == result[right]:
            raise ValueError("Recovery generations must be distinct")
    before, after = proof.get("subjectCountBefore"), proof.get("subjectCountAfter")
    if type(before) is not int or not 1 <= before < 2048 or type(after) is not int or after != before + 1:
        raise ValueError("Unexpected pending CA new-key request count")
    result.update(subjectCountBefore=before, subjectCountAfter=after)
    return result


def pending_ca_renewal_fields(proof):
    """Same actual pending request across root CA certificate renewal; no worker-clock claim."""
    flags = ('matchingActualInstalledPredecessor', 'ownedMyCleanupRegistered', 'actualPendingBeforeCaRenewal', 'pendingCngSignatureVerified', 'actualCaSameKeyRenewal', 'confirmedIssuerUnchanged', 'noReconfirmation', 'pendingCsrKeyRequestPreserved', 'predecessorPreservedAcrossCaRenewal', 'actualSameRequestApproved', 'actualSignedContinuationInstalled', 'claimBoundNativeEvidence', 'nativeSamePendingKeyAndLeaf', 'trustedTlsCutover', 'predecessorKeyAndReceiptPreserved', 'noCaResubmission')
    if not isinstance(proof, dict) or proof.get("scope") != 'real-pending-enrollment-across-same-key-ca-certificate-renewal' or proof.get("schedulerClock") != "supported-scheduler-now-input" or proof.get("backgroundWorkerIntervalQualified") is not False or any(proof.get(flag) is not True for flag in flags):
        raise ValueError("Incomplete native pending CA renewal evidence")
    result = {"scope": proof["scope"], "schedulerClock": proof["schedulerClock"], "backgroundWorkerIntervalQualified": False, **dict.fromkeys(flags, True)}
    for key in ("enrollmentId", "originalJobId", "continuationJobId"):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value):
            raise ValueError("Invalid native pending CA renewal identity")
        result[key] = value
    if len({result[key] for key in ("enrollmentId", "originalJobId", "continuationJobId")}) != 3:
        raise ValueError("Duplicate native pending CA renewal identities")
    request_id = proof.get("requestId")
    if not isinstance(request_id, str) or not re.fullmatch(r"[1-9][0-9]{0,9}", request_id) or int(request_id) > 0xffffffff:
        raise ValueError("Invalid pending native CA request")
    result["requestId"] = request_id
    for key in ("caKeySha256", "csrSha256", "spkiSha256", "leafFingerprint", "predecessorFingerprint"):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("Invalid pending native CA fingerprint")
        result[key] = value
    if result["leafFingerprint"] == result["predecessorFingerprint"]:
        raise ValueError("Pending renewal must install a distinct leaf")
    for key in ("caCertificateCountBefore", "caCertificateCountAfter"):
        value = proof.get(key)
        if type(value) is not int or not 1 <= value <= 16:
            raise ValueError("Invalid actual CA certificate count")
        result[key] = value
    if result["caCertificateCountAfter"] <= result["caCertificateCountBefore"]:
        raise ValueError("No actual CA certificate renewal")
    return result


def browser_abandon_fields(proof):
    flags = ("actualUncertainEnrollmentVisible","keepDidNotMutate","explicitConfirmationRequired","exactPublicAbandonAcknowledged","browserAndTrustDrained","actualProductionContinuation","journalAndDatabaseAbandoned","exactUnacceptedKeyAbsent","noAcceptedLeaf","zeroNativeCaRequests","onePublicAudit","originalUnknownEffectPreserved")
    if not isinstance(proof, dict) or proof.get("scope") != "browser-confirmed-real-uncertain-abandon-and-native-unaccepted-key-cleanup" or any(proof.get(flag) is not True for flag in flags):
        raise ValueError("Incomplete native browser abandonment evidence")
    result = {"scope": proof["scope"], **dict.fromkeys(flags, True)}
    for key in ("enrollmentId", "cleanupJobId"):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value):
            raise ValueError("Invalid native browser abandonment identity")
        result[key] = value
    for key, expected in (("abandonPosts", 1), ("keepPosts", 0)):
        if type(proof.get(key)) is not int or proof[key] != expected:
            raise ValueError("Invalid browser abandonment mutation count")
        result[key] = expected
    return result


def webhosting_fields(proof):
    flags = ("publicIssueAndRenewInstalled","twoIndependentCaRequests","freshSerialSpkiAndKey","webHostingProtectedCustody","myCopiesAbsent","exactNativeIisAndHttpSysStore","trustedSniTls","installedDiscoveryInventory","immutableAcceptedStore","predecessorRetentionStorePreserved","storeQualifiedCleanupRegistered")
    if (not isinstance(proof, dict) or proof.get("scope") != "real-adcs-webhosting-issue-and-fresh-key-manual-renewal" or proof.get("store") != "WebHosting" or proof.get("expiryCleanupQualified") is not False or any(proof.get(flag) is not True for flag in flags)):
        raise ValueError("Incomplete native WebHosting renewal evidence")
    result = {"scope": proof["scope"], "store": "WebHosting", "expiryCleanupQualified": False, **dict.fromkeys(flags, True)}
    for field, pattern in (("requestIds", r"[1-9][0-9]{0,9}"), ("fingerprints", r"[a-f0-9]{64}")):
        values = proof.get(field)
        if not isinstance(values, list) or len(values) != 2 or any(not isinstance(value, str) or not re.fullmatch(pattern, value) for value in values) or len(set(values)) != 2:
            raise ValueError("Invalid distinct native WebHosting generations")
        result[field] = list(values)
    if any(int(value) > 0xffffffff for value in result["requestIds"]):
        raise ValueError("Invalid native WebHosting CA request bound")
    return result


def retention24h_fields(value):
    """Public native-day proof only; timer/prepare/source fixtures cannot qualify."""
    proof = value.get("nativeRetention24h")
    flags = ("genuinePublicAdcsCutover", "distinctNativeRequestsAndLeaves", "productionLedger24HourDeadline", "oldExpiryBeyondDeadline", "immutableOriginalPrepareVerified", "sameVmTaskBootAndProcess", "soleInstalledAgentStoppedDrained", "predecessorProtectedCustodyPreserved", "actualPreDeadlinePreserved", "productionDefaultClockCollector", "actualResidentDayElapsed", "oldCertificateActuallyAbsent", "oldKeyActuallyAbsent", "replacementCngIisAndTrustedTlsUnchanged", "immutableLedgerIdentityPreserved", "currentExecutableAndSourceDigestsBound", "independentFinalNativeRecheck", "ownedAzureCleanupVerified")
    if not isinstance(proof, dict) or proof.get("scope") != "actual-domain-adcs-same-process-native-retention24h" or any(proof.get(key) is not True for key in flags):
        raise ValueError("Incomplete actual native retention24h evidence")
    result = {"scope": proof["scope"], **dict.fromkeys(flags, True)}
    uuid = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    for key, pattern in (("candidateSha", r"[a-f0-9]{40}"), ("prepareRunId", r"[1-9][0-9]{0,19}"), ("prepareRunAttempt", r"[1-9][0-9]{0,19}"), ("vmId", uuid), *((key, r"[a-f0-9]{64}") for key in ("nonce", "taskXmlSha256", "configSha256", "nodeSha256", "keeperSha256", "collectorHelperSha256", "ledgerIdentitySha256"))):
        if not isinstance(proof.get(key), str) or not re.fullmatch(pattern, proof[key]):
            raise ValueError("Invalid native retention24h identity")
        result[key] = proof[key]
    for key, low, high in (("processId", 1, 0xffffffff), ("retentionHours", 24, 24), ("monotonicElapsedMs", 86400000, 90000000), ("keptSweepCount", 24, 26), ("maximumSweepGapMs", 1, 3900000)):
        if type(proof.get(key)) is not int or not low <= proof[key] <= high:
            raise ValueError("Invalid native retention24h measured bound")
        result[key] = proof[key]
    epochs = {}
    for key in ("bootTime", "processCreatedAt", "originalCreatedAt", "verifiedCutoverAt", "oldNotAfter", "cleanupDeadline", "startedAt", "finishedAt", "preDeadlineObservedAt", "cleanupFinishedAt"):
        raw = proof.get(key)
        if not isinstance(raw, str) or len(raw) > 40 or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?(?:Z|[+-][0-9]{2}:[0-9]{2})", raw):
            raise ValueError("Invalid native retention24h actual timestamp")
        try:
            epochs[key] = round(datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp() * 1000)
        except (ValueError, OverflowError):
            raise ValueError("Invalid native retention24h timestamp") from None
        result[key] = raw
    created, cut, deadline, start, end, pre, clean = (epochs[key] for key in ("originalCreatedAt", "verifiedCutoverAt", "cleanupDeadline", "startedAt", "finishedAt", "preDeadlineObservedAt", "cleanupFinishedAt"))
    if (not created <= epochs["bootTime"] <= epochs["processCreatedAt"] <= start
            or not created <= cut <= start or start - cut > 600000 or deadline != cut + 86400000
            or epochs["oldNotAfter"] <= deadline + 3600000 or not start <= pre < deadline < end <= clean <= created + 115200000
            or abs(end - start - proof["monotonicElapsedMs"]) > 5000):
        raise ValueError("Native retention24h elapsed/deadline/expiry scope mismatch")
    for key, pattern in (("requestIds", r"[1-9][0-9]{0,9}"), ("enrollmentIds", uuid), ("jobIds", uuid), ("thumbprints", r"[A-F0-9]{40}"), ("containerNames", "tokentimer-enr-" + uuid), ("fingerprints", r"[a-f0-9]{64}"), ("spkiSha256", r"[a-f0-9]{64}"), ("serialNumbers", r"[a-f0-9]{1,128}")):
        items = proof.get(key)
        if (not isinstance(items, list) or len(items) != 2 or any(not isinstance(item, str) or not re.fullmatch(pattern, item) for item in items) or len({item.lower() for item in items}) != 2):
            raise ValueError("Invalid distinct native retention24h generations")
        result[key] = list(items)
    if any(int(item) > 0xffffffff for item in proof["requestIds"]) or any(proof["containerNames"][i] != "tokentimer-enr-" + proof["enrollmentIds"][i] for i in range(2)):
        raise ValueError("Native retention24h request/key ownership mismatch")
    nested = proof.get("interruptedDelete")
    nested_flags = ("actualDayBeforeNativeMutation", "sameOriginalProductionLedger", "ownedChildExit86", "containedNativeTreeDrained", "nativeCertificateAbsentBeforeResume", "nativeKeyPossessionRetainedBeforeResume", "incompleteLedgerUnchanged", "replacementCustodyAndTrustedTlsPreserved", "ordinaryDefaultClockResumeCompleted", "nativeCertificateAndKeyAbsentAfterResume")
    if (not isinstance(nested, dict) or nested.get("scope") != "actual-day-native-delstore-interruption-and-default-clock-resume"
            or any(nested.get(key) is not True for key in nested_flags)
            or nested.get("productionSixHourCadenceQualified") is not False or nested.get("full168HourRetentionQualified") is not False
            or nested.get("cleanupDeadline") != proof["cleanupDeadline"]
            or type(nested.get("monotonicElapsedBeforeCrashMs")) is not int
            or not 86400000 <= nested["monotonicElapsedBeforeCrashMs"] <= proof["monotonicElapsedMs"]):
        raise ValueError("Incomplete actual real-day native deletion interruption")
    nested_times = {}
    for key in ("interruptedAt", "resumedAt"):
        raw = nested.get(key)
        if not isinstance(raw, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z", raw):
            raise ValueError("Invalid actual retention interruption timestamp")
        try:
            nested_times[key] = round(datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp() * 1000)
        except (ValueError, OverflowError):
            raise ValueError("Invalid actual retention interruption timestamp") from None
    if (not deadline < nested_times["interruptedAt"] <= nested_times["resumedAt"] <= end
            or nested_times["interruptedAt"] < start + nested["monotonicElapsedBeforeCrashMs"] - 5000):
        raise ValueError("Retention interruption differs from original real-day boundary")
    result["interruptedDelete"] = {key: nested[key] for key in ("scope", *nested_flags, "monotonicElapsedBeforeCrashMs", "interruptedAt", "resumedAt", "cleanupDeadline", "productionSixHourCadenceQualified", "full168HourRetentionQualified")}
    return result


def acme_key_reuse_fields(event):
    scopes = ("real-agent-acme-filesystem", "real-agent-acme-eab-filesystem", "real-agent-acmesh-filesystem", "real-agent-acmesh-eab-filesystem", "real-agent-alpine-acmesh")
    if event.get("scope") not in scopes or event.get("name") != "real ACME: agent discovers public files registers claims issues renews deploys and persists independently verified certificate evidence":
        return {}
    value = event.get("nativeAcmeKeyReuse")
    if not isinstance(value, dict):
        raise ValueError("Missing native ACME key reuse proof")
    result = {}
    for field in ("publicProfilePolicyChanged", "manualRenewalSucceeded", "defaultSqlNowRenewalSucceeded", "claimBoundVerification", "unchangedPrivateCustody", "privateMaterialStayedLocal", "unchangedSpki", "distinctCaLeavesAndSerials", "advancingExpiry", "trustedTlsEachGeneration", "dnsCleanEachGeneration", "stableReuseProfile"):
        if value.get(field) is not True:
            raise ValueError("Incomplete native ACME key reuse proof")
        result[field] = True
    for field, expected in (("scope", "real-linux-manual-and-default-scheduler-csr-key-reuse"), ("client", "acme.sh" if "acmesh" in event["scope"] else "certbot")):
        if value.get(field) != expected:
            raise ValueError("Invalid native ACME key reuse scope")
        result[field] = expected
    for field, count, pattern in (("fingerprints", 3, r"[a-f0-9]{64}"), ("serials", 3, r"[A-F0-9]{1,64}"), ("jobIds", 2, r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}")):
        rows = value.get(field)
        if not isinstance(rows, list) or len(rows) != count or not all(isinstance(item, str) and re.fullmatch(pattern, item) for item in rows) or len(set(item.lower() for item in rows)) != count:
            raise ValueError("Invalid native ACME key reuse identity inventory")
        result[field] = list(rows)
    for field, pattern in (("spkiFingerprint", r"[a-f0-9]{64}"), ("sourceProfileFingerprint", r"[a-f0-9]{64}"), ("sourceProfileId", r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}")):
        if not isinstance(value.get(field), str) or not re.fullmatch(pattern, value[field]):
            raise ValueError("Invalid native ACME key reuse source identity")
        result[field] = value[field]
    return {"nativeAcmeKeyReuse": result}


def windows_key_reuse_refusal_fields(event):
    if (not isinstance(event.get("scope"), str) or not event["scope"].startswith("real-agent-windows-acme-iis/")
            or event.get("name") != "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence" or event.get("type") != "test:pass"):
        return {}
    proof = event.get("nativeWindowsKeyReuseRefusal")
    flags = ("publicAdmissionRefused", "profileUnchanged", "noJobAllocated", "nativeInventoryAndCustodyUnchanged", "trustedTlsUnchanged")
    if (not isinstance(proof, dict) or proof.get("scope") != "public-windows-acme-profile-reuse-refusal"
            or any(proof.get(flag) is not True for flag in flags)):
        raise ValueError("Missing public Windows ACME reuse-policy refusal")
    return {"nativeWindowsKeyReuseRefusal": {key: proof[key] for key in ("scope", *flags)}}


def installed_paths_fields(event):
    """Bounded installed Unicode-root facts; private native paths never survive."""
    if (not isinstance(event.get("scope"), str) or not event["scope"].startswith("real-agent-windows-acme-iis/")
            or event.get("name") != "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence" or event.get("type") != "test:pass"):
        return {}
    proof = event.get("nativeInstalledPaths")
    flags = ("ownedRootIdentityPreserved", "exactScmArgumentPaths", "actualSystemHostAndChild", "exactServiceConfigurationPath", "candidateEntryAndHostBytes", "actualSignedIssuance", "claimBoundResultEvidence", "actualCngIisTrustedTls")
    if (not isinstance(proof, dict) or proof.get("scope") != "installed-system-agent-unicode-spaces-literal-brackets-root"
            or any(proof.get(flag) is not True for flag in flags)):
        raise ValueError("Missing actual installed Unicode path proof")
    return {"nativeInstalledPaths": {key: proof[key] for key in ("scope", *flags)}}


def installed_crash_fields(event):
    if (not isinstance(event.get("scope"), str) or not event["scope"].startswith("real-agent-windows-acme-iis/")
            or event.get("name") != "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence" or event.get("type") != "test:pass"):
        return {}
    proof = event.get("nativeInstalledCrash")
    flags = ['retainedNativeHandles', 'freshIdentityReverified', 'capturedHandlesExited', 'capturedLineageAbsent', 'fixtureCommandPathsAbsent', 'fixtureAdjustedLeaseRecovery', 'unresolvedAttemptNotReplayed', 'startupOrphanKeyRemoved', 'priorTrustedTlsPreserved']
    if (not isinstance(proof, dict) or proof.get("scope") != "installed-system-native-handle-crash-fixture-lease-recovery"
            or any(proof.get(flag) is not True for flag in flags)
            or proof.get("atomicTreeContainmentQualified") is not False
            or proof.get("productionLeaseGraceQualified") is not False):
        raise ValueError("Missing actual installed native-handle interruption proof")
    return {"nativeInstalledCrash": {key: proof[key] for key in ("scope", *flags, "atomicTreeContainmentQualified", "productionLeaseGraceQualified")}}


def installed_iis_refusal_fields(event):
    """Project only native public-dispatch refusal facts, never private state."""
    if (not isinstance(event.get("scope"), str) or not event["scope"].startswith("real-agent-windows-acme-iis/")
            or event.get("name") != "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence" or event.get("type") != "test:pass"):
        return {}
    proof = event.get("nativeInstalledIisRefusal")
    flags = ["genuinePriorIssuance","publicDeployAdmitted","sameInstalledAgentClaimedOnce","specificUnsupportedTargetFailure","claimBoundFailureAudit","nativeInventoryAndCustodyUnchanged","bothBindingsAndTrustedTlsUnchanged","actualAcmeClientNotInvoked","dnsTrafficUnchanged","credentialAndPinUnchanged","exactOwnedShadowRemoved"]
    if (not isinstance(proof, dict) or proof.get("scope") != "installed-agent-public-standalone-iis-deploy-refusal"
            or any(proof.get(flag) is not True for flag in flags)
            or any(not isinstance(proof.get(key), str) or not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", proof[key]) for key in ("jobId", "claimId"))):
        raise ValueError("Missing installed-agent public IIS refusal proof")
    return {"nativeInstalledIisRefusal": {key: proof[key] for key in ("scope", "jobId", "claimId", *flags)}}


def installed_handoff_fields(event):
    if (not isinstance(event.get("scope"), str) or not event["scope"].startswith("real-agent-windows-acme-iis/")
            or event.get("name") != "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence" or event.get("type") != "test:pass"):
        return {}
    value = event.get("nativeInstalledStateHandoff")
    flags = ("retiredPredecessorCredentialFenced", "publicConflictBootstrapUnconsumed", "unusedConflictBootstrapRevoked", "publicReplacementBootstrapConsumed", "unmodifiedCliRegisteredReplacement", "registrationChildDrained", "sameInstalledServicePathAndSystemIdentity", "freshReplacementScmHeartbeat", "sourceStateBytesPreserved", "protectedCustodyAndJournalCopiesPreserved", "signingPinPreserved", "nativeCngBindingAndTrustedTlsPreserved", "predecessorJobsNotReplayed", "noBootstrapInServiceRegistry", "replacementRetiredAndServiceStopped", "originalRegistryRestored", "ownedStateRemoved")
    if (not isinstance(value, dict) or value.get("scope") != "explicit-operator-protected-state-installed-scm-handoff-not-automatic-reregistration"
            or any(value.get(flag) is not True for flag in flags)):
        raise ValueError("Missing explicit installed Windows service state handoff")
    return {"nativeInstalledStateHandoff": {key: value[key] for key in ("scope", *flags)}}


def arm64_installed_fields(value):
    """Closed actual installed agent scope, distinct from issuance/IIS and native PG."""
    proof = value.get("nativeArm64InstalledAgent")
    flags = ['canonicalRootAndServiceInitiallyAbsent', 'originalCandidateInstallerUnchanged', 'actualNativeArm64NodePwshAndPackagedHost', 'actualLocalSystemAgentChild', 'publicBootstrapExchangedAndScrubbed', 'authenticatedRegistrationAndHeartbeat', 'actualSignedNoopCompleted', 'actualSignedCertificateDryRunPlan', 'claimBoundPersistedEvidence', 'nativeMyCertificateObservedByAgent', 'exactProtectedMyCustodyUnchanged', 'restartCreatedFreshOwnedProcesses', 'authenticatedHeartbeatAfterRestart', 'configurationCredentialSigningPinPreserved', 'unmodifiedProductUninstall', 'retainedOwnedProcessesDrained', 'completeMachineWideSurvivorGuardBeforeDeletion', 'exactNativeCertificateAndKeyRemoved', 'exactServiceRegistryAndOwnedRootsAbsent']
    excluded = ("issuanceQualified", "iisQualified", "serverQualified", "publicCertificateAdmissionQualified")
    keys = {"scope", "architecture", "productType", "build", "certificateDryRunTarget", "postgresArchitecture", "postgresExecution", "postgresVersion", "postgresArchiveSha256", "candidateArchiveSha256", "hostSha256", "certificateFingerprint", "jobIds", "claimIds", "agentRowId", "serviceCreatedDryRun", *flags, *excluded}
    if not isinstance(proof, dict) or set(proof) != keys or proof.get("scope") != 'native-windows11-arm64-installed-agent-api-signed-file-plan-and-my-discovery' or proof.get("architecture") != "arm64" or type(proof.get("productType")) is not int or proof["productType"] != 1 or any(proof.get(flag) is not True for flag in flags) or any(proof.get(flag) is not False for flag in excluded) or proof.get("serviceCreatedDryRun") is not True:
        raise ValueError("Missing actual native ARM64 installed-agent scope")
    if not isinstance(proof.get("build"), str) or not re.fullmatch(r"[0-9]{5,6}", proof["build"]) or int(proof["build"]) < 22000:
        raise ValueError("Native ARM64 desktop required")
    lock = json.loads((ROOT / "scripts/certops-arm64-postgres-lock.json").read_text(encoding="utf-8"))
    if any(proof.get(key) != expected for key, expected in (("certificateDryRunTarget", "file-path"), ("postgresArchitecture", "x64"), ("postgresExecution", "windows11-x64-emulation"), ("postgresVersion", lock["version"]), ("postgresArchiveSha256", lock["sha256"]))):
        raise ValueError("Unqualified certificate target or PostgreSQL dependency")
    for key in ("candidateArchiveSha256", "hostSha256", "certificateFingerprint"):
        if not isinstance(proof.get(key), str) or not re.fullmatch(r"[a-f0-9]{64}", proof[key]):
            raise ValueError("Invalid actual candidate/native certificate fingerprint")
    uuid = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    if not isinstance(proof.get("agentRowId"), str) or not re.fullmatch(uuid, proof["agentRowId"]):
        raise ValueError("Invalid actual registered agent")
    for key in ("jobIds", "claimIds"):
        rows = proof.get(key)
        if not isinstance(rows, list) or len(rows) != 2 or any(not isinstance(row, str) or not re.fullmatch(uuid, row) for row in rows) or len(set(rows)) != 2:
            raise ValueError("Two distinct actual signed jobs/claims required")
    environment = value.get("qualificationEnvironment", {})
    if value.get("platform") != "win32" or value.get("architecture") != "arm64" or type(environment.get("productType")) is not int or any(environment.get(key) != expected for key, expected in (("osFamily", "windows"), ("productType", 1), ("architecture", "arm64"), ("identity", "LocalSystem"), ("osVersion", "desktop-" + proof["build"]), ("measurement", "native"))) or value.get("cleanup", {}).get("status") != "passed":
        raise ValueError("Native installed report lacks exact desktop/SYSTEM/cleanup binding")
    return {"platform": "win32", "architecture": "arm64", "nativeArm64InstalledAgent": {**proof, "jobIds": list(proof["jobIds"]), "claimIds": list(proof["claimIds"])}}


def arm64_scm_fields(value):
    """Closed measured packaged-host/mock-child scope; no raw command/path receipts."""
    proof = value.get("nativeArm64Scm")
    flags = ['canonicalServiceInitiallyAbsent', 'candidateArchiveDigestVerified', 'packagedHostExactDigestAndArm64Pe', 'nativeArm64DesktopAndRuntimes', 'exactLocalSystemServiceConfiguration', 'actualScmRunningWithOwnedChild', 'stopDrainedExactProcessTree', 'restartCreatedFreshOwnedProcesses', 'nonzeroChildExitTriggeredScmRecovery', 'retiredChildExitStoppedWithoutRespawn', 'exactServiceAndRegistryAbsent', 'allCapturedProcessesAbsent', 'ownedFixtureRemoved', 'originalFileIdentitiesPreserved']
    excluded = ("realAgentQualified", "apiQualified", "fullInstallerQualified", "iisQualified", "serverQualified")
    keys = {"scope", "architecture", "productType", "build", "hostSha256", "archiveSha256", "retirementObservationMs", "generations", *flags, *excluded}
    if not isinstance(proof, dict) or set(proof) != keys or proof.get("scope") != 'native-windows11-arm64-candidate-packaged-servicehost-mockchild-lifecycle' or proof.get("architecture") != "arm64" or type(proof.get("productType")) is not int or proof["productType"] != 1 or any(proof.get(flag) is not True for flag in flags) or any(proof.get(flag) is not False for flag in excluded):
        raise ValueError("Missing native ARM64 packaged SCM mock-child scope")
    if not isinstance(proof.get("build"), str) or not re.fullmatch(r"[0-9]{5,6}", proof["build"]) or int(proof["build"]) < 22000:
        raise ValueError("Actual Windows 11 desktop required")
    if any(not isinstance(proof.get(key), str) or not re.fullmatch(r"[a-f0-9]{64}", proof[key]) for key in ("hostSha256", "archiveSha256")) or type(proof.get("retirementObservationMs")) is not int or not 5000 <= proof["retirementObservationMs"] <= 20000:
        raise ValueError("Invalid native packaged identity/retirement observation")
    environment = value.get("qualificationEnvironment", {})
    if value.get("platform") != "win32" or value.get("architecture") != "arm64" or type(environment.get("productType")) is not int or any(environment.get(key) != expected for key, expected in (("osFamily", "windows"), ("productType", 1), ("architecture", "arm64"), ("osVersion", "desktop-" + proof["build"]), ("measurement", "native"))) or value.get("cleanup", {}).get("status") != "passed":
        raise ValueError("ARM64 SCM report lacks native desktop/cleanup binding")
    rows = proof.get("generations")
    if not isinstance(rows, list) or len(rows) != 3:
        raise ValueError("Three actual SCM process generations required")
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"hostPid", "hostCreated", "childPid", "childCreated"}:
            raise ValueError("Invalid bounded native process identity")
        for key in ("hostPid", "childPid"):
            if type(row.get(key)) is not int or not 0 < row[key] <= 0xffffffff:
                raise ValueError("Invalid actual process PID")
        if row["hostPid"] == row["childPid"]:
            raise ValueError("Host and child must be distinct")
        for prefix in ("host", "child"):
            created = row.get(prefix + "Created")
            if not isinstance(created, str) or not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z", created):
                raise ValueError("Invalid actual process creation timestamp")
            datetime.fromisoformat(created.replace("Z", "+00:00"))
            identity = (row[prefix + "Pid"], created)
            if identity in seen:
                raise ValueError("SCM recovery reused an actual process generation")
            seen.add(identity)
        if datetime.fromisoformat(row["childCreated"].replace("Z", "+00:00")) < datetime.fromisoformat(row["hostCreated"].replace("Z", "+00:00")):
            raise ValueError("Child predates its host")
    return {"platform": "win32", "architecture": "arm64", "nativeArm64Scm": {**proof, "generations": [dict(row) for row in rows]}}


def arm64_runtime_fields(value):
    """Retain only closed native desktop/CNG facts; never raw host inventories."""
    proof = value.get("nativeArm64CngRuntime")
    flags = ("csrSignatureVerified", "csrPublicKeyMatchesLeaf", "dnsSanVerified", "keyUsageVerified", "publicLeafSignatureVerified", "nativeAssociationVerified", "nativeSignatureVerified", "protectedExportDenied", "exportableControlSucceeded", "privateBuffersZeroed", "custodyUnchanged", "machineStoreReferenceFound", "exactReferenceExcluded", "ownedArtifactsAbsent")
    proof_keys = {"scope", "architecture", "helperPeMachine", "helperSha256", "helperExecuted", "serverQualified", "iisQualified", "domainAdcsQualified", "privateCaKeyPersisted", "cleanupCompleted", "cases"}
    if not isinstance(proof, dict) or set(proof) != proof_keys or proof.get("scope") != "native-windows11-arm64-cng-public-fixture":
        raise ValueError("Missing closed native ARM64 CNG proof")
    architecture = proof.get("architecture")
    arch_keys = {"productType", "build", "cpuArchitectures", "platform", "nodeArchitecture", "powershellArchitecture", "goHostArchitecture", "goHostOs", "nodePeMachine", "powershellPeMachine", "goPeMachine", "certreqPeMachine", "certutilPeMachine", "administrator"}
    if not isinstance(architecture, dict) or set(architecture) != arch_keys:
        raise ValueError("Invalid native ARM64 architecture evidence")
    if type(architecture.get("productType")) is not int or architecture["productType"] != 1 or architecture.get("administrator") is not True:
        raise ValueError("ARM64 lane requires actual desktop administrator")
    if not isinstance(architecture.get("build"), str) or not re.fullmatch(r"[0-9]{5,6}", architecture["build"]) or int(architecture["build"]) < 22000:
        raise ValueError("ARM64 lane requires actual Windows 11")
    cpus = architecture.get("cpuArchitectures")
    if not isinstance(cpus, list) or not 1 <= len(cpus) <= 64 or any(type(cpu) is not int or cpu != 12 for cpu in cpus):
        raise ValueError("ARM64 processor measurement unavailable")
    for field, expected in (("platform", "win32"), ("nodeArchitecture", "arm64"), ("powershellArchitecture", "arm64"), ("goHostArchitecture", "arm64"), ("goHostOs", "windows")):
        if architecture.get(field) != expected:
            raise ValueError("Emulated runtime cannot qualify ARM64")
    for field in ("nodePeMachine", "powershellPeMachine", "goPeMachine", "certreqPeMachine", "certutilPeMachine"):
        if type(architecture.get(field)) is not int or architecture[field] != 0xaa64:
            raise ValueError("Mixed PE architectures cannot qualify ARM64")
    if (value.get("platform") != "win32" or value.get("architecture") != "arm64" or json.dumps(value.get("nativeArchitectureProbe"), sort_keys=True) != json.dumps(architecture, sort_keys=True)
            or value.get("qualificationEnvironment") != {"osFamily": "windows", "osVersion": f"desktop-{architecture['build']}", "productType": 1, "measurement": "native", "architecture": "arm64"}):
        raise ValueError("Native ARM64 desktop identity disagrees with report")
    for field in ("serverQualified", "iisQualified", "domainAdcsQualified", "privateCaKeyPersisted"):
        if proof.get(field) is not False:
            raise ValueError("ARM64 proof exceeded desktop CNG scope")
    if proof.get("helperExecuted") is not True or proof.get("cleanupCompleted") is not True or type(proof.get("helperPeMachine")) is not int or proof["helperPeMachine"] != 0xaa64:
        raise ValueError("Actual helper runtime and cleanup are mandatory")
    if not isinstance(proof.get("helperSha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", proof["helperSha256"]):
        raise ValueError("Missing current ARM64 helper digest")
    cases = proof.get("cases")
    if not isinstance(cases, list) or len(cases) != 2 or any(not isinstance(case, dict) for case in cases):
        raise ValueError("Both ARM64 CNG profiles are mandatory")
    if not all(isinstance(case.get("profile"), str) for case in cases) or sorted(case["profile"] for case in cases) != ["ec-p256", "rsa-2048"]:
        raise ValueError("Duplicate or missing ARM64 CNG profile")
    for case in cases:
        if set(case) != {*flags, "profile", "chainVerdict", "wrongPinVerdict", "malformedVerdict", "storesScanned", "privateExportHResult"} or any(case.get(field) is not True for field in flags):
            raise ValueError("Incomplete closed ARM64 CNG observations")
        if case.get("chainVerdict") != "revocation_unknown" or case.get("wrongPinVerdict") != "ca_key_changed" or case.get("malformedVerdict") != "invalid":
            raise ValueError("ARM64 chain verdict scope mismatch")
        if type(case.get("storesScanned")) is not int or not 1 <= case["storesScanned"] <= 512:
            raise ValueError("ARM64 machine-store enumeration unavailable")
        if type(case.get("privateExportHResult")) is not int or not -2147483648 <= case["privateExportHResult"] < 0:
            raise ValueError("ARM64 native export denial unavailable")
    return {"platform": "win32", "architecture": "arm64", "nativeArchitectureProbe": dict(architecture), "nativeArm64CngRuntime": {**proof, "architecture": dict(architecture), "cases": [dict(case) for case in cases]}}


def algorithm_boundaries_fields(rows):
    cases = {"rsa2048-below-template3072": "rsa3072", "rsa3072-below-template4096": "rsa4096", "ec256-on-p384-schema-three": "ec384schema3", "ec256-on-p384-schema-four": "ec384"}
    flags = ("nativeSafeTemplateObserved", "publicConfirmedIssuerUsed", "actualSignedClaimRefusal", "noCaRequestAllocated", "noKeyGenerated", "noAcceptedLeafOrJournal", "positiveNativeCustodyUnchanged", "positiveTrustedTlsUnchanged")
    if not isinstance(rows, list) or len(rows) != 4:
        raise ValueError("Missing native algorithm/template boundaries")
    result, seen = [], set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"caseId", "positiveScenario", "positiveFingerprintSha256", "positiveRequestId", *flags} or not isinstance(row.get("caseId"), str) or row["caseId"] not in cases or row["caseId"] in seen:
            raise ValueError("Invalid native algorithm/template case")
        if row.get("positiveScenario") != f"adcs-real-{cases[row['caseId']]}-issued-cng-iis" or any(row.get(flag) is not True for flag in flags):
            raise ValueError("Native algorithm boundary lacks positive control")
        for field, pattern in (("positiveFingerprintSha256", r"[a-f0-9]{64}"), ("positiveRequestId", r"[1-9][0-9]{0,9}")):
            if not isinstance(row.get(field), str) or not re.fullmatch(pattern, row[field]):
                raise ValueError("Invalid native positive issuance identity")
        seen.add(row["caseId"])
        result.append(dict(row))
    if len({row["positiveFingerprintSha256"].lower() for row in result}) != 4 or len({row["positiveRequestId"] for row in result}) != 4 or any(int(row["positiveRequestId"]) > 0xffffffff for row in result):
        raise ValueError("Native positive issuance controls must be distinct")
    return result


def cmc_boundaries_fields(proof):
    flags = ("actualCaSignedPending", "actualPinnedSignatureVerified", "actualSignerSignatureByteTampered", "actualPristineDerControlVerified", "agentResponseUnchanged")
    hashes = ("responseSha256", "nativeHelperSha256", "originalResponseDerSha256", "tamperedResponseDerSha256")
    variants = ["empty", "truncated", "trailing-data", "oversized", "signer-signature-tampered", "wrong-ca-key-pin"]
    if not isinstance(proof, dict) or set(proof) != {"scope", *flags, "caRequestId", *hashes, "refusedVariants", "syntheticCaResponse"} or proof.get("scope") != "read-only-native-ca-signed-response-signature-boundaries" or any(proof.get(flag) is not True for flag in flags) or proof.get("syntheticCaResponse") is not False:
        raise ValueError("Missing native signed-response decoder boundaries")
    if not isinstance(proof.get("caRequestId"), str) or not re.fullmatch(r"[1-9][0-9]{0,9}", proof["caRequestId"]) or int(proof["caRequestId"]) > 0xffffffff:
        raise ValueError("Invalid signed-response CA request identity")
    if any(not isinstance(proof.get(field), str) or not re.fullmatch(r"[a-f0-9]{64}", proof[field]) for field in hashes) or proof["originalResponseDerSha256"] == proof["tamperedResponseDerSha256"] or proof.get("refusedVariants") != variants:
        raise ValueError("Invalid native signed-response signature controls")
    return {**proof, "refusedVariants": list(variants)}


def _sanitized_report(value, suites, scopes, database_scopes=()):
    if isinstance(value, dict) and value.get("scope") in database_scopes:
        keys = ("scope", "candidateSha", "evidenceLevel", "qualificationEnvironment",
                "fixtureSources", "artifactQualification", "qualificationStatus", "experimental")
        return {**{key: value[key] for key in keys if key in value},
                "tests": [{key: item[key] for key in ("file", "name", "status") if key in item}
                          for item in value.get("tests", []) if isinstance(item, dict)]}
    if isinstance(value, dict) and value.get("suite") in suites:
        keys = ("schemaVersion", "suite", "candidateSha", "startedAt", "finishedAt",
                "status", "strict", "evidenceLevel", "requiredCapabilities",
                "requiredScenarios", "missingCapabilities", "missingScenarios",
                "fixtureSource", "qualificationEnvironment", "artifactQualification", "qualificationStatus", "experimental")
        result = {key: value[key] for key in keys if key in value}
        if "cleanup" in value:
            cleanup = value["cleanup"]
            if not isinstance(cleanup, dict) or cleanup.get("status") not in ("passed", "failed", "not-run"):
                raise ValueError("Invalid owned cleanup evidence")
            result["cleanup"] = {"status": cleanup["status"]}
        contract = json.loads((ROOT / "docs/certops/qualification-suites.json").read_text())
        known_ids = contract["suites"].get(value["suite"], [])
        known_caps = contract["requiredCapabilities"].get(value["suite"], [])
        for key, known in (("requiredScenarios", known_ids), ("missingScenarios", known_ids), ("requiredCapabilities", known_caps), ("missingCapabilities", known_caps)):
            if key in result:
                if not isinstance(result[key], list) or len(result[key]) > 4096:
                    raise ValueError("Invalid execution metadata bounds")
                result[key] = [item if isinstance(item, str) and item in known else "[unrecognized]" for item in result[key]]
        result["capabilities"] = {name if name in known_caps else "[unrecognized]": {"available": capability.get("available") is True}
                                  for name, capability in value.get("capabilities", {}).items()
                                  if isinstance(capability, dict)}
        result["scenarios"] = [{key: item[key] for key in
                                ("id", "status", "evidenceLevel", "startedAt", "finishedAt")
                                if key in item} for item in value.get("scenarios", [])
                               if isinstance(item, dict)]
        if value.get("suite") == "windows-domain-adcs-retention24h":
            result["nativeRetention24h"] = retention24h_fields(value)
        if value.get("suite") == adcs_ttl24h_collection.SUITE:
            from certops_adcs_ttl24h_proof import fields as adcs_ttl24h_fields
            result["nativeAdcsTtl24h"] = adcs_ttl24h_fields(value)
        if value.get("suite") == "windows-arm64-installed-agent":
            result.update(arm64_installed_fields(value))
        if value.get("suite") == "windows-arm64-packaged-scm":
            result.update(arm64_scm_fields(value))
        if value.get("suite") == "windows-arm64-cng-runtime":
            result.update(arm64_runtime_fields(value))
        for scenario in result["scenarios"]:
            if scenario.get("id") not in known_ids:
                scenario["id"] = "[unrecognized]"
            if scenario.get("status") not in ("passed", "failed", "skipped"):
                scenario["status"] = "invalid"
            if scenario.get("evidenceLevel") not in ("unit", "integration", "real-host", "e2e"):
                scenario["evidenceLevel"] = "invalid"
            for key in ("startedAt", "finishedAt"):
                if key in scenario and (not isinstance(scenario[key], str) or not re.fullmatch(r"[0-9TZ:.+\-]{16,40}", scenario[key])):
                    scenario[key] = "invalid"
        if "cleanup" in value:
            result["cleanup"] = {"status": value["cleanup"].get("status")}
        if value.get("suite") == "enterprise-adcs-elapsed-pending-real":
            if "primaryNativePreflightDispatchCount" in value:
                count = value["primaryNativePreflightDispatchCount"]
                if type(count) is not int or not 0 <= count <= 18:
                    raise ValueError("Elapsed AD CS cannot claim the browser preflight exception")
                result["primaryNativePreflightDispatchCount"] = count
            facts = value.get("nativePendingElapsed")
            if not isinstance(facts, dict):
                raise ValueError("Missing actual pending elapsed evidence")
            bounded = {key: facts.get(key) is True for key in ("snapshotAndCsrStableAcrossRestart", "keyProtectedBeforeDeadline", "signedTerminalCleanup", "exactKeyAbsent", "noCertificateAccepted", "noCaResubmission", "lateApprovalTerminalRefusal", "lateIssuedCertificateRevoked", "outgoingTrustedTlsUnchanged")}
            for key in ("pendingTimeoutSeconds", "pollIntervalSeconds", "monotonicWaitSeconds", "databaseElapsedSeconds"):
                if type(facts.get(key)) not in (int, float) or not 0 <= facts[key] <= 86400:
                    raise ValueError("Invalid pending elapsed counter")
                bounded[key] = facts[key]
            for key in ("databaseDatesRewritten", "journalRewritten"):
                if facts.get(key) is not False:
                    raise ValueError("Pending elapsed state rewritten")
                bounded[key] = False
            for key, pattern in (("pendingSince", r"[0-9TZ:.+\-]{16,40}"), ("requestId", r"[1-9][0-9]{0,9}"), ("snapshotSha256", r"[a-f0-9]{64}")):
                if not isinstance(facts.get(key), str) or not re.fullmatch(pattern, facts[key]):
                    raise ValueError("Invalid pending elapsed identity")
                bounded[key] = facts[key]
            for key, expected in (("clocks", "actual-host-and-database"), ("schedulerClock", "default-real-now"), ("qualificationScope", "configured-one-hour-not-default-fourteen-days")):
                if facts.get(key) != expected:
                    raise ValueError("Invalid pending elapsed scope")
                bounded[key] = expected
            result["nativePendingElapsed"] = bounded
        if value.get("suite") == "windows-historical-source-upgrade":
            facts = value.get("sourceUpgrade")
            if not isinstance(facts, dict) or facts.get("provenance") != "historical-source-build" or facts.get("publishedArchiveUsedForInstallation") is not False:
                raise ValueError("Invalid historical source upgrade provenance")
            bounded = {"provenance": "historical-source-build", "publishedArchiveUsedForInstallation": False}
            for key, expression in (("historicalCommit", r"[a-f0-9]{40}"), ("historicalArchiveSha256", r"[a-f0-9]{64}"), ("historicalVersion", r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]{1,80})?"), ("candidateVersion", r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]{1,80})?")):
                if not isinstance(facts.get(key), str) or not re.fullmatch(expression, facts[key]):
                    raise ValueError("Invalid historical source upgrade identity")
                bounded[key] = facts[key]
            bounded["historicalHelpers"] = {}
            for arch in ("amd64", "arm64"):
                digest = facts.get("historicalHelpers", {}).get(arch)
                if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                    raise ValueError("Invalid historical helper fingerprint")
                bounded["historicalHelpers"][arch] = digest
            for key in ("werPolicyPreserved", "schedulerHistoryPreserved", "distinctVersionObserved", "configurationPreserved", "credentialPreserved", "signingKeyPinPreserved", "sameAgentIdentity", "authenticatedCandidateHeartbeat", "candidateHelperActivated", "nonExportableCngKeyPreserved", "iisBindingPreserved", "trustedTlsPreserved", "serviceIdentityPreserved", "ownedFixtureRemoved"):
                if facts.get(key) is not True:
                    raise ValueError("Missing historical source upgrade preservation evidence")
                bounded[key] = True
            result["sourceUpgrade"] = bounded
        if value.get("suite") == "windows-installer-first-rename-refusal":
            proof = value.get("nativeRenameRefusal")
            fields = ("nativeDirectoryHandleHeld", "nativeHandleIdentityMatched", "actualFirstRenameRefused", "stagingRemoved", "previousDirectoryAbsent", "installedFilesUnchanged", "configurationAndCredentialUnchanged", "sameRunningServicePid", "freshAuthenticatedHeartbeat", "trustedTlsUnchanged", "nativeHandleReleased", "ownedChildDrained")
            if not isinstance(proof, dict) or any(proof.get(field) is not True for field in fields):
                raise ValueError("Incomplete native first-rename refusal evidence")
            result["nativeRenameRefusal"] = dict.fromkeys(fields, True)
        if value.get("suite") == "windows-activation-second-rename":
            proof = value.get("nativeSecondRename")
            fields = ("childIdentityVerifiedBeforeActivation", "actualProductionFunctions", "nativeOrderedRestoreEvents", "originalDirectoryIdentityRestored", "heldStagingIdentityUnchanged", "explicitStagingCleanupFailure", "candidateNeverActivated", "predecessorFilesUnchanged", "sameRunningServicePid", "configurationAndCredentialUnchanged", "cngCustodyUnchanged", "bindingAndTrustedTlsUnchanged", "freshAuthenticatedHeartbeat", "nativeHandleReleased", "ownedStagingRemoved", "ownedChildDrained")
            scope = "production-activation-functions-not-installer-cli"
            if not isinstance(proof, dict) or proof.get("scope") != scope or any(proof.get(field) is not True for field in fields):
                raise ValueError("Incomplete native second-rename activation evidence")
            result["nativeSecondRename"] = {**dict.fromkeys(fields, True), "scope": scope}
        if value.get("suite") == "windows-two-unattended-renewals":
            proof = value.get("nativeTwoRenewals")
            fields = ("automaticSourceAndRealMode", "naturallyDueGenerations", "distinctIdempotencyKeys", "leafAndSpkiChangedTwice", "nativeBindingMatchesLatest", "nativeKeyProfilesVerified", "persistedEvidenceBothCycles", "inventoryMatchesActualLeaf", "profileAndManagementLineagePreserved", "retentionLineageMatchesBothCutovers", "predecessorCustodyPreserved", "noExpiryOrClockOverrides")
            scope = "two-unattended-cycles-and-preserved-predecessors-not-expiry-cleanup"
            if (not isinstance(proof, dict) or type(proof.get("successfulAutomationCycles")) is not int
                    or proof["successfulAutomationCycles"] != 2 or proof.get("expiryCleanupQualified") is not False
                    or proof.get("scope") != scope or any(proof.get(field) is not True for field in fields)):
                raise ValueError("Incomplete two-generation native renewal evidence")
            result["nativeTwoRenewals"] = {**dict.fromkeys(fields, True), "successfulAutomationCycles": 2, "expiryCleanupQualified": False, "scope": scope}
        if value.get("suite") == "browser-agent-console":
            proof = value.get("completedConsolePrivacy")
            fields = ('finalStreamDoesNotCompleteJob', 'claimBoundResultCompletesNoop', 'completedViewerTextWithdrawn', 'restoredHistoryWithoutDuplicates', 'removedMemberTextWithdrawn', 'sameConsoleRemainedMounted', 'authoritativeTerminalStatePreserved', 'foregroundRevalidationWithinThirtySeconds', 'noNativeExecutionClaim')
            if not isinstance(proof, dict) or any(proof.get(field) is not True for field in fields):
                raise ValueError("Incomplete completed-console privacy evidence")
            result["completedConsolePrivacy"] = dict.fromkeys(fields, True)
        if value.get("suite") == "windows-canonical-root-lifecycle":
            proof = value.get("nativeCanonicalRoot")
            fields = ('initialRootAbsent', 'initialServiceAbsent', 'ownershipRecordedBeforeInstall', 'originalInstallerBytesUnchanged', 'canonicalInstalledHostVerified', 'localSystemServiceVerified', 'authenticatedRegistration', 'bootstrapRegistryScrubbed', 'restartChangedServicePid', 'freshHeartbeatAfterRestart', 'candidateReapplicationSucceeded', 'configurationCredentialAndPinPreserved', 'freshHeartbeatAfterReapplication', 'unmodifiedUninstallerSucceeded', 'serviceAndAppRemoved', 'uninstallPreservedState', 'exactOwnedRootRemoved')
            scope = "unmodified-candidate-cli-canonical-root-same-version-reapplication"
            if not isinstance(proof, dict) or proof.get("scope") != scope or any(proof.get(field) is not True for field in fields):
                raise ValueError("Incomplete canonical Windows installer lifecycle evidence")
            result["nativeCanonicalRoot"] = {**dict.fromkeys(fields, True), "scope": scope}
        if value.get("suite") == "windows-host":
            runtime = value.get("nativePackagedChainRuntime")
            runtime_flags = ("candidateHelperDigestMatched", "literalUnicodeSpaceBracketPath", "defaultPackagedResolverUsed", "nativeMetadataPositiveBeforeFault", "actualCandidateWrongProtocolPeUsed", "realBridgeRefusedWrongProtocol", "ownedChildClosedBeforeRestore", "exactOriginalFileIdentityRestored", "nativeMetadataPositiveAfterRestore")
            if (not isinstance(runtime, dict) or runtime.get("scope") != "extracted-candidate-native-chain-metadata-path-and-protocol-refusal"
                    or runtime.get("metadataOnly") is not True or runtime.get("architecture") != "amd64"
                    or any(runtime.get(key) is not False for key in ("serviceInstalled", "cmcPackagedQualified", "nativeGoVerifierPackagedQualified"))
                    or any(runtime.get(flag) is not True for flag in runtime_flags)
                    or any(not isinstance(runtime.get(key), str) or not re.fullmatch(r"[a-f0-9]{64}", runtime[key]) for key in ("chainHelperSha256", "wrongProtocolHostSha256"))
                    or runtime["chainHelperSha256"] == runtime["wrongProtocolHostSha256"]):
                raise ValueError("Incomplete extracted candidate native chain runtime proof")
            result["nativePackagedChainRuntime"] = {key: runtime[key] for key in ("scope", "metadataOnly", "serviceInstalled", "cmcPackagedQualified", "nativeGoVerifierPackagedQualified", "architecture", "chainHelperSha256", "wrongProtocolHostSha256", *runtime_flags)}
            settings = value.get("nativeHttpSysClientSettings")
            flags = ("nativeNondefaultSettingsObserved", "actualProductionCutover", "publicCandidateAbsentBeforeRollback", "actualNativeRollbackSucceeded", "rawSettingsPreservedAfterCutoverAndRollback", "trustedTlsVerifiedAfterEveryTransition", "unrelatedEndpointPreserved", "originalCertificateRestored")
            expected = (("revocation-cached-no-usage", 65542, 3600, 5000), ("no-revocation-normal-usage", 5, 120, 7000))
            if (not isinstance(settings, dict) or settings.get("scope") != "native-http-sys-client-policy-preservation-not-client-auth-handshake"
                    or settings.get("clientAuthHandshakeQualified") is not False
                    or not isinstance(settings.get("cases"), list) or len(settings["cases"]) != 2):
                raise ValueError("Missing bounded native HTTP.sys client policy preservation")
            projected = []
            for item, values in zip(settings["cases"], expected):
                if (not isinstance(item, dict) or item.get("id") != values[0]
                        or any(type(item.get(key)) is not int or item[key] != target for key, target in zip(("checkMode", "freshness", "retrievalTimeout"), values[1:]))
                        or any(item.get(flag) is not True for flag in flags)):
                    raise ValueError("Incomplete native HTTP.sys client policy case")
                projected.append({key: item[key] for key in ("id", "checkMode", "freshness", "retrievalTimeout", *flags)})
            result["nativeHttpSysClientSettings"] = {"scope": settings["scope"], "clientAuthHandshakeQualified": False, "cases": projected}
            usage = value.get("nativeKeyUsage")
            if (not isinstance(usage, dict) or usage.get("scope") != "native-copied-csr-x509-usage-and-cng-signing-permission"
                    or usage.get("copiedActualCsrExtensions") is not True
                    or usage.get("privateKeyUsageClaim") != "signing-permitted-not-exact-default-ncrypt-mask"
                    or not isinstance(usage.get("cases"), list) or len(usage["cases"]) != 10):
                raise ValueError("Incomplete native certificate/CNG key usage evidence")
            expected_usage = {"rsa-2048": 160, "rsa-3072": 160, "rsa-4096": 160, "ec-p256": 128, "ec-p384": 128}
            known_cases = {f"{profile}/{store}" for profile in expected_usage for store in ("My", "WebHosting")}
            bounded_usage, seen_usage = [], set()
            for item in usage["cases"]:
                if not isinstance(item, dict) or not isinstance(item.get("caseId"), str) or item["caseId"] not in known_cases or item["caseId"] in seen_usage:
                    raise ValueError("Invalid or repeated native key usage identity")
                seen_usage.add(item["caseId"])
                if (type(item.get("certificateUsageFlags")) is not int or item["certificateUsageFlags"] != expected_usage[item["caseId"].split("/")[0]]
                        or type(item.get("cngAllowedOperations")) is not int or not 0 <= item["cngAllowedOperations"] <= 0xffffffff
                        or (item["cngAllowedOperations"] != 0x00ffffff and item["cngAllowedOperations"] & ~7 != 0)
                        or item["cngAllowedOperations"] & 2 != 2):
                    raise ValueError("Native certificate usage or signing permission mismatch")
                bounded_usage.append({key: item[key] for key in ("caseId", "certificateUsageFlags", "cngAllowedOperations")})
            result["nativeKeyUsage"] = {"scope": usage["scope"], "copiedActualCsrExtensions": True, "privateKeyUsageClaim": usage["privateKeyUsageClaim"], "cases": bounded_usage}
            survivor_fields = ("differentCertificateCrossStoreProtected", "sameCertificateCrossStoreProtected", "originalKeyPreserved", "replacementTrustedTlsPreserved", "ownedCrossStoreCopiesRemoved")
            survivors = value.get("nativeKeySurvivors")
            if not isinstance(survivors, dict) or any(survivors.get(field) is not True for field in survivor_fields):
                raise ValueError("Incomplete native cross-store CNG survivor evidence")
            result["nativeKeySurvivors"] = dict.fromkeys(survivor_fields, True)
            reference_fields = ("twoOpenReferencesPersistedAcrossProcess", "bothOpenNativeSweepPreservedCustody", "oneClosedStillProtected", "unknownReferenceDoesNotCloseOwnedReferences", "allClosedStillDeferredByRealDeadline", "nativeCustodyAndTrustedTlsUnchanged")
            references = value.get("nativeRetentionReferences")
            reference_scope = "native-collector-supporting-ledger-reference-lifecycle"
            if (not isinstance(references, dict) or references.get("scope") != reference_scope
                    or references.get("elapsed24HourQualified") is not False
                    or any(references.get(field) is not True for field in reference_fields)):
                raise ValueError("Incomplete native retention reference guard evidence")
            result["nativeRetentionReferences"] = {**dict.fromkeys(reference_fields, True), "scope": reference_scope, "elapsed24HourQualified": False}
            state_fields = ("threeReadablePositiveControls", "threeActualNativeReadDenials", "productionReadersRefused", "exactFileIdentityAndBytesPreserved", "exactAclRestored", "allReadersRecovered", "ownedTemporaryStateRemoved")
            state_read = value.get("nativeStateReadRefusals")
            state_scope = "native-temporary-state-read-denials-production-readers"
            if (not isinstance(state_read, dict) or state_read.get("scope") != state_scope
                    or state_read.get("installedServiceStartupQualified") is not False
                    or any(state_read.get(field) is not True for field in state_fields)):
                raise ValueError("Incomplete native state read refusal evidence")
            result["nativeStateReadRefusals"] = {**dict.fromkeys(state_fields, True), "scope": state_scope, "installedServiceStartupQualified": False}
            result["nativeJournalReadRefusals"] = journal_acl_fields(value.get("nativeJournalReadRefusals"))
            result["nativeOrphanJournalProtection"] = orphan_journal_fields(value.get("nativeOrphanJournalProtection"))
            result["nativeIpv6SniShadow"] = ipv6_shadow_fields(value.get("nativeIpv6SniShadow"))
            result["nativeIpv6WildcardShadow"] = ipv6_wildcard_fields(value.get("nativeIpv6WildcardShadow"))
            proof = value.get("nativeRetentionAtomicReplace")
            fields = ("nativeFileHandleHeld", "nativeFileIdentityMatched", "actualAtomicReplaceRefused", "priorRowBytesPreserved", "priorRowIdentityPreserved", "failedTemporaryFileRemoved", "nativeHandleReleased", "ownedChildDrained", "actualReplacementSucceeded", "freshProcessReadExactReplacement", "restrictivePermissionsVerified", "ownedTemporaryFixtureRemoved")
            if not isinstance(proof, dict) or any(proof.get(field) is not True for field in fields):
                raise ValueError("Incomplete native retention atomic replacement evidence")
            result["nativeRetentionAtomicReplace"] = dict.fromkeys(fields, True)
            result["nativeRetentionPolicyExpiry"] = retention_policy_expiry_fields(value.get("nativeRetentionPolicyExpiry"))
            elapsed = value.get("nativeElapsedRetention")
            counts = ("successfulCutovers", "predecessorCertificatesRemoved", "predecessorKeysRemoved", "lineageRowsFinalized")
            facts = ("immediateDeferralPreservedCustody", "immutableHistoryPreserved", "replacementTrustedBoundCustodyUnchanged", "interruptedNativeDeleteRecovered")
            if (not isinstance(elapsed, dict) or elapsed.get("mode") != "real-clock-two-cutover-expiry-grace"
                    or any(type(elapsed.get(field)) is not int or elapsed[field] != 2 for field in counts)
                    or any(elapsed.get(field) is not True for field in facts)
                    or type(elapsed.get("configuredRetentionHours")) is not int or elapsed["configuredRetentionHours"] != 24
                    or elapsed.get("fullRetentionWindowQualified") is not False
                    or type(elapsed.get("waitedMonotonicMs")) not in (int, float)
                    or not 300000 <= elapsed["waitedMonotonicMs"] < 600000):
                raise ValueError("Incomplete real-clock two-cutover retention evidence")
            result["nativeElapsedRetention"] = {"ownedInterruption": retention_interruption_fields(elapsed.get("ownedInterruption")), **dict.fromkeys(counts, 2), **dict.fromkeys(facts, True),
                "mode": "real-clock-two-cutover-expiry-grace", "configuredRetentionHours": 24,
                "fullRetentionWindowQualified": False, "waitedMonotonicMs": elapsed["waitedMonotonicMs"]}

        if value.get("suite") == "windows-acme-wrong-spki":
            proof = value.get("nativeWrongSpki")
            if not isinstance(proof, dict):
                raise ValueError("Missing Windows wrong-SPKI evidence")
            fields = ("actualSignedRenewalFailed", "actualCsrDiffersFromReturnedLeaf", "genuineCaIssuedLeafReused", "rejectedUnacceptedKeyRemoved", "predecessorCustodyUnchanged", "bindingAndTrustedTlsUnchanged", "storedProfileUnchanged", "configurationRestored")
            if any(proof.get(field) is not True for field in fields):
                raise ValueError("Incomplete Windows wrong-SPKI evidence")
            result["nativeWrongSpki"] = dict.fromkeys(fields, True)
        if value.get("suite") == "windows-native-child-output-privacy":
            for key in ("actualStdoutAndStderrEmission", "actualDelegatedSuccess", "actualAcmeSuccessLogObserved", "actualHttpUploadsSecretFree", "persistedLogsEvidenceResultsSecretFree", "scmConsoleSecretFree"):
                result[key] = value.get(key) is True
            for key, expected in (("actualNativeIdentity", "LocalSystem"), ("childOutputPolicy", "captured-and-withheld-not-live-forwarded"), ("nativeCertificateOutcome", "parent-independent-CNG-IIS-trusted-TLS")):
                if value.get(key) != expected:
                    raise ValueError("Invalid native Windows privacy scope")
                result[key] = expected
            for key in ("receiptCount", "jobLogCount", "evidenceCount", "httpUploadCount"):
                if type(value.get(key)) is not int or not 1 <= value[key] <= (32 if key == "receiptCount" else 10000):
                    raise ValueError("Invalid native Windows privacy counter")
                result[key] = value[key]
        if value.get("suite") == "core-api-migration-upgrade":
            result.update(migration_evidence(value))
        if value.get("suite") == "agent-log-maintenance-worker":
            facts = value.get("maintenance")
            if not isinstance(facts, dict) or facts.get("scope") != "actual-default-five-minute-grace-and-supported-retention-zero":
                raise ValueError("Invalid worker log maintenance scope")
            bounded = {"scope": "actual-default-five-minute-grace-and-supported-retention-zero"}
            bounded.update({key: facts.get(key) is True for key in ("actualDatabaseExpired", "originalJobSucceeded", "lateUploadRefused", "tombstoneRetained", "onlySelectedWorkerSweeps")})
            if facts.get("timestampsRewritten") is not False:
                raise ValueError("Worker log maintenance timestamps rewritten")
            bounded["timestampsRewritten"] = False
            for key in ("defaultGraceMs", "observedMonotonicMs", "abandonedStreams", "purgedLines", "repeatedPurgeDeleted", "retentionDays"):
                if type(facts.get(key)) not in (int, float) or not 0 <= facts[key] <= 420000:
                    raise ValueError("Invalid worker log maintenance counter")
                bounded[key] = facts[key]
            result["maintenance"] = bounded
        if value.get("suite") == "windows-host":
            custody = value.get("cngCustody")
            if not isinstance(custody, dict) or custody.get("privateExportBytesWritten") is not False or custody.get("privateExportBytesReported") is not False:
                raise ValueError("Invalid CNG private-export byte boundary")
            cases = custody.get("cases")
            if not isinstance(cases, list) or len(cases) != 10:
                raise ValueError("Incomplete CNG profile/store custody inventory")
            bounded_cases = []
            for case in cases:
                if not isinstance(case, dict) or not isinstance(case.get("caseId"), str) or not re.fullmatch(r"(?:rsa-(?:2048|3072|4096)|ec-p(?:256|384))/(?:My|WebHosting)", case["caseId"]):
                    raise ValueError("Invalid CNG custody case identity")
                if type(case.get("privateExportHResult")) is not int or not -2147483648 <= case["privateExportHResult"] < 0:
                    raise ValueError("Invalid native CNG export refusal code")
                bounded = {"caseId": case["caseId"], "privateExportHResult": case["privateExportHResult"]}
                bounded.update({key: case.get(key) is True for key in ("exportableControlSucceeded", "controlBytesZeroed", "protectedBytesZeroed", "protectedExportDenied", "publicNonceSignatureVerified", "originalCustodyUnchanged", "controlKeyRemoved")})
                bounded_cases.append(bounded)
            result["cngCustody"] = {"privateExportBytesWritten": False, "privateExportBytesReported": False, "workDirectoryUnchanged": custody.get("workDirectoryUnchanged") is True, "cases": bounded_cases}
            sni = value.get("nativeSamePortSni")
            if sni is not None:
                if not isinstance(sni, dict) or type(sni.get("siteCount")) is not int or sni["siteCount"] != 2 or type(sni.get("hostnameCount")) is not int or sni["hostnameCount"] != 2 or sni.get("certificateStore") != "My":
                    raise ValueError("Invalid same-port SNI target inventory")
                result["nativeSamePortSni"] = {"siteCount": 2, "hostnameCount": 2, "certificateStore": "My"}
                result["nativeSamePortSni"].update({key: sni.get(key) is True for key in ("twoSitesSamePort", "distinctHostnameSelectors", "primaryCutoverPeerUnchanged", "primaryRollbackPeerUnchanged", "peerCutoverPrimaryUnchanged", "peerRollbackPrimaryUnchanged", "sameCertificateReplayVerified", "independentAuthenticatedTls", "ownedCleanupVerified")})
            contention = value.get("nativeEnrollmentContention")
            if contention is not None:
                if not isinstance(contention, dict):
                    raise ValueError("Invalid native enrollment contention proof")
                bounded = {key: contention.get(key) is True for key in ("winnerGeneratedRealCsr", "loserLockedBeforeNativeExecution", "retryAcquiredEnrollmentLock", "retryExistingContainerRefused", "sameCsrAndSpki", "sameNonExportableKey", "winnerSignatureVerified", "ownedChildrenStopped", "ownedKeyRemoved")}
                for key in ("loserNativeCalls", "loserCertreqCalls", "retryCertreqCalls", "winnerCertreqCalls", "retryNativeCalls"):
                    if type(contention.get(key)) is not int or not 0 <= contention[key] <= 32:
                        raise ValueError("Invalid native enrollment execution counter")
                    bounded[key] = contention[key]
                result["nativeEnrollmentContention"] = bounded
        if value.get("suite") == "linux-systemd-published-upgrade":
            proof = value.get("nativePublishedLinuxUpgrade")
            if not isinstance(proof, dict) or proof.get("baselineVersion") != "0.17.2" or proof.get("publishedAssetId") != 612562598 or proof.get("publishedArchiveSize") != 410054 or proof.get("publishedArchiveSha256") != "c602fe36825c74d423c2c9b89680df3b1ac76542f71804de14dc5e2ec5aa85bf" or proof.get("rollbackClaimed") is not False:
                raise ValueError("Invalid published Linux upgrade provenance")
            bounded = {key: proof[key] for key in ("baselineVersion", "publishedAssetId", "publishedArchiveSize", "publishedArchiveSha256", "rollbackClaimed")}
            if not isinstance(proof.get("candidateVersion"), str) or not re.fullmatch(r"[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}", proof["candidateVersion"]):
                raise ValueError("Invalid candidate archive version")
            if not isinstance(proof.get("candidateArchiveSha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", proof["candidateArchiveSha256"]):
                raise ValueError("Invalid candidate archive digest")
            bounded.update({key: proof[key] for key in ("candidateVersion", "candidateArchiveSha256")})
            bounded.update({key: proof.get(key) is True for key in ("publishedFilesVerified", "baselineJobExecuted", "candidateFilesVerified", "configBytesPreserved", "credentialBytesPreserved", "sameRegistration", "bootstrapUnconsumed", "freshHeartbeat", "candidateJobExecuted", "oldJobHistoryUnchanged", "oldReplayEntryPreserved", "privatePermissionsPreserved", "originalConfigRestored")})
            for key in ("beforePid", "afterPid"):
                if type(proof.get(key)) is not int or not 1 < proof[key] <= 2147483647:
                    raise ValueError("Invalid published upgrade process identity")
                bounded[key] = proof[key]
            result["nativePublishedLinuxUpgrade"] = bounded
        if value.get("suite") == "linux-systemd-reapply":
            proof = value.get("nativeInstallerReapply")
            if not isinstance(proof, dict) or proof.get("installation") != "same-candidate-reapplication":
                raise ValueError("Invalid native installer reapplication evidence")
            bounded = {"installation": "same-candidate-reapplication"}
            bounded.update({key: proof.get(key) is True for key in ("operatorConfigBytesPreserved", "credentialBytesPreserved", "candidatePackageInstalled", "dropinPreserved", "privatePermissionsPreserved", "sameRegistration", "spareBootstrapUnconsumed", "bootstrapFileAbsent", "bootstrapAbsentAfterFreshRestart", "freshAuthenticatedHeartbeat", "originalConfigRestored")})
            for key in ("beforePid", "reappliedPid", "freshRestartPid", "nativeUid"):
                if type(proof.get(key)) is not int or not 0 < proof[key] <= 2147483647:
                    raise ValueError("Invalid native installer process identity")
                bounded[key] = proof[key]
            result["nativeInstallerReapply"] = bounded
        if value.get("suite") == "enterprise-adcs-real":
            result["nativePendingCaRenewal"] = pending_ca_renewal_fields(value.get("nativePendingCaRenewal"))
            result["nativePendingCaKeyChange"] = pending_ca_key_change_fields(value.get("nativePendingCaKeyChange"))
            if (result["nativePendingCaKeyChange"]["predecessorFingerprint"] != result["nativePendingCaRenewal"]["leafFingerprint"] or result["nativePendingCaKeyChange"]["oldCaKeySha256"] != result["nativePendingCaRenewal"]["caKeySha256"]):
                raise ValueError("Pending new-key proof must bind actual prior pending installation")
        if value.get("suite") in ("enterprise-adcs-real", "enterprise-adcs-hierarchy-real"):
            result["nativeIssuedRevocation"] = issued_revocation_fields(value.get("nativeIssuedRevocation"))
            result["nativeRequiredTemplateAttributes"] = required_template_attribute_fields(value.get("nativeRequiredTemplateAttributes"))
            result["nativeIssuedSanBoundary"] = issued_san_fields(value.get("nativeIssuedSanBoundary"))
            result["nativeBrowserAbandon"] = browser_abandon_fields(value.get("nativeBrowserAbandon"))
            result["nativeBrowserAdminBoundary"] = browser_admin_boundary_fields(value.get("nativeBrowserAdminBoundary"))
            if result["nativeBrowserAdminBoundary"]["enrollmentId"] != result["nativeBrowserAbandon"]["enrollmentId"]:
                raise ValueError("Role boundary must bind actual abandoned enrollment")
            result["nativeBrowserReconcile"] = browser_reconcile_fields(value.get("nativeBrowserReconcile"))
            result["nativeAdcsCapacity"] = adcs_capacity_fields(value.get("nativeAdcsCapacity"))
            if value.get("suite") == "enterprise-adcs-real" and result["nativePendingCaRenewal"]["predecessorFingerprint"] != result["nativeAdcsCapacity"]["fingerprints"][1]:
                raise ValueError("Pending CA renewal must preserve actual second capacity generation")
            result["nativeBrowserJobApproval"] = browser_job_approval_fields(value.get("nativeBrowserJobApproval"))
            if any(result["nativeBrowserJobApproval"][key] != result["nativeAdcsCapacity"][key] for key in ("jobIds", "enrollmentIds", "requestIds", "fingerprints")):
                raise ValueError("Browser decisions must bind both actual native capacity generations")
            result["nativeBrowserCancel"] = browser_cancel_fields(value.get("nativeBrowserCancel"))
            capacity, browser_cancel = result["nativeAdcsCapacity"], result["nativeBrowserCancel"]
            for key, field in (("priorEnrollmentId", "enrollmentIds"), ("priorJobId", "jobIds"), ("priorRequestId", "requestIds"), ("fingerprint", "fingerprints")):
                if browser_cancel[key] != capacity[field][1]:
                    raise ValueError("Browser cancellation does not preserve actual capacity issuance")
            result["nativeWebHostingRenewal"] = webhosting_fields(value.get("nativeWebHostingRenewal"))
            result["nativeAlgorithmBoundaries"] = algorithm_boundaries_fields(value.get("nativeAlgorithmBoundaries"))
            result["nativeCmcBoundaries"] = cmc_boundaries_fields(value.get("nativeCmcBoundaries"))
            foreign = value.get("nativeForeignSpkiCandidate")
            foreign_flags = ("sameRequesterNativeRetrieveSucceeded", "nativeCaIdentityMatched", "differentEnrollmentSpkiProved", "explicitCandidateRefused", "boundedSearchUnresolved", "originalJournalWatermarkPreserved", "originalNativeCustodyAndTlsPreserved", "noAdditionalCaRequest")
            if (not isinstance(foreign, dict) or foreign.get("scope") != "read-only-native-foreign-spki-candidate-not-public-uncertain-recovery"
                    or any(foreign.get(flag) is not True for flag in foreign_flags)):
                raise ValueError("Missing native other-enrollment SPKI refusal")
            bounded_foreign = {key: foreign[key] for key in ("scope", *foreign_flags)}
            for key in ("requestIds", "spkiFingerprints"):
                entries = foreign.get(key)
                if not isinstance(entries, list) or len(entries) != 2 or any(not isinstance(entry, str) for entry in entries) or len(set(entries)) != 2:
                    raise ValueError("Invalid native other-enrollment public identity")
                if key == "requestIds":
                    if any(not re.fullmatch(r"[1-9][0-9]{0,9}", entry) or int(entry) > 0xffffffff for entry in entries):
                        raise ValueError("Invalid native other-enrollment request ID")
                elif any(not re.fullmatch(r"[a-f0-9]{64}", entry) for entry in entries):
                    raise ValueError("Invalid native other-enrollment SPKI")
                bounded_foreign[key] = entries
            result["nativeForeignSpkiCandidate"] = bounded_foreign
            pair_cases = {"ca-host-mismatch", "ca-authority-mismatch", "template-pair-mismatch"}
            pair_flags = ("actualSignedJobRefused", "claimBoundOutcome", "noCaRequestAllocated", "noKeyGenerated", "noAcceptedLeafOrJournal", "originalNativeCustodyPreserved", "outgoingTrustedTlsPreserved", "configurationAndCredentialRestored")
            pairs = value.get("nativeLocalRulePairs")
            if not isinstance(pairs, list) or len(pairs) != 3:
                raise ValueError("Missing native exact CA/template rule boundaries")
            bounded_pairs, seen_pairs = [], set()
            for row in pairs:
                if (not isinstance(row, dict) or not isinstance(row.get("caseId"), str) or row["caseId"] not in pair_cases or row["caseId"] in seen_pairs
                        or any(row.get(flag) is not True for flag in pair_flags)):
                    raise ValueError("Invalid native exact CA/template rule boundary")
                seen_pairs.add(row["caseId"])
                bounded_pairs.append({key: row[key] for key in ("caseId", *pair_flags)})
            result["nativeLocalRulePairs"] = bounded_pairs
            browser = value.get("nativeBrowserAdcs")
            browser_flags = ("browserIssuerCreation", "nativeSafePreflight", "browserCaConfirmation", "postConfirmationNativePreflight", "browserProfileCreation", "browserProfileAttachment", "actualDueSelection", "defaultSweepCreatedEnrollment", "automaticSourceAndRealMode", "claimBoundEvidence", "installedEnrollment", "freshLeafAndSpki", "nativeCaRequestMatched", "nonexportableMachineCng", "nativeIisSniMatched", "independentTrustedTls", "browserInstalledStateVisible", "noSyntheticResponses", "noDateOrJournalOverrides", "ownedEnrollmentRegistered", "browserAndTrustCleaned", "otherProfilePoliciesRestored")
            fixed = {"scope": "browser-issuer-profile-default-scheduler-native-adcs", "lifecycle": "renew-existing-inventory-not-first-issue-or-manual-job", "scheduler": "production-default-sweep-not-background-worker-loop", "browserEngine": "chromium"}
            if (not isinstance(browser, dict) or any(browser.get(key) != expected for key, expected in fixed.items())
                    or any(browser.get(key) is not True for key in browser_flags)
                    or type(browser.get("browserMutationCount")) is not int or browser["browserMutationCount"] != 6
                    or type(browser.get("successfulEnrollments")) is not int or browser["successfulEnrollments"] != 1):
                raise ValueError("Invalid native AD CS browser lifecycle evidence")
            bounded_browser = {key: browser[key] for key in (*fixed, *browser_flags, "browserMutationCount", "successfulEnrollments")}
            for key in ("fingerprints", "spkiFingerprints"):
                values = browser.get(key)
                if not isinstance(values, list) or len(values) != 2 or any(not isinstance(item, str) or not re.fullmatch(r"[a-f0-9]{64}", item) for item in values) or len(set(values)) != 2:
                    raise ValueError("Invalid browser native certificate identities")
                bounded_browser[key] = values
            uuid_pattern = r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}"
            for key in ("enrollmentId", "jobId", "profileId", "issuerId"):
                if not isinstance(browser.get(key), str) or not re.fullmatch(uuid_pattern, browser[key]):
                    raise ValueError("Invalid browser native lifecycle identity")
                bounded_browser[key] = browser[key]
            if not isinstance(browser.get("requestId"), str) or not re.fullmatch(r"[1-9][0-9]{0,9}", browser["requestId"]) or int(browser["requestId"]) > 0xffffffff:
                raise ValueError("Invalid browser native CA request identity")
            bounded_browser["requestId"] = browser["requestId"]
            result["nativeBrowserAdcs"] = bounded_browser
            dispatch = value.get("browserNativePreflightDispatch")
            if (not isinstance(dispatch, dict) or type(dispatch.get("count")) is not int or dispatch["count"] != 2
                    or not isinstance(dispatch.get("jobIds"), list) or len(dispatch["jobIds"]) != 2
                    or any(not isinstance(item, str) or not re.fullmatch(uuid_pattern, item) for item in dispatch["jobIds"])
                    or len({item.lower() for item in dispatch["jobIds"]}) != 2):
                raise ValueError("Invalid browser native preflight accounting")
            result["browserNativePreflightDispatch"] = {"count": 2, "jobIds": dispatch["jobIds"]}
            cycles = value.get("nativeAdcsTwoRenewals")
            flags = ("defaultSqlNowSelection", "automaticSourceAndRealMode", "distinctExpiryGenerations", "independentCaRequests", "freshLeafSerialAndSpki", "protectedUniqueMachineKeys", "nativeIisAndSniCutovers", "independentTrustedTls", "claimBoundVerificationEvidence", "unchangedStoredProfile", "sameManagementPeriod", "predecessorCustodyPreserved", "actualInventoryMatchesLatest", "ownedEnrollmentCleanupRegistered", "noDateOrJournalOverrides")
            strings = {"scope": "two-native-adcs-default-scheduler-cycles-not-expiry-cleanup", "renewalProtocol": "fresh-enrollment-with-new-key-and-csr", "schedulerInvocation": "qualification-invoked-production-default-sweep"}
            if (not isinstance(cycles, dict) or any(cycles.get(key) != expected for key, expected in strings.items())
                    or any(cycles.get(key) is not True for key in flags)
                    or cycles.get("workerIntervalQualified") is not False or cycles.get("expiryCleanupQualified") is not False
                    or type(cycles.get("successfulAutomationCycles")) is not int or cycles["successfulAutomationCycles"] != 2):
                raise ValueError("Invalid native AD CS renewal cycle scope")
            bounded_cycles = {key: cycles[key] for key in (*strings, *flags, "workerIntervalQualified", "expiryCleanupQualified", "successfulAutomationCycles")}
            patterns = {"requestIds": r"[1-9][0-9]{0,9}", "fingerprints": r"[a-f0-9]{64}", "spkiFingerprints": r"[a-f0-9]{64}", "serialNumbers": r"[a-f0-9]{1,128}", "containerNames": r"tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"}
            for key, pattern in patterns.items():
                values = cycles.get(key)
                if (not isinstance(values, list) or len(values) != 3
                        or any(not isinstance(item, str) or not re.fullmatch(pattern, item) for item in values)
                        or len(set(values)) != 3):
                    raise ValueError("Invalid native AD CS renewal generation identities")
                bounded_cycles[key] = values
            if any(int(item) > 0xffffffff for item in cycles["requestIds"]):
                raise ValueError("Invalid native AD CS request identity")
            for key in ("caRequestCounts", "expiryEpochs"):
                values = cycles.get(key)
                if not isinstance(values, list) or len(values) != 3 or any(type(item) is not int or not 0 < item <= 9007199254740991 for item in values):
                    raise ValueError("Invalid native AD CS renewal generation counters")
                bounded_cycles[key] = values
            counts, expiry = cycles["caRequestCounts"], cycles["expiryEpochs"]
            if counts[2] > 1000 or counts[1] != counts[0] + 1 or counts[2] != counts[1] + 1 or not expiry[0] < expiry[1] < expiry[2]:
                raise ValueError("Invalid native AD CS renewal generation progression")
            result["nativeAdcsTwoRenewals"] = bounded_cycles
            cycles = value.get("nativeAdcsBackgroundRenewals")
            flags = ("defaultSqlNowSelection", "automaticSourceAndRealMode", "distinctExpiryGenerations", "independentCaRequests", "freshLeafSerialAndSpki", "protectedUniqueMachineKeys", "nativeIisAndSniCutovers", "independentTrustedTls", "claimBoundVerificationEvidence", "unchangedStoredProfile", "sameManagementPeriod", "predecessorCustodyPreserved", "actualInventoryMatchesLatest", "ownedEnrollmentCleanupRegistered", "noDateOrJournalOverrides")
            strings = {"scope": "two-real-default-interval-worker-native-adcs-renewals", "renewalProtocol": "fresh-enrollment-with-new-key-and-csr", "schedulerInvocation": "actual-production-runner-default-interval"}
            if (not isinstance(cycles, dict) or any(cycles.get(key) != expected for key, expected in strings.items())
                    or any(cycles.get(key) is not True for key in flags)
                    or cycles.get("workerIntervalQualified") is not True or cycles.get("expiryCleanupQualified") is not False
                    or type(cycles.get("successfulAutomationCycles")) is not int or cycles["successfulAutomationCycles"] != 2):
                raise ValueError("Invalid native AD CS renewal cycle scope")
            bounded_cycles = {key: cycles[key] for key in (*strings, *flags, "workerIntervalQualified", "expiryCleanupQualified", "successfulAutomationCycles")}
            patterns = {"requestIds": r"[1-9][0-9]{0,9}", "fingerprints": r"[a-f0-9]{64}", "spkiFingerprints": r"[a-f0-9]{64}", "serialNumbers": r"[a-f0-9]{1,128}", "containerNames": r"tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"}
            for key, pattern in patterns.items():
                values = cycles.get(key)
                if (not isinstance(values, list) or len(values) != 3
                        or any(not isinstance(item, str) or not re.fullmatch(pattern, item) for item in values)
                        or len(set(values)) != 3):
                    raise ValueError("Invalid native AD CS renewal generation identities")
                bounded_cycles[key] = values
            if any(int(item) > 0xffffffff for item in cycles["requestIds"]):
                raise ValueError("Invalid native AD CS request identity")
            for key in ("caRequestCounts", "expiryEpochs"):
                values = cycles.get(key)
                if not isinstance(values, list) or len(values) != 3 or any(type(item) is not int or not 0 < item <= 9007199254740991 for item in values):
                    raise ValueError("Invalid native AD CS renewal generation counters")
                bounded_cycles[key] = values
            counts, expiry = cycles["caRequestCounts"], cycles["expiryEpochs"]
            if counts[2] > 1000 or counts[1] != counts[0] + 1 or counts[2] != counts[1] + 1 or not expiry[0] < expiry[1] < expiry[2]:
                raise ValueError("Invalid native AD CS renewal generation progression")
            result["nativeAdcsBackgroundRenewals"] = bounded_cycles
            lifecycle = cycles.get("workerLifecycle")
            expected = {"failed": False, "starts": 1, "created": 2, "stops": 1, "forwarded": True, "exitCode": 0, "nativeDrained": True, "bridgeReady": True}
            if (not isinstance(lifecycle, dict) or any(type(lifecycle.get(key)) is not type(want) or lifecycle[key] != want for key, want in expected.items())
                    or any(type(lifecycle.get(key)) is not int for key in ("ticks", "finishes", "summaries", "firstTickElapsedMs"))
                    or not 2 <= lifecycle["ticks"] <= 20 or not 2 <= lifecycle["finishes"] <= lifecycle["ticks"]
                    or lifecycle["summaries"] != lifecycle["finishes"] or not 60000 <= lifecycle["firstTickElapsedMs"] <= 180000):
                raise ValueError("Invalid actual background worker lifecycle")
            result["nativeAdcsBackgroundRenewals"]["workerLifecycle"] = {key: lifecycle[key] for key in (*expected, "ticks", "finishes", "summaries", "firstTickElapsedMs")}
            abandon = value.get("nativeUncertainAbandon")
            flags = ("ownedObserverDrained", "ownedTransportBlock", "observedSubmittingTermination", "actualLeaseExpiry", "acknowledgedPublicRecovery", "sameCsrAndKey", "noAutomaticResubmit", "publicAbandonAudited", "unacceptedKeyRemoved", "originalOrphanPreserved", "recoveryPolicyUnchanged")
            counts = ("caRequestsAtFault", "caRequestsAfterRecovery", "caRequestsAfterAbandon")
            if (not isinstance(abandon, dict) or abandon.get("scope") != "native-zero-request-uncertain-abandon"
                    or abandon.get("resolvedIssuingCaAddress") != "10.64.0.4"
                    or any(abandon.get(key) is not True for key in flags)
                    or any(type(abandon.get(key)) is not int or abandon[key] != 0 for key in counts)):
                raise ValueError("Invalid native uncertain-abandon evidence")
            result["nativeUncertainAbandon"] = {key: abandon[key] for key in ("scope", "resolvedIssuingCaAddress", *flags, *counts)}
            timing = ("leaseRemainingAtFaultMs", "recoveryWaitBudgetMs", "actualLeaseWaitMs")
            if (any(type(abandon.get(key)) is not int or not 0 <= abandon[key] <= 900000 for key in timing)
                    or abandon["recoveryWaitBudgetMs"] != abandon["leaseRemainingAtFaultMs"] + 90000
                    or abandon["actualLeaseWaitMs"] + 1000 < abandon["leaseRemainingAtFaultMs"]):
                raise ValueError("Invalid actual lease recovery timing")
            result["nativeUncertainAbandon"].update({key: abandon[key] for key in timing})
            ambiguity = value.get("nativeUncertainOperatorAmbiguity")
            ambiguity_flags = ("ownedObserverDrained", "ownedTransportBlock", "observedSubmittingTermination", "actualLeaseExpiry", "acknowledgedPublicRecovery", "sameCsrAndKey", "noAutomaticResubmit", "originalOrphanPreserved", "recoveryPolicyUnchanged", "operatorCreatedSameCsrAmbiguity", "nativeCaOwnershipVerified", "automaticAttachmentRefused", "unacceptedKeyPreserved", "unrelatedTrustedTlsPreserved", "publicExplicitReconcileAudited", "exactSelectedRequestInstalled", "claimBoundVerification", "sameProtectedMachineKeyInstalled", "unusedOwnedRequestRevoked", "unusedLeafNeverAccepted")
            ambiguity_counts = ("caRequestsAfterOperatorSubmissions", "caRequestsAfterAmbiguousRecovery", "caRequestsAfterExplicitRecovery")
            if (not isinstance(ambiguity, dict)
                    or ambiguity.get("scope") != "native-zero-request-uncertainty-with-operator-created-same-csr-ambiguity"
                    or ambiguity.get("fixtureOrigin") != "operator-created-two-real-system-submissions-of-the-same-public-csr"
                    or ambiguity.get("resolvedIssuingCaAddress") != "10.64.0.4"
                    or any(ambiguity.get(key) is not True for key in ambiguity_flags)
                    or type(ambiguity.get("caRequestsAtFault")) is not int or ambiguity["caRequestsAtFault"] != 0
                    or any(type(ambiguity.get(key)) is not int or ambiguity[key] != 2 for key in ambiguity_counts)):
                raise ValueError("Invalid native operator-created uncertain ambiguity evidence")
            bounded_ambiguity = {key: ambiguity[key] for key in ("scope", "fixtureOrigin", "resolvedIssuingCaAddress", "caRequestsAtFault", *ambiguity_flags, *ambiguity_counts)}
            if (any(type(ambiguity.get(key)) is not int or not 0 <= ambiguity[key] <= 900000 for key in timing)
                    or ambiguity["recoveryWaitBudgetMs"] != ambiguity["leaseRemainingAtFaultMs"] + 90000
                    or ambiguity["actualLeaseWaitMs"] + 1000 < ambiguity["leaseRemainingAtFaultMs"] + 60000
                    or ambiguity["actualLeaseWaitMs"] > ambiguity["recoveryWaitBudgetMs"] + 1000):
                raise ValueError("Invalid native ambiguity actual lease/grace timing")
            bounded_ambiguity.update({key: ambiguity[key] for key in timing})
            for key, pattern in (("enrollmentId", uuid_pattern), ("containerName", r"tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"), ("csrSpkiSha256", r"[a-f0-9]{64}"), ("csrSha256", r"[a-f0-9]{64}")):
                if not isinstance(ambiguity.get(key), str) or not re.fullmatch(pattern, ambiguity[key]):
                    raise ValueError("Invalid native ambiguity identity")
                bounded_ambiguity[key] = ambiguity[key]
            if ambiguity["containerName"] != "tokentimer-enr-" + ambiguity["enrollmentId"]:
                raise ValueError("Native ambiguity key ownership mismatch")
            floor = ambiguity.get("reconcileSearchFrom")
            if type(floor) is not int or not 1 <= floor <= 0xffffffff or type(ambiguity.get("scanWindowSize")) is not int or ambiguity["scanWindowSize"] != 16:
                raise ValueError("Invalid native ambiguity actual scan window")
            bounded_ambiguity.update({"reconcileSearchFrom": floor, "scanWindowSize": 16})
            for key, count, pattern in (("requestIds", 2, r"[1-9][0-9]{0,9}"), ("fingerprints", 2, r"[a-f0-9]{64}"), ("serialNumbers", 2, r"[a-f0-9]{1,128}"), ("jobIds", 3, uuid_pattern)):
                items = ambiguity.get(key)
                if (not isinstance(items, list) or len(items) != count
                        or any(not isinstance(item, str) or not re.fullmatch(pattern, item) for item in items)
                        or len({item.lower() for item in items}) != count):
                    raise ValueError("Invalid native ambiguity distinct identities")
                bounded_ambiguity[key] = list(items)
            if any(not floor <= int(item) < min(floor + 16, 0x100000000) for item in ambiguity["requestIds"]):
                raise ValueError("Native ambiguity candidate outside actual default window")
            for key in ("selectedRequestId", "unusedRequestId"):
                if not isinstance(ambiguity.get(key), str) or ambiguity[key] not in ambiguity["requestIds"]:
                    raise ValueError("Native ambiguity selected/unused request mismatch")
                bounded_ambiguity[key] = ambiguity[key]
            if ambiguity["selectedRequestId"] == ambiguity["unusedRequestId"]:
                raise ValueError("Native ambiguity selected request cannot be revoked")
            result["nativeUncertainOperatorAmbiguity"] = bounded_ambiguity
            public_foreign = public_foreign_spki_fields(value.get("nativePublicForeignSpki"))
            expected_foreign = {"enrollmentId": bounded_ambiguity["enrollmentId"], "originalSpkiSha256": bounded_ambiguity["csrSpkiSha256"], "reconcileSearchFrom": bounded_ambiguity["reconcileSearchFrom"], "selectedRequestId": bounded_ambiguity["selectedRequestId"], "selectedFingerprint": bounded_ambiguity["fingerprints"][bounded_ambiguity["requestIds"].index(bounded_ambiguity["selectedRequestId"])]}
            if any(public_foreign[key] != expected for key, expected in expected_foreign.items()) or public_foreign["foreignRequestId"] in bounded_ambiguity["requestIds"] or public_foreign["failedJobId"] in bounded_ambiguity["jobIds"]:
                raise ValueError("Public foreign-key refusal must bind actual matching-candidate recovery")
            result["nativePublicForeignSpki"] = public_foreign

            browser = result["nativeBrowserReconcile"]
            expected_browser = {"enrollmentId": bounded_ambiguity["enrollmentId"], "selectedRequestId": bounded_ambiguity["selectedRequestId"], "unusedRequestId": bounded_ambiguity["unusedRequestId"], "selectedFingerprint": bounded_ambiguity["fingerprints"][bounded_ambiguity["requestIds"].index(bounded_ambiguity["selectedRequestId"])], "continuationJobId": bounded_ambiguity["jobIds"][2]}
            if any(browser[key] != expected for key, expected in expected_browser.items()):
                raise ValueError("Browser reconciliation does not match native ownership proof")
            cancellation = value.get("nativeIssuedCancellation")
            if not isinstance(cancellation, dict):
                raise ValueError("Missing native issued cancellation evidence")
            bounded_cancel = {key: cancellation.get(key) is True for key in ("actualCaIssuedBeforeCancel", "caLeafSignatureAndCsrSpkiVerified", "controlPlaneStillPendingBeforeCancel", "nonExportableKeyPresentBeforeCancel", "signedTerminalCleanupSucceeded", "exactUnacceptedKeyAbsent", "certificateNeverAccepted", "sameRequestSnapshotAndCsrPreserved", "noAdditionalCaRequest", "outgoingTrustedTlsUnchanged", "terminalReconcileRefused", "unusedIssuedLeafRevoked")}
            for key, pattern in (("requestId", r"[1-9][0-9]{0,9}"), ("snapshotSha256", r"[a-fA-F0-9]{64}")):
                if not isinstance(cancellation.get(key), str) or not re.fullmatch(pattern, cancellation[key]):
                    raise ValueError("Invalid issued cancellation identity")
                bounded_cancel[key] = cancellation[key]
            if cancellation.get("pollIntervalSeconds") != 900 or cancellation.get("schedulerClock") != "default-real-now" or cancellation.get("databaseDatesRewritten") is not False or cancellation.get("journalRewritten") is not False:
                raise ValueError("Invalid issued cancellation clock evidence")
            bounded_cancel.update({"pollIntervalSeconds": 900, "schedulerClock": "default-real-now", "databaseDatesRewritten": False, "journalRewritten": False})
            result["nativeIssuedCancellation"] = bounded_cancel
            count = value.get("primaryNativePreflightDispatchCount")
            cohorts = value.get("nativePreflightCohorts")
            if type(count) is not int or not 2 <= count <= 20 or count - dispatch["count"] > 18 or not isinstance(cohorts, list) or len(cohorts) > 128:
                raise ValueError("Invalid native preflight budget evidence")
            result["primaryNativePreflightDispatchCount"] = count
            expiry = value.get("nativeValidationExpiry")
            if not isinstance(expiry, dict):
                raise ValueError("Missing native validation deadline evidence")
            bounded_expiry = {key: expiry.get(key) is True for key in ("actualNativeRevocationUnknown", "actualSignedContinuationExpired", "persistedDeadlineSurvivedRestartAndPolicyRestoration", "exactUnacceptedKeyFreed", "noCertificateAccepted", "noCaResubmission", "outgoingTrustedTlsPreserved", "chainCacheValueRestored")}
            for key in ("configuredTimeoutSeconds", "defaultTimeoutSeconds", "storedWindowSeconds", "monotonicObservedWaitSeconds"):
                if type(expiry.get(key)) not in (int, float) or not 0 <= expiry[key] <= 86400:
                    raise ValueError("Invalid native deadline duration")
                bounded_expiry[key] = expiry[key]
            for key, pattern in (("actualDeadline", r"[0-9TZ:.+\-]{16,40}"), ("requestId", r"[1-9][0-9]{0,9}"), ("snapshotSha256", r"[a-f0-9]{64}")):
                if not isinstance(expiry.get(key), str) or not re.fullmatch(pattern, expiry[key]):
                    raise ValueError("Invalid native deadline identity")
                bounded_expiry[key] = expiry[key]
            if expiry.get("nativeAndCaClocks") != "actual" or expiry.get("qualificationScope") != "configured-five-minute-window-not-default-24-hour-elapsed":
                raise ValueError("Invalid native elapsed deadline scope")
            bounded_expiry.update({"nativeAndCaClocks": "actual", "qualificationScope": "configured-five-minute-window-not-default-24-hour-elapsed"})
            result["nativeValidationExpiry"] = bounded_expiry
            result["nativePreflightCohorts"] = []
            mutations = value.get("nativeTemplateMutations")
            if not isinstance(mutations, list) or len(mutations) > 32:
                raise ValueError("Invalid native template mutation evidence")
            result["nativeTemplateMutations"] = []
            for mutation in mutations:
                if not isinstance(mutation, dict) or any(not isinstance(mutation.get(key), str) or not re.fullmatch(pattern, mutation[key]) for key, pattern in (("caseId", r"[a-z0-9-]{1,100}"), ("template", r"TTQualification[A-Za-z0-9]{1,80}"), ("reason", r"[A-Za-z0-9_-]{1,100}"), ("preflightVerdict", r"unsafe|unreadable|unknown"))):
                    raise ValueError("Invalid bounded template verdict")
                item = {key: mutation[key] for key in ("caseId", "template", "reason", "preflightVerdict")}
                item.update({key: mutation.get(key) is True for key in ("originalConfirmedIssuerReused", "actualSignedJobRefused", "noCaRequestAllocated", "noKeyGenerated", "outgoingTrustedTlsPreserved")})
                result["nativeTemplateMutations"].append(item)
            for cohort in cohorts:
                if not isinstance(cohort, dict) or any(not isinstance(cohort.get(key), str) or not re.fullmatch(r"[a-fA-F0-9-]{36}", cohort[key]) for key in ("workspaceId", "agentId")):
                    raise ValueError("Invalid native preflight cohort identity")
                if type(cohort.get("dispatchCount")) is not int or not 1 <= cohort["dispatchCount"] <= 18 or cohort.get("dispatchLimit") != 18 or cohort.get("nativeIdentity") != "LocalSystem" or cohort.get("runtime") != "candidate-cli":
                    raise ValueError("Invalid native preflight cohort budget")
                result["nativePreflightCohorts"].append({key: cohort[key] for key in ("workspaceId", "agentId", "dispatchCount", "dispatchLimit", "nativeIdentity", "runtime")})
        if "fixtureSources" in value:
            result["fixtureSources"] = supporting_sources(value["fixtureSources"])
        if value.get("suite") == "linux-systemd-writepath":
            evidence = value.get("nativeWritePath", {})
            if not isinstance(evidence, dict):
                raise ValueError("Invalid native systemd evidence")
            result["nativeWritePath"] = {key: evidence.get(key) is True for key in ("freshExecStartPreEvidence", "hostDacWriteVerified", "allowedWrite")}
            result["nativeWritePath"].update({"deniedError": "EROFS" if evidence.get("deniedError") == "EROFS" else "invalid", "samePeerDacMode": "0777" if evidence.get("samePeerDacMode") == "0777" else "invalid", "nonRootUid": evidence.get("nonRootUid") if type(evidence.get("nonRootUid")) is int and 0 < evidence["nonRootUid"] <= 4294967295 else 0})
        if value.get("suite") == "kubernetes-host":
            evidence = value.get("nativeCompaction")
            if not isinstance(evidence, dict):
                raise ValueError("Missing native compaction evidence")
            bounded = {key: evidence.get(key) is True for key in ("productionClient", "productionObserver", "controlPlaneRestarted", "ownedSingleNodeCluster")}
            bounded["expiredStatus"] = 410 if type(evidence.get("expiredStatus")) is int and evidence["expiredStatus"] == 410 else 0
            for key in ("originalResourceVersion", "compactedRevision", "observedResourceVersion"):
                if not isinstance(evidence.get(key), str) or not re.fullmatch(r"[1-9][0-9]{0,19}", evidence[key]):
                    raise ValueError("Invalid compaction revision")
                bounded[key] = evidence[key]
            if not isinstance(evidence.get("certificateUid"), str) or not re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", evidence["certificateUid"]):
                raise ValueError("Invalid compaction certificate identity")
            bounded["certificateUid"] = evidence["certificateUid"]
            result["nativeCompaction"] = bounded
        if value.get("suite") == linux_backup_dac_proof.SUITE:
            result.update(linux_backup_dac_proof.project_report(value))
        if value.get("suite") == "windows-installer-cli-second-rename":
            rollback = value.get("nativeCliSecondRename")
            flags = ("sourceOplockGranted", "actualSourceOpenBrokeOplock", "stagingHeldBeforeCopyResumed", "nativeOrderedRestoration", "originalDirectoryIdentityPreserved", "installedBytesUnchanged", "explicitStagingCleanupFailure", "sourceBytesUnchanged", "nativeHandleReleased", "ownedInstallerDrained", "ownedDriverDrained", "ownedStagingRemoved", "originalInstallerCliBytes", "sameRunningLocalSystemServicePid", "configurationCredentialAndPinUnchanged", "freshAuthenticatedHeartbeat", "nonExportableMachineCngCustodyUnchanged", "nativeBindingAndTrustedTlsUnchanged", "ownedCertificateKeyAndEndpointRemoved")
            if (not isinstance(rollback, dict)
                    or rollback.get("scope") != "unmodified-installer-cli-canonical-root-operator-cng-binding"
                    or any(rollback.get(key) is not True for key in flags)):
                raise ValueError("Invalid full installer CLI second-rename evidence")
            result["nativeCliSecondRename"] = {key: rollback[key] for key in ("scope", *flags)}
        if value.get("suite") == "windows-certificate-dry-run":
            dry_run = value.get("nativeCertificateDryRun")
            flags = ("priorRealIssuanceVerified", "authenticatedPlansPersisted", "nativeCertificateInventoryUnchanged", "machineKeyMetadataUnchanged", "exactCngCustodyUnchanged", "httpSysBindingUnchanged", "trustedTlsUnchanged", "configurationCredentialPinUnchanged", "dnsProxyRequestsUnchanged")
            if (not isinstance(dry_run, dict)
                    or dry_run.get("scope") != "installed-windows-signed-certificate-plans-native-state-and-dns-observation"
                    or dry_run.get("admission") != "production-service-explicit-mode"
                    or any(dry_run.get(key) is not True for key in flags)
                    or type(dry_run.get("deployPlanSteps")) is not int or dry_run["deployPlanSteps"] != 3
                    or type(dry_run.get("renewPlanSteps")) is not int or dry_run["renewPlanSteps"] != 6):
                raise ValueError("Invalid native Windows certificate dry-run evidence")
            result["nativeCertificateDryRun"] = {key: dry_run[key] for key in ("scope", "admission", "deployPlanSteps", "renewPlanSteps", *flags)}
        if value.get("suite") == "native-agent-api":
            dry_run = value.get("nativeCertificateDryRun")
            flags = ("deployDryRunComplete", "renewDryRunComplete", "authenticPlanEvidence", "deployedFilesUnchangedDuringDryRun", "custodyFilesUnchangedDuringDryRun", "servedLeafUnchangedDuringDryRun", "noCommandsOrGatewayCallsDuringDryRun", "realDeployChangedFileAndTrustedTls", "realValidateAndReloadObserved", "realRenewCommandReachedCaAndDnsSentinels", "renewControlFailedBeforeIssuance", "identityAndConfigRestored", "ownedResourcesCleaned")
            counts = {"dryRunOperations": 2, "deployPlanSteps": 3, "renewPlanSteps": 6, "validateCalls": 1, "reloadCalls": 1, "caSentinelCalls": 1, "dnsSentinelCalls": 1}
            if (not isinstance(dry_run, dict)
                    or dry_run.get("scope") != "native-linux-signed-certificate-dry-run-with-local-command-controls"
                    or dry_run.get("admission") != "production-service-explicit-mode"
                    or any(dry_run.get(key) is not True for key in flags)
                    or any(type(dry_run.get(key)) is not int or dry_run[key] != expected for key, expected in counts.items())):
                raise ValueError("Invalid native certificate dry-run evidence")
            result["nativeCertificateDryRun"] = {key: dry_run[key] for key in ("scope", "admission", *flags, *counts)}
            timing = value.get("nativeDispatchTiming")
            if not isinstance(timing, dict):
                raise ValueError("Missing native dispatch timing evidence")
            bounded_timing = {key: timing.get(key) is True for key in ("nativeClockRefusalObserved", "executionSuccessAbsent", "nonceUnconsumed", "freshClaimRecoverySucceeded", "credentialAndPinUnchanged")}
            for key in ("fixtureLifetimeSeconds", "localToleranceMs", "heldMonotonicMs", "originalDispatchLifetimeSeconds", "leaseCallsBeforeRefusal", "expiredNonceResultStatus"):
                if type(timing.get(key)) not in (int, float) or not 0 <= timing[key] <= 86400000:
                    raise ValueError("Invalid native dispatch timing counter")
                bounded_timing[key] = timing[key]
            for key in ("issuedAt", "expiresAt", "releasedAt"):
                if not isinstance(timing.get(key), str) or not re.fullmatch(r"[0-9TZ:.+\-]{16,40}", timing[key]):
                    raise ValueError("Invalid native dispatch timing date")
                bounded_timing[key] = timing[key]
            for key in ("databaseDatesRewritten", "journalRewritten"):
                if timing.get(key) is not False:
                    raise ValueError("Native dispatch timing state rewritten")
                bounded_timing[key] = False
            for key, expected in (("clocks", "actual-host-monotonic-and-database"), ("fixture", "production-signer-short-lifetime-and-delayed-HTTP-delivery"), ("expiredNonceResultCode", "CERTOPS_AGENT_RESULT_NONCE_REJECTED"), ("actualServerJobState", "claimed"), ("actualRejectedOutbox", "dead-letter"), ("qualificationScope", "native-Linux-shortened-dispatch-fixture-not-stock-TTL-or-Windows-SCM")):
                if timing.get(key) != expected:
                    raise ValueError("Invalid native dispatch timing scope")
                bounded_timing[key] = expected
            result["nativeDispatchTiming"] = bounded_timing
            privacy = value.get("nativeChildOutputPrivacy")
            if not isinstance(privacy, dict) or privacy.get("executedChildren") != 2:
                raise ValueError("Invalid native child output evidence")
            result["nativeChildOutputPrivacy"] = {key: privacy.get(key) is True for key in ("stdoutEmitted", "stderrEmitted", "rawChildOutputWithheld", "genericExecutionMarkerPersisted", "jobSucceeded")}
            result["nativeChildOutputPrivacy"]["executedChildren"] = 2
            rows = value.get("nativeLogFaults")
            if not isinstance(rows, list) or len(rows) > 16:
                raise ValueError("Invalid native log transport evidence")
            known = {name for name in known_ids if name.startswith("native-agent-log-")}
            result["nativeLogFaults"] = []
            for row in rows:
                if not isinstance(row, dict) or row.get("scenario") not in known:
                    raise ValueError("Unknown native log transport scenario")
                item = {"scenario": row["scenario"]}
                item.update({key: row.get(key) is True for key in ("actualNativeConsole", "jobSucceeded", "finalAcknowledged")})
                for key in ("attempts", "persistedLines", "agentGapLines", "serverDroppedLines"):
                    if type(row.get(key)) is not int or not 0 <= row[key] <= 1000:
                        raise ValueError("Invalid native log transport counter")
                    item[key] = row[key]
                result["nativeLogFaults"].append(item)
        if value.get("suite") == "dns-provider-errors":
            inventory = json.loads((ROOT / "docs/certops/dns-provider-errors.json").read_text())
            expected = {(provider["file"], name) for provider in inventory["providers"] + inventory.get("sharedContracts", []) for name in provider["requiredTests"]}
            cases = value.get("dnsAdapterCases")
            if not isinstance(cases, list) or len(cases) > 2048:
                raise ValueError("Invalid DNS adapter case inventory")
            result["dnsAdapterCases"] = [{"file": row["file"], "name": row["name"], "status": row.get("status") if row.get("status") in ("passed", "failed", "skipped") else "invalid"}
                for row in cases if isinstance(row, dict) and (row.get("file"), row.get("name")) in expected]
        return result
    if isinstance(value, list) and value and value[0].get("scope") in scopes:
        keys = ("type", "name", "candidateSha", "scope", "skip", "todo",
                "fixtureSource", "qualificationEnvironment", "artifactQualification", "qualificationStatus", "experimental")
        return [{**{key: event[key] for key in keys if key in event},
                 **acme_key_reuse_fields(event),
                 **installed_handoff_fields(event),
                 **windows_key_reuse_refusal_fields(event),
                 **installed_iis_refusal_fields(event),
                 **installed_crash_fields(event),
                 **installed_paths_fields(event),
                 **({"windowsPublicIssuance": windows_public_issuance(event["windowsPublicIssuance"])} if "windowsPublicIssuance" in event and isinstance(event.get("scope"), str) and event["scope"].startswith("real-agent-windows-acme-iis/") else {}),
                 **({"fixtureSources": supporting_sources(event["fixtureSources"])} if "fixtureSources" in event else {}),
                 "file": event.get("fixtureSource", {}).get("file", "")}
                for event in value]
    return None


def committed_case_names(scope, kind):
    slots = json.loads((ROOT / "docs/certops/release-qualification-matrix.json").read_text())["slots"]
    matching = [slot for slot in slots if slot["kind"] == kind and slot["suite"] == scope]
    if kind == "database":
        groups = json.loads((ROOT / "tests/integration/certops-qualification-groups.json").read_text())
        return {(case["file"], case["name"]) for slot in matching
                for case in groups[slot["requiredGroup"]]["requiredTests"]}
    names = set()
    for slot in matching:
        # Node reports static describe containers in addition to mandatory test cases.
        # Their names must come from the committed source, never artifact strings.
        source = (ROOT / slot["source"]).read_text()
        names.update(re.findall(r'\bdescribe\(\s*["\']([^"\'\r\n]{1,200})["\']', source))
        names.update(slot.get("requiredTests", []))
        if "requiredInventory" in slot:
            names.update(json.loads((ROOT / slot["requiredInventory"]).read_text())["requiredTests"])
    return names


def project_case_metadata(result):
    """Retain unknown/failing cases as invalid evidence without their raw names."""
    if isinstance(result, list):
        for event in result:
            known = isinstance(event.get("name"), str) and event["name"] in committed_case_names(event.get("scope"), "stack")
            if not known:
                event["name"] = "[unrecognized]"
            if event.get("type") not in ("test:pass", "test:fail") or (not known and event.get("type") == "test:pass"):
                event["type"] = "invalid"
            for key in ("skip", "todo"):
                if key in event and type(event[key]) is not bool:
                    raise ValueError("Invalid stack execution flags")
    elif isinstance(result, dict) and "tests" in result:
        known = committed_case_names(result.get("scope"), "database")
        for case in result["tests"]:
            recognized = isinstance(case.get("file"), str) and isinstance(case.get("name"), str) and (case["file"], case["name"]) in known
            if not recognized:
                case["file"] = "[unrecognized]"
                case["name"] = "[unrecognized]"
            if case.get("status") not in ("pass", "fail", "pending") or (not recognized and case.get("status") == "pass"):
                case["status"] = "invalid"
    return result


def project_common_fields(report, suites, scopes, database_scopes):
    """Validate known scalar fields before collected artifacts are written."""
    enums = {
        "status": {"passed", "failed", "skipped", "running"},
        "evidenceLevel": {"unit", "integration", "real-host", "e2e"},
        "artifactQualification": {"workflow-checkout-source", "local-worktree-source-baseline-sha-only"},
        "qualificationStatus": {"qualified", "not-qualified"},
        "suite": set(suites), "scope": set(scopes) | set(database_scopes),
    }
    for key, allowed in enums.items():
        if key in report:
            if not isinstance(report[key], str):
                raise ValueError("Invalid qualification scalar field type")
            if report[key] not in allowed:
                report[key] = "invalid"
    for key in ("strict", "experimental"):
        if key in report and type(report[key]) is not bool:
            raise ValueError("Invalid qualification boolean field")
    if "schemaVersion" in report and (type(report["schemaVersion"]) is not int or not 0 <= report["schemaVersion"] <= 100):
        raise ValueError("Invalid qualification schema version")
    if "candidateSha" in report:
        raw = report["candidateSha"]
        if raw is not None and not isinstance(raw, str):
            raise ValueError("Invalid qualification candidate identity type")
        if isinstance(raw, str) and not re.fullmatch(r"[a-f0-9]{40}", raw):
            report["candidateSha"] = "invalid"
    for key in ("startedAt", "finishedAt"):
        if key not in report:
            continue
        raw = report[key]
        if not isinstance(raw, str):
            raise ValueError("Invalid qualification timestamp type")
        try:
            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", raw):
                raise ValueError("Timestamp format")
            datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            report[key] = "invalid"
    return report


def sanitized_report(value, suites, scopes, database_scopes=()):
    result = _sanitized_report(value, suites, scopes, database_scopes)
    for report in result if isinstance(result, list) else [result]:
        if not isinstance(report, dict):
            continue
        project_common_fields(report, suites, scopes, database_scopes)
        if "qualificationEnvironment" in report:
            report["qualificationEnvironment"] = public_environment(report["qualificationEnvironment"])
        if "fixtureSource" in report:
            report["fixtureSource"] = source_fingerprint(report["fixtureSource"])
        if "fixtureSources" in report:
            report["fixtureSources"] = supporting_sources(report["fixtureSources"])
    return project_case_metadata(result)


def extract_reports(raw, suites, scopes, database_scopes=(), authenticate_report=None):
    if len(raw) > MAX_ARCHIVE:
        raise ValueError("Artifact archive exceeds the bounded download limit")
    reports = []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if len(entries) > 500 or sum(item.file_size for item in entries) > 50 * 1024 * 1024:
            raise ValueError("Artifact uncompressed size or entry count exceeds limit")
        for item in entries:
            name = item.filename.replace("\\", "/")
            parts = PurePosixPath(name)
            if parts.is_absolute() or ".." in parts.parts or re.match(r"^[a-zA-Z]:", name) or stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError("Unsafe artifact archive path")
            if item.is_dir() or parts.suffix not in (".json", ".jsonl"):
                continue
            if item.file_size > MAX_REPORT:
                raise ValueError("Qualification report exceeds size limit")
            text = archive.read(item).decode("utf-8")
            try:
                value = (retention24h_collection.json_bytes(text.encode("utf-8")) if authenticate_report else json.loads(text)) if parts.suffix == ".json" else [json.loads(line) for line in text.splitlines() if line.strip()]
            except (ValueError, TypeError, AttributeError):
                raise ValueError("Malformed JSON qualification artifact") from None
            if authenticate_report is not None and not authenticate_report(value):
                continue
            try:
                sanitized = sanitized_report(value, suites, scopes, database_scopes)
            except (ValueError, TypeError, AttributeError):
                raise ValueError("Malformed JSON qualification artifact") from None
            if sanitized is not None:
                reports.append((parts.suffix, sanitized))
    return reports


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def download(url, token=None, redirect=False):
    """One authenticated API request and at most one unsigned artifact redirect.

    Signed URLs stay in memory. Blob requests never receive API credentials,
    follow another redirect, or bypass the existing bounded response size.
    """
    def validate(target, blob):
        if not isinstance(target, str) or len(target) > 16384 or "#" in target or any(ord(char) <= 32 or ord(char) == 127 for char in target):
            raise ValueError("Artifact download URL is invalid")
        try:
            parsed = urllib.parse.urlsplit(target)
            port = parsed.port
        except ValueError:
            raise ValueError("Artifact download URL is invalid") from None
        if (parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
                or port not in (None, 443) or parsed.fragment):
            raise ValueError("Artifact download URL is invalid")
        host = parsed.hostname or ""
        if blob:
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host) or ".." in host or not any(host.endswith(suffix) for suffix in (
                    ".blob.core.windows.net", ".githubusercontent.com", ".actions.githubusercontent.com")):
                raise ValueError("Artifact redirect host is not approved")
        elif host != "api.github.com":
            raise ValueError("Initial request must stay on GitHub API")

    def request(target, credential=None, blob=False):
        validate(target, blob)
        headers = {"User-Agent": "certops-qualification-collector"}
        if not blob:
            headers.update({"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
        if credential:
            headers["Authorization"] = "Bearer " + credential
        try:
            with urllib.request.build_opener(NoRedirect).open(urllib.request.Request(target, headers=headers), timeout=60) as response:
                raw = response.read(MAX_ARCHIVE + 1)
                if len(raw) > MAX_ARCHIVE:
                    raise ValueError("Bounded download exceeded")
                return raw
        except urllib.error.HTTPError as error:
            if redirect and not blob and error.code == 302:
                # The only allowed transition drops all GitHub authentication.
                location = error.headers.get("Location")
                validate(location, True)
                return request(location, None, True)
            raise ValueError("Qualification API/download request failed") from None

    return request(url, token)


def main():
    candidate = os.environ.get("CERTOPS_RELEASE_CANDIDATE", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    run_ids = json.loads(os.environ.get("CERTOPS_RELEASE_RUN_IDS", "[]"))
    if not re.fullmatch(r"[a-f0-9]{40}", candidate) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not token:
        raise ValueError("Explicit candidate, repository and read-only workflow token required")
    matrix = json.loads((ROOT / "docs/certops/release-qualification-matrix.json").read_text())
    limits = collection_limits(len(matrix["slots"]))
    validate_run_ids(run_ids, limits)
    suites = {slot["suite"] for slot in matrix["slots"] if slot["kind"] == "host"}
    scopes = {slot["suite"] for slot in matrix["slots"] if slot["kind"] == "stack"}
    database_scopes = {slot["suite"] for slot in matrix["slots"] if slot["kind"] == "database"}
    output = ROOT / "qualification-results/release-collection"
    output.mkdir(parents=True, exist_ok=True)
    files = []
    archive_count = 0
    downloaded_bytes = 0
    coverage = catalog_coverage()
    summary = {"schemaVersion": 1, "candidateSha": candidate, "runIds": run_ids, "status": "failed", "mandatoryEnvironments": len(matrix["slots"]), "collectedReports": 0, "qualificationScope": "committed-mandatory-matrix", "allFeaturesQualified": False, "catalogCoverage": coverage}
    try:
        for run_id in run_ids:
            endpoint = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"
            run = json.loads(download(endpoint, token))
            owner_auth = {retention24h_collection.FINALIZER: retention24h_collection,
                          adcs_ttl24h_collection.FINALIZER: adcs_ttl24h_collection}.get(run.get("path"))
            elapsed_finalizer = owner_auth is not None
            if elapsed_finalizer:
                owner_auth.validate_finalizer_run(run, repository, run_id)
            else:
                validate_run(run, candidate, repository)
            data = json.loads(download(endpoint + "/artifacts?per_page=100", token))
            if data.get("total_count", 0) > MAX_ARTIFACTS_PER_RUN:
                raise ValueError("Artifact inventory exceeds explicit bound")
            for artifact in data.get("artifacts", []):
                archive_count += 1
                if archive_count > limits["archives"]:
                    raise ValueError("Collection artifact count exceeds limit")
                if artifact.get("expired"):
                    raise ValueError("Selected candidate artifact has expired")
                artifact_id = artifact.get("id")
                if type(artifact_id) is not int or artifact.get("size_in_bytes", MAX_ARCHIVE + 1) > MAX_ARCHIVE:
                    raise ValueError("Artifact identity or size is invalid")
                raw = download(f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}/zip", token, redirect=True)
                downloaded_bytes += len(raw)
                if downloaded_bytes > MAX_TOTAL_DOWNLOAD:
                    raise ValueError("Collection total download size exceeds limit")
                if elapsed_finalizer and artifact.get("digest") != "sha256:" + hashlib.sha256(raw).hexdigest():
                    raise ValueError("Real-day finalizer artifact digest does not match GitHub")
                def authenticate_elapsed_report(report):
                    if not isinstance(report, dict):
                        return False
                    if report.get("suite") != owner_auth.SUITE:
                        if report.get("suite") in suites or report.get("scope") in scopes | database_scopes:
                            raise ValueError("Real-day finalizer cannot supply other qualification suites")
                        return False
                    # Scheduled controllers can finish several original campaigns.
                    # Select the explicitly requested native candidate only;
                    # never relabel another campaign with the controller SHA.
                    if report.get("candidateSha") != candidate:
                        return False
                    def fetch_retention_owner(url, redirect=False):
                        nonlocal downloaded_bytes, archive_count
                        owner_raw = download(url, token, redirect=redirect)
                        downloaded_bytes += len(owner_raw)
                        if redirect:
                            archive_count += 1
                        if downloaded_bytes > MAX_TOTAL_DOWNLOAD or archive_count > limits["archives"]:
                            raise ValueError("Real-day ownership exceeds collection budget")
                        return owner_raw
                    owner_auth.authenticate(report, run, run_id, candidate, repository, fetch_retention_owner)
                    return True
                reports = extract_reports(raw, suites, scopes, database_scopes, authenticate_report=authenticate_elapsed_report) if elapsed_finalizer else extract_reports(raw, suites, scopes, database_scopes)
                for suffix, report in reports:
                    if len(files) >= limits["reports"]:
                        raise ValueError("Collection qualification report count exceeds limit")
                    destination = output / f"report-{run_id}-{artifact_id}-{len(files)}{suffix}"
                    destination.write_text(json.dumps(report) if suffix == ".json" else "\n".join(json.dumps(item) for item in report), encoding="utf-8")
                    files.append(str(destination))
        summary["collectedReports"] = len(files)
        if not files:
            raise ValueError("No mandatory qualification reports collected")
        environment = {**os.environ, "GITHUB_SHA": candidate}
        result = subprocess.run(["node", "scripts/certops-release-qualification.js", candidate, *files], cwd=ROOT, env=environment, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            # Report identities and bounded verdicts are useful; raw artifacts
            # and subprocess diagnostics are not copied into the summary.
            raise ValueError("Mandatory release matrix qualification failed")
        validate_matrix_summary(json.loads(result.stdout), candidate, len(matrix["slots"]), coverage)
        summary["status"] = "passed"
    finally:
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print("Committed mandatory matrix passed; full feature specifications remain separately tracked")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Even argument/download failures produce a sanitized failed verdict;
        # an older local summary must never look like the current result.
        output = ROOT / "qualification-results/release-collection"
        output.mkdir(parents=True, exist_ok=True)
        candidate = os.environ.get("CERTOPS_RELEASE_CANDIDATE", "")
        (output / "summary.json").write_text(json.dumps({"schemaVersion": 1, "candidateSha": candidate if re.fullmatch(r"[a-f0-9]{40}", candidate) else None, "status": "failed", "qualificationScope": "committed-mandatory-matrix", "allFeaturesQualified": False}, indent=2) + "\n", encoding="utf-8")
        print(str(error) if isinstance(error, ValueError) else "Qualification collection failed", file=sys.stderr)
        sys.exit(1)
