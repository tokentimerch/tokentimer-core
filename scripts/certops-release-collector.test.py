import certops_qualification_manifest as qualification_manifest

def adcs_result_outbox_evidence():
    import certops_adcs_result_outbox_proof as proof
    return {"scope": proof.SCOPE, "enrollmentId": "10000000-0000-4000-8000-000000000001", "jobId": "10000000-0000-4000-8000-000000000002", "claimId": "10000000-0000-4000-8000-000000000003", "requestId": 42, "fingerprints": ["1" * 64, "2" * 64], "caRequestCounts": [10, 11, 11], "recordedAttempts": 1, "retryDelayMs": 15000, "atomicTreeContainmentQualified": False, "backgroundTimerQualified": False, **{key: True for key in proof.FLAGS}}


def signing_pin_refusal_proof():
    return json.loads("{\"scope\":\"installed-system-corrupt-signing-pin-startup-refusal\",\"pins\":[\"malformed-pin-json\",\"invalid-pin-shape\"],\"startupFailureCount\":2,\"missingPinQualified\":false,\"inFlightMutationQualified\":false,\"twoActualSystemPinFailures\":true,\"freshStoppedServiceForEach\":true,\"configurationAndCredentialPreserved\":true,\"nativeCngAndBindingPreserved\":true,\"trustedTlsPreserved\":true,\"noNewAgentOrJob\":true,\"exactOriginalPinRestored\":true,\"actualRepairedSystemChild\":true,\"freshAuthenticatedHeartbeat\":true,\"ownedPinGuardCleared\":true}")


def installed_verify_rollback_proof():
    return json.loads("{\"scope\":\"installed-public-renewal-native-shadow-verify-failure-rollback-and-retry\",\"certificateId\":\"11111111-1111-4111-8111-111111111111\",\"jobIds\":[\"22222222-2222-4222-8222-222222222222\",\"44444444-4444-4444-8444-444444444444\"],\"claimIds\":[\"33333333-3333-4333-8333-333333333333\",\"55555555-5555-4555-8555-555555555555\"],\"fingerprints\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"],\"spkiFingerprints\":[\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"],\"failedJobStatus\":\"failed\",\"failureCode\":\"VERIFY_FAILED\",\"rolledBack\":true,\"retryJobStatus\":\"succeeded\",\"bindFailureQualified\":false,\"rollbackFailureQualified\":false,\"expiryCleanupQualified\":false,\"transientNewBindingObservationQualified\":false,\"appIdPreservationQualified\":false,\"originalNativeSniAndTrustedTls\":true,\"exactOwnedShadowAndSiblingAdmission\":true,\"shadowInitiallyServedSamePredecessor\":true,\"actualPublicSignedCurrentClaim\":true,\"actualCaLeafAndProtectedCngAccepted\":true,\"claimBoundVerifyFailureAndRollbackEvidence\":true,\"nativePredecessorBindingRestored\":true,\"predecessorKeyAndTrustedTlsPreserved\":true,\"siblingBindingAndTrustedTlsPreserved\":true,\"exactShadowRemovedBeforeRetry\":true,\"freshPublicSignedRetrySucceeded\":true,\"freshLeafSpkiProtectedKeyAndTrustedTls\":true,\"profileAndProtectedStatePreserved\":true,\"failedAcceptedLeafOwnershipRecorded\":true,\"ownedEndpointCleanupCompleted\":true}")


def cng_journal_acl_proof():
    return {"scope":"native-prepared-cng-preserved-through-unreadable-adcs-journal","caEnrollmentQualified":False,"installedServiceQualified":False,"actualPreparedNativeKeyPrerequisite":True,"actualFreshOsReadAndListDenied":True,"productionJournalNotAbsent":True,"actualOrphanReconciliationDeferred":True,"sameNativePrivateKeyPossession":True,"sameJournalBytesAndFileIdentities":True,"exactRetainedHandleAclsRestored":True,"ownedNativeChildrenDrained":True,"productionJournalReadersRecovered":True}
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
import subprocess
from certops_adcs_ocsp_proof import FLAGS as OCSP_FLAGS, FALSE_FLAGS as OCSP_FALSE_FLAGS, SCOPE as OCSP_SCOPE
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch


def ocsp_evidence():
    return {
        "scope": OCSP_SCOPE,
        "enrollmentIds": ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"],
        "jobIds": ["33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"],
        "requestIds": [41, 42], "signerRequestId": 40,
        "leafFingerprints": ["a" * 64, "b" * 64], "signerFingerprint": "c" * 64,
        "issuerKeySha256": "d" * 64, "nativeHelperSha256": "e" * 64, "publicCrlSha256": "f" * 64,
        "responseSha256": ["1" * 64, "2" * 64, "3" * 64],
        "caRequestCounts": [39, 40, 41, 42], "nativeVerdicts": ["valid", "revocation_unknown", "valid"],
        "deferredRecovery": {"originalJobId":"55555555-5555-4555-8555-555555555555","originalClaimId":"66666666-6666-4666-8666-666666666666","continuationJobId":"33333333-3333-4333-8333-333333333333","continuationClaimId":"77777777-7777-4777-8777-777777777777","requestId":41},
        **{key: True for key in OCSP_FLAGS}, **{key: False for key in OCSP_FALSE_FLAGS},
    }


def revoked_ocsp_evidence():
    import certops_adcs_ocsp_revoked_proof as proof
    base = ocsp_evidence()
    return {
        "scope": proof.SCOPE,
        "historicalEnrollmentId": base["enrollmentIds"][0],
        "currentEnrollmentId": base["enrollmentIds"][1],
        "historicalRequestId": base["requestIds"][0],
        "currentRequestId": base["requestIds"][1],
        "originalCrlSha256": base["publicCrlSha256"],
        "revokedCrlSha256": "8" * 64,
        "originalCrlNumber": "0",
        "revokedCrlNumber": "1",
        "historicalFingerprint": base["leafFingerprints"][0],
        "currentFingerprint": base["leafFingerprints"][1],
        "historicalSerial": "A2",
        "revocationTime": "2026-10-15T10:00:00.000Z",
        "responseSha256": "9" * 64,
        "signerFingerprint": base["signerFingerprint"],
        "issuerKeySha256": base["issuerKeySha256"],
        "nativeVerdict": "revoked",
        "caRequestCounts": [base["caRequestCounts"][-1], base["caRequestCounts"][-1]],
        **{key: True for key in proof.FLAGS},
        **{key: False for key in proof.FALSE_FLAGS},
    }

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("collector", Path(__file__).with_name("certops-release-collector.py"))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def adcs_capacity_proof():
    flags = ("freshConfirmedIssuer", "actualPostConfirmationPreflight", "sixConcurrentPublicRequests", "fivePersistedPendingApprovals", "sixthTransactionRolledBack", "noCaRequestsBeforeApproval", "noNativeKeysBeforeApproval", "distinctAuthorizedApprover", "firstNativeCompletionFreesSlot", "refusedSubjectReenteredPublicly", "twoClaimBoundNativeInstallations", "twoDistinctOwnedCaRequests", "twoNonexportableMachineKeys", "twoNativeIisAndTrustedTls", "fourUnapprovedJobsPubliclyRejected", "approvalSettingRestored")
    return {"scope": "actual-native-adcs-per-issuer-five-public-approvals-and-terminal-release", "cap": 5, "initialAccepted": 5, "initialRefused": 1, "nativeCompleted": 2, **dict.fromkeys(flags, True), "requestIds": ["17", "18"], "fingerprints": ["a" * 64, "b" * 64], "enrollmentIds": ["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"], "jobIds": ["33333333-3333-3333-3333-333333333333", "44444444-4444-4444-4444-444444444444"]}


def browser_admin_boundary_proof():
    return {"scope":"public-manager-viewer-adcs-admin-boundary-not-mounted-admin-withdrawal","enrollmentId":"11111111-1111-1111-1111-111111111111","forbiddenMutations":4,"roleChanges":2,"adminDemotions":0,"mountedAdminWithdrawalQualified":False,"distinctOwnedNonownerActors":True,"noGlobalAdminBypassAssumed":True,"publicManagerViewerManagerTransitions":True,"managerAndViewerUiDenied":True,"bothRolesReconcileAndAbandonForbidden":True,"publicOwnerAdminPatchDemotionRefused":True,"exactOwnerAdminUnchanged":True,"actualUncertainEnrollmentAndJobsUnchanged":True,"nativeCaAndUnacceptedKeyUnchanged":True,"servingNativeCustodyAndTrustedTlsUnchanged":True,"targetCertOpsAuditUnchanged":True,"exactMembershipAudits":True,"managerMembershipRestored":True,"browserAndTrustDrained":True}


def browser_abandon_proof():
    return {"scope":"browser-confirmed-real-uncertain-abandon-and-native-unaccepted-key-cleanup","enrollmentId":"11111111-1111-1111-1111-111111111111","cleanupJobId":"22222222-2222-2222-2222-222222222222","abandonPosts":1,"keepPosts":0,"actualUncertainEnrollmentVisible":True,"keepDidNotMutate":True,"explicitConfirmationRequired":True,"exactPublicAbandonAcknowledged":True,"browserAndTrustDrained":True,"actualProductionContinuation":True,"journalAndDatabaseAbandoned":True,"exactUnacceptedKeyAbsent":True,"noAcceptedLeaf":True,"zeroNativeCaRequests":True,"onePublicAudit":True,"originalUnknownEffectPreserved":True}


def webhosting_proof():
    return {"scope":"real-adcs-webhosting-issue-and-fresh-key-manual-renewal","store":"WebHosting","expiryCleanupQualified":False,"requestIds":["17","18"],"fingerprints":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"publicIssueAndRenewInstalled":True,"twoIndependentCaRequests":True,"freshSerialSpkiAndKey":True,"webHostingProtectedCustody":True,"myCopiesAbsent":True,"exactNativeIisAndHttpSysStore":True,"trustedSniTls":True,"installedDiscoveryInventory":True,"immutableAcceptedStore":True,"predecessorRetentionStorePreserved":True,"storeQualifiedCleanupRegistered":True}


def policy_expiry_proof():
    from certops_retention_policy_expiry import FLAGS, COUNTS, SCOPE
    return {str(hours): {
        "ownedInterruption": {"scope": "owned-short-retention-native-interruption-drain", "assignedBeforeResume": True, "rootExit86": True, "nativeActiveZero": True, "nativeHandlesClosed": True, "wrapperClosed": True}, "scope": SCOPE, "configuredRetentionHours": hours,
        "verifiedCutoverAt": "2026-10-15T10:00:00.000Z",
        "oldNotAfter": "2026-10-15T10:02:00.000Z",
        "cleanupDeadline": "2026-10-15T10:07:00.000Z",
        "preDeadlineObservedAt": "2026-10-15T10:01:00.000Z",
        "cleanupObservedAt": "2026-10-15T10:07:01.000Z",
        "waitStartedAt": "2026-10-15T10:01:00.000Z",
        "waitFinishedAt": "2026-10-15T10:07:01.000Z",
        "waitedMonotonicMs": 361000,
        "installedServiceTimerQualified": False, "fullRetentionWindowQualified": False,
        **dict.fromkeys(FLAGS, True), **dict.fromkeys(COUNTS, 2),
    } for hours in (168, 720)}


def retention_reference_proof():
    fields = ("twoOpenReferencesPersistedAcrossProcess", "bothOpenNativeSweepPreservedCustody", "oneClosedStillProtected", "unknownReferenceDoesNotCloseOwnedReferences", "allClosedStillDeferredByRealDeadline", "nativeCustodyAndTrustedTlsUnchanged")
    return {**dict.fromkeys(fields, True), "scope": "native-collector-supporting-ledger-reference-lifecycle", "elapsed24HourQualified": False}


def browser_job_approval_proof():
    return {"scope":"browser-control-plane-job-approval-for-two-real-adcs-capacity-installations","approvePosts":2,"rejectPosts":1,"cancelPosts":0,"caOfficerApprovalQualified":False,"jobIds":["33333333-3333-3333-3333-333333333333","44444444-4444-4444-4444-444444444444"],"enrollmentIds":["11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222"],"payloadHashes":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"requestIds":["17","18"],"fingerprints":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"rejectedJobId":"77777777-7777-7777-7777-777777777777","rejectedEnrollmentId":"88888888-8888-8888-8888-888888888888","rejectedPayloadHash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","rejectedCanonicalIntentHash":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","twoDistinctOwnedPendingJobs":True,"distinctManagerApprover":True,"exactJobVisibleInActualDashboard":True,"cancelDidNotMutate":True,"twoExactPublicApprovalPosts":True,"appendOnlyDecisionsBoundToActor":True,"payloadAndCanonicalIntentHashesVerified":True,"browserAndTrustDrained":True,"sameApprovedJobsInstalledNatively":True,"capacityGenerationsCrossBound":True,"oneExactPublicRejectionPost":True,"rejectedJobNeverClaimedOrSubmitted":True,"rejectedIntentAndNativeAbsencePreserved":True}


def ipv4_wildcard_proof():
    return {'scope': 'native-ipv4-wildcard-sni-shadow-rollback-with-ipv4-sibling', 'installedAgentQualified': False, 'caQualified': False, 'actualIpv4LoopbackAvailable': True, 'borrowedCertificatesVerified': True, 'actualIpv4ShadowObserved': True, 'productionPrecedenceWarning': True, 'actualProductionVerifyFailed': True, 'actualProductionRollback': True, 'nativeHostnameEndpointRestored': True, 'trustedIpv4ShadowObserved': True, 'trustedIpv4BaselineRecovered': True, 'ipv4SiblingUnchanged': True, 'ownedSitesAndEndpointsRemoved': True}


def ipv6_wildcard_proof():
    return {'scope': 'native-ipv6-wildcard-sni-shadow-rollback-with-ipv4-sibling', 'installedAgentQualified': False, 'caQualified': False, 'actualIpv6LoopbackAvailable': True, 'borrowedCertificatesVerified': True, 'actualIpv6ShadowObserved': True, 'productionPrecedenceWarning': True, 'actualProductionVerifyFailed': True, 'actualProductionRollback': True, 'nativeHostnameEndpointRestored': True, 'trustedIpv6ShadowObserved': True, 'trustedIpv6BaselineRecovered': True, 'ipv4SiblingUnchanged': True, 'ownedSitesAndEndpointsRemoved': True}


def ipv6_shadow_proof():
    return {'scope': 'native-ipv6-sni-shadow-rollback-with-ipv4-sibling', 'installedAgentQualified': False, 'caQualified': False, 'actualIpv6LoopbackAvailable': True, 'borrowedCertificatesVerified': True, 'actualIpv6ShadowObserved': True, 'productionPrecedenceWarning': True, 'actualProductionVerifyFailed': True, 'actualProductionRollback': True, 'nativeHostnameEndpointRestored': True, 'trustedIpv6ShadowObserved': True, 'trustedIpv6BaselineRecovered': True, 'ipv4SiblingUnchanged': True, 'ownedSitesAndEndpointsRemoved': True}


def orphan_journal_proof():
    return {'scope': 'native-cng-supporting-prepared-journal-orphan-protection', 'installedServiceQualified': False, 'caEnrollmentQualified': False, 'orphanAgePolicyQualified': False, 'actualPreparedCngCsr': True, 'actualUnresolvedJobPrerequisites': True, 'unprotectedNativeOrphanRemoved': True, 'openJournalKeyPreserved': True, 'corruptJournalFailsClosed': True, 'exactJournalBytesRestored': True, 'untrackedNativeKeyPreserved': True, 'independentPrivateKeyPossession': True, 'actualGlobalStoreInventory': True, 'terminalFixtureClosureAllowsCleanup': True, 'ownedNativeKeysAndStateRemoved': True}


def ledger_read_proof():
    fields=("productionLedgerCreated","actualNativeReadDataDenied","actualNativeListDirectoryDenied","productionUnreadableNotAbsent","retainedExactAclHandles","sameOwnedFileIdentitiesAndBytes","exactNativeAclsRestored","productionReadersRecovered","containedChildrenDrained","ownedTemporaryStateRemoved")
    return {"scope":"native-temporary-retention-ledger-access-refusal-not-certificate-cleanup",**dict.fromkeys(fields,True),"installedServiceQualified":False,"nativeCertificateCleanupQualified":False,"elapsedRetentionQualified":False}


def journal_read_proof():
    return {"scope":"native-temporary-adcs-journal-acl-refusals-not-installed-enrollment","installedServiceQualified":False,"nativeCngQualified":False,"genuinePreparedPublicCsr":True,"twoActualNativeAccessDenials":True,"journalUnreadableNotAbsent":True,"globalProtectionScanDeferred":True,"exactFileIdentitiesAndBytesPreserved":True,"exactNativeAclsRestored":True,"productionReadersRecovered":True,"ownedTemporaryStateRemoved":True}


def iis_public_only_proof():
    return {"scope":'native-iis-public-only-certificate-association-refusal',"refusalCode":"BIND_FAILED","installedSignedJobQualified":False,"candidateFingerprint":"a"*64,"predecessorFingerprint":"b"*64,**{k:True for k in ['actualPublicOnlyMyCertificate', 'originalNativeKeyAbsent', 'actualProductionDeploymentRefused', 'actualRollbackSucceeded', 'predecessorBindingAndTrustedTlsPreserved', 'unrelatedBindingAndTrustedTlsPreserved', 'exactOwnedPublicCopyRemoved']}}


def credential_weak_acl_proof():
    return json.loads("{\"scope\":\"native-public-control-credential-weak-acl-refusal\",\"installedServiceStartupQualified\":false,\"nativeCertificateQualified\":false,\"untrustedProcessReadQualified\":false,\"actualOriginalCredentialReadable\":true,\"nativeOriginalHandleAndIdentity\":true,\"actualExplicitUntrustedReadAce\":true,\"protectedDaclRemainedReadable\":true,\"actualProductionAclRefusal\":true,\"credentialBytesAndIdentityUnchanged\":true,\"exactOriginalDaclRestored\":true,\"productionCredentialReaderRecovered\":true,\"containedHolderDrained\":true,\"ownedTemporaryStateRemoved\":true}")


def state_read_proof():
    fields = ("threeReadablePositiveControls", "threeActualNativeReadDenials", "productionReadersRefused", "exactFileIdentityAndBytesPreserved", "exactAclRestored", "allReadersRecovered", "ownedTemporaryStateRemoved")
    return {**dict.fromkeys(fields, True), "scope": "native-temporary-state-read-denials-production-readers", "installedServiceStartupQualified": False}


def survivor_proof():
    return dict.fromkeys(("differentCertificateCrossStoreProtected", "sameCertificateCrossStoreProtected", "originalKeyPreserved", "replacementTrustedTlsPreserved", "ownedCrossStoreCopiesRemoved"), True)


def packaged_chain_runtime_proof():
    flags = ("candidateHelperDigestMatched", "literalUnicodeSpaceBracketPath", "defaultPackagedResolverUsed", "nativeMetadataPositiveBeforeFault", "actualCandidateWrongProtocolPeUsed", "realBridgeRefusedWrongProtocol", "ownedChildClosedBeforeRestore", "exactOriginalFileIdentityRestored", "nativeMetadataPositiveAfterRestore")
    return {"scope": "extracted-candidate-native-chain-metadata-path-and-protocol-refusal", "metadataOnly": True, "serviceInstalled": False, "cmcPackagedQualified": False, "nativeGoVerifierPackagedQualified": False, "architecture": "amd64", "chainHelperSha256": "a" * 64, "wrongProtocolHostSha256": "b" * 64, **dict.fromkeys(flags, True)}


def http_client_settings_proof():
    flags = ("nativeNondefaultSettingsObserved", "actualProductionCutover", "publicCandidateAbsentBeforeRollback", "actualNativeRollbackSucceeded", "rawSettingsPreservedAfterCutoverAndRollback", "trustedTlsVerifiedAfterEveryTransition", "unrelatedEndpointPreserved", "originalCertificateRestored")
    return {"scope": "native-http-sys-client-policy-preservation-not-client-auth-handshake", "clientAuthHandshakeQualified": False, "cases": [{"id": name, "checkMode": mode, "freshness": freshness, "retrievalTimeout": timeout, **dict.fromkeys(flags, True)} for name, mode, freshness, timeout in (("revocation-cached-no-usage", 65542, 3600, 5000), ("no-revocation-normal-usage", 5, 120, 7000))]}


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


def pending_key_survivor_proof():
    return {"scope":"native-pending-key-policy-refusal-then-public-cancellation","store":"WebHosting","recovery":"public-cancel-then-terminal-cleanup","firstError":"Local policy refusal could not free the protected enrollment key; retry required","enrollmentId":"11111111-1111-1111-1111-111111111111","requestId":"17","failedJobId":"22222222-2222-2222-2222-222222222222","cleanupJobId":"33333333-3333-3333-3333-333333333333","fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","csrSpkiSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","caRequestCounts":[7,7,7],"automaticRetryQualified":False,"schedulerDefaultClockQualified":False,"actualOwnedPendingRequest":True,"actualOwnedCaLeafSameCsrSpki":True,"exactWebHostingAssociationAndProtectedKey":True,"nativeSurvivorReferenceObserved":True,"signedCleanupRefusedWhileReferenced":True,"pendingJournalAndKeyPreserved":True,"noAdditionalCaRequest":True,"exactPublicAssociationOnlyRemoved":True,"publicCancellationAcknowledged":True,"signedTerminalCleanupCompleted":True,"predecessorCustodyIisTlsPreserved":True,"configurationCredentialRestored":True,"ownedCaLeafRevoked":True,"ownershipGuardReleased":True}


def local_pairs_proof():
    fields = ("actualSignedJobRefused", "claimBoundOutcome", "noCaRequestAllocated", "noKeyGenerated", "noAcceptedLeafOrJournal", "originalNativeCustodyPreserved", "outgoingTrustedTlsPreserved", "configurationAndCredentialRestored")
    return [{"caseId": case, **dict.fromkeys(fields, True)} for case in ("ca-host-mismatch", "ca-authority-mismatch", "template-pair-mismatch", "empty-allowlist")]


def algorithm_proof():
    cases = (("rsa2048-below-template3072", "rsa3072"), ("rsa3072-below-template4096", "rsa4096"), ("ec256-on-p384-schema-three", "ec384schema3"), ("ec256-on-p384-schema-four", "ec384"))
    flags = ("nativeSafeTemplateObserved", "publicConfirmedIssuerUsed", "actualSignedClaimRefusal", "noCaRequestAllocated", "noKeyGenerated", "noAcceptedLeafOrJournal", "positiveNativeCustodyUnchanged", "positiveTrustedTlsUnchanged")
    return [{"caseId": case, "positiveScenario": f"adcs-real-{positive}-issued-cng-iis", "positiveFingerprintSha256": format(index+10, "x") * 64, "positiveRequestId": str(index+17), **dict.fromkeys(flags, True)} for index, (case, positive) in enumerate(cases)]


def cmc_proof():
    flags = ("actualCaSignedPending", "actualPinnedSignatureVerified", "actualSignerSignatureByteTampered", "actualPristineDerControlVerified", "agentResponseUnchanged")
    return {"scope": "read-only-native-ca-signed-response-signature-boundaries", **dict.fromkeys(flags, True), "syntheticCaResponse": False, "caRequestId": "17", "responseSha256": "a" * 64, "nativeHelperSha256": "b" * 64, "originalResponseDerSha256": "c" * 64, "tamperedResponseDerSha256": "d" * 64, "refusedVariants": ["empty", "truncated", "trailing-data", "oversized", "signer-signature-tampered", "wrong-ca-key-pin"]}


def browser_adcs_proof():
    flags = ("browserIssuerCreation", "nativeSafePreflight", "noEnrollmentBeforeConfirmation", "browserCaConfirmation", "postConfirmationNativePreflight", "browserProfileCreation", "browserProfileAttachment", "actualDueSelection", "defaultSweepCreatedEnrollment", "automaticSourceAndRealMode", "claimBoundEvidence", "installedEnrollment", "freshLeafAndSpki", "nativeCaRequestMatched", "nonexportableMachineCng", "nativeIisSniMatched", "independentTrustedTls", "browserInstalledStateVisible", "noSyntheticResponses", "noDateOrJournalOverrides", "ownedEnrollmentRegistered", "browserAndTrustCleaned", "otherProfilePoliciesRestored")
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


def browser_cancel_proof():
    c = adcs_capacity_proof()
    return {"scope": 'browser-cancel-requested-approval-gated-renewal-preserves-issued-native-custody', "enrollmentId": "55555555-5555-5555-5555-555555555555", "jobId": "66666666-6666-6666-6666-666666666666", "priorEnrollmentId": c["enrollmentIds"][1], "priorJobId": c["jobIds"][1], "priorRequestId": c["requestIds"][1], "fingerprint": c["fingerprints"][1], "cancelPosts": 1, "otherMutations": 0, "capacityBeforeCancel": 5, "capacityAfterCancel": 4, "initialSixConcurrencyQualified": False, "caSubmissionCancellationQualified": False, **dict.fromkeys(['additionalSequentialPublicRenewal', 'requestedPendingApprovalObserved', 'newJobNeverClaimed', 'exactPublicCancelAcknowledged', 'browserAndTrustDrained', 'onlyNewEnrollmentAndJobCancelled', 'oldInstalledEnrollmentUnchanged', 'oldProtectedCngAndIisUnchanged', 'oldTrustedTlsUnchanged', 'newContainerAndJournalAbsent', 'subjectCaRequestsUnchanged', 'exactHumanCancelAudit', 'capacitySlotReleased', 'cleanupOwnershipRegistered'], True)}


def pending_ca_key_change_proof():
    return json.loads('{"scope": "real-pending-request-refused-across-ca-new-key-and-fresh-reconfirmation", "schedulerClock": "supported-scheduler-now-input", "backgroundWorkerIntervalQualified": false, "issuerId": "00000001-1111-1111-1111-111111111111", "oldEnrollmentId": "00000002-1111-1111-1111-111111111111", "oldOriginalJobId": "00000003-1111-1111-1111-111111111111", "oldContinuationJobId": "00000004-1111-1111-1111-111111111111", "freshEnrollmentId": "00000005-1111-1111-1111-111111111111", "freshOriginalJobId": "00000006-1111-1111-1111-111111111111", "freshContinuationJobId": "00000007-1111-1111-1111-111111111111", "preflightJobId": "00000008-1111-1111-1111-111111111111", "oldRequestId": "17", "freshRequestId": "18", "oldCaKeySha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "newCaKeySha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "oldSnapshotSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "freshSnapshotSha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "oldSpkiSha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "freshSpkiSha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "predecessorFingerprint": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "freshFingerprint": "2222222222222222222222222222222222222222222222222222222222222222", "subjectCountBefore": 2, "subjectCountAfter": 3, "actualPendingBeforeRekey": true, "pendingNativeSignatureVerified": true, "actualSingleNewKeyRekey": true, "originalSnapshotNeverRepinned": true, "signedContinuationRefusedChangedKey": true, "oldUnacceptedKeyRemoved": true, "oldRequestDeniedByOwnedOfficer": true, "oldRequestNeverResubmitted": true, "predecessorCustodyAndTlsPreserved": true, "sameIssuerPublicReconfirmed": true, "freshSnapshotAndCngKey": true, "freshActualPendingApproved": true, "freshSignedNativeInstallation": true, "claimBoundNativeEvidence": true, "nativeIisAndTrustedTls": true, "registeredCleanupResolved": true}')


def pending_ca_proof():
    return {"scope": 'real-pending-enrollment-across-same-key-ca-certificate-renewal', "schedulerClock": "supported-scheduler-now-input", "backgroundWorkerIntervalQualified": False, "enrollmentId": "11111111-1111-1111-1111-111111111111", "originalJobId": "22222222-2222-2222-2222-222222222222", "continuationJobId": "33333333-3333-3333-3333-333333333333", "requestId": "17", "caKeySha256": "a"*64, "caCertificateCountBefore": 1, "caCertificateCountAfter": 2, "csrSha256": "b"*64, "spkiSha256": "c"*64, "leafFingerprint": "d"*64, "predecessorFingerprint": adcs_capacity_proof()["fingerprints"][1], **dict.fromkeys(('matchingActualInstalledPredecessor', 'ownedMyCleanupRegistered', 'actualPendingBeforeCaRenewal', 'pendingCngSignatureVerified', 'actualCaSameKeyRenewal', 'confirmedIssuerUnchanged', 'noReconfirmation', 'pendingCsrKeyRequestPreserved', 'predecessorPreservedAcrossCaRenewal', 'actualSameRequestApproved', 'actualSignedContinuationInstalled', 'claimBoundNativeEvidence', 'nativeSamePendingKeyAndLeaf', 'trustedTlsCutover', 'predecessorKeyAndReceiptPreserved', 'noCaResubmission'), True)}


def same_certificate_late_approval_proof():
    return {**cancelled_late_approval_proof(),"scope":"real-cancelled-request-late-issued-after-same-certificate-renewal","certificateId":"33333333-3333-4333-8333-333333333333","sameCertificateRenewalQualified":True,"backgroundTimerQualified":False}


def cancelled_late_approval_proof():
    return {"scope":"real-cancelled-request-late-issued-after-distinct-same-endpoint-successor","cancelledEnrollmentId":"11111111-1111-1111-1111-111111111111","successorEnrollmentId":"22222222-2222-2222-2222-222222222222","requestIds":["17","18"],"fingerprints":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"sameCertificateRenewalQualified":False,"publicCancellationAuditVerified":True,"terminalCleanupAlreadyCompleted":True,"distinctActualSuccessorInstalled":True,"nativePendingCsrRequesterTemplateOwned":True,"actualOfficerLateApproval":True,"actualCaLeafMatchesOriginalCsr":True,"defaultClockDoesNotRevive":True,"overdueSchedulerDoesNotRevive":True,"publicInstallationRetryRefused":True,"originalJournalAndJobsUnchanged":True,"cancelledKeyRemainsAbsent":True,"lateLeafNeverAccepted":True,"successorClaimEvidenceUnchanged":True,"successorNativeCustodyBindingTlsUnchanged":True,"noCaResubmission":True,"ownedUnusedLateLeafRevoked":True}


def issued_revocation_proof():
    return {"scope": "actual-ca-issued-owned-revoked-leaf-refused-before-accept", "errorCode": "ADCS_CERTIFICATE_INVALID", "schedulerDefaultClockQualified": False, "requestId": "17", "enrollmentId": "11111111-1111-1111-1111-111111111111", "continuationJobId": "22222222-2222-2222-2222-222222222222", **dict.fromkeys(["matchingNativePositiveControl","actualOwnedPendingRequest","actualCaSignatureAndOnlineRevoked","sameRequestCsrSpkiAndTemplate","actualOnlineChainValidBeforeRevocation","nativePendingIdentityBeforeManualDispatch","realRevokedLeafReachedProductionValidation","productionSignedContinuationRefused","rejectedBeforeCertificateAccept","predecessorBindingTlsAndCngUnchanged","unacceptedKeyRemovedAndJournalPreserved","noCaResubmission","ownedCaRequestRevoked","cleanupOwnershipRegistered"], True)}


def issued_san_proof():
    return {"scope": "actual-ca-issued-owned-wrong-san-refused-before-accept", "errorCode": "ADCS_CERTIFICATE_INVALID", "requestId": "17", "enrollmentId": "11111111-1111-1111-1111-111111111111", "continuationJobId": "22222222-2222-2222-2222-222222222222", **dict.fromkeys(["matchingNativePositiveControl","actualOwnedPendingCaMutation","actualCaSignature","sameRequestCsrSpkiAndTemplate","exactUnauthorizedDnsSan","productionSignedContinuationRefused","rejectedBeforeCertificateAccept","predecessorBindingTlsAndCngUnchanged","unacceptedKeyRemovedAndJournalPreserved","noCaResubmission","ownedCaRequestRevoked","cleanupOwnershipRegistered"], True)}


def browser_reconcile_proof():
    native = operator_ambiguity_proof()
    return {"scope": "browser-requestid-reconcile-real-operator-created-same-csr-ambiguity", "fixtureOrigin": "operator-created-two-real-system-submissions-of-the-same-public-csr", **dict.fromkeys(["actualUncertainRequestIdForm","invalidRequestIdDidNotMutate","exactOwnedRequestIdPosted","exactPublicReconcileAcknowledged","browserAndTrustDrained","nativeSelectedRequestInstalled","nativeSameProtectedMachineKey","nativeClaimBoundVerification","nativeExactReconcileAudit","unusedOwnedRequestRevoked","unusedLeafNeverAccepted","originalOrphanPreserved"], True), "enrollmentId": native["enrollmentId"], "selectedRequestId": native["selectedRequestId"], "unusedRequestId": native["unusedRequestId"], "selectedFingerprint": native["fingerprints"][0], "continuationJobId": native["jobIds"][2], "reconcilePosts": 1, "invalidRequestPosts": 0}


def http_crl_proof():
    return json.loads("{\"scope\":\"native-hierarchy-http-intermediate-crl-unavailable-and-recovered\",\"transport\":\"http\",\"revocationTarget\":\"intermediate\",\"nativeHelperSha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"publicCrlSha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"leafFingerprint\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"nativeVerdicts\":[\"valid\",\"revocation_unknown\",\"valid\"],\"installedAgentQualified\":false,\"httpOnlyLeafQualified\":false,\"ocspQualified\":false,\"actualIntermediateHttpOnlyCdp\":true,\"actualPublicHttpCrlFetched\":true,\"freshNativeChainValidBefore\":true,\"exactProgramScopedHttpBlock\":true,\"httpAvailableOutsideHelper\":true,\"issuingCaLdapAvailable\":true,\"freshNativeRevocationUnknown\":true,\"exactFirewallRuleRemoved\":true,\"freshNativeChainValidAfter\":true,\"originalChainCachePolicyRestored\":true,\"sameNonexportableCngCustody\":true,\"sameNativeBindingAndTrustedTls\":true,\"ownedGuardReleased\":true}")


def http_leaf_crl_evidence():
    return {
        "scope": collector.http_leaf_crl_proof.SCOPE,
        "enrollmentId": "10000000-0000-4000-8000-000000000001",
        "jobId": "10000000-0000-4000-8000-000000000002", "requestId": 42,
        "restoredEnrollmentId": "10000000-0000-4000-8000-000000000003",
        "restoredJobId": "10000000-0000-4000-8000-000000000004",
        "restoredRequestId": 43, "restoredLeafFingerprint": "6" * 64,
        "leafFingerprint": "1" * 64, "publicCrlSha256": "2" * 64,
        "nativeHelperSha256": "3" * 64, "originalPublicationSha256": "4" * 64,
        "appliedPublicationSha256": "5" * 64, "caRequestCounts": [10, 11, 12],
        "nativeVerdicts": ["valid", "revocation_unknown", "valid"],
        "endpointStatusCodes": [200, 503, 200], "ocspQualified": False,
        "caOutageQualified": False, "signedCmcRenewalQualified": False,
        "deferredRecovery":{"originalJobId":"10000000-0000-4000-8000-000000000005","originalClaimId":"10000000-0000-4000-8000-000000000006","continuationJobId":"10000000-0000-4000-8000-000000000002","continuationClaimId":"10000000-0000-4000-8000-000000000007","requestId":42},
        **{key: True for key in collector.http_leaf_crl_proof.FLAGS},
    }



def live_enroll_acl_proof():
    return json.loads("{\"scope\":\"real-same-template-machine-enroll-denial-exact-dacl-restore-and-issuance\",\"templateGuid\":\"11111111-2222-4333-8444-555555555555\",\"templateOid\":\"1.3.6.1.4.1.311.21.8.100\",\"machineSid\":\"S-1-5-21-1-2-3-1000\",\"originalDaclSha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"appliedDaclSha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"restoredDaclSha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"deniedCaRequestDelta\":1,\"caRequestCounts\":[10,11,12],\"enrollmentIds\":[\"11111111-1111-4111-8111-111111111111\",\"22222222-2222-4222-8222-222222222222\"],\"jobIds\":[\"33333333-3333-4333-8333-333333333333\",\"44444444-4444-4444-8444-444444444444\"],\"fingerprints\":[\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"],\"caHresult\":\"0x80094012\",\"preflightRefusalQualified\":false,\"signedCmcRenewalQualified\":false,\"sameConfirmedIssuerTemplateAndAlgorithm\":true,\"actualMachineSidDenied\":true,\"nativeTemplateDeniedHresult\":true,\"deniedKeyAbsentAndJournalRetained\":true,\"deniedAttemptPreservedNativeCustodyAndTls\":true,\"exactDaclRestored\":true,\"actualCaCacheRestartAndPing\":true,\"freshPublicEnrollmentInstalled\":true,\"independentIssuedCaRequest\":true,\"newNonexportableMachineKey\":true,\"nativeMyAndIisSniCutover\":true,\"independentTrustedTls\":true,\"claimBoundEvidence\":true,\"ownedCleanupRegisteredBeforeObservation\":true}")


def required_template_attribute_proof():
    return json.loads('{"scope": "actual-ldap-required-template-attribute-refusal-and-exact-native-restoration", "predecessorFingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "templateOid": "1.3.6.1.4.1.311.21.8.2", "cases": [{"caseId": "minimum-key-zero", "preflightVerdict": "unreadable", "reason": "template_unreadable", "observedField": "minimalKeySize", "observedValue": 0, "enrollmentId": "00000001-1111-1111-1111-111111111111", "jobId": "00000002-1111-1111-1111-111111111111", "knownSafeNativeControlBefore": true, "restorationRegisteredBeforeMutation": true, "actualLdapMutationObserved": true, "actualNativePreflightUnreadable": true, "publicConfirmationRefused": true, "signedInstalledJobRefused": true, "noCaRequestOrCngAllocation": true, "installedPredecessorPreserved": true, "exactOriginalAttributesRestored": true, "freshNativeSafeControlAfter": true, "originalConfigCredentialPreserved": true}, {"caseId": "subject-name-flag-absent", "preflightVerdict": "unreadable", "reason": "template_unreadable", "observedField": "enrolleeSuppliesSubject", "observedValue": null, "enrollmentId": "00000003-1111-1111-1111-111111111111", "jobId": "00000004-1111-1111-1111-111111111111", "knownSafeNativeControlBefore": true, "restorationRegisteredBeforeMutation": true, "actualLdapMutationObserved": true, "actualNativePreflightUnreadable": true, "publicConfirmationRefused": true, "signedInstalledJobRefused": true, "noCaRequestOrCngAllocation": true, "installedPredecessorPreserved": true, "exactOriginalAttributesRestored": true, "freshNativeSafeControlAfter": true, "originalConfigCredentialPreserved": true}]}')


def public_foreign_spki_proof():
    return json.loads('{"scope": "public-uncertain-request-rejects-owned-same-san-foreign-spki-before-positive-recovery", "enrollmentId": "11111111-1111-1111-1111-111111111111", "failedJobId": "55555555-5555-5555-5555-555555555555", "foreignRequestId": "103", "selectedRequestId": "101", "foreignFingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "selectedFingerprint": "1111111111111111111111111111111111111111111111111111111111111111", "foreignSpkiSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "originalSpkiSha256": "3333333333333333333333333333333333333333333333333333333333333333", "foreignCsrSha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "reconcileSearchFrom": 100, "foreignSubjectRequestCount": 1, "originalSubjectRequestCount": 2, "ownedRequestRegisteredBeforeSubmit": true, "softwarePrivateKeyRemovedBeforeSubmit": true, "sameActualCaAndSystemRequester": true, "sameAuthorizedSanAndTemplate": true, "differentOwnedCnAndSpki": true, "actualPublicProposalAccepted": true, "actualSignedSpkiMismatchRefusal": true, "originalUncertainJournalAndWatermarkPreserved": true, "originalCngPossessionPreserved": true, "noForeignCertificateAccepted": true, "servingSiblingTrustedTlsPreserved": true, "noAdditionalCaSubmissionOnRefusal": true, "exactUnusedForeignRequestRevoked": true, "matchingCandidatePositiveRecovery": true, "cleanupOwnershipResolved": true}')


def operator_ambiguity_proof():
    flags = ("ownedObserverDrained", "ownedTransportBlock", "observedSubmittingTermination", "actualLeaseExpiry", "acknowledgedPublicRecovery", "sameCsrAndKey", "noAutomaticResubmit", "originalOrphanPreserved", "recoveryPolicyUnchanged", "operatorCreatedSameCsrAmbiguity", "nativeCaOwnershipVerified", "automaticAttachmentRefused", "unacceptedKeyPreserved", "unrelatedTrustedTlsPreserved", "publicExplicitReconcileAudited", "exactSelectedRequestInstalled", "claimBoundVerification", "sameProtectedMachineKeyInstalled", "unusedOwnedRequestRevoked", "unusedLeafNeverAccepted")
    enrollment = "11111111-1111-1111-1111-111111111111"
    return {**dict.fromkeys(flags, True), "scope": "native-zero-request-uncertainty-with-operator-created-same-csr-ambiguity", "fixtureOrigin": "operator-created-two-real-system-submissions-of-the-same-public-csr", "resolvedIssuingCaAddress": "10.64.0.4", "leaseRemainingAtFaultMs": 60000, "recoveryWaitBudgetMs": 150000, "actualLeaseWaitMs": 120000, "caRequestsAtFault": 0, "caRequestsAfterOperatorSubmissions": 2, "caRequestsAfterAmbiguousRecovery": 2, "caRequestsAfterExplicitRecovery": 2, "requestIds": ["101", "102"], "fingerprints": ["1" * 64, "2" * 64], "serialNumbers": ["aa", "bb"], "csrSpkiSha256": "3" * 64, "csrSha256": "4" * 64, "selectedRequestId": "101", "unusedRequestId": "102", "enrollmentId": enrollment, "containerName": "tokentimer-enr-" + enrollment, "jobIds": [value * 8 + "-" + value * 4 + "-" + value * 4 + "-" + value * 4 + "-" + value * 12 for value in ("2", "3", "4")], "reconcileSearchFrom": 100, "scanWindowSize": 16}


def background_adcs_proof():
    return {**two_adcs_renewals_proof(), "scope": "two-real-default-interval-worker-native-adcs-renewals", "schedulerInvocation": "actual-production-runner-default-interval", "workerIntervalQualified": True,
            "workerLifecycle": {"failed": False, "starts": 1, "ticks": 2, "finishes": 2, "summaries": 2, "created": 2, "stops": 1, "forwarded": True, "firstTickElapsedMs": 60010, "exitCode": 0, "nativeDrained": True, "bridgeReady": True}}


def two_adcs_renewals_proof():
    flags = ("defaultSqlNowSelection", "automaticSourceAndRealMode", "distinctExpiryGenerations", "independentCaRequests", "freshLeafSerialAndSpki", "protectedUniqueMachineKeys", "nativeIisAndSniCutovers", "independentTrustedTls", "claimBoundVerificationEvidence", "unchangedStoredProfile", "sameManagementPeriod", "predecessorCustodyPreserved", "actualInventoryMatchesLatest", "ownedEnrollmentCleanupRegistered", "noDateOrJournalOverrides")
    return {**dict.fromkeys(flags, True), "scope": "two-native-adcs-default-scheduler-cycles-not-expiry-cleanup", "renewalProtocol": "fresh-enrollment-with-new-key-and-csr", "schedulerInvocation": "qualification-invoked-production-default-sweep", "workerIntervalQualified": False, "successfulAutomationCycles": 2, "expiryCleanupQualified": False,
            "requestIds": ["17", "18", "19"], "caRequestCounts": [7, 8, 9], "fingerprints": [value * 64 for value in ("a", "b", "c")], "spkiFingerprints": [value * 64 for value in ("d", "e", "f")], "serialNumbers": ["a1", "b2", "c3"],
            "containerNames": [f"tokentimer-enr-{value * 8}-{value * 4}-4{value * 3}-8{value * 3}-{value * 12}" for value in ("a", "b", "c")], "expiryEpochs": [1792497600000, 1792497601000, 1792497602000]}


def elapsed_proof():
    return {"ownedInterruption": {"scope": "owned-short-retention-native-interruption-drain", "assignedBeforeResume": True, "rootExit86": True, "nativeActiveZero": True, "nativeHandlesClosed": True, "wrapperClosed": True}, "mode": "real-clock-two-cutover-expiry-grace", "successfulCutovers": 2,
            "predecessorCertificatesRemoved": 2, "predecessorKeysRemoved": 2, "lineageRowsFinalized": 2,
            "immediateDeferralPreservedCustody": True, "immutableHistoryPreserved": True,
            "replacementTrustedBoundCustodyUnchanged": True, "interruptedNativeDeleteRecovered": True,
            "configuredRetentionHours": 24, "fullRetentionWindowQualified": False, "waitedMonotonicMs": 420000}


def public_retirement_proof():
    return {'scope': 'public-idle-installed-windows-agent-retirement', 'inFlightRetirementQualified': False, 'anonymousStatus': 401, 'viewerStatus': 403, 'managerStatus': 200, 'replayStatus': 200, 'retirementAuditCount': 1, 'noRespawnObservedMs': 5000, 'sameOwnedSystemRuntimeBeforeRetirement': True, 'anonymousAndViewerRefused': True, 'authorizedManagerPublicRetirement': True, 'sameActorAppendOnlyAudit': True, 'idempotentWithoutDuplicateAudit': True, 'actualAuthenticatedRetirementExit86': True, 'nativeScmCleanExitZero': True, 'measuredNoRespawnWindow': True, 'capturedHostAndChildAbsent': True, 'nativeCustodyAndTrustedTlsPreserved': True, 'credentialConfigurationAndPinPreserved': True, 'noJobClaimMutation': True, 'ownedRetirementGuardCleared': True}


def retention_config_proof():
    return {'scope': 'installed-system-invalid-retention-policy-startup-refusal', 'policies': ['below-minimum-hours', 'above-maximum-hours', 'zero-sweep-interval'], 'startupFailureCount': 3, 'retentionTimerQualified': False, 'threeActualSystemValidationFailures': True, 'freshStoppedServiceForEach': True, 'credentialAndPinPreserved': True, 'nativeCngAndBindingPreserved': True, 'trustedTlsPreserved': True, 'noNewAgentOrJob': True, 'exactOriginalConfigurationRestored': True, 'actualRepairedSystemChild': True, 'freshAuthenticatedHeartbeat': True, 'ownedPolicyGuardCleared': True}


def configured_timer_proof():
    return {'scope': 'production-configured-real-timer-empty-ledger-supporting', 'configuredIntervalMs': 100, 'defaultIntervalMs': 21600000, 'defaultRetentionHours': 168, 'actualCallbacks': 3, 'actualDelayedCallbacks': 2, 'waitedMonotonicMs': 200, 'defaultSixHourElapsedQualified': False, 'installedServiceQualified': False, 'nativeDeletionQualified': False, 'productionCollectorReturnedEmpty': True, 'actualAbortDrained': True, 'ownedEmptyStatePreserved': True}


def credential_refusal_proof():
    return {'scope': 'installed-system-invalid-credential-startup-refusal', 'credentials': ['empty-credential', 'malformed-credential'], 'startupFailureCount': 2, 'inFlightMutationQualified': False, 'twoActualSystemCredentialFailures': True, 'freshStoppedServiceForEach': True, 'configurationAndPinPreserved': True, 'nativeCngAndBindingPreserved': True, 'trustedTlsPreserved': True, 'noNewAgentOrJob': True, 'exactOriginalCredentialRestored': True, 'actualRepairedSystemChild': True, 'freshAuthenticatedHeartbeat': True, 'ownedCredentialGuardCleared': True}


def config_encoding_proof():
    return {"scope":"installed-system-unsupported-config-encoding-startup-refusal","encodings":["utf8-bom","utf16le-bom","utf16be-bom"],"startupFailureCount":3,**dict.fromkeys(("threeActualSystemStartupParseFailures","freshStoppedServiceForEach","credentialAndPinPreserved","nativeCngAndBindingPreserved","trustedTlsPreserved","noNewAgentOrJob","exactOriginalConfigurationRestored","actualRepairedSystemChild","freshAuthenticatedHeartbeat","ownedEncodingGuardCleared"),True)}


def multi_target_admission_proof():
    flags = ("publicProfileTargetEditRefused", "publicRenewalSnapshotOverrideRefused", "storedProfileUnchanged", "noJobAllocated", "sameInstalledSystemProcesses", "nativeInventoryAndCustodyUnchanged", "trustedTlsUnchanged", "credentialAndPinUnchanged", "actualAcmeAndDnsUnchanged", "ownedAdmissionGuardCleared")
    return {"scope": "public-immutable-windows-multi-target-admission-refusal", "profilePatchStatus": 422, "renewOverrideStatus": 400, "signedJobExecutionQualified": False, "multiTargetDeploymentQualified": False, **dict.fromkeys(flags, True)}


def active_service_controls_proof():
    flags = ("actualDnsPostBarrier", "sameCurrentClaimAndAttempt", "sameDurablePendingJournal", "samePendingNonexportableCngKey", "interrogateSucceeded", "pauseAndContinueRefused", "sameInstalledSystemProcesses", "sameServingCngBindingAndTrustedTls", "sameProtectedStateBytes", "ownedControlGuardCleared")
    return {"scope": "installed-scm-controls-during-real-cng-dns-renewal", "controlCount": 3, "certificateOperationInterruptionQualified": False, "defaultLeaseGraceQualified": False, **dict.fromkeys(flags, True)}


def service_controls_proof():
    return {"scope":"installed-system-service-interrogate-and-unsupported-pause-continue","controlCount":3,"certificateOperationInterruptionQualified":False,**dict.fromkeys(("exactOwnedInstalledService","interrogateSucceeded","pauseAndContinueRefused","sameNativeHostAndChild","unchangedCredentialAndConfiguration","unchangedNativeCngAndBinding","trustedTlsPreserved","freshAuthenticatedHeartbeat","unchangedJobClaims","ownedControlGuardCleared"),True)}


def installed_paths_proof():
    return {"scope": "installed-system-agent-unicode-spaces-literal-brackets-root", **dict.fromkeys(("ownedRootIdentityPreserved", "exactScmArgumentPaths", "actualSystemHostAndChild", "exactServiceConfigurationPath", "candidateEntryAndHostBytes", "actualSignedIssuance", "claimBoundResultEvidence", "actualCngIisTrustedTls"), True)}


def installed_iis_refusal_proof():
    return json.loads('{"scope":"installed-agent-public-standalone-iis-deploy-refusal","jobId":"11111111-1111-1111-1111-111111111111","claimId":"22222222-2222-2222-2222-222222222222","genuinePriorIssuance":true,"publicDeployAdmitted":true,"sameInstalledAgentClaimedOnce":true,"specificUnsupportedTargetFailure":true,"claimBoundFailureAudit":true,"nativeInventoryAndCustodyUnchanged":true,"bothBindingsAndTrustedTlsUnchanged":true,"actualAcmeClientNotInvoked":true,"dnsTrafficUnchanged":true,"credentialAndPinUnchanged":true,"exactOwnedShadowRemoved":true}')


class CollectorTests(unittest.TestCase):
    def test_public_only_iis_refusal_actual_js_parity_and_closed_public_projection(self):
        proof=json.loads(subprocess.check_output(["node","-e",'const h=require("./packages/agent/scripts/host/iis-public-only-fixture"),p=require("./scripts/fixtures/certops-windows-iis-public-only.cjs").fixture();h.verifyProof(p);console.log(JSON.stringify(p))'],cwd=collector.ROOT,text=True))
        self.assertEqual(proof,iis_public_only_proof())
        self.assertEqual(collector.iis_public_only_fields(proof),proof)
        for key,value in proof.items():
            missing=dict(proof);del missing[key]
            with self.subTest(key=key),self.assertRaises(ValueError):collector.iis_public_only_fields(missing)
            for invalid in (None,1,"true",not value if isinstance(value,bool) else "foreign"):
                with self.assertRaises(ValueError):collector.iis_public_only_fields({**proof,key:invalid})
        self.assertNotIn("sentinel",json.dumps(collector.iis_public_only_fields({**proof,"privateContainer":"sentinel"})))

    def test_native_weak_acl_projection_matches_actual_js_and_scope(self):
        proof=json.loads(subprocess.check_output(["node","-e",'const h=require("./packages/agent/scripts/host/credential-weak-acl-fixture"),p=require("./scripts/fixtures/certops-windows-credential-weak-acl.cjs").fixture();h.verifyProof(p);console.log(JSON.stringify(p))'],cwd=collector.ROOT,text=True))
        self.assertEqual(proof,credential_weak_acl_proof())
        self.assertEqual(collector.credential_weak_acl_fields(proof),proof)
        for key,value in proof.items():
            missing=dict(proof);del missing[key]
            with self.subTest(key=key),self.assertRaises(ValueError):collector.credential_weak_acl_fields(missing)
            for invalid in (None,1,"true",not value if isinstance(value,bool) else "foreign"):
                with self.assertRaises(ValueError):collector.credential_weak_acl_fields({**proof,key:invalid})
        self.assertNotIn("sentinel",json.dumps(collector.credential_weak_acl_fields({**proof,"rawCredential":"sentinel"})))

    def test_signing_pin_refusal_projection_matches_actual_js_and_excludes_registration(self):
        actual=json.loads(subprocess.check_output(["node","-e",'const h=require("./tests/e2e/helpers/certops-windows-signing-pin-refusal"),p=require("./scripts/fixtures/certops-windows-signing-pin-refusal.cjs").fixture();h.verifyProof(p);console.log(JSON.stringify(p))'],cwd=collector.ROOT,text=True))
        self.assertEqual(actual,signing_pin_refusal_proof())
        event={"scope":"real-agent-windows-acme-iis/rsa-2048","name":"real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence","type":"test:pass","nativeInstalledSigningPinRefusal":actual}
        self.assertEqual(collector.signing_pin_refusal_fields(event),{"nativeInstalledSigningPinRefusal":actual})
        for key in actual:
            missing=dict(actual);del missing[key]
            with self.subTest(key=key),self.assertRaises(ValueError):collector.signing_pin_refusal_fields({**event,"nativeInstalledSigningPinRefusal":missing})
        for patch in ({"twoActualSystemPinFailures":False},{"startupFailureCount":True},{"missingPinQualified":True},{"inFlightMutationQualified":True},{"pins":[]}):
            with self.assertRaises(ValueError):collector.signing_pin_refusal_fields({**event,"nativeInstalledSigningPinRefusal":{**actual,**patch}})
        self.assertNotIn("sentinel",json.dumps(collector.signing_pin_refusal_fields({**event,"nativeInstalledSigningPinRefusal":{**actual,"rawPin":"sentinel"}})))

    def test_installed_verify_rollback_closed_projection_and_real_js_parity(self):
        fixture = subprocess.check_output(["node", "-e", 'const h=require("./tests/e2e/helpers/certops-windows-installed-verify-rollback"),p=require("./scripts/fixtures/certops-windows-installed-verify-rollback.cjs").fixture();h.verifyProof(p);console.log(JSON.stringify(p))'], cwd=collector.ROOT, text=True)
        proof=json.loads(fixture)
        self.assertEqual(proof,installed_verify_rollback_proof())
        event={"scope":"real-agent-windows-acme-iis/rsa-2048","name":"real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence","type":"test:pass","nativeInstalledVerifyRollback":proof}
        self.assertEqual(collector.installed_verify_rollback_fields(event),{"nativeInstalledVerifyRollback":proof})
        for key in proof:
            missing=dict(proof);del missing[key]
            with self.subTest(key=key),self.assertRaises(ValueError):collector.installed_verify_rollback_fields({**event,"nativeInstalledVerifyRollback":missing})
        for patch in ({"rolledBack":False},{"actualCaLeafAndProtectedCngAccepted":False},{"transientNewBindingObservationQualified":True},{"appIdPreservationQualified":True},{"jobIds":[proof["jobIds"][0]]*2},{"fingerprints":["a"*64]*3},{"claimIds":[True,False]}):
            with self.assertRaises(ValueError):collector.installed_verify_rollback_fields({**event,"nativeInstalledVerifyRollback":{**proof,**patch}})
        self.assertNotIn("sentinel",json.dumps(collector.installed_verify_rollback_fields({**event,"nativeInstalledVerifyRollback":{**proof,"privateCngReceipt":"sentinel"}})))

    def test_windows_multi_target_public_refusal_strips_private_and_refuses_missing_or_promoted_facts(self):
        proof=multi_target_admission_proof()
        event={"scope":"real-agent-windows-acme-iis/rsa-2048","name":"real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence","type":"test:pass","nativeWindowsMultiTargetAdmission":{**proof,"privateNative":"sentinel"}}
        self.assertEqual(collector.multi_target_admission_fields(event),{"nativeWindowsMultiTargetAdmission":proof})
        for key in proof:
            missing=dict(proof);del missing[key]
            with self.subTest(key=key),self.assertRaises(ValueError):collector.multi_target_admission_fields({**event,"nativeWindowsMultiTargetAdmission":missing})
        for patch in ({"noJobAllocated":False},{"profilePatchStatus":True},{"signedJobExecutionQualified":True},{"multiTargetDeploymentQualified":True}):
            with self.assertRaises(ValueError):collector.multi_target_admission_fields({**event,"nativeWindowsMultiTargetAdmission":{**proof,**patch}})
        self.assertEqual(collector.multi_target_admission_fields({**event,"scope":"real-agent-acme-filesystem"}),{})

    def test_active_certificate_scm_controls_are_bounded_and_private_identity_is_stripped(self):
        proof = active_service_controls_proof()
        event = {"scope": "real-agent-windows-acme-iis/rsa-2048", "name": "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence", "type": "test:pass", "nativeInstalledActiveServiceControls": {**proof,"privateNative":"sentinel"}}
        self.assertEqual(collector.active_service_controls_fields(event), {"nativeInstalledActiveServiceControls":proof})
        for field in proof:
            missing=dict(proof);del missing[field]
            with self.subTest(field=field),self.assertRaises(ValueError):collector.active_service_controls_fields({**event,"nativeInstalledActiveServiceControls":missing})
        for patch in ({"actualDnsPostBarrier":False},{"controlCount":True},{"defaultLeaseGraceQualified":True},{"certificateOperationInterruptionQualified":True},{"scope":"idle-controls"}):
            with self.assertRaises(ValueError):collector.active_service_controls_fields({**event,"nativeInstalledActiveServiceControls":{**proof,**patch}})
        self.assertEqual(collector.active_service_controls_fields({**event,"scope":"real-agent-acme-filesystem"}),{})

    def test_same_certificate_late_approval_projection_is_complete(self):
        proof=same_certificate_late_approval_proof()
        self.assertEqual(collector.same_certificate_late_approval_fields({**proof,"rawCsr":"private"}),proof)
        for key in proof:
            bad=dict(proof);del bad[key]
            with self.assertRaises(ValueError): collector.same_certificate_late_approval_fields(bad)
        for key,value in proof.items():
            if isinstance(value,bool):
                with self.assertRaises(ValueError): collector.same_certificate_late_approval_fields({**proof,key:not value})

    def test_native_cng_journal_acl_projection_is_complete_and_private(self):
        proof = cng_journal_acl_proof()
        self.assertEqual(collector.cng_journal_acl_fields({**proof, "rawContainer": "private"}), proof)
        for key in proof:
            changed = dict(proof)
            del changed[key]
            with self.assertRaises(ValueError): collector.cng_journal_acl_fields(changed)
        for key, value in proof.items():
            if value is True:
                with self.assertRaises(ValueError): collector.cng_journal_acl_fields({**proof, key: False})
        for patch in ({"scope":"software-only"},{"caEnrollmentQualified":True},{"installedServiceQualified":True}):
            with self.assertRaises(ValueError): collector.cng_journal_acl_fields({**proof, **patch})

    def test_http_intermediate_crl_requires_native_facts_without_scope_promotion(self):
        proof = http_crl_proof()
        self.assertEqual(collector.http_crl_proof.fields({**proof, "privateCachePolicy": "sentinel"}), proof)
        for key, expected in proof.items():
            missing = dict(proof); del missing[key]
            with self.assertRaises(ValueError): collector.http_crl_proof.fields(missing)
            if type(expected) is bool:
                for bad in (not expected, 1, None):
                    with self.assertRaises(ValueError): collector.http_crl_proof.fields({**proof, key: bad})
        with self.assertRaises(ValueError): collector.http_crl_proof.fields({**proof, "nativeVerdicts": ["valid", "invalid", "valid"]})

    def test_live_machine_enroll_acl_projection_requires_all_facts(self):
        proof = live_enroll_acl_proof()
        self.assertEqual(collector.live_enroll_acl_proof.fields({**proof, "privateDacl": "sentinel"}), proof)
        for key, expected in proof.items():
            missing = dict(proof); del missing[key]
            with self.assertRaises(ValueError): collector.live_enroll_acl_proof.fields(missing)
            if type(expected) is bool:
                for bad in (not expected, 1, None, "true"):
                    with self.assertRaises(ValueError): collector.live_enroll_acl_proof.fields({**proof, key: bad})
        for patch in ({"deniedCaRequestDelta": 2}, {"caRequestCounts": [10, 11, 13]}, {"restoredDaclSha256": "e"*64}, {"caHresult": "0x80070005"}, {"enrollmentIds": [proof["enrollmentIds"][0]]*2}):
            with self.assertRaises(ValueError): collector.live_enroll_acl_proof.fields({**proof, **patch})

    def test_public_idle_retirement_projection_requires_all_facts(self):
        proof=public_retirement_proof()
        event={"scope":"real-agent-windows-acme-iis/rsa-2048","name":"real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence","type":"test:pass","nativeInstalledPublicRetirement":{**proof,"privatePath":"secret"}}
        self.assertEqual(collector.public_retirement_fields(event),{"nativeInstalledPublicRetirement":proof})
        for key in proof:
            missing=dict(proof);del missing[key]
            with self.assertRaises(ValueError):collector.public_retirement_fields({**event,"nativeInstalledPublicRetirement":missing})
        for key,value in proof.items():
            if value is True:
                with self.assertRaises(ValueError):collector.public_retirement_fields({**event,"nativeInstalledPublicRetirement":{**proof,key:False}})
        for value in (True,4999,30001):
            with self.assertRaises(ValueError):collector.public_retirement_fields({**event,"nativeInstalledPublicRetirement":{**proof,"noRespawnObservedMs":value}})
        with self.assertRaises(ValueError):collector.public_retirement_fields({**event,"nativeInstalledPublicRetirement":{**proof,"inFlightRetirementQualified":True}})

    def test_installed_retention_config_requires_measured_failures_and_strips_private_fields(self):
        proof=retention_config_proof()
        event={"scope":"real-agent-windows-acme-iis/rsa-2048","name":"real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence","type":"test:pass","nativeInstalledRetentionConfig":{**proof,"rawConfig":"secret"}}
        self.assertEqual(collector.retention_config_fields(event),{"nativeInstalledRetentionConfig":proof})
        for key in proof:
            missing=dict(proof);del missing[key]
            with self.assertRaises(ValueError):collector.retention_config_fields({**event,"nativeInstalledRetentionConfig":missing})
        for key,value in proof.items():
            if value is True:
                with self.assertRaises(ValueError):collector.retention_config_fields({**event,"nativeInstalledRetentionConfig":{**proof,key:False}})
        for key,value in (("retentionTimerQualified",True),("startupFailureCount",True),("policies",["below-minimum-hours"])):
            with self.assertRaises(ValueError):collector.retention_config_fields({**event,"nativeInstalledRetentionConfig":{**proof,key:value}})

    def test_configured_timer_projection_cannot_promote_six_hour_or_native_claims(self):
        proof=configured_timer_proof()
        self.assertEqual(collector.configured_retention_timer_fields({**proof,"privatePath":"secret"}),proof)
        for key in proof:
            missing=dict(proof);del missing[key]
            with self.assertRaises(ValueError):collector.configured_retention_timer_fields(missing)
        for key,value in (("defaultSixHourElapsedQualified",True),("installedServiceQualified",True),("nativeDeletionQualified",True),("waitedMonotonicMs",True),("waitedMonotonicMs",139),("waitedMonotonicMs",5001),("actualCallbacks",1),("actualDelayedCallbacks",0)):
            with self.assertRaises(ValueError):collector.configured_retention_timer_fields({**proof,key:value})

    def test_installed_credential_refusal_requires_real_failures_and_strips_private_fields(self):
        proof=credential_refusal_proof()
        event={"scope":"real-agent-windows-acme-iis/rsa-2048","name":"real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence","type":"test:pass","nativeInstalledCredentialRefusal":{**proof,"rawCredential":"secret"}}
        self.assertEqual(collector.credential_refusal_fields(event),{"nativeInstalledCredentialRefusal":proof})
        for key in proof:
            missing=dict(proof);del missing[key]
            with self.assertRaises(ValueError):collector.credential_refusal_fields({**event,"nativeInstalledCredentialRefusal":missing})
        for key,value in proof.items():
            if value is True:
                with self.assertRaises(ValueError):collector.credential_refusal_fields({**event,"nativeInstalledCredentialRefusal":{**proof,key:False}})
        for key,value in (("inFlightMutationQualified",True),("startupFailureCount",True),("credentials",["empty-credential"])):
            with self.assertRaises(ValueError):collector.credential_refusal_fields({**event,"nativeInstalledCredentialRefusal":{**proof,key:value}})

    def test_installed_config_encoding_projection_requires_every_refusal_and_strips_private_data(self):
        proof=config_encoding_proof()
        event={"scope":"real-agent-windows-acme-iis/rsa-2048","name":"real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence","type":"test:pass","nativeInstalledConfigEncoding":{**proof,"rawConfig":"sentinel"}}
        self.assertEqual(collector.config_encoding_fields(event),{"nativeInstalledConfigEncoding":proof})
        for key, expected in proof.items():
            missing=dict(proof);del missing[key]
            with self.assertRaises(ValueError):collector.config_encoding_fields({**event,"nativeInstalledConfigEncoding":missing})
            for wrong in ([False,1,None,"true"] if type(expected) is bool else ["invalid"]):
                with self.assertRaises(ValueError):collector.config_encoding_fields({**event,"nativeInstalledConfigEncoding":{**proof,key:wrong}})
        for cases in (["utf8-bom"],["utf8-bom"]*3,list(reversed(proof["encodings"]))):
            with self.assertRaises(ValueError):collector.config_encoding_fields({**event,"nativeInstalledConfigEncoding":{**proof,"encodings":cases}})
        with self.assertRaises(ValueError):collector.config_encoding_fields({**event,"nativeInstalledConfigEncoding":None})
        self.assertEqual(collector.config_encoding_fields({**event,"name":"unrelated"}),{})

    def test_installed_scm_projection_requires_actual_controls_and_strips_private_data(self):
        proof = service_controls_proof()
        event = {"scope":"real-agent-windows-acme-iis/rsa-2048","name":"real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence","type":"test:pass","nativeInstalledServiceControls":{**proof,"rawPrivateProcess":"sentinel"}}
        self.assertEqual(collector.service_controls_fields(event),{"nativeInstalledServiceControls":proof})
        for key, expected in proof.items():
            missing = dict(proof); del missing[key]
            with self.assertRaises(ValueError): collector.service_controls_fields({**event,"nativeInstalledServiceControls":missing})
            for invalid in ([not expected,1,None,"true"] if type(expected) is bool else ["invalid"]):
                with self.assertRaises(ValueError): collector.service_controls_fields({**event,"nativeInstalledServiceControls":{**proof,key:invalid}})
        with self.assertRaises(ValueError): collector.service_controls_fields({**event,"nativeInstalledServiceControls":None})
        self.assertEqual(collector.service_controls_fields({**event,"name":"unrelated"}),{})

    def test_ipv4_wildcard_requires_all_facts_and_strips_private_metadata(self):
        proof = ipv4_wildcard_proof()
        self.assertEqual(collector.ipv4_wildcard_fields({**proof, "privateReceipt": "sentinel"}), proof)
        with self.assertRaises(ValueError): collector.ipv4_wildcard_fields(ipv6_shadow_proof())
        for key, expected in proof.items():
            missing = dict(proof); del missing[key]
            with self.assertRaises(ValueError): collector.ipv4_wildcard_fields(missing)
            for bad in ([not expected, 1, "true", None] if type(expected) is bool else ["ipv6-wildcard"]):
                invalid = {**proof, key: bad}
                with self.assertRaises(ValueError): collector.ipv4_wildcard_fields(invalid)

    def test_ipv6_wildcard_requires_all_facts_and_cannot_substitute_concrete_scope(self):
        proof = ipv6_wildcard_proof()
        self.assertEqual(collector.ipv6_wildcard_fields({**proof, "privateReceipt": "sentinel"}), proof)
        with self.assertRaises(ValueError): collector.ipv6_wildcard_fields(ipv6_shadow_proof())
        for key, expected in proof.items():
            missing = dict(proof); del missing[key]
            with self.assertRaises(ValueError): collector.ipv6_wildcard_fields(missing)
            for bad in ([not expected, 1, "true", None] if type(expected) is bool else ["ipv4-wildcard"]):
                invalid = {**proof, key: bad}
                with self.assertRaises(ValueError): collector.ipv6_wildcard_fields(invalid)

    def test_ipv6_shadow_projection_requires_all_native_facts_and_rejects_promotion(self):
        proof = ipv6_shadow_proof()
        self.assertEqual(collector.ipv6_shadow_fields({**proof, "privateEndpointReceipt": "sentinel"}), proof)
        with self.assertRaises(ValueError): collector.ipv6_shadow_fields(None)
        for key, expected in proof.items():
            missing = dict(proof); del missing[key]
            with self.assertRaises(ValueError): collector.ipv6_shadow_fields(missing)
            for bad in ([not expected, 1, "true", None] if type(expected) is bool else ["installed-native-agent"]):
                invalid = {**proof, key: bad}
                with self.assertRaises(ValueError): collector.ipv6_shadow_fields(invalid)

    def test_orphan_journal_projection_requires_all_facts_without_unsupported_promotion(self):
        proof = orphan_journal_proof()
        self.assertEqual(collector.orphan_journal_fields({**proof, "rawPrivateReceipt": "sentinel"}), proof)
        with self.assertRaises(ValueError): collector.orphan_journal_fields(None)
        for key, expected in proof.items():
            missing = dict(proof); del missing[key]
            with self.assertRaises(ValueError): collector.orphan_journal_fields(missing)
            for bad in ([not expected, 1, "true", None] if type(expected) is bool else ["installed-native-enrollment"]):
                invalid = {**proof, key: bad}
                with self.assertRaises(ValueError): collector.orphan_journal_fields(invalid)

    def test_retention_ledger_acl_projection_requires_all_native_facts_and_strips_private_fields(self):
        proof=ledger_read_proof()
        self.assertEqual(collector.ledger_acl_fields({**proof,"rawSddl":"sentinel","nativePath":"sentinel"}),proof)
        with self.assertRaises(ValueError): collector.ledger_acl_fields(None)
        for key,expected in proof.items():
            missing=dict(proof); del missing[key]
            with self.assertRaises(ValueError): collector.ledger_acl_fields(missing)
            for bad in ([not expected,1,"true",None] if type(expected) is bool else ["installed-retention-cleanup"]):
                with self.assertRaises(ValueError): collector.ledger_acl_fields({**proof,key:bad})

    def test_journal_acl_projection_requires_all_native_facts_and_strips_private_fields(self):
        proof = journal_read_proof()
        self.assertEqual(collector.journal_acl_fields({**proof, "rawPrivateJournal": "sentinel"}), proof)
        with self.assertRaises(ValueError): collector.journal_acl_fields(None)
        for key, expected in proof.items():
            missing = dict(proof); del missing[key]
            with self.assertRaises(ValueError): collector.journal_acl_fields(missing)
            for bad in ([not expected, 1, "true", None] if type(expected) is bool else ["installed-native-enrollment"]):
                invalid = {**proof, key: bad}
                with self.assertRaises(ValueError): collector.journal_acl_fields(invalid)

    def test_windows_public_reuse_refusal_projection_is_bounded_and_scope_specific(self):
        flags = ("publicAdmissionRefused", "profileUnchanged", "noJobAllocated", "nativeInventoryAndCustodyUnchanged", "trustedTlsUnchanged")
        proof = {"scope": "public-windows-acme-profile-reuse-refusal", **dict.fromkeys(flags, True)}
        event = {"scope": "real-agent-windows-acme-iis/rsa-2048", "name": "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence", "type": "test:pass", "nativeWindowsKeyReuseRefusal": {**proof, "rawKeyInventory": "private-sentinel"}}
        self.assertEqual(collector.windows_key_reuse_refusal_fields(event), {"nativeWindowsKeyReuseRefusal": proof})
        for flag in flags:
            for wrong in (False, 1, None, "true"):
                bad = json.loads(json.dumps(event)); bad["nativeWindowsKeyReuseRefusal"][flag] = wrong
                with self.assertRaises(ValueError): collector.windows_key_reuse_refusal_fields(bad)
            bad = json.loads(json.dumps(event)); del bad["nativeWindowsKeyReuseRefusal"][flag]
            with self.assertRaises(ValueError): collector.windows_key_reuse_refusal_fields(bad)
        for proof_patch in ({"scope": "installed-agent-invalid-signed-job"},):
            bad = json.loads(json.dumps(event)); bad["nativeWindowsKeyReuseRefusal"].update(proof_patch)
            with self.assertRaises(ValueError): collector.windows_key_reuse_refusal_fields(bad)
        bad = dict(event); del bad["nativeWindowsKeyReuseRefusal"]
        with self.assertRaises(ValueError): collector.windows_key_reuse_refusal_fields(bad)
        self.assertEqual(collector.windows_key_reuse_refusal_fields({**event, "scope": "real-agent-acme-filesystem"}), {})

    def test_resident_domain_retention_strips_private_data_and_rejects_short_or_incomplete_days(self):
        source = "const f=require('./scripts/certops-retention24h-test-fixture.cjs'),h=require('./scripts/certops-retention24h-proof');process.stdout.write(JSON.stringify(h.verifyCompositeProof(f())))"
        proof = json.loads(subprocess.check_output(["node", "-e", source], cwd=collector.ROOT, text=True, timeout=15))
        report = {"suite": "windows-domain-adcs-retention24h", "nativeRetention24h": {**proof, "rawCertificateInventory": "private-sentinel", "privateKey": "private-sentinel"}}
        projected = collector.sanitized_report(report, {report["suite"]}, set())
        self.assertEqual(projected["nativeRetention24h"], proof)
        self.assertNotIn("private-sentinel", json.dumps(projected))
        for key, expected in proof.items():
            with self.subTest(field=key):
                invalid = json.loads(json.dumps(report)); del invalid["nativeRetention24h"][key]
                with self.assertRaises(ValueError):
                    collector.sanitized_report(invalid, {report["suite"]}, set())
                invalid = json.loads(json.dumps(report)); invalid["nativeRetention24h"][key] = False if expected is True else "invalid"
                with self.assertRaises(ValueError):
                    collector.sanitized_report(invalid, {report["suite"]}, set())
        for change in ({"bootTime": proof["finishedAt"]}, {"processCreatedAt": proof["finishedAt"]}, {"monotonicElapsedMs": 86399999}, {"monotonicElapsedMs": True}, {"keptSweepCount": 2}, {"maximumSweepGapMs": 3900001}, {"oldNotAfter": proof["cleanupDeadline"]}, {"preDeadlineObservedAt": proof["cleanupDeadline"]}, {"cleanupFinishedAt": proof["startedAt"]}, {"scope": "resident-timing-only-native-oracles-required"}, {"requestIds": ["11", "11"]}, {"requestIds": ["11", "4294967296"]}):
            with self.subTest(change=change):
                invalid = {**report, "nativeRetention24h": {**proof, **change}}
                with self.assertRaises(ValueError):
                    collector.sanitized_report(invalid, {report["suite"]}, set())

    def test_short_retention_collector_refuses_missing_process_custody(self):
        for target in ("nativeElapsedRetention", "nativeRetentionPolicyExpiry"):
            for field in elapsed_proof()["ownedInterruption"]:
                suite = "windows-host"
                value = {"suite": suite, "nativeKeySurvivors": survivor_proof(), "nativeRetentionPolicyExpiry": policy_expiry_proof(), "nativeElapsedRetention": elapsed_proof()}
                proof = value[target] if target == "nativeElapsedRetention" else value[target]["168"]
                del proof["ownedInterruption"][field]
                with self.subTest(target=target, field=field), self.assertRaises(ValueError): collector.sanitized_report(value, {suite}, set())

    def test_real_day_native_interruption_nested_facts_are_required_and_sanitized(self):
        source = "const f=require('./scripts/certops-retention24h-test-fixture.cjs'),h=require('./scripts/certops-retention24h-proof');process.stdout.write(JSON.stringify(h.verifyCompositeProof(f())))"
        proof = json.loads(subprocess.check_output(["node", "-e", source], cwd=collector.ROOT, text=True, timeout=15))
        report = {"suite": "windows-domain-adcs-retention24h", "nativeRetention24h": proof}
        for key, expected in proof["interruptedDelete"].items():
            bad = json.loads(json.dumps(report)); del bad["nativeRetention24h"]["interruptedDelete"][key]
            with self.subTest(missing=key), self.assertRaises(ValueError): collector.retention24h_fields(bad)
            bad = json.loads(json.dumps(report)); bad["nativeRetention24h"]["interruptedDelete"][key] = False if expected is True else True
            with self.subTest(tampered=key), self.assertRaises(ValueError): collector.retention24h_fields(bad)
        for patch in ({"cleanupDeadline": proof["oldNotAfter"]}, {"interruptedAt": proof["cleanupDeadline"]}, {"resumedAt": proof["cleanupFinishedAt"]}, {"monotonicElapsedBeforeCrashMs": proof["monotonicElapsedMs"] + 1}):
            bad = json.loads(json.dumps(report)); bad["nativeRetention24h"]["interruptedDelete"].update(patch)
            with self.subTest(patch=patch), self.assertRaises(ValueError): collector.retention24h_fields(bad)
        report["nativeRetention24h"]["interruptedDelete"]["rawNativeReceipt"] = "private-sentinel"
        self.assertNotIn("private-sentinel", json.dumps(collector.retention24h_fields(report)))

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
        matrix = qualification_manifest.load(collector.ROOT / "docs/certops/qualification-suites.json")
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
            proof["materialPaths"] = {"scope":"actual-linux-acme-space-unicode-config-state-material-paths", "observedGenerations":3, **dict.fromkeys("ownedDirectoryIdentityStable canonicalAncestorsWithoutAliases configAndClientStateObserved privateCustodyAndCertificateObserved signedProfilePathPreserved spaceAndUnicodeInEveryPath".split(),True), **dict.fromkeys("clientExecutablePathQualified repositoryOrHookPathQualified otherPlatformsQualified".split(),False)}
            baseline_source = "const reuse=" + json.dumps(proof) + ";process.stdout.write(JSON.stringify({nativeAcmeBackgroundRenewals:require('./scripts/test-support/acme-background-proof.cjs').proof(reuse.client,reuse),nativeAcmeStageFaults:require('./scripts/test-support/acme-stage-proof.cjs').proof(reuse.client)}))"
            baseline = json.loads(subprocess.check_output(["node","-e",baseline_source],cwd=collector.ROOT))
            if scope == "real-agent-acme-filesystem":
                baseline["nativeAcmeBulkRenewal"] = json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require('./scripts/test-support/acme-bulk-proof.cjs').proof(" + json.dumps(proof) + ")))"], cwd=collector.ROOT))
                baseline["nativeAcmeRenewalSetup"] = json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require('./scripts/test-support/acme-native-adoption-proof.cjs').proof(" + json.dumps(baseline["nativeAcmeBulkRenewal"]) + ")))"], cwd=collector.ROOT))
                baseline["nativeAcmeCertificateOutbox"] = json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require('./scripts/test-support/acme-certificate-outbox-proof.cjs').proof(" + json.dumps(baseline["nativeAcmeBulkRenewal"]) + ")))"], cwd=collector.ROOT))
                baseline["nativeAcmeDisabledProfile"] = json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require('./scripts/test-support/acme-disabled-profile-proof.cjs').proof(" + json.dumps(baseline["nativeAcmeBulkRenewal"]) + ")))"], cwd=collector.ROOT))
                baseline["nativeAcmeRenewalAlert"] = json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require('./scripts/test-support/acme-renewal-alert-proof.cjs').proof(" + json.dumps(baseline["nativeAcmeCertificateOutbox"]) + ")))"], cwd=collector.ROOT))
                baseline["qualificationEnvironment"] = {"measurement":"native","osFamily":"linux","distributionId":"ubuntu","distributionVersion":"24.04","executionSurface":"host"}
            def project(value):
                return collector.sanitized_report([{**baseline, "scope": scope, "name": main, "type": "test:pass", "nativeAcmeKeyReuse": value}], set(), {scope})
            result = project({**proof, "rawKey": "private-sentinel", "windowsQualified": True, "workerLoopQualified": True})
            self.assertEqual(result[0]["nativeAcmeKeyReuse"], proof)
            if scope == "real-agent-acme-filesystem":
                self.assertEqual(result[0]["nativeAcmeRenewalAlert"], baseline["nativeAcmeRenewalAlert"])
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
        result = collector.sanitized_report({"suite": suite, "cngCustody": custody, "nativeIisPublicOnly":iis_public_only_proof(), "nativeIpv4WildcardShadow": ipv4_wildcard_proof(), "nativeIpv6WildcardShadow": ipv6_wildcard_proof(), "nativeIpv6SniShadow": ipv6_shadow_proof(), "supportingConfiguredRetentionTimer": configured_timer_proof(), "nativeCngJournalAcl": cng_journal_acl_proof(), "nativeOrphanJournalProtection": orphan_journal_proof(), "nativeLedgerReadRefusals": ledger_read_proof(), "nativeJournalReadRefusals": journal_read_proof(), "nativeCredentialWeakAcl":credential_weak_acl_proof(), "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeHttpSysClientSettings": http_client_settings_proof(), "nativePackagedChainRuntime": packaged_chain_runtime_proof(), "nativeKeySurvivors": survivor_proof(), "nativeRetentionPolicyExpiry": policy_expiry_proof(), "nativeElapsedRetention": elapsed_proof(), "nativeRetentionAtomicReplace": {**proof, "rawLedger": "sentinel", "nativePath": "sentinel"}}, {suite}, set())
        self.assertEqual(result["nativeRetentionAtomicReplace"], proof)
        survivor_report = {"suite": suite, "cngCustody": custody, "nativeIisPublicOnly":iis_public_only_proof(), "nativeIpv4WildcardShadow": ipv4_wildcard_proof(), "nativeIpv6WildcardShadow": ipv6_wildcard_proof(), "nativeIpv6SniShadow": ipv6_shadow_proof(), "supportingConfiguredRetentionTimer": configured_timer_proof(), "nativeCngJournalAcl": cng_journal_acl_proof(), "nativeOrphanJournalProtection": orphan_journal_proof(), "nativeLedgerReadRefusals": ledger_read_proof(), "nativeJournalReadRefusals": journal_read_proof(), "nativeCredentialWeakAcl":credential_weak_acl_proof(), "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeHttpSysClientSettings": http_client_settings_proof(), "nativePackagedChainRuntime": packaged_chain_runtime_proof(), "nativeRetentionAtomicReplace": proof, "nativeRetentionPolicyExpiry": policy_expiry_proof(), "nativeElapsedRetention": elapsed_proof(), "nativeKeySurvivors": {**survivor_proof(), "rawInventory": "sentinel", "containerName": "sentinel"}}
        self.assertEqual(collector.sanitized_report(survivor_report, {suite}, set())["nativeKeySurvivors"], survivor_proof())
        self.assertNotIn("sentinel", json.dumps(collector.sanitized_report(survivor_report, {suite}, set())))
        policy_private = policy_expiry_proof()
        policy_private["168"]["rawNativeInventory"] = "private-policy-sentinel"
        projected_policy = collector.sanitized_report({**survivor_report, "nativeRetentionPolicyExpiry": policy_private}, {suite}, set())["nativeRetentionPolicyExpiry"]
        self.assertEqual(projected_policy, policy_expiry_proof())
        for invalid in (None, {}, {"168": policy_expiry_proof()["168"]}):
            with self.assertRaises(ValueError): collector.sanitized_report({**survivor_report, "nativeRetentionPolicyExpiry": invalid}, {suite}, set())
        for policy in ("168", "720"):
            for field in policy_expiry_proof()[policy]:
                bad_policy = policy_expiry_proof()
                del bad_policy[policy][field]
                with self.assertRaises(ValueError): collector.sanitized_report({**survivor_report, "nativeRetentionPolicyExpiry": bad_policy}, {suite}, set())
            for change in ({"actualProductionCollectorUsed": False}, {"configuredRetentionHours": 24}, {"scope": "installed-service-timer"}, {"waitedMonotonicMs": 299999}, {"fullRetentionWindowQualified": True}):
                bad_policy = policy_expiry_proof()
                bad_policy[policy].update(change)
                with self.assertRaises(ValueError): collector.sanitized_report({**survivor_report, "nativeRetentionPolicyExpiry": bad_policy}, {suite}, set())
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
        weak_report={**state_report,"nativeCredentialWeakAcl":{**credential_weak_acl_proof(),"rawCredential":"sentinel"}}
        extracted=collector.extract_reports(self.archive("windows-host.json",weak_report),{suite},set())[0][1]
        self.assertEqual(extracted["nativeCredentialWeakAcl"],credential_weak_acl_proof())
        self.assertNotIn("sentinel",json.dumps(extracted))
        for patch in (None,{"actualProductionAclRefusal":False},{"installedServiceStartupQualified":True},{"untrustedProcessReadQualified":True}):
            bad=dict(weak_report)
            if patch is None:del bad["nativeCredentialWeakAcl"]
            else:bad["nativeCredentialWeakAcl"]={**credential_weak_acl_proof(),**patch}
            with self.assertRaises(ValueError):collector.extract_reports(self.archive("windows-host.json",bad),{suite},set())
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
        result = collector.sanitized_report({"suite": suite, "cngCustody": custody, "nativeIisPublicOnly":iis_public_only_proof(), "nativeIpv4WildcardShadow": ipv4_wildcard_proof(), "nativeIpv6WildcardShadow": ipv6_wildcard_proof(), "nativeIpv6SniShadow": ipv6_shadow_proof(), "supportingConfiguredRetentionTimer": configured_timer_proof(), "nativeCngJournalAcl": cng_journal_acl_proof(), "nativeOrphanJournalProtection": orphan_journal_proof(), "nativeLedgerReadRefusals": ledger_read_proof(), "nativeJournalReadRefusals": journal_read_proof(), "nativeCredentialWeakAcl":credential_weak_acl_proof(), "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeHttpSysClientSettings": http_client_settings_proof(), "nativePackagedChainRuntime": packaged_chain_runtime_proof(), "nativeRetentionAtomicReplace": proof,
            "nativeKeySurvivors": survivor_proof(), "nativeRetentionPolicyExpiry": policy_expiry_proof(), "nativeElapsedRetention": {**elapsed, "rawLedger": "sentinel", "nativeKeyPath": "sentinel"}}, {suite}, set())
        self.assertEqual(result["nativeElapsedRetention"], elapsed)
        self.assertNotIn("sentinel", json.dumps(result))
        for change in ({"successfulCutovers": True}, {"predecessorCertificatesRemoved": 1}, {"predecessorKeysRemoved": 1},
                       {"lineageRowsFinalized": 1}, {"immediateDeferralPreservedCustody": False}, {"immutableHistoryPreserved": False},
                       {"replacementTrustedBoundCustodyUnchanged": False}, {"interruptedNativeDeleteRecovered": False},
                       {"configuredRetentionHours": 1}, {"fullRetentionWindowQualified": True},
                       {"waitedMonotonicMs": 299999}, {"waitedMonotonicMs": 600000}, {"waitedMonotonicMs": float("nan")},
                       {"mode": "synthetic-clock"}):
            with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite, "cngCustody": custody, "nativeIisPublicOnly":iis_public_only_proof(), "nativeIpv4WildcardShadow": ipv4_wildcard_proof(), "nativeIpv6WildcardShadow": ipv6_wildcard_proof(), "nativeIpv6SniShadow": ipv6_shadow_proof(), "supportingConfiguredRetentionTimer": configured_timer_proof(), "nativeCngJournalAcl": cng_journal_acl_proof(), "nativeOrphanJournalProtection": orphan_journal_proof(), "nativeLedgerReadRefusals": ledger_read_proof(), "nativeJournalReadRefusals": journal_read_proof(), "nativeCredentialWeakAcl":credential_weak_acl_proof(), "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeHttpSysClientSettings": http_client_settings_proof(), "nativePackagedChainRuntime": packaged_chain_runtime_proof(),
                "nativeRetentionAtomicReplace": proof, "nativeKeySurvivors": survivor_proof(), "nativeRetentionPolicyExpiry": policy_expiry_proof(), "nativeElapsedRetention": {**elapsed, **change}}, {suite}, set())
        with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite, "cngCustody": custody, "nativeIisPublicOnly":iis_public_only_proof(), "nativeIpv4WildcardShadow": ipv4_wildcard_proof(), "nativeIpv6WildcardShadow": ipv6_wildcard_proof(), "nativeIpv6SniShadow": ipv6_shadow_proof(), "supportingConfiguredRetentionTimer": configured_timer_proof(), "nativeCngJournalAcl": cng_journal_acl_proof(), "nativeOrphanJournalProtection": orphan_journal_proof(), "nativeLedgerReadRefusals": ledger_read_proof(), "nativeJournalReadRefusals": journal_read_proof(), "nativeCredentialWeakAcl":credential_weak_acl_proof(), "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeHttpSysClientSettings": http_client_settings_proof(), "nativePackagedChainRuntime": packaged_chain_runtime_proof(), "nativeRetentionAtomicReplace": proof}, {suite}, set())

        self.assertNotIn("sentinel", json.dumps(result))
        for field in fields:
            with self.assertRaises(ValueError): collector.sanitized_report({"suite": suite, "nativeKeySurvivors": survivor_proof(), "nativeRetentionPolicyExpiry": policy_expiry_proof(), "nativeElapsedRetention": elapsed_proof(), "nativeRetentionAtomicReplace": {**proof, field: False}}, {suite}, set())
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
        fixture_matrix={"slots":[{"id":f"fixture-{i}","kind":"host","suite":"fixture"} for i in range(201)]}
        summary.update(collector.qualification_profiles.summary_fields(collector.qualification_profiles.select_profile(fixture_matrix),True))
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
            (root / "docs/certops/qualification-suites.json").write_text(json.dumps(fixture_matrix))
            with patch.object(collector, "ROOT", root), patch.dict(collector.os.environ, {"CERTOPS_RELEASE_CANDIDATE": candidate, "CERTOPS_RELEASE_RUN_IDS": json.dumps(run_ids), "GITHUB_REPOSITORY": "owner/repo", "GITHUB_TOKEN": "offline-fixture"}), patch.object(collector, "download", side_effect=download), patch.object(collector, "validate_run"), patch.object(collector, "catalog_coverage", return_value=coverage), patch.object(collector, "extract_reports", return_value=[(".json", {"suite": "fixture"})]), patch.object(collector.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps(summary))) as verifier:
                output = io.StringIO()
                with redirect_stdout(output):
                    collector.main()
                self.assertEqual(output.getvalue().strip(), "Committed mandatory matrix passed; full feature specifications remain separately tracked")
                self.assertEqual(len(verifier.call_args.args[0][5:]), 201)
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
        matrix = qualification_manifest.load(collector.ROOT / "docs/certops/qualification-suites.json")
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

    def test_installed_weak_acl_fields_are_exact_and_reject_missing_recovery(self):
        proof={"scope":"installed-system-weak-credential-dacl-refusal-and-exact-recovery","untrustedSid":"S-1-1-0","readMask":1,"startupFailureCount":1,"inFlightMutationQualified":False,"actualNativeWeakReadableCredential":True,"exactProductionAclRefusal":True,"failedStartupProcessesDrained":True,"noAuthenticatedHeartbeatDuringRefusal":True,"noAgentOrJobMutation":True,"exactOriginalCredentialBytesAndDaclRestored":True,"nativeCngIisAndTrustedTlsPreserved":True,"freshRepairedSystemHeartbeat":True,"ownedGuardCleared":True}
        event=dict(scope="real-agent-windows-acme-iis/rsa-2048",name="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence",type="test:pass",nativeInstalledWeakCredentialAcl=proof)
        self.assertEqual(collector.installed_weak_acl_fields(event),{"nativeInstalledWeakCredentialAcl":proof})
        for key in proof:
            invalid=dict(proof);del invalid[key]
            with self.assertRaises(ValueError):collector.installed_weak_acl_fields({**event,"nativeInstalledWeakCredentialAcl":invalid})

    def test_source_junction_is_exact_and_cannot_promote_other_reparse_cases(self):
        proof={"scope":"full-installer-owned-package-source-junction-refusal","reparseTag":2684354563,"otherReparseVariantsQualified":False,"actualNoFollowMountPointTagAndTarget":True,"originalLinkAndTargetHandlesHeld":True,"actualFullInstallerCopyRefusal":True,"samePredecessorHostAndChild":True,"freshAuthenticatedHeartbeat":True,"installedFilesAndPrivateStateUnchanged":True,"nativeCngIisAndTrustedTlsUnchanged":True,"sentinelTargetUnchanged":True,"noStagingOrRecoverySwap":True,"originalJunctionRemovedByHandle":True,"retainedChildAndHandlesDrained":True,"candidateInventoryRestored":True,"ownedGuardCleared":True}
        event=dict(scope="real-agent-windows-acme-iis/rsa-2048",name="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence",type="test:pass",nativeInstalledSourceJunction=proof)
        self.assertEqual(collector.source_junction_fields(event),{"nativeInstalledSourceJunction":proof})
        for key in proof:
            invalid=dict(proof);del invalid[key]
            with self.assertRaises(ValueError):collector.source_junction_fields({**event,"nativeInstalledSourceJunction":invalid})
        with self.assertRaises(ValueError):collector.source_junction_fields({**event,"nativeInstalledSourceJunction":{**proof,"otherReparseVariantsQualified":True}})

    def test_windows_public_admission_preserves_only_bounded_measured_facts(self):
        fields = ("anonymousAdmissionRefused", "viewerAdmissionRefused", "authorizedAdmissionCreated", "idempotentSameJob", "publicRequesterPreserved", "serverDerivedOsStoreKeyMode", "publicPayloadPreserved", "nativeJobSucceeded", "nativeCngIisTrustedTlsVerified", "ownedActorCleanup")
        facts = {**dict.fromkeys(fields, True), "anonymousStatus": 401, "viewerStatus": 403, "createStatus": 201, "replayStatus": 201, "source": "api", "mode": "real", "authorizedRole": "workspace_manager", "rawSession": {"password": "raw-session-secret-sentinel"}}
        scope = "real-agent-windows-acme-iis/rsa-2048"
        event = {"scope": scope, "name": "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence", "type": "test:pass", "windowsPublicIssuance": facts, "nativeInstalledStateHandoff": installed_handoff_proof(), "nativeInstalledIisRefusal": installed_iis_refusal_proof(), "nativeInstalledCrash": {'scope': 'installed-system-native-handle-crash-fixture-lease-recovery', 'retainedNativeHandles': True, 'freshIdentityReverified': True, 'capturedHandlesExited': True, 'capturedLineageAbsent': True, 'fixtureCommandPathsAbsent': True, 'fixtureAdjustedLeaseRecovery': True, 'unresolvedAttemptNotReplayed': True, 'startupOrphanKeyRemoved': True, 'priorTrustedTlsPreserved': True, 'atomicTreeContainmentQualified': False, 'productionLeaseGraceQualified': False}, "nativeInstalledPublicRetirement": public_retirement_proof(), "nativeInstalledRetentionConfig": retention_config_proof(), "nativeInstalledWeakCredentialAcl": {"scope":"installed-system-weak-credential-dacl-refusal-and-exact-recovery","untrustedSid":"S-1-1-0","readMask":1,"startupFailureCount":1,"inFlightMutationQualified":False,"actualNativeWeakReadableCredential":True,"exactProductionAclRefusal":True,"failedStartupProcessesDrained":True,"noAuthenticatedHeartbeatDuringRefusal":True,"noAgentOrJobMutation":True,"exactOriginalCredentialBytesAndDaclRestored":True,"nativeCngIisAndTrustedTlsPreserved":True,"freshRepairedSystemHeartbeat":True,"ownedGuardCleared":True}, "nativeInstalledSourceJunction": {"scope":"full-installer-owned-package-source-junction-refusal","reparseTag":2684354563,"otherReparseVariantsQualified":False,"actualNoFollowMountPointTagAndTarget":True,"originalLinkAndTargetHandlesHeld":True,"actualFullInstallerCopyRefusal":True,"samePredecessorHostAndChild":True,"freshAuthenticatedHeartbeat":True,"installedFilesAndPrivateStateUnchanged":True,"nativeCngIisAndTrustedTlsUnchanged":True,"sentinelTargetUnchanged":True,"noStagingOrRecoverySwap":True,"originalJunctionRemovedByHandle":True,"retainedChildAndHandlesDrained":True,"candidateInventoryRestored":True,"ownedGuardCleared":True}, "nativeInstalledCredentialRefusal": credential_refusal_proof(), "nativeInstalledConfigEncoding": config_encoding_proof(), "nativeInstalledSigningPinRefusal":signing_pin_refusal_proof(), "nativeInstalledVerifyRollback":installed_verify_rollback_proof(), "nativeWindowsMultiTargetAdmission": multi_target_admission_proof(), "nativeInstalledActiveServiceControls": active_service_controls_proof(), "nativeInstalledServiceControls": service_controls_proof(), "nativeInstalledPaths": installed_paths_proof(), "nativeWindowsKeyReuseRefusal": {"scope": "public-windows-acme-profile-reuse-refusal", **dict.fromkeys(("publicAdmissionRefused", "profileUnchanged", "noJobAllocated", "nativeInventoryAndCustodyUnchanged", "trustedTlsUnchanged"), True)}}
        output = collector.sanitized_report([event], set(), {scope})
        self.assertEqual(output[0]["windowsPublicIssuance"]["source"], "api")
        self.assertNotIn("raw-session-secret-sentinel", json.dumps(output))
        extracted=collector.extract_reports(self.archive("windows.json",[event]),set(),{scope})
        self.assertEqual(extracted[0][1][0]["nativeInstalledVerifyRollback"],installed_verify_rollback_proof())
        self.assertEqual(extracted[0][1][0]["nativeInstalledSigningPinRefusal"],signing_pin_refusal_proof())
        for patch in (None,{"twoActualSystemPinFailures":False},{"missingPinQualified":True}):
            invalid=dict(event)
            if patch is None:del invalid["nativeInstalledSigningPinRefusal"]
            else:invalid["nativeInstalledSigningPinRefusal"]={**signing_pin_refusal_proof(),**patch}
            with self.assertRaises(ValueError):collector.extract_reports(self.archive("windows.json",[invalid]),set(),{scope})
        for patch in (None,{"nativePredecessorBindingRestored":False},{"transientNewBindingObservationQualified":True}):
            invalid=dict(event)
            if patch is None:del invalid["nativeInstalledVerifyRollback"]
            else:invalid["nativeInstalledVerifyRollback"]={**installed_verify_rollback_proof(),**patch}
            with self.assertRaises(ValueError):collector.extract_reports(self.archive("windows.json",[invalid]),set(),{scope})
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
        result = collector.sanitized_report({"suite": suite, "nativeKeySurvivors": survivor_proof(), "nativeRetentionPolicyExpiry": policy_expiry_proof(), "nativeElapsedRetention": elapsed_proof(), "nativeRetentionAtomicReplace": atomic, "cngCustody": custody, "nativeIisPublicOnly":iis_public_only_proof(), "nativeIpv4WildcardShadow": ipv4_wildcard_proof(), "nativeIpv6WildcardShadow": ipv6_wildcard_proof(), "nativeIpv6SniShadow": ipv6_shadow_proof(), "supportingConfiguredRetentionTimer": configured_timer_proof(), "nativeCngJournalAcl": cng_journal_acl_proof(), "nativeOrphanJournalProtection": orphan_journal_proof(), "nativeLedgerReadRefusals": ledger_read_proof(), "nativeJournalReadRefusals": journal_read_proof(), "nativeCredentialWeakAcl":credential_weak_acl_proof(), "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeHttpSysClientSettings": http_client_settings_proof(), "nativePackagedChainRuntime": packaged_chain_runtime_proof(), "nativeSamePortSni": sni}, {suite}, set())
        self.assertEqual(result["nativeSamePortSni"]["siteCount"], 2)
        self.assertTrue(result["nativeSamePortSni"]["peerRollbackPrimaryUnchanged"])
        usage_report = {"suite": suite, "nativeKeySurvivors": survivor_proof(), "nativeRetentionPolicyExpiry": policy_expiry_proof(), "nativeElapsedRetention": elapsed_proof(), "nativeRetentionAtomicReplace": atomic, "cngCustody": custody, "nativeIisPublicOnly":iis_public_only_proof(), "nativeIpv4WildcardShadow": ipv4_wildcard_proof(), "nativeIpv6WildcardShadow": ipv6_wildcard_proof(), "nativeIpv6SniShadow": ipv6_shadow_proof(), "supportingConfiguredRetentionTimer": configured_timer_proof(), "nativeCngJournalAcl": cng_journal_acl_proof(), "nativeOrphanJournalProtection": orphan_journal_proof(), "nativeLedgerReadRefusals": ledger_read_proof(), "nativeJournalReadRefusals": journal_read_proof(), "nativeCredentialWeakAcl":credential_weak_acl_proof(), "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeHttpSysClientSettings": http_client_settings_proof(), "nativePackagedChainRuntime": packaged_chain_runtime_proof()}
        usage_report["nativeKeyUsage"]["rawKeyPath"] = "sentinel"
        usage_report["nativeKeyUsage"]["cases"][0]["privateBlob"] = "sentinel"
        projected_usage = collector.sanitized_report(usage_report, {suite}, set())
        self.assertEqual(projected_usage["nativeKeyUsage"], key_usage_proof())
        runtime_report = json.loads(json.dumps(usage_report)); runtime_report["nativePackagedChainRuntime"]["rawProcessLog"] = "private-sentinel"
        projected_runtime = collector.sanitized_report(runtime_report, {suite}, set())["nativePackagedChainRuntime"]
        self.assertEqual(projected_runtime, packaged_chain_runtime_proof()); self.assertNotIn("private-sentinel", json.dumps(projected_runtime))
        for field, original in packaged_chain_runtime_proof().items():
            invalid = json.loads(json.dumps(runtime_report)); del invalid["nativePackagedChainRuntime"][field]
            with self.assertRaises(ValueError): collector.sanitized_report(invalid, {suite}, set())
            invalid = json.loads(json.dumps(runtime_report)); invalid["nativePackagedChainRuntime"][field] = not original if type(original) is bool else "wrong"
            with self.assertRaises(ValueError): collector.sanitized_report(invalid, {suite}, set())
        invalid = json.loads(json.dumps(runtime_report)); invalid["nativePackagedChainRuntime"]["wrongProtocolHostSha256"] = "a" * 64
        with self.assertRaises(ValueError): collector.sanitized_report(invalid, {suite}, set())
        invalid = json.loads(json.dumps(runtime_report)); del invalid["nativePackagedChainRuntime"]
        with self.assertRaises(ValueError): collector.sanitized_report(invalid, {suite}, set())

        settings_report = json.loads(json.dumps(usage_report))
        settings_report["nativeHttpSysClientSettings"]["rawRegistry"] = "private-sentinel"
        settings_report["nativeHttpSysClientSettings"]["cases"][0]["nativeKeyName"] = "private-sentinel"
        projected_settings = collector.sanitized_report(settings_report, {suite}, set())["nativeHttpSysClientSettings"]
        self.assertEqual(projected_settings, http_client_settings_proof())
        self.assertNotIn("private-sentinel", json.dumps(projected_settings))
        for index, item in enumerate(http_client_settings_proof()["cases"]):
            for field in item:
                invalid = json.loads(json.dumps(settings_report)); del invalid["nativeHttpSysClientSettings"]["cases"][index][field]
                with self.assertRaises(ValueError): collector.sanitized_report(invalid, {suite}, set())
                invalid = json.loads(json.dumps(settings_report)); invalid["nativeHttpSysClientSettings"]["cases"][index][field] = False if item[field] is True else "wrong"
                with self.assertRaises(ValueError): collector.sanitized_report(invalid, {suite}, set())
        for patch in ({"scope": "client-auth-handshake"}, {"clientAuthHandshakeQualified": True}, {"cases": http_client_settings_proof()["cases"][:1]}, {"cases": [http_client_settings_proof()["cases"][0]] * 2}):
            invalid = json.loads(json.dumps(settings_report)); invalid["nativeHttpSysClientSettings"].update(patch)
            with self.assertRaises(ValueError): collector.sanitized_report(invalid, {suite}, set())
        invalid = json.loads(json.dumps(settings_report)); del invalid["nativeHttpSysClientSettings"]
        with self.assertRaises(ValueError): collector.sanitized_report(invalid, {suite}, set())
        for key in ("checkMode", "freshness", "retrievalTimeout"):
            for wrong in (0, -1, 4294967296, True, None):
                invalid = json.loads(json.dumps(settings_report)); invalid["nativeHttpSysClientSettings"]["cases"][0][key] = wrong
                with self.assertRaises(ValueError): collector.sanitized_report(invalid, {suite}, set())

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
                collector.sanitized_report({"suite": suite, "cngCustody": custody, "nativeIisPublicOnly":iis_public_only_proof(), "nativeIpv4WildcardShadow": ipv4_wildcard_proof(), "nativeIpv6WildcardShadow": ipv6_wildcard_proof(), "nativeIpv6SniShadow": ipv6_shadow_proof(), "supportingConfiguredRetentionTimer": configured_timer_proof(), "nativeCngJournalAcl": cng_journal_acl_proof(), "nativeOrphanJournalProtection": orphan_journal_proof(), "nativeLedgerReadRefusals": ledger_read_proof(), "nativeJournalReadRefusals": journal_read_proof(), "nativeCredentialWeakAcl":credential_weak_acl_proof(), "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeHttpSysClientSettings": http_client_settings_proof(), "nativePackagedChainRuntime": packaged_chain_runtime_proof(), "nativeSamePortSni": {**sni, **change}}, {suite}, set())
        missing = collector.sanitized_report({"suite": suite, "nativeKeySurvivors": survivor_proof(), "nativeRetentionPolicyExpiry": policy_expiry_proof(), "nativeElapsedRetention": elapsed_proof(), "nativeRetentionAtomicReplace": atomic, "cngCustody": custody, "nativeIisPublicOnly":iis_public_only_proof(), "nativeIpv4WildcardShadow": ipv4_wildcard_proof(), "nativeIpv6WildcardShadow": ipv6_wildcard_proof(), "nativeIpv6SniShadow": ipv6_shadow_proof(), "supportingConfiguredRetentionTimer": configured_timer_proof(), "nativeCngJournalAcl": cng_journal_acl_proof(), "nativeOrphanJournalProtection": orphan_journal_proof(), "nativeLedgerReadRefusals": ledger_read_proof(), "nativeJournalReadRefusals": journal_read_proof(), "nativeCredentialWeakAcl":credential_weak_acl_proof(), "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeHttpSysClientSettings": http_client_settings_proof(), "nativePackagedChainRuntime": packaged_chain_runtime_proof(), "nativeSamePortSni": {**sni, "ownedCleanupVerified": False}}, {suite}, set())
        self.assertFalse(missing["nativeSamePortSni"]["ownedCleanupVerified"])
        contention = {**dict.fromkeys(("winnerGeneratedRealCsr", "loserLockedBeforeNativeExecution", "retryAcquiredEnrollmentLock", "retryExistingContainerRefused", "sameCsrAndSpki", "sameNonExportableKey", "winnerSignatureVerified", "ownedChildrenStopped", "ownedKeyRemoved"), True), "loserNativeCalls": 0, "loserCertreqCalls": 0, "retryCertreqCalls": 0, "winnerCertreqCalls": 1, "retryNativeCalls": 1, "privateRaw": "sentinel"}
        projected = collector.sanitized_report({"suite": suite, "nativeKeySurvivors": survivor_proof(), "nativeRetentionPolicyExpiry": policy_expiry_proof(), "nativeElapsedRetention": elapsed_proof(), "nativeRetentionAtomicReplace": atomic, "cngCustody": custody, "nativeIisPublicOnly":iis_public_only_proof(), "nativeIpv4WildcardShadow": ipv4_wildcard_proof(), "nativeIpv6WildcardShadow": ipv6_wildcard_proof(), "nativeIpv6SniShadow": ipv6_shadow_proof(), "supportingConfiguredRetentionTimer": configured_timer_proof(), "nativeCngJournalAcl": cng_journal_acl_proof(), "nativeOrphanJournalProtection": orphan_journal_proof(), "nativeLedgerReadRefusals": ledger_read_proof(), "nativeJournalReadRefusals": journal_read_proof(), "nativeCredentialWeakAcl":credential_weak_acl_proof(), "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeHttpSysClientSettings": http_client_settings_proof(), "nativePackagedChainRuntime": packaged_chain_runtime_proof(), "nativeEnrollmentContention": contention}, {suite}, set())
        self.assertEqual(projected["nativeEnrollmentContention"]["loserNativeCalls"], 0)
        self.assertNotIn("sentinel", json.dumps(projected))
        for bad in (True, "0", -1, 33):
            with self.assertRaises(ValueError):
                collector.sanitized_report({"suite": suite, "cngCustody": custody, "nativeIisPublicOnly":iis_public_only_proof(), "nativeIpv4WildcardShadow": ipv4_wildcard_proof(), "nativeIpv6WildcardShadow": ipv6_wildcard_proof(), "nativeIpv6SniShadow": ipv6_shadow_proof(), "supportingConfiguredRetentionTimer": configured_timer_proof(), "nativeCngJournalAcl": cng_journal_acl_proof(), "nativeOrphanJournalProtection": orphan_journal_proof(), "nativeLedgerReadRefusals": ledger_read_proof(), "nativeJournalReadRefusals": journal_read_proof(), "nativeCredentialWeakAcl":credential_weak_acl_proof(), "nativeStateReadRefusals": state_read_proof(), "nativeRetentionReferences": retention_reference_proof(), "nativeKeyUsage": key_usage_proof(), "nativeHttpSysClientSettings": http_client_settings_proof(), "nativePackagedChainRuntime": packaged_chain_runtime_proof(), "nativeEnrollmentContention": {**contention, "loserNativeCalls": bad}}, {suite}, set())
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
        value = {"suite": "kubernetes-host", "nativeCompaction": evidence, "nativeKubernetesRbacStartupRecovery": json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require('./scripts/test-support/kubernetes-rbac-artifact.cjs').proof()))"], cwd=Path(__file__).resolve().parent.parent, text=True))}
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
        value = {"suite": "enterprise-adcs-real", "nativeLocalRulePairs": local_pairs_proof(), "nativePendingKeySurvivor": pending_key_survivor_proof(), "nativeForeignSpkiCandidate": foreign_spki_proof(), "primaryNativePreflightDispatchCount": 18, "nativePreflightCohorts": [cohort], "nativeTemplateMutations": [], "nativeValidationExpiry": {"configuredTimeoutSeconds": 300, "defaultTimeoutSeconds": 86400, "storedWindowSeconds": 299, "monotonicObservedWaitSeconds": 301, "actualDeadline": "2026-10-14T12:00:00.000Z", "requestId": "17", "snapshotSha256": "a" * 64, "nativeAndCaClocks": "actual", "qualificationScope": "configured-five-minute-window-not-default-24-hour-elapsed"}}
        value["nativeIssuedCancellation"] = {"requestId": "17", "snapshotSha256": "a" * 64, "pollIntervalSeconds": 900, "schedulerClock": "default-real-now", "databaseDatesRewritten": False, "journalRewritten": False, "private": "sentinel"}
        value["nativeAdcsCapacity"] = {**adcs_capacity_proof(), "privateManagerCredential": "sentinel"}
        value["nativeBrowserJobApproval"] = {**browser_job_approval_proof(), "privateTrace": "sentinel"}
        value["nativeBrowserCancel"] = {**browser_cancel_proof(), "privateTrace": "sentinel"}
        value["nativePendingCaRenewal"] = {**pending_ca_proof(), "privateTrace": "sentinel"}
        value["nativePendingCaKeyChange"] = {**pending_ca_key_change_proof(), "privateTrace": "sentinel"}
        value["nativeIssuedRevocation"] = {**issued_revocation_proof(), "privateTrace": "sentinel"}
        value["nativeSameCertificateLateApproval"] = same_certificate_late_approval_proof()
        value["nativeCancelledLateApproval"] = {**cancelled_late_approval_proof(), "rawPublicCsr": "sentinel"}
        value["nativeIssuedSanBoundary"] = {**issued_san_proof(), "privateTrace": "sentinel"}
        value["nativeBrowserReconcile"] = {**browser_reconcile_proof(), "privateTrace": "sentinel"}
        value["nativeBrowserAdminBoundary"] = {**browser_admin_boundary_proof(), "privateTrace": "sentinel"}
        value["nativeBrowserAbandon"] = {**browser_abandon_proof(), "privateTrace": "sentinel"}
        value["nativeWebHostingRenewal"] = webhosting_proof()
        value["nativeWebHostingRenewal"]["privateJournal"] = "sentinel"
        value["nativeAlgorithmBoundaries"] = algorithm_proof()
        value["nativeCmcBoundaries"] = cmc_proof()
        value["nativeUncertainAbandon"] = uncertain_abandon_proof()
        value["nativeUncertainOperatorAmbiguity"] = operator_ambiguity_proof()
        value["nativeUncertainOperatorUnique"] = json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require('./scripts/fixtures/certops-adcs-unique-candidate.cjs').proof()))"], cwd=Path(__file__).resolve().parent.parent, text=True))
        value["nativePublicForeignSpki"] = {**public_foreign_spki_proof(), "privateTrace": "sentinel"}
        value["nativeRequiredTemplateAttributes"] = {**required_template_attribute_proof(), "privateTrace": "sentinel"}
        value["nativeLiveEnrollAcl"] = {**live_enroll_acl_proof(), "privateDacl": "sentinel"}
        value["nativeHttpOnlyLeafCrl"] = {**http_leaf_crl_evidence(), "privatePublication": "sentinel"}
        value["nativeOcspResponder"] = ocsp_evidence()
        value["nativeOcspRevoked"] = revoked_ocsp_evidence()
        value["nativeAdcsResultOutbox"] = {**adcs_result_outbox_evidence(), "privateCredential": "discard"}
        value["nativeUncertainOperatorAmbiguity"]["privateKey"] = "sentinel"
        value["nativeBrowserAdcs"] = browser_adcs_proof()
        value["nativeBrowserAdcs"]["privateCookie"] = "sentinel"
        value["browserNativePreflightDispatch"] = {"count": 2, "jobIds": ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"], "privateReceipt": "sentinel"}
        value["nativeAdcsTwoRenewals"] = two_adcs_renewals_proof()
        value["nativeAdcsBackgroundRenewals"] = background_adcs_proof()
        value["nativeAdcsTwoRenewals"]["privateKey"] = "sentinel"
        value["nativeUncertainAbandon"]["private"] = "sentinel"
        result = collector.extract_reports(self.archive("adcs.json", value), {"enterprise-adcs-real"}, set())
        self.assertEqual(result[0][1]["nativeCancelledLateApproval"], cancelled_late_approval_proof())
        for key in cancelled_late_approval_proof():
            invalid = json.loads(json.dumps(value)); del invalid["nativeCancelledLateApproval"][key]
            with self.assertRaises(ValueError): collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
            invalid = json.loads(json.dumps(value)); invalid["nativeCancelledLateApproval"][key] = False if isinstance(cancelled_late_approval_proof()[key], bool) else "invalid"
            if key == "sameCertificateRenewalQualified": invalid["nativeCancelledLateApproval"][key] = True
            with self.assertRaises(ValueError): collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for patch_value in ({"requestIds": ["17", "4294967296"]}, {"requestIds": ["17", "17"]}, {"fingerprints": ["a"*64, "a"*64]}, {"cancelledEnrollmentId": cancelled_late_approval_proof()["successorEnrollmentId"]}):
            invalid = json.loads(json.dumps(value)); invalid["nativeCancelledLateApproval"].update(patch_value)
            with self.assertRaises(ValueError): collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        invalid = json.loads(json.dumps(value)); del invalid["nativeCancelledLateApproval"]
        with self.assertRaises(ValueError): collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        self.assertEqual(result[0][1]["nativePendingCaRenewal"], pending_ca_proof())
        self.assertEqual(result[0][1]["nativePendingCaKeyChange"], pending_ca_key_change_proof())
        for key, expected in pending_ca_key_change_proof().items():
            invalid = json.loads(json.dumps(value)); del invalid["nativePendingCaKeyChange"][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for patch_value in ({"oldRequestId": "4294967296"}, {"freshRequestId": "17"}, {"subjectCountBefore": True}, {"subjectCountAfter": 99}, {"freshSpkiSha256": "e"*64}, {"freshSnapshotSha256": "c"*64}, {"predecessorFingerprint": "f"*64}, {"oldCaKeySha256": "f"*64}, {"registeredCleanupResolved": False}):
            invalid = json.loads(json.dumps(value)); invalid["nativePendingCaKeyChange"].update(patch_value)
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())

        for key, expected in pending_ca_proof().items():
            invalid = json.loads(json.dumps(value)); del invalid["nativePendingCaRenewal"][key]
            with self.subTest(pending_ca_missing=key), self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
            invalid = json.loads(json.dumps(value)); invalid["nativePendingCaRenewal"][key] = not expected if isinstance(expected, bool) else "invalid"
            with self.subTest(pending_ca_invalid=key), self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for patch in ({"requestId": "4294967296"}, {"caCertificateCountAfter": 17}, {"caCertificateCountAfter": 1}, {"caCertificateCountBefore": True}, {"continuationJobId": pending_ca_proof()["originalJobId"]}, {"leafFingerprint": pending_ca_proof()["predecessorFingerprint"]}, {"schedulerClock": "default-real-now"}, {"backgroundWorkerIntervalQualified": True}, {"predecessorFingerprint": "f"*64}):
            invalid = json.loads(json.dumps(value)); invalid["nativePendingCaRenewal"].update(patch)
            with self.subTest(pending_ca_patch=patch), self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        invalid = json.loads(json.dumps(value)); del invalid["nativePendingCaRenewal"]
        with self.assertRaises(ValueError):
            collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        self.assertEqual(result[0][1]["nativePreflightCohorts"][0]["dispatchCount"], 18)
        self.assertNotIn("sentinel", json.dumps(result))
        self.assertEqual(result[0][1]["nativeUncertainOperatorAmbiguity"], operator_ambiguity_proof())
        self.assertEqual(result[0][1]["nativePublicForeignSpki"], public_foreign_spki_proof())
        self.assertEqual(result[0][1]["nativeRequiredTemplateAttributes"], required_template_attribute_proof())
        for key in required_template_attribute_proof():
            invalid = json.loads(json.dumps(value)); del invalid["nativeRequiredTemplateAttributes"][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for index, patch_value in ((0, {"observedValue": False}), (1, {"observedValue": 0}), (0, {"preflightVerdict": "unsafe"}), (1, {"exactOriginalAttributesRestored": False}), (0, {"caseId": "subject-name-flag-absent"})):
            invalid = json.loads(json.dumps(value)); invalid["nativeRequiredTemplateAttributes"]["cases"][index].update(patch_value)
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())

        for key in public_foreign_spki_proof():
            invalid = json.loads(json.dumps(value)); del invalid["nativePublicForeignSpki"][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for patch_value in ({"foreignRequestId": "101"}, {"foreignSubjectRequestCount": True}, {"originalSubjectRequestCount": 3}, {"actualSignedSpkiMismatchRefusal": False}, {"selectedFingerprint": "f"*64}, {"failedJobId": operator_ambiguity_proof()["jobIds"][1]}, {"originalSpkiSha256": "f"*64}, {"reconcileSearchFrom": 99}):
            invalid = json.loads(json.dumps(value)); invalid["nativePublicForeignSpki"].update(patch_value)
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())

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
        self.assertEqual(result[0][1]["nativeHttpOnlyLeafCrl"], http_leaf_crl_evidence())
        self.assertEqual(result[0][1]["nativeOcspResponder"], ocsp_evidence())
        self.assertEqual(result[0][1]["nativeOcspRevoked"], collector.ocsp_revoked_proof.fields(revoked_ocsp_evidence(), ocsp_evidence()))
        self.assertEqual(result[0][1]["nativeAdcsResultOutbox"], adcs_result_outbox_evidence())
        for key in (None, *adcs_result_outbox_evidence()):
            bad = json.loads(json.dumps(value))
            if key is None:
                del bad["nativeAdcsResultOutbox"]
            else:
                del bad["nativeAdcsResultOutbox"][key]
            with self.subTest(adcs_outbox_missing=key), self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value["suite"]}, set())
        for patch in ({"caRequestCounts": [10, 11, 12]}, {"retryDelayMs": 1}, {"sameLeafKeyAndCaRequestAfterRestart": False}, {"backgroundTimerQualified": True}):
            bad = json.loads(json.dumps(value))
            bad["nativeAdcsResultOutbox"].update(patch)
            with self.subTest(adcs_outbox_invalid=patch), self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value["suite"]}, set())
        for missing in (None, *collector.ocsp_proof.FIELDS):
            bad = json.loads(json.dumps(value))
            if missing is None:
                del bad["nativeOcspResponder"]
            else:
                del bad["nativeOcspResponder"][missing]
            with self.subTest(missing_ocsp=missing), self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value["suite"]}, set())
        for missing in (None, *collector.ocsp_revoked_proof.FIELDS):
            bad = json.loads(json.dumps(value))
            if missing is None:
                del bad["nativeOcspRevoked"]
            else:
                del bad["nativeOcspRevoked"][missing]
            with self.subTest(missing_ocsp_revoked=missing), self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value["suite"]}, set())
        for key in (None, *http_leaf_crl_evidence()):
            bad = json.loads(json.dumps(value))
            if key is None:
                del bad["nativeHttpOnlyLeafCrl"]
            else:
                del bad["nativeHttpOnlyLeafCrl"][key]
            with self.subTest(http_leaf_missing=key), self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value["suite"]}, set())
        for patch_value in ({"actualOwnedHttp503": False}, {"installedAgentFaultRecoveryQualified": False}, {"caRequestCounts": [10, 11, 13]}, {"restoredRequestId": 42}):
            bad = json.loads(json.dumps(value))
            bad["nativeHttpOnlyLeafCrl"].update(patch_value)
            with self.subTest(http_leaf_invalid=patch_value), self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value["suite"]}, set())
        self.assertEqual(result[0][1]["nativeBrowserAdcs"], browser_adcs_proof())
        self.assertEqual(result[0][1]["nativeLocalRulePairs"], local_pairs_proof())
        self.assertEqual(result[0][1]["nativePendingKeySurvivor"], pending_key_survivor_proof())
        for key in pending_key_survivor_proof():
            invalid = pending_key_survivor_proof()
            del invalid[key]
            with self.subTest(survivor_missing=key), self.assertRaises(ValueError):
                collector.pending_key_survivor_fields(invalid)
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
        for rows in (None, [], [row for row in local_pairs_proof() if row["caseId"] != "empty-allowlist"], [local_pairs_proof()[0]] * 4, [{**row, "caseId": "unknown"} for row in local_pairs_proof()]):
            bad = json.loads(json.dumps(value))
            bad["nativeLocalRulePairs"] = rows
            with self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value["suite"]}, set())

        self.assertNotIn("privateReceipt", result[0][1]["browserNativePreflightDispatch"])
        hierarchy = json.loads(json.dumps(value))
        hierarchy["suite"] = "enterprise-adcs-hierarchy-real"
        hierarchy["nativeHttpIntermediateCrl"] = http_crl_proof()
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
        self.assertEqual(result[0][1]["nativeBrowserJobApproval"], browser_job_approval_proof())
        for key, expected in browser_job_approval_proof().items():
            invalid = json.loads(json.dumps(value)); del invalid["nativeBrowserJobApproval"][key]
            with self.assertRaises(ValueError): collector.sanitized_report(invalid, {value["suite"]}, set())
            invalid = json.loads(json.dumps(value)); invalid["nativeBrowserJobApproval"][key] = not expected if type(expected) is bool else "invalid"
            with self.assertRaises(ValueError): collector.sanitized_report(invalid, {value["suite"]}, set())
        for patch in ({"approvePosts": True}, {"rejectPosts": True}, {"cancelPosts": False}, {"requestIds": ["17", "4294967296"]}, {"jobIds": list(reversed(value["nativeAdcsCapacity"]["jobIds"]))}, {"rejectedJobId": value["nativeAdcsCapacity"]["jobIds"][0]}):
            invalid = json.loads(json.dumps(value)); invalid["nativeBrowserJobApproval"].update(patch)
            with self.assertRaises(ValueError): collector.sanitized_report(invalid, {value["suite"]}, set())
        self.assertEqual(result[0][1]["nativeBrowserCancel"], browser_cancel_proof())
        self.assertNotIn("sentinel", json.dumps(result[0][1]["nativeBrowserCancel"]))
        for key, expected in browser_cancel_proof().items():
            invalid = json.loads(json.dumps(value)); del invalid["nativeBrowserCancel"][key]
            with self.assertRaises(ValueError): collector.sanitized_report(invalid, {value["suite"]}, set())
            invalid = json.loads(json.dumps(value)); invalid["nativeBrowserCancel"][key] = not expected if type(expected) is bool else "invalid"
            with self.assertRaises(ValueError): collector.sanitized_report(invalid, {value["suite"]}, set())
        for patch in ({"cancelPosts": True}, {"otherMutations": False}, {"priorRequestId": "4294967296"}, {"priorRequestId": "17"}, {"fingerprint": "a" * 64}, {"priorJobId": "55555555-5555-5555-5555-555555555555"}, {"initialSixConcurrencyQualified": True}):
            invalid = json.loads(json.dumps(value)); invalid["nativeBrowserCancel"].update(patch)
            with self.assertRaises(ValueError): collector.sanitized_report(invalid, {value["suite"]}, set())
        self.assertEqual(result[0][1]["nativeIssuedRevocation"], issued_revocation_proof())
        for key, expected in issued_revocation_proof().items():
            invalid = json.loads(json.dumps(value)); del invalid["nativeIssuedRevocation"][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
            invalid = json.loads(json.dumps(value)); invalid["nativeIssuedRevocation"][key] = not expected if isinstance(expected, bool) else "invalid"
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for patch in ({"requestId": "4294967296"}, {"requestId": 17}, {"schedulerDefaultClockQualified": 0}):
            invalid = json.loads(json.dumps(value)); invalid["nativeIssuedRevocation"].update(patch)
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        self.assertEqual(result[0][1]["nativeIssuedSanBoundary"], issued_san_proof())
        for key, expected in issued_san_proof().items():
            invalid = json.loads(json.dumps(value)); del invalid["nativeIssuedSanBoundary"][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
            invalid = json.loads(json.dumps(value)); invalid["nativeIssuedSanBoundary"][key] = False if expected is True else "invalid"
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for patch in ({"requestId": "4294967296"}, {"requestId": 17}, {"errorCode": "ADCS_CA_KEY_CHANGED"}):
            invalid = json.loads(json.dumps(value)); invalid["nativeIssuedSanBoundary"].update(patch)
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        self.assertEqual(result[0][1]["nativeBrowserReconcile"], browser_reconcile_proof())
        for key, expected in browser_reconcile_proof().items():
            invalid = json.loads(json.dumps(value)); del invalid["nativeBrowserReconcile"][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
            invalid = json.loads(json.dumps(value)); invalid["nativeBrowserReconcile"][key] = False if expected is True else "invalid"
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for patch in ({"reconcilePosts": True}, {"invalidRequestPosts": False}, {"selectedRequestId": "4294967296"}, {"unusedRequestId": "101"}, {"selectedFingerprint": "a" * 64}, {"continuationJobId": "55555555-5555-5555-5555-555555555555"}, {"enrollmentId": "55555555-5555-5555-5555-555555555555"}):
            invalid = json.loads(json.dumps(value)); invalid["nativeBrowserReconcile"].update(patch)
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        self.assertEqual(result[0][1]["nativeBrowserAdminBoundary"], browser_admin_boundary_proof())
        for key, expected in browser_admin_boundary_proof().items():
            invalid = json.loads(json.dumps(value)); del invalid["nativeBrowserAdminBoundary"][key]
            with self.assertRaises(ValueError): collector.sanitized_report(invalid, {value["suite"]}, set())
            invalid = json.loads(json.dumps(value)); invalid["nativeBrowserAdminBoundary"][key] = not expected if type(expected) is bool else "invalid"
            with self.assertRaises(ValueError): collector.sanitized_report(invalid, {value["suite"]}, set())
        self.assertEqual(result[0][1]["nativeBrowserAbandon"], browser_abandon_proof())
        for key, expected in browser_abandon_proof().items():
            invalid = json.loads(json.dumps(value)); del invalid["nativeBrowserAbandon"][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
            invalid = json.loads(json.dumps(value)); invalid["nativeBrowserAbandon"][key] = False if expected is True else "invalid"
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for field in ("abandonPosts", "keepPosts"):
            invalid = json.loads(json.dumps(value)); invalid["nativeBrowserAbandon"][field] = True if field == "abandonPosts" else False
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        self.assertEqual(result[0][1]["nativeWebHostingRenewal"], webhosting_proof())
        self.assertEqual(result[0][1]["nativeAdcsCapacity"], adcs_capacity_proof())
        self.assertNotIn("privateManagerCredential", result[0][1]["nativeAdcsCapacity"])
        for key, expected in adcs_capacity_proof().items():
            invalid = json.loads(json.dumps(value)); del invalid["nativeAdcsCapacity"][key]
            with self.subTest(capacity_missing=key), self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
            invalid = json.loads(json.dumps(value)); invalid["nativeAdcsCapacity"][key] = False if expected is True else "invalid"
            with self.subTest(capacity_bad=key), self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for field in ("requestIds", "fingerprints", "enrollmentIds", "jobIds"):
            invalid = json.loads(json.dumps(value)); invalid["nativeAdcsCapacity"][field][1] = invalid["nativeAdcsCapacity"][field][0]
            with self.subTest(capacity_duplicate=field), self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for field, bad in (("cap", True), ("initialRefused", True), ("requestIds", ["17", "4294967296"]), ("requestIds", ["0", "18"])):
            invalid = json.loads(json.dumps(value)); invalid["nativeAdcsCapacity"][field] = bad
            with self.subTest(capacity_bound=field, bad=bad), self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for key, expected in webhosting_proof().items():
            invalid = json.loads(json.dumps(value))
            del invalid["nativeWebHostingRenewal"][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
            invalid = json.loads(json.dumps(value))
            invalid["nativeWebHostingRenewal"][key] = not expected if type(expected) is bool else "invalid"
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        self.assertEqual(result[0][1]["nativeAdcsTwoRenewals"], two_adcs_renewals_proof())
        self.assertEqual(result[0][1]["nativeAdcsBackgroundRenewals"], background_adcs_proof())
        for key in background_adcs_proof():
            invalid = json.loads(json.dumps(value)); del invalid["nativeAdcsBackgroundRenewals"][key]
            with self.subTest(background_missing=key), self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())
        for key, bad in {"failed": True, "ticks": 1, "finishes": 1, "created": 3, "stops": 0, "forwarded": False, "firstTickElapsedMs": 59999, "exitCode": 1, "nativeDrained": False, "bridgeReady": False}.items():
            invalid = json.loads(json.dumps(value)); invalid["nativeAdcsBackgroundRenewals"]["workerLifecycle"][key] = bad
            with self.subTest(background_lifecycle=key), self.assertRaises(ValueError):
                collector.extract_reports(self.archive("adcs.json", invalid), {"enterprise-adcs-real"}, set())

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
        self.assertGreaterEqual(len(declared), 257)
        public_sources = [{"file": name, "sha256": hashlib.sha256((collector.ROOT / name).read_bytes()).hexdigest()} for name in declared[:257]]
        for count in (97, 128, 129, 192, 256):
            self.assertEqual(collector.supporting_sources(public_sources[:count]), public_sources[:count])
        with self.assertRaises(ValueError):
            collector.supporting_sources(public_sources)
        with self.assertRaises(ValueError):
            collector.supporting_sources([public_sources[0], public_sources[0]])
        for escaped in ("../outside.js", "C:\\private.js", "/private.js", "inside/../private.js"):
            with self.assertRaises(ValueError):
                collector.supporting_sources([{"file": escaped, "sha256": "a" * 64}])

    def test_algorithm_and_cmc_closed_native_proofs_refuse_missing_and_duplicate_controls(self):
        self.assertEqual(collector.algorithm_boundaries_fields(algorithm_proof()), algorithm_proof())
        self.assertEqual(collector.cmc_boundaries_fields(cmc_proof()), cmc_proof())
        for field in algorithm_proof()[0]:
            if type(algorithm_proof()[0][field]) is bool:
                for wrong in (False, 1, None, "true"):
                    rows = algorithm_proof()
                    rows[0][field] = wrong
                    with self.assertRaises(ValueError):
                        collector.algorithm_boundaries_fields(rows)
        for key in ("positiveRequestId", "positiveFingerprintSha256"):
            rows = algorithm_proof()
            rows[1][key] = rows[0][key]
            with self.assertRaises(ValueError):
                collector.algorithm_boundaries_fields(rows)
        for field in cmc_proof():
            if type(cmc_proof()[field]) is bool and field != "syntheticCaResponse":
                value = cmc_proof()
                value[field] = 1
                with self.assertRaises(ValueError):
                    collector.cmc_boundaries_fields(value)
        for mutate in (lambda value: value.update(syntheticCaResponse=True), lambda value: value.update(tamperedResponseDerSha256=value["originalResponseDerSha256"]), lambda value: value["refusedVariants"].pop(), lambda value: value.update(rawPrivate="unexpected")):
            value = cmc_proof()
            mutate(value)
            with self.assertRaises(ValueError):
                collector.cmc_boundaries_fields(value)
        with self.assertRaises(ValueError):
            collector.algorithm_boundaries_fields(None)
        with self.assertRaises(ValueError):
            collector.cmc_boundaries_fields(None)

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


    def test_installed_crash_projection_requires_native_facts_without_scope_promotion(self):
        flags = ["retainedNativeHandles", "freshIdentityReverified", "capturedHandlesExited", "capturedLineageAbsent", "fixtureCommandPathsAbsent", "fixtureAdjustedLeaseRecovery", "unresolvedAttemptNotReplayed", "startupOrphanKeyRemoved", "priorTrustedTlsPreserved"]
        proof = {"scope": "installed-system-native-handle-crash-fixture-lease-recovery", **dict.fromkeys(flags, True), "atomicTreeContainmentQualified": False, "productionLeaseGraceQualified": False}
        event = {"scope": "real-agent-windows-acme-iis/rsa-2048", "name": "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence", "type": "test:pass", "nativeInstalledCrash": {**proof, "rawProcessCommand": "private"}}
        self.assertEqual(collector.installed_crash_fields(event), {"nativeInstalledCrash": proof})
        for key in proof:
            missing = json.loads(json.dumps(event)); del missing["nativeInstalledCrash"][key]
            with self.assertRaises(ValueError): collector.installed_crash_fields(missing)
            wrong = json.loads(json.dumps(event)); wrong["nativeInstalledCrash"][key] = True if key.endswith("Qualified") else False
            with self.assertRaises(ValueError): collector.installed_crash_fields(wrong)
        self.assertEqual(collector.installed_crash_fields({**event, "scope": "real-agent-acme-filesystem"}), {})
        self.assertEqual(collector.installed_crash_fields({**event, "type": "test:fail"}), {})

    def test_installed_iis_refusal_projection_is_bounded_and_requires_claim_audit(self):
        proof = installed_iis_refusal_proof()
        for profile in ("rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384"):
            event = {"scope": "real-agent-windows-acme-iis/" + profile, "name": "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence", "type": "test:pass", "nativeInstalledIisRefusal": {**proof, "rawCngInventory": "must-not-survive"}}
            self.assertEqual(collector.installed_iis_refusal_fields(event), {"nativeInstalledIisRefusal": proof})
            self.assertNotIn("must-not-survive", json.dumps(collector.installed_iis_refusal_fields(event)))
            for field in proof:
                wrong = json.loads(json.dumps(event)); del wrong["nativeInstalledIisRefusal"][field]
                with self.assertRaises(ValueError): collector.installed_iis_refusal_fields(wrong)
                wrong = json.loads(json.dumps(event)); wrong["nativeInstalledIisRefusal"][field] = False
                with self.assertRaises(ValueError): collector.installed_iis_refusal_fields(wrong)
        for field, wrong in (("jobId", "not-uuid"), ("claimId", "not-uuid"), ("scope", "direct-executor"), ("claimBoundFailureAudit", 1)):
            bad = json.loads(json.dumps(event)); bad["nativeInstalledIisRefusal"][field] = wrong
            with self.assertRaises(ValueError): collector.installed_iis_refusal_fields(bad)
        for wrong in (None, [], "unknown", {}):
            with self.assertRaises(ValueError): collector.installed_iis_refusal_fields({**event, "nativeInstalledIisRefusal": wrong})
        missing = dict(event); del missing["nativeInstalledIisRefusal"]
        with self.assertRaises(ValueError): collector.installed_iis_refusal_fields(missing)
        self.assertEqual(collector.installed_iis_refusal_fields({**event, "scope": "real-agent-acme-filesystem"}), {})
        self.assertEqual(collector.installed_iis_refusal_fields({**event, "type": "test:fail"}), {})


    def test_installed_unicode_paths_projection_requires_actual_facts_and_strips_private_paths(self):
        proof = installed_paths_proof()
        for profile in ("rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384"):
            event = {"scope": "real-agent-windows-acme-iis/" + profile, "name": "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence", "type": "test:pass", "nativeInstalledPaths": {**proof, "rawNativePath": "sentinel"}}
            self.assertEqual(collector.installed_paths_fields(event), {"nativeInstalledPaths": proof})
            self.assertNotIn("sentinel", json.dumps(collector.installed_paths_fields(event)))
            for field in proof:
                missing = json.loads(json.dumps(event)); del missing["nativeInstalledPaths"][field]
                with self.assertRaises(ValueError): collector.installed_paths_fields(missing)
                for invalid in (False, 1, "true", None):
                    wrong = json.loads(json.dumps(event)); wrong["nativeInstalledPaths"][field] = invalid
                    with self.assertRaises(ValueError): collector.installed_paths_fields(wrong)
            for invalid in (None, [], "native"):
                with self.assertRaises(ValueError): collector.installed_paths_fields({**event, "nativeInstalledPaths": invalid})
            missing = dict(event); del missing["nativeInstalledPaths"]
            with self.assertRaises(ValueError): collector.installed_paths_fields(missing)
        self.assertEqual(collector.installed_paths_fields({**event, "scope": "real-agent-acme-filesystem"}), {})
        self.assertEqual(collector.installed_paths_fields({**event, "type": "test:fail"}), {})


if __name__ == "__main__":
    unittest.main()
