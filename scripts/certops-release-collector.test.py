def adcs_result_outbox_evidence():
    import certops_adcs_result_outbox_proof as proof
    return {'scope': proof.SCOPE, 'enrollmentId': '10000000-0000-4000-8000-000000000001', 'jobId': '10000000-0000-4000-8000-000000000002', 'claimId': '10000000-0000-4000-8000-000000000003', 'requestId': 42, 'fingerprints': ['1' * 64, '2' * 64], 'caRequestCounts': [10, 11, 11], 'recordedAttempts': 1, 'retryDelayMs': 15000, 'atomicTreeContainmentQualified': False, 'backgroundTimerQualified': False, **{key: True for key in proof.FLAGS}}
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
    return {'scope': OCSP_SCOPE, 'enrollmentIds': ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'], 'jobIds': ['33333333-3333-4333-8333-333333333333', '44444444-4444-4444-8444-444444444444'], 'requestIds': [41, 42], 'signerRequestId': 40, 'leafFingerprints': ['a' * 64, 'b' * 64], 'signerFingerprint': 'c' * 64, 'issuerKeySha256': 'd' * 64, 'nativeHelperSha256': 'e' * 64, 'publicCrlSha256': 'f' * 64, 'responseSha256': ['1' * 64, '2' * 64, '3' * 64], 'caRequestCounts': [39, 40, 41, 42], 'nativeVerdicts': ['valid', 'revocation_unknown', 'valid'], 'deferredRecovery': {'originalJobId': '55555555-5555-4555-8555-555555555555', 'originalClaimId': '66666666-6666-4666-8666-666666666666', 'continuationJobId': '33333333-3333-4333-8333-333333333333', 'continuationClaimId': '77777777-7777-4777-8777-777777777777', 'requestId': 41}, **{key: True for key in OCSP_FLAGS}, **{key: False for key in OCSP_FALSE_FLAGS}}

def revoked_ocsp_evidence():
    import certops_adcs_ocsp_revoked_proof as proof
    base = ocsp_evidence()
    return {'scope': proof.SCOPE, 'historicalEnrollmentId': base['enrollmentIds'][0], 'currentEnrollmentId': base['enrollmentIds'][1], 'historicalRequestId': base['requestIds'][0], 'currentRequestId': base['requestIds'][1], 'originalCrlSha256': base['publicCrlSha256'], 'revokedCrlSha256': '8' * 64, 'originalCrlNumber': '0', 'revokedCrlNumber': '1', 'historicalFingerprint': base['leafFingerprints'][0], 'currentFingerprint': base['leafFingerprints'][1], 'historicalSerial': 'A2', 'revocationTime': '2026-10-15T10:00:00.000Z', 'responseSha256': '9' * 64, 'signerFingerprint': base['signerFingerprint'], 'issuerKeySha256': base['issuerKeySha256'], 'nativeVerdict': 'revoked', 'caRequestCounts': [base['caRequestCounts'][-1], base['caRequestCounts'][-1]], **{key: True for key in proof.FLAGS}, **{key: False for key in proof.FALSE_FLAGS}}
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('collector', Path(__file__).with_name('certops-release-collector.py'))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)

def adcs_capacity_proof():
    flags = ('freshConfirmedIssuer', 'actualPostConfirmationPreflight', 'sixConcurrentPublicRequests', 'fivePersistedPendingApprovals', 'sixthTransactionRolledBack', 'noCaRequestsBeforeApproval', 'noNativeKeysBeforeApproval', 'distinctAuthorizedApprover', 'firstNativeCompletionFreesSlot', 'refusedSubjectReenteredPublicly', 'twoClaimBoundNativeInstallations', 'twoDistinctOwnedCaRequests', 'twoNonexportableMachineKeys', 'twoNativeIisAndTrustedTls', 'fourUnapprovedJobsPubliclyRejected', 'approvalSettingRestored')
    return {'scope': 'actual-native-adcs-per-issuer-five-public-approvals-and-terminal-release', 'cap': 5, 'initialAccepted': 5, 'initialRefused': 1, 'nativeCompleted': 2, **dict.fromkeys(flags, True), 'requestIds': ['17', '18'], 'fingerprints': ['a' * 64, 'b' * 64], 'enrollmentIds': ['11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222'], 'jobIds': ['33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444444']}

def browser_admin_boundary_proof():
    return {'scope': 'public-manager-viewer-adcs-admin-boundary-not-mounted-admin-withdrawal', 'enrollmentId': '11111111-1111-1111-1111-111111111111', 'forbiddenMutations': 4, 'roleChanges': 2, 'adminDemotions': 0, 'mountedAdminWithdrawalQualified': False, 'distinctOwnedNonownerActors': True, 'noGlobalAdminBypassAssumed': True, 'publicManagerViewerManagerTransitions': True, 'managerAndViewerUiDenied': True, 'bothRolesReconcileAndAbandonForbidden': True, 'publicOwnerAdminPatchDemotionRefused': True, 'exactOwnerAdminUnchanged': True, 'actualUncertainEnrollmentAndJobsUnchanged': True, 'nativeCaAndUnacceptedKeyUnchanged': True, 'servingNativeCustodyAndTrustedTlsUnchanged': True, 'targetCertOpsAuditUnchanged': True, 'exactMembershipAudits': True, 'managerMembershipRestored': True, 'browserAndTrustDrained': True}

def browser_abandon_proof():
    return {'scope': 'browser-confirmed-real-uncertain-abandon-and-native-unaccepted-key-cleanup', 'enrollmentId': '11111111-1111-1111-1111-111111111111', 'cleanupJobId': '22222222-2222-2222-2222-222222222222', 'abandonPosts': 1, 'keepPosts': 0, 'actualUncertainEnrollmentVisible': True, 'keepDidNotMutate': True, 'explicitConfirmationRequired': True, 'exactPublicAbandonAcknowledged': True, 'browserAndTrustDrained': True, 'actualProductionContinuation': True, 'journalAndDatabaseAbandoned': True, 'exactUnacceptedKeyAbsent': True, 'noAcceptedLeaf': True, 'zeroNativeCaRequests': True, 'onePublicAudit': True, 'originalUnknownEffectPreserved': True}

def webhosting_proof():
    return {'scope': 'real-adcs-webhosting-issue-and-fresh-key-manual-renewal', 'store': 'WebHosting', 'expiryCleanupQualified': False, 'requestIds': ['17', '18'], 'fingerprints': ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'], 'publicIssueAndRenewInstalled': True, 'twoIndependentCaRequests': True, 'freshSerialSpkiAndKey': True, 'webHostingProtectedCustody': True, 'myCopiesAbsent': True, 'exactNativeIisAndHttpSysStore': True, 'trustedSniTls': True, 'installedDiscoveryInventory': True, 'immutableAcceptedStore': True, 'predecessorRetentionStorePreserved': True, 'storeQualifiedCleanupRegistered': True}

def browser_job_approval_proof():
    return {'scope': 'browser-control-plane-job-approval-for-two-real-adcs-capacity-installations', 'approvePosts': 2, 'rejectPosts': 1, 'cancelPosts': 0, 'caOfficerApprovalQualified': False, 'jobIds': ['33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444444'], 'enrollmentIds': ['11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222'], 'payloadHashes': ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'], 'requestIds': ['17', '18'], 'fingerprints': ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'], 'rejectedJobId': '77777777-7777-7777-7777-777777777777', 'rejectedEnrollmentId': '88888888-8888-8888-8888-888888888888', 'rejectedPayloadHash': 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 'rejectedCanonicalIntentHash': 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'twoDistinctOwnedPendingJobs': True, 'distinctManagerApprover': True, 'exactJobVisibleInActualDashboard': True, 'cancelDidNotMutate': True, 'twoExactPublicApprovalPosts': True, 'appendOnlyDecisionsBoundToActor': True, 'payloadAndCanonicalIntentHashesVerified': True, 'browserAndTrustDrained': True, 'sameApprovedJobsInstalledNatively': True, 'capacityGenerationsCrossBound': True, 'oneExactPublicRejectionPost': True, 'rejectedJobNeverClaimedOrSubmitted': True, 'rejectedIntentAndNativeAbsencePreserved': True}

def foreign_spki_proof():
    flags = ('sameRequesterNativeRetrieveSucceeded', 'nativeCaIdentityMatched', 'differentEnrollmentSpkiProved', 'explicitCandidateRefused', 'boundedSearchUnresolved', 'originalJournalWatermarkPreserved', 'originalNativeCustodyAndTlsPreserved', 'noAdditionalCaRequest')
    return {'scope': 'read-only-native-foreign-spki-candidate-not-public-uncertain-recovery', **dict.fromkeys(flags, True), 'requestIds': ['17', '18'], 'spkiFingerprints': ['a' * 64, 'b' * 64]}

def local_rule_tightening_proof():
    return {"enrollmentId":"11111111-1111-1111-1111-111111111111","continuationJobId":"22222222-2222-2222-2222-222222222222","requestId":"17","snapshotSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","caRequestCounts":[7,7],"actualSignedRetrievalPending":True,"originalCngKeyUsable":True,"frozenContextPreserved":True,"noAdditionalCaRequest":True,"outgoingTrustedTlsPreserved":True,"explicitTerminalCleanupAfterDenial":True}


def pending_key_survivor_proof():
    return {"scope":"native-pending-key-policy-change-retrieval-install-and-survivor-protection","store":"WebHosting","recovery":"signed-retrieval-and-isolated-iis-installation","enrollmentId":"11111111-1111-1111-1111-111111111111","requestId":"17","continuationJobId":"22222222-2222-2222-2222-222222222222","fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","csrSpkiSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","caRequestCounts":[7,7,7],"actualOwnedPendingRequest":True,"actualOwnedCaLeafSameCsrSpki":True,"exactWebHostingAssociationAndProtectedKey":True,"nativeSurvivorReferenceObserved":True,"signedRetrievalInstalled":True,"frozenEnrollmentIdentityPreserved":True,"originalKeyUsableAfterReconciliation":True,"installedKeyProtectedFromCleanup":True,"installedReferenceSurvivesSecondaryRemoval":True,"noAdditionalCaRequest":True,"exactPublicAssociationOnlyRemoved":True,"predecessorCustodyIisTlsPreserved":True,"configurationCredentialRestored":True,"ownedCaLeafRevoked":True,"ownershipGuardReleased":True}

def local_pairs_proof():
    fields = ('actualSignedJobRefused', 'claimBoundOutcome', 'noCaRequestAllocated', 'noKeyGenerated', 'noAcceptedLeafOrJournal', 'originalNativeCustodyPreserved', 'outgoingTrustedTlsPreserved', 'configurationAndCredentialRestored')
    return [{'caseId': case, **dict.fromkeys(fields, True)} for case in ('ca-host-mismatch', 'ca-authority-mismatch', 'template-pair-mismatch', 'empty-allowlist')]

def algorithm_proof():
    cases = (('rsa2048-below-template3072', 'rsa3072'), ('rsa3072-below-template4096', 'rsa4096'), ('ec256-on-p384-schema-three', 'ec384schema3'), ('ec256-on-p384-schema-four', 'ec384'))
    flags = ('nativeSafeTemplateObserved', 'publicConfirmedIssuerUsed', 'actualSignedClaimRefusal', 'noCaRequestAllocated', 'noKeyGenerated', 'noAcceptedLeafOrJournal', 'positiveNativeCustodyUnchanged', 'positiveTrustedTlsUnchanged')
    return [{'caseId': case, 'positiveScenario': f'adcs-real-{positive}-issued-cng-iis', 'positiveFingerprintSha256': format(index + 10, 'x') * 64, 'positiveRequestId': str(index + 17), **dict.fromkeys(flags, True)} for index, (case, positive) in enumerate(cases)]

def cmc_proof():
    flags = ('actualCaSignedPending', 'actualPinnedSignatureVerified', 'actualSignerSignatureByteTampered', 'actualPristineDerControlVerified', 'agentResponseUnchanged')
    return {'scope': 'read-only-native-ca-signed-response-signature-boundaries', **dict.fromkeys(flags, True), 'syntheticCaResponse': False, 'caRequestId': '17', 'responseSha256': 'a' * 64, 'nativeHelperSha256': 'b' * 64, 'originalResponseDerSha256': 'c' * 64, 'tamperedResponseDerSha256': 'd' * 64, 'refusedVariants': ['empty', 'truncated', 'trailing-data', 'oversized', 'signer-signature-tampered', 'wrong-ca-key-pin']}

def browser_adcs_proof():
    flags = ('browserIssuerCreation', 'nativeSafePreflight', 'noEnrollmentBeforeConfirmation', 'browserCaConfirmation', 'postConfirmationNativePreflight', 'browserProfileCreation', 'browserProfileAttachment', 'actualDueSelection', 'defaultSweepCreatedEnrollment', 'automaticSourceAndRealMode', 'claimBoundEvidence', 'installedEnrollment', 'freshLeafAndSpki', 'nativeCaRequestMatched', 'nonexportableMachineCng', 'nativeIisSniMatched', 'independentTrustedTls', 'browserInstalledStateVisible', 'noSyntheticResponses', 'noDateOrJournalOverrides', 'ownedEnrollmentRegistered', 'browserAndTrustCleaned', 'otherProfilePoliciesRestored')

    def uuid(value):
        return f'{value * 8}-{value * 4}-4{value * 3}-8{value * 3}-{value * 12}'
    return {**dict.fromkeys(flags, True), 'scope': 'browser-issuer-profile-default-scheduler-native-adcs', 'lifecycle': 'renew-existing-inventory-not-first-issue-or-manual-job', 'scheduler': 'production-default-sweep-not-background-worker-loop', 'browserEngine': 'chromium', 'browserMutationCount': 6, 'successfulEnrollments': 1, 'fingerprints': ['a' * 64, 'b' * 64], 'spkiFingerprints': ['c' * 64, 'd' * 64], 'requestId': '17', 'enrollmentId': uuid('a'), 'jobId': uuid('b'), 'profileId': uuid('c'), 'issuerId': uuid('d')}

def uncertain_abandon_proof():
    result = dict.fromkeys(('ownedObserverDrained', 'ownedTransportBlock', 'observedSubmittingTermination', 'actualLeaseExpiry', 'acknowledgedPublicRecovery', 'sameCsrAndKey', 'noAutomaticResubmit', 'publicAbandonAudited', 'unacceptedKeyRemoved', 'originalOrphanPreserved', 'recoveryPolicyUnchanged'), True)
    return {**result, 'leaseRemainingAtFaultMs': 60000, 'recoveryWaitBudgetMs': 150000, 'actualLeaseWaitMs': 61000, 'scope': 'native-zero-request-uncertain-abandon', 'resolvedIssuingCaAddress': '10.64.0.4', 'caRequestsAtFault': 0, 'caRequestsAfterRecovery': 0, 'caRequestsAfterAbandon': 0}

def browser_cancel_proof():
    c = adcs_capacity_proof()
    return {'scope': 'browser-cancel-requested-approval-gated-renewal-preserves-issued-native-custody', 'enrollmentId': '55555555-5555-5555-5555-555555555555', 'jobId': '66666666-6666-6666-6666-666666666666', 'priorEnrollmentId': c['enrollmentIds'][1], 'priorJobId': c['jobIds'][1], 'priorRequestId': c['requestIds'][1], 'fingerprint': c['fingerprints'][1], 'cancelPosts': 1, 'otherMutations': 0, 'capacityBeforeCancel': 5, 'capacityAfterCancel': 4, 'initialSixConcurrencyQualified': False, 'caSubmissionCancellationQualified': False, **dict.fromkeys(['additionalSequentialPublicRenewal', 'requestedPendingApprovalObserved', 'newJobNeverClaimed', 'exactPublicCancelAcknowledged', 'browserAndTrustDrained', 'onlyNewEnrollmentAndJobCancelled', 'oldInstalledEnrollmentUnchanged', 'oldProtectedCngAndIisUnchanged', 'oldTrustedTlsUnchanged', 'newContainerAndJournalAbsent', 'subjectCaRequestsUnchanged', 'exactHumanCancelAudit', 'capacitySlotReleased', 'cleanupOwnershipRegistered'], True)}

def pending_ca_key_change_proof():
    return json.loads('{"scope": "real-pending-request-refused-across-ca-new-key-and-fresh-reconfirmation", "schedulerClock": "supported-scheduler-now-input", "backgroundWorkerIntervalQualified": false, "issuerId": "00000001-1111-1111-1111-111111111111", "oldEnrollmentId": "00000002-1111-1111-1111-111111111111", "oldOriginalJobId": "00000003-1111-1111-1111-111111111111", "oldContinuationJobId": "00000004-1111-1111-1111-111111111111", "freshEnrollmentId": "00000005-1111-1111-1111-111111111111", "freshOriginalJobId": "00000006-1111-1111-1111-111111111111", "freshContinuationJobId": "00000007-1111-1111-1111-111111111111", "preflightJobId": "00000008-1111-1111-1111-111111111111", "oldRequestId": "17", "freshRequestId": "18", "oldCaKeySha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "newCaKeySha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "oldSnapshotSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "freshSnapshotSha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "oldSpkiSha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "freshSpkiSha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "predecessorFingerprint": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "freshFingerprint": "2222222222222222222222222222222222222222222222222222222222222222", "subjectCountBefore": 2, "subjectCountAfter": 3, "actualPendingBeforeRekey": true, "pendingNativeSignatureVerified": true, "actualSingleNewKeyRekey": true, "originalSnapshotNeverRepinned": true, "signedContinuationRefusedChangedKey": true, "oldUnacceptedKeyRemoved": true, "oldRequestDeniedByOwnedOfficer": true, "oldRequestNeverResubmitted": true, "predecessorCustodyAndTlsPreserved": true, "sameIssuerPublicReconfirmed": true, "freshSnapshotAndCngKey": true, "freshActualPendingApproved": true, "freshSignedNativeInstallation": true, "claimBoundNativeEvidence": true, "nativeIisAndTrustedTls": true, "registeredCleanupResolved": true}')

def pending_ca_proof():
    return {'scope': 'real-pending-enrollment-across-same-key-ca-certificate-renewal', 'schedulerClock': 'supported-scheduler-now-input', 'backgroundWorkerIntervalQualified': False, 'enrollmentId': '11111111-1111-1111-1111-111111111111', 'originalJobId': '22222222-2222-2222-2222-222222222222', 'continuationJobId': '33333333-3333-3333-3333-333333333333', 'requestId': '17', 'caKeySha256': 'a' * 64, 'caCertificateCountBefore': 1, 'caCertificateCountAfter': 2, 'csrSha256': 'b' * 64, 'spkiSha256': 'c' * 64, 'leafFingerprint': 'd' * 64, 'predecessorFingerprint': adcs_capacity_proof()['fingerprints'][1], **dict.fromkeys(('matchingActualInstalledPredecessor', 'ownedMyCleanupRegistered', 'actualPendingBeforeCaRenewal', 'pendingCngSignatureVerified', 'actualCaSameKeyRenewal', 'confirmedIssuerUnchanged', 'noReconfirmation', 'pendingCsrKeyRequestPreserved', 'predecessorPreservedAcrossCaRenewal', 'actualSameRequestApproved', 'actualSignedContinuationInstalled', 'claimBoundNativeEvidence', 'nativeSamePendingKeyAndLeaf', 'trustedTlsCutover', 'predecessorKeyAndReceiptPreserved', 'noCaResubmission'), True)}

def same_certificate_late_approval_proof():
    return {**cancelled_late_approval_proof(), 'scope': 'real-cancelled-request-late-issued-after-same-certificate-renewal', 'certificateId': '33333333-3333-4333-8333-333333333333', 'sameCertificateRenewalQualified': True, 'backgroundTimerQualified': False}

def cancelled_late_approval_proof():
    return {'scope': 'real-cancelled-request-late-issued-after-distinct-same-endpoint-successor', 'cancelledEnrollmentId': '11111111-1111-1111-1111-111111111111', 'successorEnrollmentId': '22222222-2222-2222-2222-222222222222', 'requestIds': ['17', '18'], 'fingerprints': ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'], 'sameCertificateRenewalQualified': False, 'publicCancellationAuditVerified': True, 'terminalCleanupAlreadyCompleted': True, 'distinctActualSuccessorInstalled': True, 'nativePendingCsrRequesterTemplateOwned': True, 'actualOfficerLateApproval': True, 'actualCaLeafMatchesOriginalCsr': True, 'defaultClockDoesNotRevive': True, 'overdueSchedulerDoesNotRevive': True, 'publicInstallationRetryRefused': True, 'originalJournalAndJobsUnchanged': True, 'cancelledKeyRemainsAbsent': True, 'lateLeafNeverAccepted': True, 'successorClaimEvidenceUnchanged': True, 'successorNativeCustodyBindingTlsUnchanged': True, 'noCaResubmission': True, 'ownedUnusedLateLeafRevoked': True}

def issued_revocation_proof():
    return {'scope': 'actual-ca-issued-owned-revoked-leaf-refused-before-accept', 'errorCode': 'ADCS_CERTIFICATE_INVALID', 'schedulerDefaultClockQualified': False, 'requestId': '17', 'enrollmentId': '11111111-1111-1111-1111-111111111111', 'continuationJobId': '22222222-2222-2222-2222-222222222222', **dict.fromkeys(['matchingNativePositiveControl', 'actualOwnedPendingRequest', 'actualCaSignatureAndOnlineRevoked', 'sameRequestCsrSpkiAndTemplate', 'actualOnlineChainValidBeforeRevocation', 'nativePendingIdentityBeforeManualDispatch', 'realRevokedLeafReachedProductionValidation', 'productionSignedContinuationRefused', 'rejectedBeforeCertificateAccept', 'predecessorBindingTlsAndCngUnchanged', 'unacceptedKeyRemovedAndJournalPreserved', 'noCaResubmission', 'ownedCaRequestRevoked', 'cleanupOwnershipRegistered'], True)}

def issued_san_proof():
    return {'scope': 'actual-ca-issued-owned-wrong-san-refused-before-accept', 'errorCode': 'ADCS_CERTIFICATE_INVALID', 'requestId': '17', 'enrollmentId': '11111111-1111-1111-1111-111111111111', 'continuationJobId': '22222222-2222-2222-2222-222222222222', **dict.fromkeys(['matchingNativePositiveControl', 'actualOwnedPendingCaMutation', 'actualCaSignature', 'sameRequestCsrSpkiAndTemplate', 'exactUnauthorizedDnsSan', 'productionSignedContinuationRefused', 'rejectedBeforeCertificateAccept', 'predecessorBindingTlsAndCngUnchanged', 'unacceptedKeyRemovedAndJournalPreserved', 'noCaResubmission', 'ownedCaRequestRevoked', 'cleanupOwnershipRegistered'], True)}

def browser_reconcile_proof():
    native = operator_ambiguity_proof()
    return {'scope': 'browser-requestid-reconcile-real-operator-created-same-csr-ambiguity', 'fixtureOrigin': 'operator-created-two-real-system-submissions-of-the-same-public-csr', **dict.fromkeys(['actualUncertainRequestIdForm', 'invalidRequestIdDidNotMutate', 'exactOwnedRequestIdPosted', 'exactPublicReconcileAcknowledged', 'browserAndTrustDrained', 'nativeSelectedRequestInstalled', 'nativeSameProtectedMachineKey', 'nativeClaimBoundVerification', 'nativeExactReconcileAudit', 'unusedOwnedRequestRevoked', 'unusedLeafNeverAccepted', 'originalOrphanPreserved'], True), 'enrollmentId': native['enrollmentId'], 'selectedRequestId': native['selectedRequestId'], 'unusedRequestId': native['unusedRequestId'], 'selectedFingerprint': native['fingerprints'][0], 'continuationJobId': native['jobIds'][2], 'reconcilePosts': 1, 'invalidRequestPosts': 0}

def http_crl_proof():
    return json.loads('{"scope":"native-hierarchy-http-intermediate-crl-unavailable-and-recovered","transport":"http","revocationTarget":"intermediate","nativeHelperSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","publicCrlSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","leafFingerprint":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","nativeVerdicts":["valid","revocation_unknown","valid"],"installedAgentQualified":false,"httpOnlyLeafQualified":false,"ocspQualified":false,"actualIntermediateHttpOnlyCdp":true,"actualPublicHttpCrlFetched":true,"freshNativeChainValidBefore":true,"exactProgramScopedHttpBlock":true,"httpAvailableOutsideHelper":true,"issuingCaLdapAvailable":true,"freshNativeRevocationUnknown":true,"exactFirewallRuleRemoved":true,"freshNativeChainValidAfter":true,"originalChainCachePolicyRestored":true,"sameNonexportableCngCustody":true,"sameNativeBindingAndTrustedTls":true,"ownedGuardReleased":true}')

def http_leaf_crl_evidence():
    return {'scope': collector.http_leaf_crl_proof.SCOPE, 'enrollmentId': '10000000-0000-4000-8000-000000000001', 'jobId': '10000000-0000-4000-8000-000000000002', 'requestId': 42, 'restoredEnrollmentId': '10000000-0000-4000-8000-000000000003', 'restoredJobId': '10000000-0000-4000-8000-000000000004', 'restoredRequestId': 43, 'restoredLeafFingerprint': '6' * 64, 'leafFingerprint': '1' * 64, 'publicCrlSha256': '2' * 64, 'nativeHelperSha256': '3' * 64, 'originalPublicationSha256': '4' * 64, 'appliedPublicationSha256': '5' * 64, 'caRequestCounts': [10, 11, 12], 'nativeVerdicts': ['valid', 'revocation_unknown', 'valid'], 'endpointStatusCodes': [200, 503, 200], 'ocspQualified': False, 'caOutageQualified': False, 'signedCmcRenewalQualified': False, 'deferredRecovery': {'originalJobId': '10000000-0000-4000-8000-000000000005', 'originalClaimId': '10000000-0000-4000-8000-000000000006', 'continuationJobId': '10000000-0000-4000-8000-000000000002', 'continuationClaimId': '10000000-0000-4000-8000-000000000007', 'requestId': 42}, **{key: True for key in collector.http_leaf_crl_proof.FLAGS}}

def live_enroll_acl_proof():
    return json.loads('{"scope":"real-same-template-machine-enroll-denial-exact-dacl-restore-and-issuance","templateGuid":"11111111-2222-4333-8444-555555555555","templateOid":"1.3.6.1.4.1.311.21.8.100","machineSid":"S-1-5-21-1-2-3-1000","originalDaclSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","appliedDaclSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","restoredDaclSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","deniedCaRequestDelta":1,"caRequestCounts":[10,11,12],"enrollmentIds":["11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222"],"jobIds":["33333333-3333-4333-8333-333333333333","44444444-4444-4444-8444-444444444444"],"fingerprints":["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],"caHresult":"0x80094012","preflightRefusalQualified":false,"signedCmcRenewalQualified":false,"sameConfirmedIssuerTemplateAndAlgorithm":true,"actualMachineSidDenied":true,"nativeTemplateDeniedHresult":true,"deniedKeyAbsentAndJournalRetained":true,"deniedAttemptPreservedNativeCustodyAndTls":true,"exactDaclRestored":true,"actualCaCacheRestartAndPing":true,"freshPublicEnrollmentInstalled":true,"independentIssuedCaRequest":true,"newNonexportableMachineKey":true,"nativeMyAndIisSniCutover":true,"independentTrustedTls":true,"claimBoundEvidence":true,"ownedCleanupRegisteredBeforeObservation":true}')

def required_template_attribute_proof():
    return json.loads('{"scope": "actual-ldap-required-template-attribute-refusal-and-exact-native-restoration", "predecessorFingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "templateOid": "1.3.6.1.4.1.311.21.8.2", "cases": [{"caseId": "minimum-key-zero", "preflightVerdict": "unreadable", "reason": "template_unreadable", "observedField": "minimalKeySize", "observedValue": 0, "enrollmentId": "00000001-1111-1111-1111-111111111111", "jobId": "00000002-1111-1111-1111-111111111111", "knownSafeNativeControlBefore": true, "restorationRegisteredBeforeMutation": true, "actualLdapMutationObserved": true, "actualNativePreflightUnreadable": true, "publicConfirmationRefused": true, "signedInstalledJobRefused": true, "noCaRequestOrCngAllocation": true, "installedPredecessorPreserved": true, "exactOriginalAttributesRestored": true, "freshNativeSafeControlAfter": true, "originalConfigCredentialPreserved": true}, {"caseId": "subject-name-flag-absent", "preflightVerdict": "unreadable", "reason": "template_unreadable", "observedField": "enrolleeSuppliesSubject", "observedValue": null, "enrollmentId": "00000003-1111-1111-1111-111111111111", "jobId": "00000004-1111-1111-1111-111111111111", "knownSafeNativeControlBefore": true, "restorationRegisteredBeforeMutation": true, "actualLdapMutationObserved": true, "actualNativePreflightUnreadable": true, "publicConfirmationRefused": true, "signedInstalledJobRefused": true, "noCaRequestOrCngAllocation": true, "installedPredecessorPreserved": true, "exactOriginalAttributesRestored": true, "freshNativeSafeControlAfter": true, "originalConfigCredentialPreserved": true}]}')

def public_foreign_spki_proof():
    return json.loads('{"scope": "public-uncertain-request-rejects-owned-same-san-foreign-spki-before-positive-recovery", "enrollmentId": "11111111-1111-1111-1111-111111111111", "failedJobId": "55555555-5555-5555-5555-555555555555", "foreignRequestId": "103", "selectedRequestId": "101", "foreignFingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "selectedFingerprint": "1111111111111111111111111111111111111111111111111111111111111111", "foreignSpkiSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "originalSpkiSha256": "3333333333333333333333333333333333333333333333333333333333333333", "foreignCsrSha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "reconcileSearchFrom": 100, "foreignSubjectRequestCount": 1, "originalSubjectRequestCount": 2, "ownedRequestRegisteredBeforeSubmit": true, "softwarePrivateKeyRemovedBeforeSubmit": true, "sameActualCaAndSystemRequester": true, "sameAuthorizedSanAndTemplate": true, "differentOwnedCnAndSpki": true, "actualPublicProposalAccepted": true, "actualSignedSpkiMismatchRefusal": true, "originalUncertainJournalAndWatermarkPreserved": true, "originalCngPossessionPreserved": true, "noForeignCertificateAccepted": true, "servingSiblingTrustedTlsPreserved": true, "noAdditionalCaSubmissionOnRefusal": true, "exactUnusedForeignRequestRevoked": true, "matchingCandidatePositiveRecovery": true, "cleanupOwnershipResolved": true}')

def operator_ambiguity_proof():
    flags = ('ownedObserverDrained', 'ownedTransportBlock', 'observedSubmittingTermination', 'actualLeaseExpiry', 'acknowledgedPublicRecovery', 'sameCsrAndKey', 'noAutomaticResubmit', 'originalOrphanPreserved', 'recoveryPolicyUnchanged', 'operatorCreatedSameCsrAmbiguity', 'nativeCaOwnershipVerified', 'automaticAttachmentRefused', 'unacceptedKeyPreserved', 'unrelatedTrustedTlsPreserved', 'publicExplicitReconcileAudited', 'exactSelectedRequestInstalled', 'claimBoundVerification', 'sameProtectedMachineKeyInstalled', 'unusedOwnedRequestRevoked', 'unusedLeafNeverAccepted')
    enrollment = '11111111-1111-1111-1111-111111111111'
    return {**dict.fromkeys(flags, True), 'scope': 'native-zero-request-uncertainty-with-operator-created-same-csr-ambiguity', 'fixtureOrigin': 'operator-created-two-real-system-submissions-of-the-same-public-csr', 'resolvedIssuingCaAddress': '10.64.0.4', 'leaseRemainingAtFaultMs': 60000, 'recoveryWaitBudgetMs': 150000, 'actualLeaseWaitMs': 120000, 'caRequestsAtFault': 0, 'caRequestsAfterOperatorSubmissions': 2, 'caRequestsAfterAmbiguousRecovery': 2, 'caRequestsAfterExplicitRecovery': 2, 'requestIds': ['101', '102'], 'fingerprints': ['1' * 64, '2' * 64], 'serialNumbers': ['aa', 'bb'], 'csrSpkiSha256': '3' * 64, 'csrSha256': '4' * 64, 'selectedRequestId': '101', 'unusedRequestId': '102', 'enrollmentId': enrollment, 'containerName': 'tokentimer-enr-' + enrollment, 'jobIds': [value * 8 + '-' + value * 4 + '-' + value * 4 + '-' + value * 4 + '-' + value * 12 for value in ('2', '3', '4')], 'reconcileSearchFrom': 100, 'scanWindowSize': 16}

def background_adcs_proof():
    return {**two_adcs_renewals_proof(), 'scope': 'two-real-default-interval-worker-native-adcs-renewals', 'schedulerInvocation': 'actual-production-runner-default-interval', 'workerIntervalQualified': True, 'workerLifecycle': {'failed': False, 'starts': 1, 'ticks': 2, 'finishes': 2, 'summaries': 2, 'created': 2, 'stops': 1, 'forwarded': True, 'firstTickElapsedMs': 60010, 'exitCode': 0, 'nativeDrained': True, 'bridgeReady': True}}

def two_adcs_renewals_proof():
    flags = ('defaultSqlNowSelection', 'automaticSourceAndRealMode', 'distinctExpiryGenerations', 'independentCaRequests', 'freshLeafSerialAndSpki', 'protectedUniqueMachineKeys', 'nativeIisAndSniCutovers', 'independentTrustedTls', 'claimBoundVerificationEvidence', 'unchangedStoredProfile', 'sameManagementPeriod', 'predecessorCustodyPreserved', 'actualInventoryMatchesLatest', 'ownedEnrollmentCleanupRegistered', 'noDateOrJournalOverrides')
    return {**dict.fromkeys(flags, True), 'scope': 'two-native-adcs-default-scheduler-cycles-not-expiry-cleanup', 'renewalProtocol': 'fresh-enrollment-with-new-key-and-csr', 'schedulerInvocation': 'qualification-invoked-production-default-sweep', 'workerIntervalQualified': False, 'successfulAutomationCycles': 2, 'expiryCleanupQualified': False, 'requestIds': ['17', '18', '19'], 'caRequestCounts': [7, 8, 9], 'fingerprints': [value * 64 for value in ('a', 'b', 'c')], 'spkiFingerprints': [value * 64 for value in ('d', 'e', 'f')], 'serialNumbers': ['a1', 'b2', 'c3'], 'containerNames': [f'tokentimer-enr-{value * 8}-{value * 4}-4{value * 3}-8{value * 3}-{value * 12}' for value in ('a', 'b', 'c')], 'expiryEpochs': [1792497600000, 1792497601000, 1792497602000]}

class CollectorTests(unittest.TestCase):

    def test_same_certificate_late_approval_projection_is_complete(self):
        proof = same_certificate_late_approval_proof()
        self.assertEqual(collector.same_certificate_late_approval_fields({**proof, 'rawCsr': 'private'}), proof)
        for key in proof:
            bad = dict(proof)
            del bad[key]
            with self.assertRaises(ValueError):
                collector.same_certificate_late_approval_fields(bad)
        for key, value in proof.items():
            if isinstance(value, bool):
                with self.assertRaises(ValueError):
                    collector.same_certificate_late_approval_fields({**proof, key: not value})

    def test_http_intermediate_crl_requires_native_facts_without_scope_promotion(self):
        proof = http_crl_proof()
        self.assertEqual(collector.http_crl_proof.fields({**proof, 'privateCachePolicy': 'sentinel'}), proof)
        for key, expected in proof.items():
            missing = dict(proof)
            del missing[key]
            with self.assertRaises(ValueError):
                collector.http_crl_proof.fields(missing)
            if type(expected) is bool:
                for bad in (not expected, 1, None):
                    with self.assertRaises(ValueError):
                        collector.http_crl_proof.fields({**proof, key: bad})
        with self.assertRaises(ValueError):
            collector.http_crl_proof.fields({**proof, 'nativeVerdicts': ['valid', 'invalid', 'valid']})

    def test_live_machine_enroll_acl_projection_requires_all_facts(self):
        proof = live_enroll_acl_proof()
        self.assertEqual(collector.live_enroll_acl_proof.fields({**proof, 'privateDacl': 'sentinel'}), proof)
        for key, expected in proof.items():
            missing = dict(proof)
            del missing[key]
            with self.assertRaises(ValueError):
                collector.live_enroll_acl_proof.fields(missing)
            if type(expected) is bool:
                for bad in (not expected, 1, None, 'true'):
                    with self.assertRaises(ValueError):
                        collector.live_enroll_acl_proof.fields({**proof, key: bad})
        for patch in ({'deniedCaRequestDelta': 2}, {'caRequestCounts': [10, 11, 13]}, {'restoredDaclSha256': 'e' * 64}, {'caHresult': '0x80070005'}, {'enrollmentIds': [proof['enrollmentIds'][0]] * 2}):
            with self.assertRaises(ValueError):
                collector.live_enroll_acl_proof.fields({**proof, **patch})



    def test_collection_budgets_follow_committed_growth_with_absolute_caps(self):
        self.assertEqual(collector.collection_limits(1), {'runs': 100, 'archives': 200, 'reports': 200})
        for slots in (201, 256, 512):
            limits = collector.collection_limits(slots)
            for budget in limits.values():
                self.assertGreaterEqual(budget, slots * 2)
                self.assertLessEqual(budget, collector.MAX_COLLECTION_ITEMS)
            collector.validate_run_ids(list(range(1, slots + 1)), limits)
        for invalid in (0, -1, 513, 1024, True, 201.0, '201', None):
            with self.assertRaises(ValueError):
                collector.collection_limits(invalid)
        matrix = json.loads((collector.ROOT / 'docs/certops/qualification-suites.json').read_text())
        self.assertGreaterEqual(collector.collection_limits(len(matrix['slots']))['reports'], len(matrix['slots']))

    def test_growth_preserves_run_identity_and_independent_download_bounds(self):
        limits = collector.collection_limits(201)
        for invalid in ([], [1, 1], [True], [-1], [0], [1.0], ['1'], list(range(1, limits['runs'] + 2))):
            with self.assertRaises(ValueError):
                collector.validate_run_ids(invalid, limits)
        self.assertEqual(collector.MAX_ARCHIVE, 20 * 1024 * 1024)
        self.assertEqual(collector.MAX_REPORT, 2 * 1024 * 1024)
        self.assertEqual(collector.MAX_TOTAL_DOWNLOAD, 512 * 1024 * 1024)
        self.assertEqual(collector.MAX_ARTIFACTS_PER_RUN, 100)

    def test_generic_top_fields_cannot_carry_nested_private_metadata(self):
        keys = ('status', 'strict', 'schemaVersion', 'startedAt', 'finishedAt', 'evidenceLevel', 'artifactQualification', 'qualificationStatus', 'experimental', 'candidateSha')
        for key in keys:
            with self.assertRaises(ValueError):
                collector.sanitized_report({'suite': 'adcs-api-release-gates', key: {'secret': 'sentinel'}}, {'adcs-api-release-gates'}, set())
        for shape in ({'suite': 'adcs-api-release-gates'}, {'scope': 'fixture-database'}, [{'scope': 'fixture-stack', 'name': 'unknown', 'type': 'test:fail'}]):
            report = shape[0] if isinstance(shape, list) else shape
            report.update({'candidateSha': 'sentinel', 'artifactQualification': 'sentinel', 'experimental': False})
            output = collector.sanitized_report(shape, {'adcs-api-release-gates'}, {'fixture-stack'}, {'fixture-database'})
            self.assertNotIn('sentinel', json.dumps(output))
        output = collector.sanitized_report({'suite': 'adcs-api-release-gates', 'status': 'failed', 'strict': False, 'schemaVersion': 1, 'candidateSha': None, 'startedAt': '2026-02-30T12:00:00Z'}, {'adcs-api-release-gates'}, set())
        self.assertEqual(output['status'], 'failed')
        self.assertIs(output['strict'], False)
        self.assertIsNone(output['candidateSha'])
        self.assertEqual(output['startedAt'], 'invalid')

    def test_event_names_project_committed_cases_and_keep_unrecognized_failures(self):
        scope = 'distribution-postgres-postgres'
        manifest = next(slot for slot in json.loads((collector.ROOT / 'docs/certops/qualification-suites.json').read_text())['slots'] if slot['suite'] == scope)
        events = [{'scope': scope, 'name': manifest['requiredTests'][0], 'type': 'test:pass'}, {'scope': scope, 'name': 'password=sentinel', 'type': 'test:fail'}, {'scope': scope, 'name': {'secret': 'sentinel'}, 'type': 'test:pass'}]
        result = collector.sanitized_report(events, set(), {scope})
        self.assertEqual(result[0]['name'], events[0]['name'])
        self.assertEqual(result[1]['type'], 'test:fail')
        self.assertEqual(result[2]['type'], 'invalid')
        self.assertEqual(len(result), 3)
        self.assertNotIn('sentinel', json.dumps(result))
        parent = collector.sanitized_report([{'scope': scope, 'name': manifest['requiredTests'][0], 'type': 'test:pass'}], set(), {scope})
        self.assertEqual(parent[0]['type'], 'test:pass')
        group = json.loads((collector.ROOT / 'tests/integration/certops-qualification-groups.json').read_text())['adcs']
        case = group['requiredTests'][0]
        report = {'scope': 'adcs-database-integration', 'tests': [{**case, 'status': 'pass'}, {'file': 'private/sentinel', 'name': 'sentinel', 'status': 'fail'}, {'file': case['file'], 'name': 'sentinel', 'status': 'pass'}]}
        result = collector.sanitized_report(report, set(), set(), {report['scope']})
        self.assertEqual(result['tests'][0], {**case, 'status': 'pass'})
        self.assertEqual([row['status'] for row in result['tests']], ['pass', 'fail', 'invalid'])
        self.assertNotIn('sentinel', json.dumps(result))

    def test_common_metadata_is_projected_for_every_report_kind(self):
        source = {'file': 'tests/e2e/certops-adcs-gates-api-e2e.test.js', 'sha256': 'a' * 64, 'rawSecret': 'sentinel'}
        environment = {'osFamily': 'linux', 'measurement': 'native', 'credential': {'password': 'sentinel'}}
        variants = [{'suite': 'adcs-api-release-gates', 'fixtureSource': source, 'qualificationEnvironment': environment}, [{'scope': 'fixture-scope', 'fixtureSource': source, 'qualificationEnvironment': environment}], {'scope': 'fixture-database', 'fixtureSources': [source], 'qualificationEnvironment': environment}]
        for value in variants:
            result = collector.sanitized_report(value, {'adcs-api-release-gates'}, {'fixture-scope'}, {'fixture-database'})
            self.assertNotIn('sentinel', json.dumps(result))
            item = result[0] if isinstance(result, list) else result
            self.assertEqual(item['qualificationEnvironment'], {'osFamily': 'linux', 'measurement': 'native'})
        for invalid in (['linux'], {'osFamily': ['linux']}, {'keySize': True}, {'build': 'password=sentinel'}):
            with self.assertRaises(ValueError):
                collector.sanitized_report({'suite': 'adcs-api-release-gates', 'qualificationEnvironment': invalid}, {'adcs-api-release-gates'}, set())
        with self.assertRaises(ValueError):
            collector.sanitized_report({'suite': 'adcs-api-release-gates', 'fixtureSource': {**source, 'sha256': []}}, {'adcs-api-release-gates'}, set())

    def test_elapsed_pending_preserves_only_bounded_native_facts(self):
        facts = {'pendingTimeoutSeconds': 3600, 'pollIntervalSeconds': 60, 'monotonicWaitSeconds': 3601, 'databaseElapsedSeconds': 3602, 'pendingSince': '2026-10-14T12:00:00.000Z', 'requestId': '17', 'snapshotSha256': 'a' * 64, 'clocks': 'actual-host-and-database', 'schedulerClock': 'default-real-now', 'databaseDatesRewritten': False, 'journalRewritten': False, 'qualificationScope': 'configured-one-hour-not-default-fourteen-days', 'private': 'sentinel'}
        value = {'suite': 'enterprise-adcs-elapsed-pending-real', 'nativePendingElapsed': facts}
        result = collector.sanitized_report(value, {value['suite']}, set())
        self.assertEqual(result['nativePendingElapsed']['monotonicWaitSeconds'], 3601)
        self.assertNotIn('sentinel', json.dumps(result))
        value['primaryNativePreflightDispatchCount'] = 18
        self.assertEqual(collector.sanitized_report(value, {value['suite']}, set())['primaryNativePreflightDispatchCount'], 18)
        for count in (19, 20, True, '18'):
            invalid = json.loads(json.dumps(value))
            invalid['primaryNativePreflightDispatchCount'] = count
            invalid['nativeBrowserAdcs'] = browser_adcs_proof()
            with self.assertRaises(ValueError):
                collector.sanitized_report(invalid, {value['suite']}, set())
        facts['journalRewritten'] = True
        with self.assertRaises(ValueError):
            collector.sanitized_report(value, {value['suite']}, set())
        facts['journalRewritten'] = False
        facts['monotonicWaitSeconds'] = '3601'
        with self.assertRaises(ValueError):
            collector.sanitized_report(value, {value['suite']}, set())

    def test_local_policy_proofs_reject_destructive_or_incomplete_recovery(self):
        for factory, verify in ((local_rule_tightening_proof, collector.local_rule_tightening_fields), (pending_key_survivor_proof, collector.pending_key_survivor_fields)):
            self.assertEqual(verify(factory()), factory())
            for key in factory():
                missing = factory()
                del missing[key]
                with self.subTest(missing=key), self.assertRaises(ValueError):
                    verify(missing)
            invalid = factory()
            invalid['caRequestCounts'][-1] += 1
            with self.assertRaises(ValueError):
                verify(invalid)
            invalid = factory()
            invalid['firstError'] = 'Local policy refusal could not free the protected enrollment key; retry required'
            with self.assertRaises(ValueError):
                verify(invalid)
            for key,value in factory().items():
                if value is True:
                    for wrong in (False, 1, None, 'true'):
                        invalid = factory()
                        invalid[key] = wrong
                        with self.subTest(flag=key, value=wrong), self.assertRaises(ValueError):
                            verify(invalid)

    def test_uncommitted_execution_names_and_values_are_never_artifacts(self):
        sentinel = 'private-sentinel'
        value = {'suite': 'adcs-api-release-gates', 'requiredScenarios': [sentinel], 'missingScenarios': [sentinel], 'requiredCapabilities': [sentinel], 'capabilities': {sentinel: {'available': {'private': sentinel}}}, 'scenarios': [{'id': sentinel, 'status': sentinel, 'evidenceLevel': sentinel, 'startedAt': sentinel}]}
        result = collector.extract_reports(self.archive('failed.json', value), {'adcs-api-release-gates'}, set())
        self.assertNotIn(sentinel, json.dumps(result))
        self.assertEqual(result[0][1]['scenarios'][0]['id'], '[unrecognized]')

    def test_native_cohort_budgets_are_bounded_without_private_fields(self):
        cohort = {'workspaceId': 'a' * 36, 'agentId': 'b' * 36, 'dispatchCount': 18, 'dispatchLimit': 18, 'nativeIdentity': 'LocalSystem', 'runtime': 'candidate-cli', 'privateState': 'sentinel'}
        value = {'suite': 'enterprise-adcs-real', 'nativeLocalRulePairs': local_pairs_proof(), 'nativePendingKeySurvivor': pending_key_survivor_proof(), 'nativeLocalRuleTightening': local_rule_tightening_proof(), 'nativeForeignSpkiCandidate': foreign_spki_proof(), 'primaryNativePreflightDispatchCount': 18, 'nativePreflightCohorts': [cohort], 'nativeTemplateMutations': [], 'nativeValidationExpiry': {'configuredTimeoutSeconds': 300, 'defaultTimeoutSeconds': 86400, 'storedWindowSeconds': 299, 'monotonicObservedWaitSeconds': 301, 'actualDeadline': '2026-10-14T12:00:00.000Z', 'requestId': '17', 'snapshotSha256': 'a' * 64, 'nativeAndCaClocks': 'actual', 'qualificationScope': 'configured-five-minute-window-not-default-24-hour-elapsed'}}
        value['nativeIssuedCancellation'] = {'requestId': '17', 'snapshotSha256': 'a' * 64, 'pollIntervalSeconds': 900, 'schedulerClock': 'default-real-now', 'databaseDatesRewritten': False, 'journalRewritten': False, 'private': 'sentinel'}
        value['nativeAdcsCapacity'] = {**adcs_capacity_proof(), 'privateManagerCredential': 'sentinel'}
        value['nativeBrowserJobApproval'] = {**browser_job_approval_proof(), 'privateTrace': 'sentinel'}
        value['nativeBrowserCancel'] = {**browser_cancel_proof(), 'privateTrace': 'sentinel'}
        value['nativePendingCaRenewal'] = {**pending_ca_proof(), 'privateTrace': 'sentinel'}
        value['nativePendingCaKeyChange'] = {**pending_ca_key_change_proof(), 'privateTrace': 'sentinel'}
        value['nativeIssuedRevocation'] = {**issued_revocation_proof(), 'privateTrace': 'sentinel'}
        value['nativeSameCertificateLateApproval'] = same_certificate_late_approval_proof()
        value['nativeCancelledLateApproval'] = {**cancelled_late_approval_proof(), 'rawPublicCsr': 'sentinel'}
        value['nativeIssuedSanBoundary'] = {**issued_san_proof(), 'privateTrace': 'sentinel'}
        value['nativeBrowserReconcile'] = {**browser_reconcile_proof(), 'privateTrace': 'sentinel'}
        value['nativeBrowserAdminBoundary'] = {**browser_admin_boundary_proof(), 'privateTrace': 'sentinel'}
        value['nativeBrowserAbandon'] = {**browser_abandon_proof(), 'privateTrace': 'sentinel'}
        value['nativeWebHostingRenewal'] = webhosting_proof()
        value['nativeWebHostingRenewal']['privateJournal'] = 'sentinel'
        value['nativeAlgorithmBoundaries'] = algorithm_proof()
        value['nativeCmcBoundaries'] = cmc_proof()
        value['nativeUncertainAbandon'] = uncertain_abandon_proof()
        value['nativeUncertainOperatorAmbiguity'] = operator_ambiguity_proof()
        value['nativeUncertainOperatorUnique'] = json.loads(subprocess.check_output(['node', '-e', "process.stdout.write(JSON.stringify(require('./scripts/fixtures/certops-adcs-unique-candidate.cjs').proof()))"], cwd=Path(__file__).resolve().parent.parent, text=True))
        value['nativePublicForeignSpki'] = {**public_foreign_spki_proof(), 'privateTrace': 'sentinel'}
        value['nativeRequiredTemplateAttributes'] = {**required_template_attribute_proof(), 'privateTrace': 'sentinel'}
        value['nativeLiveEnrollAcl'] = {**live_enroll_acl_proof(), 'privateDacl': 'sentinel'}
        value['nativeHttpOnlyLeafCrl'] = {**http_leaf_crl_evidence(), 'privatePublication': 'sentinel'}
        value['nativeOcspResponder'] = ocsp_evidence()
        value['nativeOcspRevoked'] = revoked_ocsp_evidence()
        value['nativeAdcsResultOutbox'] = {**adcs_result_outbox_evidence(), 'privateCredential': 'discard'}
        value['nativeUncertainOperatorAmbiguity']['privateKey'] = 'sentinel'
        value['nativeBrowserAdcs'] = browser_adcs_proof()
        value['nativeBrowserAdcs']['privateCookie'] = 'sentinel'
        value['browserNativePreflightDispatch'] = {'count': 2, 'jobIds': ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'], 'privateReceipt': 'sentinel'}
        value['nativeAdcsTwoRenewals'] = two_adcs_renewals_proof()
        value['nativeAdcsBackgroundRenewals'] = background_adcs_proof()
        value['nativeAdcsTwoRenewals']['privateKey'] = 'sentinel'
        value['nativeUncertainAbandon']['private'] = 'sentinel'
        result = collector.extract_reports(self.archive('adcs.json', value), {'enterprise-adcs-real'}, set())
        self.assertEqual(result[0][1]['nativeCancelledLateApproval'], cancelled_late_approval_proof())
        for key in cancelled_late_approval_proof():
            invalid = json.loads(json.dumps(value))
            del invalid['nativeCancelledLateApproval'][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
            invalid = json.loads(json.dumps(value))
            invalid['nativeCancelledLateApproval'][key] = False if isinstance(cancelled_late_approval_proof()[key], bool) else 'invalid'
            if key == 'sameCertificateRenewalQualified':
                invalid['nativeCancelledLateApproval'][key] = True
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for patch_value in ({'requestIds': ['17', '4294967296']}, {'requestIds': ['17', '17']}, {'fingerprints': ['a' * 64, 'a' * 64]}, {'cancelledEnrollmentId': cancelled_late_approval_proof()['successorEnrollmentId']}):
            invalid = json.loads(json.dumps(value))
            invalid['nativeCancelledLateApproval'].update(patch_value)
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        invalid = json.loads(json.dumps(value))
        del invalid['nativeCancelledLateApproval']
        with self.assertRaises(ValueError):
            collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        self.assertEqual(result[0][1]['nativePendingCaRenewal'], pending_ca_proof())
        self.assertEqual(result[0][1]['nativePendingCaKeyChange'], pending_ca_key_change_proof())
        for key, expected in pending_ca_key_change_proof().items():
            invalid = json.loads(json.dumps(value))
            del invalid['nativePendingCaKeyChange'][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for patch_value in ({'oldRequestId': '4294967296'}, {'freshRequestId': '17'}, {'subjectCountBefore': True}, {'subjectCountAfter': 99}, {'freshSpkiSha256': 'e' * 64}, {'freshSnapshotSha256': 'c' * 64}, {'predecessorFingerprint': 'f' * 64}, {'oldCaKeySha256': 'f' * 64}, {'registeredCleanupResolved': False}):
            invalid = json.loads(json.dumps(value))
            invalid['nativePendingCaKeyChange'].update(patch_value)
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for key, expected in pending_ca_proof().items():
            invalid = json.loads(json.dumps(value))
            del invalid['nativePendingCaRenewal'][key]
            with self.subTest(pending_ca_missing=key), self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
            invalid = json.loads(json.dumps(value))
            invalid['nativePendingCaRenewal'][key] = not expected if isinstance(expected, bool) else 'invalid'
            with self.subTest(pending_ca_invalid=key), self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for patch in ({'requestId': '4294967296'}, {'caCertificateCountAfter': 17}, {'caCertificateCountAfter': 1}, {'caCertificateCountBefore': True}, {'continuationJobId': pending_ca_proof()['originalJobId']}, {'leafFingerprint': pending_ca_proof()['predecessorFingerprint']}, {'schedulerClock': 'default-real-now'}, {'backgroundWorkerIntervalQualified': True}, {'predecessorFingerprint': 'f' * 64}):
            invalid = json.loads(json.dumps(value))
            invalid['nativePendingCaRenewal'].update(patch)
            with self.subTest(pending_ca_patch=patch), self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        invalid = json.loads(json.dumps(value))
        del invalid['nativePendingCaRenewal']
        with self.assertRaises(ValueError):
            collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        self.assertEqual(result[0][1]['nativePreflightCohorts'][0]['dispatchCount'], 18)
        self.assertNotIn('sentinel', json.dumps(result))
        self.assertEqual(result[0][1]['nativeUncertainOperatorAmbiguity'], operator_ambiguity_proof())
        self.assertEqual(result[0][1]['nativePublicForeignSpki'], public_foreign_spki_proof())
        self.assertEqual(result[0][1]['nativeRequiredTemplateAttributes'], required_template_attribute_proof())
        for key in required_template_attribute_proof():
            invalid = json.loads(json.dumps(value))
            del invalid['nativeRequiredTemplateAttributes'][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for index, patch_value in ((0, {'observedValue': False}), (1, {'observedValue': 0}), (0, {'preflightVerdict': 'unsafe'}), (1, {'exactOriginalAttributesRestored': False}), (0, {'caseId': 'subject-name-flag-absent'})):
            invalid = json.loads(json.dumps(value))
            invalid['nativeRequiredTemplateAttributes']['cases'][index].update(patch_value)
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for key in public_foreign_spki_proof():
            invalid = json.loads(json.dumps(value))
            del invalid['nativePublicForeignSpki'][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for patch_value in ({'foreignRequestId': '101'}, {'foreignSubjectRequestCount': True}, {'originalSubjectRequestCount': 3}, {'actualSignedSpkiMismatchRefusal': False}, {'selectedFingerprint': 'f' * 64}, {'failedJobId': operator_ambiguity_proof()['jobIds'][1]}, {'originalSpkiSha256': 'f' * 64}, {'reconcileSearchFrom': 99}):
            invalid = json.loads(json.dumps(value))
            invalid['nativePublicForeignSpki'].update(patch_value)
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for key, expected in operator_ambiguity_proof().items():
            invalid = json.loads(json.dumps(value))
            del invalid['nativeUncertainOperatorAmbiguity'][key]
            with self.subTest(ambiguity_missing=key), self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
            bad_values = (False, None, 1, 'true') if type(expected) is bool else (None, False, 'invalid')
            for bad_value in bad_values:
                invalid = json.loads(json.dumps(value))
                invalid['nativeUncertainOperatorAmbiguity'][key] = bad_value
                with self.subTest(ambiguity_field=key, value=bad_value), self.assertRaises(ValueError):
                    collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for patch in ({'fixtureOrigin': 'lost-submit-response'}, {'caRequestsAtFault': 1}, {'caRequestsAfterAmbiguousRecovery': 3}, {'actualLeaseWaitMs': 60000}, {'actualLeaseWaitMs': 152000}, {'reconcileSearchFrom': 102}, {'scanWindowSize': 64}, {'selectedRequestId': '103'}, {'unusedRequestId': '101'}, {'requestIds': ['101', '101']}, {'jobIds': ['22222222-2222-2222-2222-222222222222'] * 3}):
            invalid = json.loads(json.dumps(value))
            invalid['nativeUncertainOperatorAmbiguity'].update(patch)
            with self.subTest(ambiguity_patch=patch), self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        self.assertEqual(result[0][1]['nativeHttpOnlyLeafCrl'], http_leaf_crl_evidence())
        self.assertEqual(result[0][1]['nativeOcspResponder'], ocsp_evidence())
        self.assertEqual(result[0][1]['nativeOcspRevoked'], collector.ocsp_revoked_proof.fields(revoked_ocsp_evidence(), ocsp_evidence()))
        self.assertEqual(result[0][1]['nativeAdcsResultOutbox'], adcs_result_outbox_evidence())
        for key in (None, *adcs_result_outbox_evidence()):
            bad = json.loads(json.dumps(value))
            if key is None:
                del bad['nativeAdcsResultOutbox']
            else:
                del bad['nativeAdcsResultOutbox'][key]
            with self.subTest(adcs_outbox_missing=key), self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value['suite']}, set())
        for patch in ({'caRequestCounts': [10, 11, 12]}, {'retryDelayMs': 1}, {'sameLeafKeyAndCaRequestAfterRestart': False}, {'backgroundTimerQualified': True}):
            bad = json.loads(json.dumps(value))
            bad['nativeAdcsResultOutbox'].update(patch)
            with self.subTest(adcs_outbox_invalid=patch), self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value['suite']}, set())
        for missing in (None, *collector.ocsp_proof.FIELDS):
            bad = json.loads(json.dumps(value))
            if missing is None:
                del bad['nativeOcspResponder']
            else:
                del bad['nativeOcspResponder'][missing]
            with self.subTest(missing_ocsp=missing), self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value['suite']}, set())
        for missing in (None, *collector.ocsp_revoked_proof.FIELDS):
            bad = json.loads(json.dumps(value))
            if missing is None:
                del bad['nativeOcspRevoked']
            else:
                del bad['nativeOcspRevoked'][missing]
            with self.subTest(missing_ocsp_revoked=missing), self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value['suite']}, set())
        for key in (None, *http_leaf_crl_evidence()):
            bad = json.loads(json.dumps(value))
            if key is None:
                del bad['nativeHttpOnlyLeafCrl']
            else:
                del bad['nativeHttpOnlyLeafCrl'][key]
            with self.subTest(http_leaf_missing=key), self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value['suite']}, set())
        for patch_value in ({'actualOwnedHttp503': False}, {'installedAgentFaultRecoveryQualified': False}, {'caRequestCounts': [10, 11, 13]}, {'restoredRequestId': 42}):
            bad = json.loads(json.dumps(value))
            bad['nativeHttpOnlyLeafCrl'].update(patch_value)
            with self.subTest(http_leaf_invalid=patch_value), self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value['suite']}, set())
        self.assertEqual(result[0][1]['nativeBrowserAdcs'], browser_adcs_proof())
        self.assertEqual(result[0][1]['nativeLocalRulePairs'], local_pairs_proof())
        self.assertEqual(result[0][1]['nativePendingKeySurvivor'], pending_key_survivor_proof())
        for key in pending_key_survivor_proof():
            invalid = pending_key_survivor_proof()
            del invalid[key]
            with self.subTest(survivor_missing=key), self.assertRaises(ValueError):
                collector.pending_key_survivor_fields(invalid)
        self.assertEqual(result[0][1]['nativeForeignSpkiCandidate'], foreign_spki_proof())
        for flag, fact in foreign_spki_proof().items():
            if fact is not True:
                continue
            for invalid in (False, None, 1, 'true'):
                bad = json.loads(json.dumps(value))
                bad['nativeForeignSpkiCandidate'][flag] = invalid
                with self.subTest(foreign_flag=flag, invalid=invalid), self.assertRaises(ValueError):
                    collector.sanitized_report(bad, {value['suite']}, set())
            bad = json.loads(json.dumps(value))
            del bad['nativeForeignSpkiCandidate'][flag]
            with self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value['suite']}, set())
        for change in ({'scope': 'public-uncertain-recovery'}, {'requestIds': ['17', '17']}, {'requestIds': ['17', '4294967296']}, {'spkiFingerprints': ['a' * 64, 'a' * 64]}):
            bad = json.loads(json.dumps(value))
            bad['nativeForeignSpkiCandidate'].update(change)
            with self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value['suite']}, set())
        private_foreign = json.loads(json.dumps(value))
        private_foreign['nativeForeignSpkiCandidate'].update({'rawKey': 'foreign-private-sentinel', 'publicRecoveryQualified': True})
        sanitized_foreign = collector.sanitized_report(private_foreign, {value['suite']}, set())
        self.assertEqual(sanitized_foreign['nativeForeignSpkiCandidate'], foreign_spki_proof())
        self.assertNotIn('foreign-private-sentinel', json.dumps(sanitized_foreign))
        private_pairs = json.loads(json.dumps(value))
        private_pairs['nativeLocalRulePairs'][0]['rawKey'] = 'private-pair-sentinel'
        self.assertNotIn('private-pair-sentinel', json.dumps(collector.sanitized_report(private_pairs, {value['suite']}, set())))
        for flag in local_pairs_proof()[0]:
            if flag == 'caseId':
                continue
            for invalid in (False, None, 1, 'true'):
                bad = json.loads(json.dumps(value))
                bad['nativeLocalRulePairs'][0][flag] = invalid
                with self.subTest(pair_flag=flag, invalid=invalid), self.assertRaises(ValueError):
                    collector.sanitized_report(bad, {value['suite']}, set())
            bad = json.loads(json.dumps(value))
            del bad['nativeLocalRulePairs'][0][flag]
            with self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value['suite']}, set())
        for rows in (None, [], [row for row in local_pairs_proof() if row['caseId'] != 'empty-allowlist'], [local_pairs_proof()[0]] * 4, [{**row, 'caseId': 'unknown'} for row in local_pairs_proof()]):
            bad = json.loads(json.dumps(value))
            bad['nativeLocalRulePairs'] = rows
            with self.assertRaises(ValueError):
                collector.sanitized_report(bad, {value['suite']}, set())
        self.assertNotIn('privateReceipt', result[0][1]['browserNativePreflightDispatch'])
        hierarchy = json.loads(json.dumps(value))
        hierarchy['suite'] = 'enterprise-adcs-hierarchy-real'
        hierarchy['nativeHttpIntermediateCrl'] = http_crl_proof()
        self.assertEqual(collector.extract_reports(self.archive('hierarchy.json', hierarchy), {hierarchy['suite']}, set())[0][1]['nativeBrowserAdcs'], browser_adcs_proof())
        del hierarchy['nativeBrowserAdcs']
        with self.assertRaises(ValueError):
            collector.extract_reports(self.archive('hierarchy.json', hierarchy), {hierarchy['suite']}, set())
        for key, expected in browser_adcs_proof().items():
            with self.subTest(browser_adcs_field=key):
                invalid = json.loads(json.dumps(value))
                del invalid['nativeBrowserAdcs'][key]
                with self.assertRaises(ValueError):
                    collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
                invalid = json.loads(json.dumps(value))
                invalid['nativeBrowserAdcs'][key] = [expected[0], expected[0]] if isinstance(expected, list) else False if type(expected) is bool else expected + 1 if type(expected) is int else 'unqualified'
                with self.assertRaises(ValueError):
                    collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for count in (2, 18, 19, 20):
            valid = json.loads(json.dumps(value))
            valid['primaryNativePreflightDispatchCount'] = count
            self.assertEqual(collector.extract_reports(self.archive('adcs.json', valid), {'enterprise-adcs-real'}, set())[0][1]['primaryNativePreflightDispatchCount'], count)
        for key in ('nativeBrowserAdcs', 'browserNativePreflightDispatch'):
            invalid = json.loads(json.dumps(value))
            invalid['primaryNativePreflightDispatchCount'] = 20
            del invalid[key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for dispatch in ({'count': 3, 'jobIds': value['browserNativePreflightDispatch']['jobIds']}, {'count': True, 'jobIds': value['browserNativePreflightDispatch']['jobIds']}, {'count': 2, 'jobIds': ['invalid', 'invalid']}, {'count': 2, 'jobIds': ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA']}, {'count': 2, 'jobIds': [value['browserNativePreflightDispatch']['jobIds'][0]]}):
            invalid = json.loads(json.dumps(value))
            invalid['browserNativePreflightDispatch'] = dispatch
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for count in (1, 21, -1, True, '20'):
            invalid = json.loads(json.dumps(value))
            invalid['primaryNativePreflightDispatchCount'] = count
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        invalid = json.loads(json.dumps(value))
        invalid['nativeBrowserAdcs']['requestId'] = '4294967296'
        with self.assertRaises(ValueError):
            collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        self.assertEqual(result[0][1]['nativeBrowserJobApproval'], browser_job_approval_proof())
        for key, expected in browser_job_approval_proof().items():
            invalid = json.loads(json.dumps(value))
            del invalid['nativeBrowserJobApproval'][key]
            with self.assertRaises(ValueError):
                collector.sanitized_report(invalid, {value['suite']}, set())
            invalid = json.loads(json.dumps(value))
            invalid['nativeBrowserJobApproval'][key] = not expected if type(expected) is bool else 'invalid'
            with self.assertRaises(ValueError):
                collector.sanitized_report(invalid, {value['suite']}, set())
        for patch in ({'approvePosts': True}, {'rejectPosts': True}, {'cancelPosts': False}, {'requestIds': ['17', '4294967296']}, {'jobIds': list(reversed(value['nativeAdcsCapacity']['jobIds']))}, {'rejectedJobId': value['nativeAdcsCapacity']['jobIds'][0]}):
            invalid = json.loads(json.dumps(value))
            invalid['nativeBrowserJobApproval'].update(patch)
            with self.assertRaises(ValueError):
                collector.sanitized_report(invalid, {value['suite']}, set())
        self.assertEqual(result[0][1]['nativeBrowserCancel'], browser_cancel_proof())
        self.assertNotIn('sentinel', json.dumps(result[0][1]['nativeBrowserCancel']))
        for key, expected in browser_cancel_proof().items():
            invalid = json.loads(json.dumps(value))
            del invalid['nativeBrowserCancel'][key]
            with self.assertRaises(ValueError):
                collector.sanitized_report(invalid, {value['suite']}, set())
            invalid = json.loads(json.dumps(value))
            invalid['nativeBrowserCancel'][key] = not expected if type(expected) is bool else 'invalid'
            with self.assertRaises(ValueError):
                collector.sanitized_report(invalid, {value['suite']}, set())
        for patch in ({'cancelPosts': True}, {'otherMutations': False}, {'priorRequestId': '4294967296'}, {'priorRequestId': '17'}, {'fingerprint': 'a' * 64}, {'priorJobId': '55555555-5555-5555-5555-555555555555'}, {'initialSixConcurrencyQualified': True}):
            invalid = json.loads(json.dumps(value))
            invalid['nativeBrowserCancel'].update(patch)
            with self.assertRaises(ValueError):
                collector.sanitized_report(invalid, {value['suite']}, set())
        self.assertEqual(result[0][1]['nativeIssuedRevocation'], issued_revocation_proof())
        for key, expected in issued_revocation_proof().items():
            invalid = json.loads(json.dumps(value))
            del invalid['nativeIssuedRevocation'][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
            invalid = json.loads(json.dumps(value))
            invalid['nativeIssuedRevocation'][key] = not expected if isinstance(expected, bool) else 'invalid'
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for patch in ({'requestId': '4294967296'}, {'requestId': 17}, {'schedulerDefaultClockQualified': 0}):
            invalid = json.loads(json.dumps(value))
            invalid['nativeIssuedRevocation'].update(patch)
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        self.assertEqual(result[0][1]['nativeIssuedSanBoundary'], issued_san_proof())
        for key, expected in issued_san_proof().items():
            invalid = json.loads(json.dumps(value))
            del invalid['nativeIssuedSanBoundary'][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
            invalid = json.loads(json.dumps(value))
            invalid['nativeIssuedSanBoundary'][key] = False if expected is True else 'invalid'
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for patch in ({'requestId': '4294967296'}, {'requestId': 17}, {'errorCode': 'ADCS_CA_KEY_CHANGED'}):
            invalid = json.loads(json.dumps(value))
            invalid['nativeIssuedSanBoundary'].update(patch)
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        self.assertEqual(result[0][1]['nativeBrowserReconcile'], browser_reconcile_proof())
        for key, expected in browser_reconcile_proof().items():
            invalid = json.loads(json.dumps(value))
            del invalid['nativeBrowserReconcile'][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
            invalid = json.loads(json.dumps(value))
            invalid['nativeBrowserReconcile'][key] = False if expected is True else 'invalid'
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for patch in ({'reconcilePosts': True}, {'invalidRequestPosts': False}, {'selectedRequestId': '4294967296'}, {'unusedRequestId': '101'}, {'selectedFingerprint': 'a' * 64}, {'continuationJobId': '55555555-5555-5555-5555-555555555555'}, {'enrollmentId': '55555555-5555-5555-5555-555555555555'}):
            invalid = json.loads(json.dumps(value))
            invalid['nativeBrowserReconcile'].update(patch)
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        self.assertEqual(result[0][1]['nativeBrowserAdminBoundary'], browser_admin_boundary_proof())
        for key, expected in browser_admin_boundary_proof().items():
            invalid = json.loads(json.dumps(value))
            del invalid['nativeBrowserAdminBoundary'][key]
            with self.assertRaises(ValueError):
                collector.sanitized_report(invalid, {value['suite']}, set())
            invalid = json.loads(json.dumps(value))
            invalid['nativeBrowserAdminBoundary'][key] = not expected if type(expected) is bool else 'invalid'
            with self.assertRaises(ValueError):
                collector.sanitized_report(invalid, {value['suite']}, set())
        self.assertEqual(result[0][1]['nativeBrowserAbandon'], browser_abandon_proof())
        for key, expected in browser_abandon_proof().items():
            invalid = json.loads(json.dumps(value))
            del invalid['nativeBrowserAbandon'][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
            invalid = json.loads(json.dumps(value))
            invalid['nativeBrowserAbandon'][key] = False if expected is True else 'invalid'
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for field in ('abandonPosts', 'keepPosts'):
            invalid = json.loads(json.dumps(value))
            invalid['nativeBrowserAbandon'][field] = True if field == 'abandonPosts' else False
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        self.assertEqual(result[0][1]['nativeWebHostingRenewal'], webhosting_proof())
        self.assertEqual(result[0][1]['nativeAdcsCapacity'], adcs_capacity_proof())
        self.assertNotIn('privateManagerCredential', result[0][1]['nativeAdcsCapacity'])
        for key, expected in adcs_capacity_proof().items():
            invalid = json.loads(json.dumps(value))
            del invalid['nativeAdcsCapacity'][key]
            with self.subTest(capacity_missing=key), self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
            invalid = json.loads(json.dumps(value))
            invalid['nativeAdcsCapacity'][key] = False if expected is True else 'invalid'
            with self.subTest(capacity_bad=key), self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for field in ('requestIds', 'fingerprints', 'enrollmentIds', 'jobIds'):
            invalid = json.loads(json.dumps(value))
            invalid['nativeAdcsCapacity'][field][1] = invalid['nativeAdcsCapacity'][field][0]
            with self.subTest(capacity_duplicate=field), self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for field, bad in (('cap', True), ('initialRefused', True), ('requestIds', ['17', '4294967296']), ('requestIds', ['0', '18'])):
            invalid = json.loads(json.dumps(value))
            invalid['nativeAdcsCapacity'][field] = bad
            with self.subTest(capacity_bound=field, bad=bad), self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for key, expected in webhosting_proof().items():
            invalid = json.loads(json.dumps(value))
            del invalid['nativeWebHostingRenewal'][key]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
            invalid = json.loads(json.dumps(value))
            invalid['nativeWebHostingRenewal'][key] = not expected if type(expected) is bool else 'invalid'
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        self.assertEqual(result[0][1]['nativeAdcsTwoRenewals'], two_adcs_renewals_proof())
        self.assertEqual(result[0][1]['nativeAdcsBackgroundRenewals'], background_adcs_proof())
        for key in background_adcs_proof():
            invalid = json.loads(json.dumps(value))
            del invalid['nativeAdcsBackgroundRenewals'][key]
            with self.subTest(background_missing=key), self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for key, bad in {'failed': True, 'ticks': 1, 'finishes': 1, 'created': 3, 'stops': 0, 'forwarded': False, 'firstTickElapsedMs': 59999, 'exitCode': 1, 'nativeDrained': False, 'bridgeReady': False}.items():
            invalid = json.loads(json.dumps(value))
            invalid['nativeAdcsBackgroundRenewals']['workerLifecycle'][key] = bad
            with self.subTest(background_lifecycle=key), self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for key, expected in two_adcs_renewals_proof().items():
            with self.subTest(two_adcs_renewals_field=key):
                invalid = json.loads(json.dumps(value))
                del invalid['nativeAdcsTwoRenewals'][key]
                with self.assertRaises(ValueError):
                    collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
                invalid = json.loads(json.dumps(value))
                invalid['nativeAdcsTwoRenewals'][key] = expected + expected[:1] if isinstance(expected, list) else not expected if type(expected) is bool else 1 if type(expected) is int else 'unqualified'
                with self.assertRaises(ValueError):
                    collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for key in ('requestIds', 'fingerprints', 'spkiFingerprints', 'serialNumbers', 'containerNames', 'expiryEpochs'):
            invalid = json.loads(json.dumps(value))
            invalid['nativeAdcsTwoRenewals'][key][2] = invalid['nativeAdcsTwoRenewals'][key][1]
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for change in ({'requestIds': ['17', '18', '4294967296']}, {'caRequestCounts': [999, 1000, 1001]}, {'caRequestCounts': [7, 8, 10]}, {'caRequestCounts': [True, 2, 3]}, {'expiryEpochs': [1, 2, 9007199254740992]}, {'workerIntervalQualified': True}, {'expiryCleanupQualified': True}):
            invalid = json.loads(json.dumps(value))
            invalid['nativeAdcsTwoRenewals'].update(change)
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for key, expected in uncertain_abandon_proof().items():
            with self.subTest(uncertain_abandon_field=key):
                invalid = json.loads(json.dumps(value))
                del invalid['nativeUncertainAbandon'][key]
                with self.assertRaises(ValueError):
                    collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
                invalid = json.loads(json.dumps(value))
                invalid['nativeUncertainAbandon'][key] = False if type(expected) is bool else 1 if type(expected) is int else 'unqualified'
                with self.assertRaises(ValueError):
                    collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        for key in ('caRequestsAtFault', 'caRequestsAfterRecovery', 'caRequestsAfterAbandon'):
            invalid = json.loads(json.dumps(value))
            invalid['nativeUncertainAbandon'][key] = False
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive('adcs.json', invalid), {'enterprise-adcs-real'}, set())
        cohort['dispatchCount'] = 19
        with self.assertRaises(ValueError):
            collector.extract_reports(self.archive('adcs.json', value), {'enterprise-adcs-real'}, set())

    def test_supporting_sources_are_bounded_to_committed_public_files(self):
        file = 'tests/e2e/helpers/certops-adcs-browser-abandon.js'
        value = [{'file': file, 'sha256': 'a' * 64, 'privateConfig': 'sentinel'}, {'file': 'private/sentinel.json', 'sha256': 'b' * 64}]
        self.assertEqual(collector.supporting_sources(value), [{'file': file, 'sha256': 'a' * 64}])
        with self.assertRaises(ValueError):
            collector.supporting_sources([{'file': file, 'sha256': 'private-value'}])
        from unittest.mock import patch
        with patch.object(collector, 'declared_sources', return_value=set(name for name in subprocess.check_output(['git', 'ls-files'], cwd=collector.ROOT, text=True).splitlines() if (collector.ROOT / name).is_file())):
            declared = sorted(name for name in subprocess.check_output(['git', 'ls-files'], cwd=collector.ROOT, text=True).splitlines() if (collector.ROOT / name).is_file())
            self.assertGreaterEqual(len(declared), 257)
            public_sources = [{'file': name, 'sha256': hashlib.sha256((collector.ROOT / name).read_bytes()).hexdigest()} for name in declared[:257]]
            for count in (97, 128, 129, 192, 256):
                self.assertEqual(collector.supporting_sources(public_sources[:count]), public_sources[:count])
            with self.assertRaises(ValueError):
                collector.supporting_sources(public_sources)
            with self.assertRaises(ValueError):
                collector.supporting_sources([public_sources[0], public_sources[0]])
            for escaped in ('../outside.js', 'C:\\private.js', '/private.js', 'inside/../private.js'):
                with self.assertRaises(ValueError):
                    collector.supporting_sources([{'file': escaped, 'sha256': 'a' * 64}])

    def test_algorithm_and_cmc_closed_native_proofs_refuse_missing_and_duplicate_controls(self):
        self.assertEqual(collector.algorithm_boundaries_fields(algorithm_proof()), algorithm_proof())
        self.assertEqual(collector.cmc_boundaries_fields(cmc_proof()), cmc_proof())
        for field in algorithm_proof()[0]:
            if type(algorithm_proof()[0][field]) is bool:
                for wrong in (False, 1, None, 'true'):
                    rows = algorithm_proof()
                    rows[0][field] = wrong
                    with self.assertRaises(ValueError):
                        collector.algorithm_boundaries_fields(rows)
        for key in ('positiveRequestId', 'positiveFingerprintSha256'):
            rows = algorithm_proof()
            rows[1][key] = rows[0][key]
            with self.assertRaises(ValueError):
                collector.algorithm_boundaries_fields(rows)
        for field in cmc_proof():
            if type(cmc_proof()[field]) is bool and field != 'syntheticCaResponse':
                value = cmc_proof()
                value[field] = 1
                with self.assertRaises(ValueError):
                    collector.cmc_boundaries_fields(value)
        for mutate in (lambda value: value.update(syntheticCaResponse=True), lambda value: value.update(tamperedResponseDerSha256=value['originalResponseDerSha256']), lambda value: value['refusedVariants'].pop(), lambda value: value.update(rawPrivate='unexpected')):
            value = cmc_proof()
            mutate(value)
            with self.assertRaises(ValueError):
                collector.cmc_boundaries_fields(value)
        with self.assertRaises(ValueError):
            collector.algorithm_boundaries_fields(None)
        with self.assertRaises(ValueError):
            collector.cmc_boundaries_fields(None)

    def migration(self):
        return {'suite': 'core-api-migration-upgrade', 'sourceProvenance': 'historical-source-build-to-candidate-source', 'sourceIdentity': {kind: {'sha': letter * 40, 'version': '0.17.3', 'lockfileSha256': letter * 64, 'privateConfig': 'sentinel'} for kind, letter in (('baseline', 'a'), ('candidate', 'b'))}, 'databaseRuntime': {'imageId': 'sha256:' + 'c' * 64, 'serverVersion': '16.6', 'password': 'sentinel'}, 'baselineSchema': {'tables': 5, 'columns': 30, 'migrations': [{'version': 1, 'name': 'core_schema', 'secret': 'sentinel'}]}, 'candidateSchema': {'tables': 6, 'columns': 35, 'migrations': [{'version': 1, 'name': 'core_schema'}, {'version': 2, 'name': 'new_schema'}]}, 'actualTlsObservedPromotion': True, 'repeatMigrationSchemaUnchanged': True}

    def test_matrix_success_cannot_declare_all_features_qualified(self):
        coverage = {'total': 2, 'planned': 1, 'partial': 1, 'implemented': 0, 'implementationStatus': 'incomplete', 'executionEvidence': 'reported-separately'}
        value = {'schemaVersion': 1, 'status': 'passed', 'candidateSha': 'a' * 40, 'mandatoryEnvironments': 1, 'qualificationScope': 'committed-mandatory-matrix', 'allFeaturesQualified': False, 'catalogCoverage': coverage}
        collector.validate_matrix_summary(value, 'a' * 40, 1, coverage)
        for changes in ({'allFeaturesQualified': True}, {'qualificationScope': 'all-features'}, {'catalogCoverage': {**coverage, 'implementationStatus': 'all-specifications-implemented'}}, {'candidateSha': 'b' * 40}):
            with self.assertRaises(ValueError):
                collector.validate_matrix_summary({**value, **changes}, 'a' * 40, 1, coverage)

    def archive(self, name, value):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            archive.writestr(name, json.dumps(value))
        return output.getvalue()

    def test_trusted_run_identity(self):
        run = {'status': 'completed', 'conclusion': 'success', 'head_sha': 'a' * 40, 'head_branch': 'main', 'repository': {'full_name': 'owner/repo'}, 'head_repository': {'full_name': 'owner/repo'}, 'path': '.github/workflows/certops-enterprise-adcs-qualification.yml', 'event': 'workflow_dispatch'}
        collector.validate_run(run, 'a' * 40, 'owner/repo')
        for workflow in ('certops-enterprise-adcs-hierarchy-qualification.yml', 'certops-native-issuer-reassignment.yml'):
            trusted = {**run, 'path': '.github/workflows/' + workflow}
            with self.assertRaises(ValueError):
                collector.validate_run(trusted, 'a' * 40, 'owner/repo')
            for field, value in (('head_branch', 'feature'), ('head_sha', 'b' * 40), ('event', 'pull_request'), ('conclusion', 'cancelled')):
                with self.subTest(workflow=workflow, field=field), self.assertRaises(ValueError):
                    collector.validate_run({**trusted, field: value}, 'a' * 40, 'owner/repo')
        for field, value in (('head_sha', 'b' * 40), ('head_branch', 'other'), ('conclusion', 'failure'), ('path', '.github/workflows/ci.yml'), ('event', 'pull_request')):
            with self.assertRaises(ValueError):
                collector.validate_run({**run, field: value}, 'a' * 40, 'owner/repo')

    def test_archive_cannot_escape_output_or_use_drive_path(self):
        for name in ('../report.json', '/report.json', 'C:/report.json', 'folder/../../report.json', 'folder\\..\\..\\report.json'):
            with self.assertRaises(ValueError):
                collector.extract_reports(self.archive(name, {}), {'fixture'}, set())

    def test_only_report_evidence_is_retained_without_probe_secrets(self):
        value = {'suite': 'fixture', 'status': 'failed', 'capabilities': {'api': {'available': True, 'evidence': 'password=secret'}}, 'scenarios': [], 'privateDebug': 'never-copy'}
        reports = collector.extract_reports(self.archive('nested/report.json', value), {'fixture'}, set())
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0][1]['status'], 'failed')
        self.assertNotIn('secret', json.dumps(reports))
        self.assertNotIn('never-copy', json.dumps(reports))
        self.assertEqual(collector.extract_reports(self.archive('other.json', {'suite': 'unknown'}), {'fixture'}, set()), [])
if __name__ == '__main__':
    unittest.main()
