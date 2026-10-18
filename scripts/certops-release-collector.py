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
import certops_qualification_profiles as qualification_profiles
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from certops_adcs_unique_candidate_proof import fields as unique_candidate_fields
import certops_adcs_live_enroll_acl_proof as live_enroll_acl_proof
import certops_adcs_result_outbox_proof as adcs_result_outbox_proof
import certops_adcs_http_crl_proof as http_crl_proof
import certops_adcs_http_leaf_crl_proof as http_leaf_crl_proof
import certops_adcs_ocsp_proof as ocsp_proof
import certops_adcs_ocsp_revoked_proof as ocsp_revoked_proof
import certops_native_issuer_reassignment_proof as issuer_reassignment_proof
import certops_adcs_browser_enrollment_proof as browser_enrollment_proof
import certops_adcs_uncertain_abandon_proof as uncertain_abandon_proof
ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = {'.github/workflows/certops-enterprise-adcs-qualification.yml', '.github/workflows/certops-distribution-qualification.yml', '.github/workflows/certops-qualification.yml'}
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
        raise ValueError('Committed matrix slot count exceeds collection policy')
    return {'runs': max(100, slot_count * 2), 'archives': max(200, slot_count * 2), 'reports': max(200, slot_count * 2)}

def validate_run_ids(run_ids, limits):
    if not isinstance(run_ids, list) or not 1 <= len(run_ids) <= limits['runs'] or any((type(item) is not int or item < 1 for item in run_ids)) or (len(set(run_ids)) != len(run_ids)):
        raise ValueError('Run IDs must be a bounded unique JSON array of positive integers')

def catalog_coverage():
    catalog = json.loads((ROOT / 'docs/certops/qualification-suites.json').read_text())
    rows = catalog.get('scenarios')
    if catalog.get('schemaVersion') != 1 or not isinstance(rows, list) or (not rows):
        raise ValueError('Invalid committed scenario catalog')
    counts = {'total': len(rows), 'planned': 0, 'partial': 0, 'implemented': 0}
    for row in rows:
        if row.get('status') not in ('planned', 'partial', 'implemented'):
            raise ValueError('Invalid catalog implementation status')
        counts[row['status']] += 1
    return {**counts, 'implementationStatus': 'all-specifications-implemented' if counts['implemented'] == counts['total'] else 'incomplete', 'executionEvidence': 'reported-separately'}

def validate_matrix_summary(value, candidate, environments, coverage, selection=None):
    if not isinstance(value, dict) or value.get('schemaVersion') != 1 or value.get('status') != 'passed' or (value.get('candidateSha') != candidate) or (value.get('mandatoryEnvironments') != environments) or (value.get('qualificationScope') != (qualification_profiles.summary_fields(selection)['qualificationScope'] if selection else 'committed-mandatory-matrix')) or (value.get('allFeaturesQualified') is not False) or (value.get('catalogCoverage') != coverage):
        raise ValueError('Matrix summary cannot promote incomplete feature specifications')
    if selection is not None and (type(value.get('fullMatrixQualified')) is not bool or any((value.get(key) != expected for key, expected in qualification_profiles.summary_fields(selection, True).items()))):
        raise ValueError('Qualification profile selected/omitted matrix mismatch')

def validate_run(run, candidate, repository):
    if run.get('status') != 'completed' or run.get('conclusion') != 'success' or run.get('head_sha') != candidate or (run.get('head_branch') != 'main') or (run.get('repository', {}).get('full_name') != repository) or (run.get('head_repository', {}).get('full_name') != repository) or (run.get('path') not in WORKFLOWS) or (run.get('event') not in ('push', 'workflow_dispatch')):
        raise ValueError('Selected run is not successful trusted-main candidate qualification')

def declared_sources():
    slots = json.loads((ROOT / 'docs/certops/qualification-suites.json').read_text())['slots']
    declared = {source for slot in slots for source in slot.get('requiredSources', [])}
    declared.update((slot['source'] for slot in slots if 'source' in slot))
    groups = json.loads((ROOT / 'tests/integration/certops-qualification-groups.json').read_text())
    declared.update(('tests/integration/' + file for group in groups.values() for file in group['files']))
    return declared

def source_fingerprint(value):
    if not isinstance(value, dict) or value.get('file') not in declared_sources() or (not isinstance(value.get('sha256'), str)) or (not re.fullmatch('[a-f0-9]{64}', value['sha256'])):
        raise ValueError('Invalid committed source fingerprint')
    return {'file': value['file'], 'sha256': value['sha256']}

def public_environment(value):
    """Project measured, bounded facts; never retain arbitrary probe metadata."""
    if not isinstance(value, dict):
        raise ValueError('Invalid qualification environment')
    patterns = {'osFamily': 'windows|linux', 'measurement': 'native', 'osVersion': '[0-9][A-Za-z0-9_.+-]{0,95}|desktop-[0-9]{1,8}|unsupported', 'distribution': '[A-Za-z0-9_.-]{1,40}', 'distributionId': '[a-z0-9_.-]{1,32}', 'distributionVersion': '[0-9][A-Za-z0-9_.-]{0,31}', 'nativeLanguage': '[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8}){0,3}', 'identity': 'LocalSystem|uid:[0-9]{1,10}', 'build': '[0-9]{1,8}', 'keyProfile': 'rsa-(?:2048|3072|4096)|ec-p(?:256|384)', 'keyAlgorithm': 'rsa|ecdsa', 'executionSurface': 'host|container|disposable-container|disposable-vm', 'libc': 'glibc|musl|unknown', 'architecture': 'x64|arm64|ia32', 'dnsProvider': '[a-z][a-z0-9-]{0,31}'}
    result = {}
    for key, pattern in patterns.items():
        if key not in value:
            continue
        raw = value[key]
        if not isinstance(raw, str):
            raise ValueError('Invalid qualification environment field type')
        if key == 'identity' and (not re.fullmatch(pattern, raw)):
            continue
        if not re.fullmatch(pattern, raw):
            raise ValueError('Invalid qualification environment field')
        result[key] = raw
    for key, allowed in (('productType', (1, 2, 3)), ('keySize', (256, 384, 2048, 3072, 4096))):
        if key in value:
            if type(value[key]) is not int or value[key] not in allowed:
                raise ValueError('Invalid native environment numeric field')
            result[key] = value[key]
    return result

def supporting_sources(value):
    declared = declared_sources()
    if not isinstance(value, list) or len(value) > 256:
        raise ValueError('Invalid supporting source inventory')
    result, seen = ([], set())
    for source in value:
        file = source.get('file') if isinstance(source, dict) else None
        if isinstance(file, str) and (file.startswith(('/', '\\')) or re.match('^[A-Za-z]:', file) or '..' in re.split('[\\\\/]', file)):
            raise ValueError('Supporting source escaped repository')
        if not isinstance(source, dict) or not isinstance(file, str) or file not in declared:
            continue
        if file in seen:
            raise ValueError('Duplicate supporting source identity')
        seen.add(file)
        if not isinstance(source.get('sha256'), str) or not re.fullmatch('[a-f0-9]{64}', source['sha256']):
            raise ValueError('Invalid supporting source fingerprint')
        result.append({'file': source['file'], 'sha256': source['sha256']})
    return result

def adcs_capacity_fields(proof):
    flags = ('freshConfirmedIssuer', 'actualPostConfirmationPreflight', 'sixConcurrentPublicRequests', 'fivePersistedPendingApprovals', 'sixthTransactionRolledBack', 'noCaRequestsBeforeApproval', 'noNativeKeysBeforeApproval', 'distinctAuthorizedApprover', 'firstNativeCompletionFreesSlot', 'refusedSubjectReenteredPublicly', 'twoClaimBoundNativeInstallations', 'twoDistinctOwnedCaRequests', 'twoNonexportableMachineKeys', 'twoNativeIisAndTrustedTls', 'fourUnapprovedJobsPubliclyRejected', 'approvalSettingRestored')
    if not isinstance(proof, dict) or proof.get('scope') != 'actual-native-adcs-per-issuer-five-public-approvals-and-terminal-release' or any((proof.get(flag) is not True for flag in flags)):
        raise ValueError('Incomplete native AD CS capacity evidence')
    result = {'scope': proof['scope'], **dict.fromkeys(flags, True)}
    for field, expected in (('cap', 5), ('initialAccepted', 5), ('initialRefused', 1), ('nativeCompleted', 2)):
        if type(proof.get(field)) is not int or proof[field] != expected:
            raise ValueError('Invalid native AD CS capacity count')
        result[field] = expected
    uuid = '[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'
    for field, pattern in (('requestIds', '[1-9][0-9]{0,9}'), ('fingerprints', '[a-f0-9]{64}'), ('enrollmentIds', uuid), ('jobIds', uuid)):
        values = proof.get(field)
        if not isinstance(values, list) or len(values) != 2 or any((not isinstance(value, str) or not re.fullmatch(pattern, value) for value in values)) or (len(set(values)) != 2):
            raise ValueError('Invalid distinct native AD CS capacity identities')
        result[field] = list(values)
    if any((int(value) > 4294967295 for value in result['requestIds'])):
        raise ValueError('Invalid native AD CS capacity request bound')
    return result

def browser_cancel_fields(proof):
    flags = ['additionalSequentialPublicRenewal', 'requestedPendingApprovalObserved', 'newJobNeverClaimed', 'exactPublicCancelAcknowledged', 'browserAndTrustDrained', 'onlyNewEnrollmentAndJobCancelled', 'oldInstalledEnrollmentUnchanged', 'oldProtectedCngAndIisUnchanged', 'oldTrustedTlsUnchanged', 'newContainerAndJournalAbsent', 'subjectCaRequestsUnchanged', 'exactHumanCancelAudit', 'capacitySlotReleased', 'cleanupOwnershipRegistered']
    if not isinstance(proof, dict) or proof.get('scope') != 'browser-cancel-requested-approval-gated-renewal-preserves-issued-native-custody' or any((proof.get(flag) is not True for flag in flags)):
        raise ValueError('Missing native browser requested cancellation evidence')
    result = {'scope': proof['scope'], **dict.fromkeys(flags, True)}
    for key in ('enrollmentId', 'jobId', 'priorEnrollmentId', 'priorJobId', 'priorRequestId', 'fingerprint'):
        pattern = '[a-f0-9]{64}' if key == 'fingerprint' else '[1-9][0-9]{0,9}' if key == 'priorRequestId' else '[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'
        if not isinstance(proof.get(key), str) or not re.fullmatch(pattern, proof[key]):
            raise ValueError('Invalid browser requested cancellation identity')
        result[key] = proof[key]
    if int(result['priorRequestId']) > 4294967295 or len({result[key] for key in ('enrollmentId', 'jobId', 'priorEnrollmentId', 'priorJobId')}) != 4:
        raise ValueError('Invalid browser cancellation request/UUID bounds')
    for key, expected in (('cancelPosts', 1), ('otherMutations', 0), ('capacityBeforeCancel', 5), ('capacityAfterCancel', 4)):
        if type(proof.get(key)) is not int or proof[key] != expected:
            raise ValueError('Invalid browser cancellation mutation/capacity count')
        result[key] = expected
    for key in ('initialSixConcurrencyQualified', 'caSubmissionCancellationQualified'):
        if proof.get(key) is not False:
            raise ValueError('Browser cancellation scope cannot be promoted')
        result[key] = False
    return result

def same_certificate_late_approval_fields(proof):
    if not isinstance(proof, dict) or proof.get('scope') != 'real-cancelled-request-late-issued-after-same-certificate-renewal' or proof.get('sameCertificateRenewalQualified') is not True or (proof.get('backgroundTimerQualified') is not False) or (not isinstance(proof.get('certificateId'), str)) or (not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', proof['certificateId'])):
        raise ValueError('Invalid same-certificate cancelled late-approval proof')
    old = cancelled_late_approval_fields({**proof, 'scope': 'real-cancelled-request-late-issued-after-distinct-same-endpoint-successor', 'sameCertificateRenewalQualified': False})
    return {**old, 'scope': proof['scope'], 'certificateId': proof['certificateId'], 'sameCertificateRenewalQualified': True, 'backgroundTimerQualified': False}

def cancelled_late_approval_fields(proof):
    flags = ['publicCancellationAuditVerified', 'terminalCleanupAlreadyCompleted', 'distinctActualSuccessorInstalled', 'nativePendingCsrRequesterTemplateOwned', 'actualOfficerLateApproval', 'actualCaLeafMatchesOriginalCsr', 'defaultClockDoesNotRevive', 'overdueSchedulerDoesNotRevive', 'publicInstallationRetryRefused', 'originalJournalAndJobsUnchanged', 'cancelledKeyRemainsAbsent', 'lateLeafNeverAccepted', 'successorClaimEvidenceUnchanged', 'successorNativeCustodyBindingTlsUnchanged', 'noCaResubmission', 'ownedUnusedLateLeafRevoked']
    scope = 'real-cancelled-request-late-issued-after-distinct-same-endpoint-successor'
    if not isinstance(proof, dict) or proof.get('scope') != scope or proof.get('sameCertificateRenewalQualified') is not False or any((proof.get(flag) is not True for flag in flags)):
        raise ValueError('Incomplete native cancelled late approval evidence')
    result = {'scope': scope, 'sameCertificateRenewalQualified': False, **dict.fromkeys(flags, True)}
    for key in ('cancelledEnrollmentId', 'successorEnrollmentId'):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value):
            raise ValueError('Invalid late approval enrollment identity')
        result[key] = value
    if result['cancelledEnrollmentId'] == result['successorEnrollmentId']:
        raise ValueError('Late approval requires a distinct actual successor')
    for key, pattern in (('requestIds', '[1-9][0-9]{0,9}'), ('fingerprints', '[a-f0-9]{64}')):
        value = proof.get(key)
        if not isinstance(value, list) or len(value) != 2 or any((not isinstance(item, str) or not re.fullmatch(pattern, item) for item in value)) or (len(set(value)) != 2):
            raise ValueError('Invalid late approval public native identities')
        result[key] = value[:]
    if any((int(value) > 4294967295 for value in result['requestIds'])):
        raise ValueError('Late approval request exceeds native uint32')
    return result

def issued_revocation_fields(proof):
    flags = ['matchingNativePositiveControl', 'actualOwnedPendingRequest', 'actualCaSignatureAndOnlineRevoked', 'sameRequestCsrSpkiAndTemplate', 'actualOnlineChainValidBeforeRevocation', 'nativePendingIdentityBeforeManualDispatch', 'realRevokedLeafReachedProductionValidation', 'productionSignedContinuationRefused', 'rejectedBeforeCertificateAccept', 'predecessorBindingTlsAndCngUnchanged', 'unacceptedKeyRemovedAndJournalPreserved', 'noCaResubmission', 'ownedCaRequestRevoked', 'cleanupOwnershipRegistered']
    if not isinstance(proof, dict) or proof.get('scope') != 'actual-ca-issued-owned-revoked-leaf-refused-before-accept' or proof.get('errorCode') != 'ADCS_CERTIFICATE_INVALID' or (proof.get('schedulerDefaultClockQualified') is not False) or any((proof.get(flag) is not True for flag in flags)):
        raise ValueError('Incomplete native issued revocation refusal')
    result = {'scope': proof['scope'], 'errorCode': proof['errorCode'], 'schedulerDefaultClockQualified': False, **dict.fromkeys(flags, True)}
    for key in ('requestId', 'enrollmentId', 'continuationJobId'):
        value = proof.get(key)
        pattern = '[1-9][0-9]{0,9}' if key == 'requestId' else '[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError('Invalid native issued revocation identity')
        result[key] = value
    if int(result['requestId']) > 4294967295:
        raise ValueError('Invalid native revocation request bound')
    return result

def issued_san_fields(proof):
    flags = ['matchingNativePositiveControl', 'actualOwnedPendingCaMutation', 'actualCaSignature', 'sameRequestCsrSpkiAndTemplate', 'exactUnauthorizedDnsSan', 'productionSignedContinuationRefused', 'rejectedBeforeCertificateAccept', 'predecessorBindingTlsAndCngUnchanged', 'unacceptedKeyRemovedAndJournalPreserved', 'noCaResubmission', 'ownedCaRequestRevoked', 'cleanupOwnershipRegistered']
    if not isinstance(proof, dict) or proof.get('scope') != 'actual-ca-issued-owned-wrong-san-refused-before-accept' or proof.get('errorCode') != 'ADCS_CERTIFICATE_INVALID' or any((proof.get(flag) is not True for flag in flags)):
        raise ValueError('Incomplete native issued SAN refusal')
    result = {'scope': proof['scope'], 'errorCode': proof['errorCode'], **dict.fromkeys(flags, True)}
    for key in ('requestId', 'enrollmentId', 'continuationJobId'):
        value = proof.get(key)
        pattern = '[1-9][0-9]{0,9}' if key == 'requestId' else '[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError('Invalid native issued SAN identity')
        result[key] = value
    if int(result['requestId']) > 4294967295:
        raise ValueError('Invalid native SAN request bound')
    return result

def browser_reconcile_fields(proof):
    flags = ['actualUncertainRequestIdForm', 'invalidRequestIdDidNotMutate', 'exactOwnedRequestIdPosted', 'exactPublicReconcileAcknowledged', 'browserAndTrustDrained', 'nativeSelectedRequestInstalled', 'nativeSameProtectedMachineKey', 'nativeClaimBoundVerification', 'nativeExactReconcileAudit', 'unusedOwnedRequestRevoked', 'unusedLeafNeverAccepted', 'originalOrphanPreserved']
    if not isinstance(proof, dict) or proof.get('scope') != 'browser-requestid-reconcile-real-operator-created-same-csr-ambiguity' or proof.get('fixtureOrigin') != 'operator-created-two-real-system-submissions-of-the-same-public-csr' or any((proof.get(flag) is not True for flag in flags)):
        raise ValueError('Incomplete native browser reconciliation evidence')
    result = {'scope': proof['scope'], 'fixtureOrigin': proof['fixtureOrigin'], **dict.fromkeys(flags, True)}
    for key in ('enrollmentId', 'continuationJobId', 'selectedFingerprint', 'selectedRequestId', 'unusedRequestId'):
        pattern = '[a-f0-9]{64}' if key == 'selectedFingerprint' else '[1-9][0-9]{0,9}' if key.endswith('RequestId') else '[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError('Invalid native browser reconciliation identity')
        result[key] = value
    if any((int(result[key]) > 4294967295 for key in ('selectedRequestId', 'unusedRequestId'))) or result['selectedRequestId'] == result['unusedRequestId']:
        raise ValueError('Invalid native browser reconciliation requests')
    for key, expected in (('reconcilePosts', 1), ('invalidRequestPosts', 0)):
        if type(proof.get(key)) is not int or proof[key] != expected:
            raise ValueError('Invalid browser reconciliation mutation count')
        result[key] = expected
    return result

def browser_admin_boundary_fields(proof):
    flags = ['distinctOwnedNonownerActors', 'noGlobalAdminBypassAssumed', 'publicManagerViewerManagerTransitions', 'managerAndViewerUiDenied', 'bothRolesReconcileAndAbandonForbidden', 'publicOwnerAdminPatchDemotionRefused', 'exactOwnerAdminUnchanged', 'actualUncertainEnrollmentAndJobsUnchanged', 'nativeCaAndUnacceptedKeyUnchanged', 'servingNativeCustodyAndTrustedTlsUnchanged', 'targetCertOpsAuditUnchanged', 'exactMembershipAudits', 'managerMembershipRestored', 'browserAndTrustDrained']
    if not isinstance(proof, dict) or proof.get('scope') != 'public-manager-viewer-adcs-admin-boundary-not-mounted-admin-withdrawal' or proof.get('mountedAdminWithdrawalQualified') is not False or any((proof.get(flag) is not True for flag in flags)):
        raise ValueError('Incomplete supported browser role-boundary evidence')
    enrollment = proof.get('enrollmentId')
    if not isinstance(enrollment, str) or not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', enrollment):
        raise ValueError('Invalid browser role-boundary enrollment')
    result = {'scope': proof['scope'], 'enrollmentId': enrollment, 'mountedAdminWithdrawalQualified': False, **dict.fromkeys(flags, True)}
    for key, expected in (('forbiddenMutations', 4), ('roleChanges', 2), ('adminDemotions', 0)):
        if type(proof.get(key)) is not int or proof[key] != expected:
            raise ValueError('Invalid browser role-boundary counts')
        result[key] = expected
    return result

def browser_job_approval_fields(proof):
    flags = ['twoDistinctOwnedPendingJobs', 'distinctManagerApprover', 'exactJobVisibleInActualDashboard', 'cancelDidNotMutate', 'twoExactPublicApprovalPosts', 'appendOnlyDecisionsBoundToActor', 'payloadAndCanonicalIntentHashesVerified', 'browserAndTrustDrained', 'sameApprovedJobsInstalledNatively', 'capacityGenerationsCrossBound', 'oneExactPublicRejectionPost', 'rejectedJobNeverClaimedOrSubmitted', 'rejectedIntentAndNativeAbsencePreserved']
    if not isinstance(proof, dict) or proof.get('scope') != 'browser-control-plane-job-approval-for-two-real-adcs-capacity-installations' or proof.get('caOfficerApprovalQualified') is not False or any((proof.get(flag) is not True for flag in flags)):
        raise ValueError('Incomplete actual browser job decision evidence')
    result = {'scope': proof['scope'], 'caOfficerApprovalQualified': False, **dict.fromkeys(flags, True)}
    for key, expected in (('approvePosts', 2), ('rejectPosts', 1), ('cancelPosts', 0)):
        if type(proof.get(key)) is not int or proof[key] != expected:
            raise ValueError('Invalid browser job decision count')
        result[key] = expected
    for key, pattern in (('jobIds', '[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'), ('enrollmentIds', '[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'), ('payloadHashes', '[a-f0-9]{64}'), ('requestIds', '[1-9][0-9]{0,9}'), ('fingerprints', '[a-f0-9]{64}')):
        values = proof.get(key)
        if not isinstance(values, list) or len(values) != 2 or any((not isinstance(value, str) or not re.fullmatch(pattern, value) for value in values)) or (len(set(values)) != 2):
            raise ValueError('Invalid browser job decision identities')
        result[key] = list(values)
    if any((int(value) > 4294967295 for value in result['requestIds'])):
        raise ValueError('Invalid browser job CA request bound')
    for key in ('rejectedJobId', 'rejectedEnrollmentId', 'rejectedPayloadHash', 'rejectedCanonicalIntentHash'):
        value = proof.get(key)
        pattern = '[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}' if key.endswith('Id') else '[a-f0-9]{64}'
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError('Invalid browser rejection identity')
        result[key] = value
    if result['rejectedJobId'] in result['jobIds'] or result['rejectedEnrollmentId'] in result['enrollmentIds']:
        raise ValueError('Rejected job cannot be an installed approved generation')
    return result

def required_template_attribute_fields(proof):
    """Only actual zero/missing required LDAP attribute observations qualify."""
    flags = ('knownSafeNativeControlBefore', 'restorationRegisteredBeforeMutation', 'actualLdapMutationObserved', 'actualNativePreflightUnreadable', 'publicConfirmationRefused', 'signedInstalledJobRefused', 'noCaRequestOrCngAllocation', 'installedPredecessorPreserved', 'exactOriginalAttributesRestored', 'freshNativeSafeControlAfter', 'originalConfigCredentialPreserved')
    if not isinstance(proof, dict) or proof.get('scope') != 'actual-ldap-required-template-attribute-refusal-and-exact-native-restoration':
        raise ValueError('Invalid required template attribute scope')
    fingerprint, oid, cases = (proof.get('predecessorFingerprint'), proof.get('templateOid'), proof.get('cases'))
    if not isinstance(fingerprint, str) or not re.fullmatch('[a-f0-9]{64}', fingerprint) or (not isinstance(oid, str)) or (not re.fullmatch('[0-9]+(?:\\.[0-9]+)+', oid)) or (not isinstance(cases, list)) or (len(cases) != 2):
        raise ValueError('Invalid required template attribute identities')
    result = {'scope': proof['scope'], 'predecessorFingerprint': fingerprint, 'templateOid': oid, 'cases': []}
    ids = set()
    for item, expected in zip(cases, (('minimum-key-zero', 'minimalKeySize', 0), ('subject-name-flag-absent', 'enrolleeSuppliesSubject', None))):
        if not isinstance(item, dict) or any((item.get(key) is not True for key in flags)) or item.get('caseId') != expected[0] or (item.get('observedField') != expected[1]) or (item.get('preflightVerdict') != 'unreadable') or (item.get('reason') != 'template_unreadable'):
            raise ValueError('Incomplete live required template refusal/restoration')
        observed = item.get('observedValue')
        if 'observedValue' not in item or (expected[2] is None and observed is not None) or (expected[2] == 0 and expected[2] is not None and (type(observed) is not int or observed != 0)):
            raise ValueError('Wrong actual zero/null template observation')
        bounded = {'caseId': expected[0], 'observedField': expected[1], 'observedValue': expected[2], 'preflightVerdict': 'unreadable', 'reason': 'template_unreadable', **dict.fromkeys(flags, True)}
        for key in ('enrollmentId', 'jobId'):
            value = item.get(key)
            if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value) or value in ids:
                raise ValueError('Invalid or reused required template job identity')
            ids.add(value)
            bounded[key] = value
        result['cases'].append(bounded)
    return result

def public_foreign_spki_fields(proof):
    """Bounded public projection of actual signed foreign-key candidate refusal."""
    flags = ('ownedRequestRegisteredBeforeSubmit', 'softwarePrivateKeyRemovedBeforeSubmit', 'sameActualCaAndSystemRequester', 'sameAuthorizedSanAndTemplate', 'differentOwnedCnAndSpki', 'actualPublicProposalAccepted', 'actualSignedSpkiMismatchRefusal', 'originalUncertainJournalAndWatermarkPreserved', 'originalCngPossessionPreserved', 'noForeignCertificateAccepted', 'servingSiblingTrustedTlsPreserved', 'noAdditionalCaSubmissionOnRefusal', 'exactUnusedForeignRequestRevoked', 'matchingCandidatePositiveRecovery', 'cleanupOwnershipResolved')
    if not isinstance(proof, dict) or proof.get('scope') != 'public-uncertain-request-rejects-owned-same-san-foreign-spki-before-positive-recovery' or any((proof.get(key) is not True for key in flags)):
        raise ValueError('Incomplete public foreign SPKI evidence')
    result = {'scope': proof['scope'], **dict.fromkeys(flags, True)}
    for key in ('enrollmentId', 'failedJobId'):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value):
            raise ValueError('Invalid public foreign SPKI identity')
        result[key] = value
    if result['enrollmentId'] == result['failedJobId']:
        raise ValueError('Repeated public foreign SPKI identity')
    for key in ('foreignRequestId', 'selectedRequestId'):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch('[1-9][0-9]{0,9}', value) or int(value) > 4294967295:
            raise ValueError('Invalid public foreign SPKI request')
        result[key] = value
    if result['foreignRequestId'] == result['selectedRequestId']:
        raise ValueError('Foreign request cannot be installed')
    for key in ('foreignFingerprint', 'selectedFingerprint', 'foreignSpkiSha256', 'originalSpkiSha256', 'foreignCsrSha256'):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
            raise ValueError('Invalid public foreign SPKI digest')
        result[key] = value
    if result['foreignFingerprint'] == result['selectedFingerprint'] or result['foreignSpkiSha256'] == result['originalSpkiSha256']:
        raise ValueError('Foreign and original native identities must differ')
    floor = proof.get('reconcileSearchFrom')
    if type(floor) is not int or not 1 <= floor <= 4294967295 or int(result['foreignRequestId']) < floor:
        raise ValueError('Invalid original reconciliation floor')
    if type(proof.get('foreignSubjectRequestCount')) is not int or proof['foreignSubjectRequestCount'] != 1 or type(proof.get('originalSubjectRequestCount')) is not int or (proof['originalSubjectRequestCount'] != 2):
        raise ValueError('Invalid actual foreign/original request counts')
    result.update(reconcileSearchFrom=floor, foreignSubjectRequestCount=1, originalSubjectRequestCount=2)
    return result

def pending_ca_key_change_fields(proof):
    """Actual pending refusal after CA rekey plus fresh same-issuer recovery; public projection only."""
    flags = ('actualPendingBeforeRekey', 'pendingNativeSignatureVerified', 'actualSingleNewKeyRekey', 'originalSnapshotNeverRepinned', 'signedContinuationRefusedChangedKey', 'oldUnacceptedKeyRemoved', 'oldRequestDeniedByOwnedOfficer', 'oldRequestNeverResubmitted', 'predecessorCustodyAndTlsPreserved', 'sameIssuerPublicReconfirmed', 'freshSnapshotAndCngKey', 'freshActualPendingApproved', 'freshSignedNativeInstallation', 'claimBoundNativeEvidence', 'nativeIisAndTrustedTls', 'registeredCleanupResolved')
    if not isinstance(proof, dict) or proof.get('scope') != 'real-pending-request-refused-across-ca-new-key-and-fresh-reconfirmation' or proof.get('schedulerClock') != 'supported-scheduler-now-input' or (proof.get('backgroundWorkerIntervalQualified') is not False) or any((proof.get(key) is not True for key in flags)):
        raise ValueError('Incomplete pending CA new-key evidence')
    result = {'scope': proof['scope'], 'schedulerClock': proof['schedulerClock'], 'backgroundWorkerIntervalQualified': False, **dict.fromkeys(flags, True)}
    ids = ('issuerId', 'oldEnrollmentId', 'oldOriginalJobId', 'oldContinuationJobId', 'freshEnrollmentId', 'freshOriginalJobId', 'freshContinuationJobId', 'preflightJobId')
    for key in ids:
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value):
            raise ValueError('Invalid pending CA new-key identity')
        result[key] = value
    if len({result[key] for key in ids}) != len(ids):
        raise ValueError('Repeated pending CA new-key identity')
    for key in ('oldRequestId', 'freshRequestId'):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch('[1-9][0-9]{0,9}', value) or int(value) > 4294967295:
            raise ValueError('Invalid pending CA new-key request')
        result[key] = value
    if result['oldRequestId'] == result['freshRequestId']:
        raise ValueError('Fresh recovery must use a new request')
    for key in ('oldCaKeySha256', 'newCaKeySha256', 'oldSnapshotSha256', 'freshSnapshotSha256', 'oldSpkiSha256', 'freshSpkiSha256', 'predecessorFingerprint', 'freshFingerprint'):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
            raise ValueError('Invalid pending CA new-key digest')
        result[key] = value
    for left, right in (('oldCaKeySha256', 'newCaKeySha256'), ('oldSnapshotSha256', 'freshSnapshotSha256'), ('oldSpkiSha256', 'freshSpkiSha256'), ('predecessorFingerprint', 'freshFingerprint')):
        if result[left] == result[right]:
            raise ValueError('Recovery generations must be distinct')
    before, after = (proof.get('subjectCountBefore'), proof.get('subjectCountAfter'))
    if type(before) is not int or not 1 <= before < 2048 or type(after) is not int or (after != before + 1):
        raise ValueError('Unexpected pending CA new-key request count')
    result.update(subjectCountBefore=before, subjectCountAfter=after)
    return result

def pending_ca_renewal_fields(proof):
    """Same actual pending request across root CA certificate renewal; no worker-clock claim."""
    flags = ('matchingActualInstalledPredecessor', 'ownedMyCleanupRegistered', 'actualPendingBeforeCaRenewal', 'pendingCngSignatureVerified', 'actualCaSameKeyRenewal', 'confirmedIssuerUnchanged', 'noReconfirmation', 'pendingCsrKeyRequestPreserved', 'predecessorPreservedAcrossCaRenewal', 'actualSameRequestApproved', 'actualSignedContinuationInstalled', 'claimBoundNativeEvidence', 'nativeSamePendingKeyAndLeaf', 'trustedTlsCutover', 'predecessorKeyAndReceiptPreserved', 'noCaResubmission')
    if not isinstance(proof, dict) or proof.get('scope') != 'real-pending-enrollment-across-same-key-ca-certificate-renewal' or proof.get('schedulerClock') != 'supported-scheduler-now-input' or (proof.get('backgroundWorkerIntervalQualified') is not False) or any((proof.get(flag) is not True for flag in flags)):
        raise ValueError('Incomplete native pending CA renewal evidence')
    result = {'scope': proof['scope'], 'schedulerClock': proof['schedulerClock'], 'backgroundWorkerIntervalQualified': False, **dict.fromkeys(flags, True)}
    for key in ('enrollmentId', 'originalJobId', 'continuationJobId'):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value):
            raise ValueError('Invalid native pending CA renewal identity')
        result[key] = value
    if len({result[key] for key in ('enrollmentId', 'originalJobId', 'continuationJobId')}) != 3:
        raise ValueError('Duplicate native pending CA renewal identities')
    request_id = proof.get('requestId')
    if not isinstance(request_id, str) or not re.fullmatch('[1-9][0-9]{0,9}', request_id) or int(request_id) > 4294967295:
        raise ValueError('Invalid pending native CA request')
    result['requestId'] = request_id
    for key in ('caKeySha256', 'csrSha256', 'spkiSha256', 'leafFingerprint', 'predecessorFingerprint'):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
            raise ValueError('Invalid pending native CA fingerprint')
        result[key] = value
    if result['leafFingerprint'] == result['predecessorFingerprint']:
        raise ValueError('Pending renewal must install a distinct leaf')
    for key in ('caCertificateCountBefore', 'caCertificateCountAfter'):
        value = proof.get(key)
        if type(value) is not int or not 1 <= value <= 16:
            raise ValueError('Invalid actual CA certificate count')
        result[key] = value
    if result['caCertificateCountAfter'] <= result['caCertificateCountBefore']:
        raise ValueError('No actual CA certificate renewal')
    return result

def browser_abandon_fields(proof):
    flags = ('actualUncertainEnrollmentVisible', 'keepDidNotMutate', 'explicitConfirmationRequired', 'exactPublicAbandonAcknowledged', 'browserAndTrustDrained', 'actualProductionContinuation', 'journalAndDatabaseAbandoned', 'exactUnacceptedKeyAbsent', 'noAcceptedLeaf', 'zeroNativeCaRequests', 'onePublicAudit', 'originalUnknownEffectPreserved')
    if not isinstance(proof, dict) or proof.get('scope') != 'browser-confirmed-real-uncertain-abandon-and-native-unaccepted-key-cleanup' or any((proof.get(flag) is not True for flag in flags)):
        raise ValueError('Incomplete native browser abandonment evidence')
    result = {'scope': proof['scope'], **dict.fromkeys(flags, True)}
    for key in ('enrollmentId', 'cleanupJobId'):
        value = proof.get(key)
        if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value):
            raise ValueError('Invalid native browser abandonment identity')
        result[key] = value
    for key, expected in (('abandonPosts', 1), ('keepPosts', 0)):
        if type(proof.get(key)) is not int or proof[key] != expected:
            raise ValueError('Invalid browser abandonment mutation count')
        result[key] = expected
    return result

def webhosting_fields(proof):
    flags = ('publicIssueAndRenewInstalled', 'twoIndependentCaRequests', 'freshSerialSpkiAndKey', 'webHostingProtectedCustody', 'myCopiesAbsent', 'exactNativeIisAndHttpSysStore', 'trustedSniTls', 'installedDiscoveryInventory', 'immutableAcceptedStore', 'predecessorRetentionStorePreserved', 'storeQualifiedCleanupRegistered')
    if not isinstance(proof, dict) or proof.get('scope') != 'real-adcs-webhosting-issue-and-fresh-key-manual-renewal' or proof.get('store') != 'WebHosting' or (proof.get('expiryCleanupQualified') is not False) or any((proof.get(flag) is not True for flag in flags)):
        raise ValueError('Incomplete native WebHosting renewal evidence')
    result = {'scope': proof['scope'], 'store': 'WebHosting', 'expiryCleanupQualified': False, **dict.fromkeys(flags, True)}
    for field, pattern in (('requestIds', '[1-9][0-9]{0,9}'), ('fingerprints', '[a-f0-9]{64}')):
        values = proof.get(field)
        if not isinstance(values, list) or len(values) != 2 or any((not isinstance(value, str) or not re.fullmatch(pattern, value) for value in values)) or (len(set(values)) != 2):
            raise ValueError('Invalid distinct native WebHosting generations')
        result[field] = list(values)
    if any((int(value) > 4294967295 for value in result['requestIds'])):
        raise ValueError('Invalid native WebHosting CA request bound')
    return result

def algorithm_boundaries_fields(rows):
    cases = {'rsa2048-below-template3072': 'rsa3072', 'rsa3072-below-template4096': 'rsa4096', 'ec256-on-p384-schema-three': 'ec384schema3', 'ec256-on-p384-schema-four': 'ec384'}
    flags = ('nativeSafeTemplateObserved', 'publicConfirmedIssuerUsed', 'actualSignedClaimRefusal', 'noCaRequestAllocated', 'noKeyGenerated', 'noAcceptedLeafOrJournal', 'positiveNativeCustodyUnchanged', 'positiveTrustedTlsUnchanged')
    if not isinstance(rows, list) or len(rows) != 4:
        raise ValueError('Missing native algorithm/template boundaries')
    result, seen = ([], set())
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'caseId', 'positiveScenario', 'positiveFingerprintSha256', 'positiveRequestId', *flags} or (not isinstance(row.get('caseId'), str)) or (row['caseId'] not in cases) or (row['caseId'] in seen):
            raise ValueError('Invalid native algorithm/template case')
        if row.get('positiveScenario') != f"adcs-real-{cases[row['caseId']]}-issued-cng-iis" or any((row.get(flag) is not True for flag in flags)):
            raise ValueError('Native algorithm boundary lacks positive control')
        for field, pattern in (('positiveFingerprintSha256', '[a-f0-9]{64}'), ('positiveRequestId', '[1-9][0-9]{0,9}')):
            if not isinstance(row.get(field), str) or not re.fullmatch(pattern, row[field]):
                raise ValueError('Invalid native positive issuance identity')
        seen.add(row['caseId'])
        result.append(dict(row))
    if len({row['positiveFingerprintSha256'].lower() for row in result}) != 4 or len({row['positiveRequestId'] for row in result}) != 4 or any((int(row['positiveRequestId']) > 4294967295 for row in result)):
        raise ValueError('Native positive issuance controls must be distinct')
    return result

def cmc_boundaries_fields(proof):
    flags = ('actualCaSignedPending', 'actualPinnedSignatureVerified', 'actualSignerSignatureByteTampered', 'actualPristineDerControlVerified', 'agentResponseUnchanged')
    hashes = ('responseSha256', 'nativeHelperSha256', 'originalResponseDerSha256', 'tamperedResponseDerSha256')
    variants = ['empty', 'truncated', 'trailing-data', 'oversized', 'signer-signature-tampered', 'wrong-ca-key-pin']
    if not isinstance(proof, dict) or set(proof) != {'scope', *flags, 'caRequestId', *hashes, 'refusedVariants', 'syntheticCaResponse'} or proof.get('scope') != 'read-only-native-ca-signed-response-signature-boundaries' or any((proof.get(flag) is not True for flag in flags)) or (proof.get('syntheticCaResponse') is not False):
        raise ValueError('Missing native signed-response decoder boundaries')
    if not isinstance(proof.get('caRequestId'), str) or not re.fullmatch('[1-9][0-9]{0,9}', proof['caRequestId']) or int(proof['caRequestId']) > 4294967295:
        raise ValueError('Invalid signed-response CA request identity')
    if any((not isinstance(proof.get(field), str) or not re.fullmatch('[a-f0-9]{64}', proof[field]) for field in hashes)) or proof['originalResponseDerSha256'] == proof['tamperedResponseDerSha256'] or proof.get('refusedVariants') != variants:
        raise ValueError('Invalid native signed-response signature controls')
    return {**proof, 'refusedVariants': list(variants)}

def local_rule_tightening_fields(p):
    flags = ["actualSignedRetrievalPending","originalCngKeyUsable","frozenContextPreserved","noAdditionalCaRequest","outgoingTrustedTlsPreserved","explicitTerminalCleanupAfterDenial"]
    keys = {*flags, 'enrollmentId', 'continuationJobId', 'requestId', 'snapshotSha256', 'caRequestCounts'}
    if not isinstance(p, dict) or set(p) != keys or any(p.get(k) is not True for k in flags):
        raise ValueError('Native pending retrieval must preserve frozen context and original key')
    for key in ('enrollmentId', 'continuationJobId'):
        if not isinstance(p.get(key), str) or not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', p[key]):
            raise ValueError('Actual pending retrieval identities required')
    if not isinstance(p.get('requestId'), str) or not re.fullmatch('[1-9][0-9]{0,9}', p['requestId']) or int(p['requestId']) > 4294967295 or not isinstance(p.get('snapshotSha256'), str) or not re.fullmatch('[a-f0-9]{64}', p['snapshotSha256']):
        raise ValueError('Frozen pending request and snapshot required')
    counts = p.get('caRequestCounts')
    if not isinstance(counts, list) or len(counts) != 2 or any(type(n) is not int or not 0 < n <= 9007199254740991 or n != counts[0] for n in counts):
        raise ValueError('Pending retrieval must not submit another request')
    return {key: p[key] for key in keys}


def pending_key_survivor_fields(p):
    flags = ["actualOwnedPendingRequest","actualOwnedCaLeafSameCsrSpki","exactWebHostingAssociationAndProtectedKey","nativeSurvivorReferenceObserved","signedRetrievalInstalled","frozenEnrollmentIdentityPreserved","originalKeyUsableAfterReconciliation","installedKeyProtectedFromCleanup","installedReferenceSurvivesSecondaryRemoval","noAdditionalCaRequest","exactPublicAssociationOnlyRemoved","predecessorCustodyIisTlsPreserved","configurationCredentialRestored","ownedCaLeafRevoked","ownershipGuardReleased"]
    fixed = dict(scope="native-pending-key-policy-change-retrieval-install-and-survivor-protection", store='WebHosting', recovery='signed-retrieval-and-isolated-iis-installation')
    keys = {*fixed, *flags, 'enrollmentId', 'requestId', 'continuationJobId', 'fingerprint', 'csrSpkiSha256', 'caRequestCounts'}
    if not isinstance(p, dict) or set(p) != keys or any(p.get(k) != v for k,v in fixed.items()) or any(p.get(k) is not True for k in flags):
        raise ValueError('Native survivor must preserve usable installed custody after retrieval')
    for key in ('enrollmentId', 'continuationJobId'):
        if not isinstance(p.get(key), str) or not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', p[key]):
            raise ValueError('Actual survivor enrollment and continuation identities required')
    if not isinstance(p.get('requestId'), str) or not re.fullmatch('[1-9][0-9]{0,9}', p['requestId']) or int(p['requestId']) > 4294967295:
        raise ValueError('Actual survivor request required')
    for key in ('fingerprint', 'csrSpkiSha256'):
        if not isinstance(p.get(key), str) or not re.fullmatch('[a-f0-9]{64}', p[key]):
            raise ValueError('Actual shared public leaf and CSR SPKI required')
    counts = p.get('caRequestCounts')
    if not isinstance(counts, list) or len(counts) != 3 or any(type(n) is not int or not 0 < n <= 9007199254740991 or n != counts[0] for n in counts):
        raise ValueError('Native survivor recovery cannot submit another CA request')
    return {key: p[key] for key in keys}


def _sanitized_report(value, suites, scopes, database_scopes=()):
    if isinstance(value, dict) and value.get('scope') in database_scopes:
        keys = ('scope', 'candidateSha', 'evidenceLevel', 'qualificationEnvironment', 'fixtureSources', 'artifactQualification', 'qualificationStatus', 'experimental')
        return {**{key: value[key] for key in keys if key in value}, 'tests': [{key: item[key] for key in ('file', 'name', 'status') if key in item} for item in value.get('tests', []) if isinstance(item, dict)]}
    if isinstance(value, dict) and value.get('suite') in suites:
        keys = ('schemaVersion', 'suite', 'candidateSha', 'startedAt', 'finishedAt', 'status', 'strict', 'evidenceLevel', 'requiredCapabilities', 'requiredScenarios', 'missingCapabilities', 'missingScenarios', 'fixtureSource', 'qualificationEnvironment', 'artifactQualification', 'qualificationStatus', 'experimental')
        result = {key: value[key] for key in keys if key in value}
        if 'cleanup' in value:
            cleanup = value['cleanup']
            if not isinstance(cleanup, dict) or cleanup.get('status') not in ('passed', 'failed', 'not-run'):
                raise ValueError('Invalid owned cleanup evidence')
            result['cleanup'] = {'status': cleanup['status']}
        contract = json.loads((ROOT / 'docs/certops/qualification-suites.json').read_text())
        known_ids = contract['suites'].get(value['suite'], [])
        known_caps = contract['requiredCapabilities'].get(value['suite'], [])
        for key, known in (('requiredScenarios', known_ids), ('missingScenarios', known_ids), ('requiredCapabilities', known_caps), ('missingCapabilities', known_caps)):
            if key in result:
                if not isinstance(result[key], list) or len(result[key]) > 4096:
                    raise ValueError('Invalid execution metadata bounds')
                result[key] = [item if isinstance(item, str) and item in known else '[unrecognized]' for item in result[key]]
        result['capabilities'] = {name if name in known_caps else '[unrecognized]': {'available': capability.get('available') is True} for name, capability in value.get('capabilities', {}).items() if isinstance(capability, dict)}
        result['scenarios'] = [{key: item[key] for key in ('id', 'status', 'evidenceLevel', 'startedAt', 'finishedAt') if key in item} for item in value.get('scenarios', []) if isinstance(item, dict)]
        for scenario in result['scenarios']:
            if scenario.get('id') not in known_ids:
                scenario['id'] = '[unrecognized]'
            if scenario.get('status') not in ('passed', 'failed', 'skipped'):
                scenario['status'] = 'invalid'
            if scenario.get('evidenceLevel') not in ('unit', 'integration', 'real-host', 'e2e'):
                scenario['evidenceLevel'] = 'invalid'
            for key in ('startedAt', 'finishedAt'):
                if key in scenario and (not isinstance(scenario[key], str) or not re.fullmatch('[0-9TZ:.+\\-]{16,40}', scenario[key])):
                    scenario[key] = 'invalid'
        if 'cleanup' in value:
            result['cleanup'] = {'status': value['cleanup'].get('status')}
        if value.get('suite') == 'enterprise-adcs-elapsed-pending-real':
            if 'primaryNativePreflightDispatchCount' in value:
                count = value['primaryNativePreflightDispatchCount']
                if type(count) is not int or not 0 <= count <= 18:
                    raise ValueError('Elapsed AD CS cannot claim the browser preflight exception')
                result['primaryNativePreflightDispatchCount'] = count
            facts = value.get('nativePendingElapsed')
            if not isinstance(facts, dict):
                raise ValueError('Missing actual pending elapsed evidence')
            bounded = {key: facts.get(key) is True for key in ('snapshotAndCsrStableAcrossRestart', 'keyProtectedBeforeDeadline', 'signedTerminalCleanup', 'exactKeyAbsent', 'noCertificateAccepted', 'noCaResubmission', 'lateApprovalTerminalRefusal', 'lateIssuedCertificateRevoked', 'outgoingTrustedTlsUnchanged')}
            for key in ('pendingTimeoutSeconds', 'pollIntervalSeconds', 'monotonicWaitSeconds', 'databaseElapsedSeconds'):
                if type(facts.get(key)) not in (int, float) or not 0 <= facts[key] <= 86400:
                    raise ValueError('Invalid pending elapsed counter')
                bounded[key] = facts[key]
            for key in ('databaseDatesRewritten', 'journalRewritten'):
                if facts.get(key) is not False:
                    raise ValueError('Pending elapsed state rewritten')
                bounded[key] = False
            for key, pattern in (('pendingSince', '[0-9TZ:.+\\-]{16,40}'), ('requestId', '[1-9][0-9]{0,9}'), ('snapshotSha256', '[a-f0-9]{64}')):
                if not isinstance(facts.get(key), str) or not re.fullmatch(pattern, facts[key]):
                    raise ValueError('Invalid pending elapsed identity')
                bounded[key] = facts[key]
            for key, expected in (('clocks', 'actual-host-and-database'), ('schedulerClock', 'default-real-now'), ('qualificationScope', 'configured-one-hour-not-default-fourteen-days')):
                if facts.get(key) != expected:
                    raise ValueError('Invalid pending elapsed scope')
                bounded[key] = expected
            result['nativePendingElapsed'] = bounded
        if value.get('suite') == 'adcs-uncertain-abandon':
            result['nativeAdcsUncertainAbandon'] = uncertain_abandon_proof.fields(value, browser_abandon_fields)
            result.update(platform='win32', architecture='x64')
        if value.get('suite') == 'adcs-browser-enrollment':
            result['nativeAdcsBrowserEnrollment'] = browser_enrollment_proof.fields(value)
            result.update(platform='win32', architecture='x64')
        if value.get('suite') == 'native-adcs-issuer-reassignment':
            result['nativeIssuerReassignment'] = issuer_reassignment_proof.fields(value)
            result.update(nativeCell='qualified', platform='win32', architecture='x64')
        if value.get('suite') == 'enterprise-adcs-real':
            result['nativePendingCaRenewal'] = pending_ca_renewal_fields(value.get('nativePendingCaRenewal'))
            result['nativePendingCaKeyChange'] = pending_ca_key_change_fields(value.get('nativePendingCaKeyChange'))
            if result['nativePendingCaKeyChange']['predecessorFingerprint'] != result['nativePendingCaRenewal']['leafFingerprint'] or result['nativePendingCaKeyChange']['oldCaKeySha256'] != result['nativePendingCaRenewal']['caKeySha256']:
                raise ValueError('Pending new-key proof must bind actual prior pending installation')
        if value.get('suite') == 'enterprise-adcs-hierarchy-real':
            result['nativeHttpIntermediateCrl'] = http_crl_proof.fields(value.get('nativeHttpIntermediateCrl'))
        if value.get('suite') in ('enterprise-adcs-real', 'enterprise-adcs-hierarchy-real'):
            result['nativeIssuedRevocation'] = issued_revocation_fields(value.get('nativeIssuedRevocation'))
            result['nativeCancelledLateApproval'] = cancelled_late_approval_fields(value.get('nativeCancelledLateApproval'))
            result['nativeSameCertificateLateApproval'] = same_certificate_late_approval_fields(value.get('nativeSameCertificateLateApproval'))
            result['nativeRequiredTemplateAttributes'] = required_template_attribute_fields(value.get('nativeRequiredTemplateAttributes'))
            result['nativeLiveEnrollAcl'] = live_enroll_acl_proof.fields(value.get('nativeLiveEnrollAcl'))
            result['nativeHttpOnlyLeafCrl'] = http_leaf_crl_proof.fields(value.get('nativeHttpOnlyLeafCrl'))
            result['nativeOcspResponder'] = ocsp_proof.fields(value.get('nativeOcspResponder'))
            result['nativeOcspRevoked'] = ocsp_revoked_proof.fields(value.get('nativeOcspRevoked'), value.get('nativeOcspResponder'))
            result['nativeAdcsResultOutbox'] = adcs_result_outbox_proof.fields(value.get('nativeAdcsResultOutbox'))
            result['nativeIssuedSanBoundary'] = issued_san_fields(value.get('nativeIssuedSanBoundary'))
            result['nativeBrowserAbandon'] = browser_abandon_fields(value.get('nativeBrowserAbandon'))
            result['nativeBrowserAdminBoundary'] = browser_admin_boundary_fields(value.get('nativeBrowserAdminBoundary'))
            if result['nativeBrowserAdminBoundary']['enrollmentId'] != result['nativeBrowserAbandon']['enrollmentId']:
                raise ValueError('Role boundary must bind actual abandoned enrollment')
            result['nativeBrowserReconcile'] = browser_reconcile_fields(value.get('nativeBrowserReconcile'))
            result['nativeAdcsCapacity'] = adcs_capacity_fields(value.get('nativeAdcsCapacity'))
            if value.get('suite') == 'enterprise-adcs-real' and result['nativePendingCaRenewal']['predecessorFingerprint'] != result['nativeAdcsCapacity']['fingerprints'][1]:
                raise ValueError('Pending CA renewal must preserve actual second capacity generation')
            result['nativeBrowserJobApproval'] = browser_job_approval_fields(value.get('nativeBrowserJobApproval'))
            if any((result['nativeBrowserJobApproval'][key] != result['nativeAdcsCapacity'][key] for key in ('jobIds', 'enrollmentIds', 'requestIds', 'fingerprints'))):
                raise ValueError('Browser decisions must bind both actual native capacity generations')
            result['nativeBrowserCancel'] = browser_cancel_fields(value.get('nativeBrowserCancel'))
            capacity, browser_cancel = (result['nativeAdcsCapacity'], result['nativeBrowserCancel'])
            for key, field in (('priorEnrollmentId', 'enrollmentIds'), ('priorJobId', 'jobIds'), ('priorRequestId', 'requestIds'), ('fingerprint', 'fingerprints')):
                if browser_cancel[key] != capacity[field][1]:
                    raise ValueError('Browser cancellation does not preserve actual capacity issuance')
            result['nativeWebHostingRenewal'] = webhosting_fields(value.get('nativeWebHostingRenewal'))
            result['nativeAlgorithmBoundaries'] = algorithm_boundaries_fields(value.get('nativeAlgorithmBoundaries'))
            result['nativeCmcBoundaries'] = cmc_boundaries_fields(value.get('nativeCmcBoundaries'))
            foreign = value.get('nativeForeignSpkiCandidate')
            foreign_flags = ('sameRequesterNativeRetrieveSucceeded', 'nativeCaIdentityMatched', 'differentEnrollmentSpkiProved', 'explicitCandidateRefused', 'boundedSearchUnresolved', 'originalJournalWatermarkPreserved', 'originalNativeCustodyAndTlsPreserved', 'noAdditionalCaRequest')
            if not isinstance(foreign, dict) or foreign.get('scope') != 'read-only-native-foreign-spki-candidate-not-public-uncertain-recovery' or any((foreign.get(flag) is not True for flag in foreign_flags)):
                raise ValueError('Missing native other-enrollment SPKI refusal')
            bounded_foreign = {key: foreign[key] for key in ('scope', *foreign_flags)}
            for key in ('requestIds', 'spkiFingerprints'):
                entries = foreign.get(key)
                if not isinstance(entries, list) or len(entries) != 2 or any((not isinstance(entry, str) for entry in entries)) or (len(set(entries)) != 2):
                    raise ValueError('Invalid native other-enrollment public identity')
                if key == 'requestIds':
                    if any((not re.fullmatch('[1-9][0-9]{0,9}', entry) or int(entry) > 4294967295 for entry in entries)):
                        raise ValueError('Invalid native other-enrollment request ID')
                elif any((not re.fullmatch('[a-f0-9]{64}', entry) for entry in entries)):
                    raise ValueError('Invalid native other-enrollment SPKI')
                bounded_foreign[key] = entries
            result['nativeForeignSpkiCandidate'] = bounded_foreign
            pair_cases = {'ca-host-mismatch', 'ca-authority-mismatch', 'template-pair-mismatch', 'empty-allowlist'}
            pair_flags = ('actualSignedJobRefused', 'claimBoundOutcome', 'noCaRequestAllocated', 'noKeyGenerated', 'noAcceptedLeafOrJournal', 'originalNativeCustodyPreserved', 'outgoingTrustedTlsPreserved', 'configurationAndCredentialRestored')
            pairs = value.get('nativeLocalRulePairs')
            if not isinstance(pairs, list) or len(pairs) != len(pair_cases):
                raise ValueError('Missing native exact CA/template rule boundaries')
            bounded_pairs, seen_pairs = ([], set())
            for row in pairs:
                if not isinstance(row, dict) or not isinstance(row.get('caseId'), str) or row['caseId'] not in pair_cases or (row['caseId'] in seen_pairs) or any((row.get(flag) is not True for flag in pair_flags)):
                    raise ValueError('Invalid native exact CA/template rule boundary')
                seen_pairs.add(row['caseId'])
                bounded_pairs.append({key: row[key] for key in ('caseId', *pair_flags)})
            result['nativeLocalRulePairs'] = bounded_pairs
            result['nativeLocalRuleTightening'] = local_rule_tightening_fields(value.get('nativeLocalRuleTightening'))
            result['nativePendingKeySurvivor'] = pending_key_survivor_fields(value.get('nativePendingKeySurvivor'))
            result['nativeBrowserAdcs'] = browser_enrollment_proof.journey_fields(value.get('nativeBrowserAdcs'))
            uuid_pattern = '[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}'
            dispatch = value.get('browserNativePreflightDispatch')
            if not isinstance(dispatch, dict) or type(dispatch.get('count')) is not int or dispatch['count'] != 2 or (not isinstance(dispatch.get('jobIds'), list)) or (len(dispatch['jobIds']) != 2) or any((not isinstance(item, str) or not re.fullmatch(uuid_pattern, item) for item in dispatch['jobIds'])) or (len({item.lower() for item in dispatch['jobIds']}) != 2):
                raise ValueError('Invalid browser native preflight accounting')
            result['browserNativePreflightDispatch'] = {'count': 2, 'jobIds': dispatch['jobIds']}
            cycles = value.get('nativeAdcsTwoRenewals')
            flags = ('defaultSqlNowSelection', 'automaticSourceAndRealMode', 'distinctExpiryGenerations', 'independentCaRequests', 'freshLeafSerialAndSpki', 'protectedUniqueMachineKeys', 'nativeIisAndSniCutovers', 'independentTrustedTls', 'claimBoundVerificationEvidence', 'unchangedStoredProfile', 'sameManagementPeriod', 'predecessorCustodyPreserved', 'actualInventoryMatchesLatest', 'ownedEnrollmentCleanupRegistered', 'noDateOrJournalOverrides')
            strings = {'scope': 'two-native-adcs-default-scheduler-cycles-not-expiry-cleanup', 'renewalProtocol': 'fresh-enrollment-with-new-key-and-csr', 'schedulerInvocation': 'qualification-invoked-production-default-sweep'}
            if not isinstance(cycles, dict) or any((cycles.get(key) != expected for key, expected in strings.items())) or any((cycles.get(key) is not True for key in flags)) or (cycles.get('workerIntervalQualified') is not False) or (cycles.get('expiryCleanupQualified') is not False) or (type(cycles.get('successfulAutomationCycles')) is not int) or (cycles['successfulAutomationCycles'] != 2):
                raise ValueError('Invalid native AD CS renewal cycle scope')
            bounded_cycles = {key: cycles[key] for key in (*strings, *flags, 'workerIntervalQualified', 'expiryCleanupQualified', 'successfulAutomationCycles')}
            patterns = {'requestIds': '[1-9][0-9]{0,9}', 'fingerprints': '[a-f0-9]{64}', 'spkiFingerprints': '[a-f0-9]{64}', 'serialNumbers': '[a-f0-9]{1,128}', 'containerNames': 'tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'}
            for key, pattern in patterns.items():
                values = cycles.get(key)
                if not isinstance(values, list) or len(values) != 3 or any((not isinstance(item, str) or not re.fullmatch(pattern, item) for item in values)) or (len(set(values)) != 3):
                    raise ValueError('Invalid native AD CS renewal generation identities')
                bounded_cycles[key] = values
            if any((int(item) > 4294967295 for item in cycles['requestIds'])):
                raise ValueError('Invalid native AD CS request identity')
            for key in ('caRequestCounts', 'expiryEpochs'):
                values = cycles.get(key)
                if not isinstance(values, list) or len(values) != 3 or any((type(item) is not int or not 0 < item <= 9007199254740991 for item in values)):
                    raise ValueError('Invalid native AD CS renewal generation counters')
                bounded_cycles[key] = values
            counts, expiry = (cycles['caRequestCounts'], cycles['expiryEpochs'])
            if counts[2] > 1000 or counts[1] != counts[0] + 1 or counts[2] != counts[1] + 1 or (not expiry[0] < expiry[1] < expiry[2]):
                raise ValueError('Invalid native AD CS renewal generation progression')
            result['nativeAdcsTwoRenewals'] = bounded_cycles
            cycles = value.get('nativeAdcsBackgroundRenewals')
            flags = ('defaultSqlNowSelection', 'automaticSourceAndRealMode', 'distinctExpiryGenerations', 'independentCaRequests', 'freshLeafSerialAndSpki', 'protectedUniqueMachineKeys', 'nativeIisAndSniCutovers', 'independentTrustedTls', 'claimBoundVerificationEvidence', 'unchangedStoredProfile', 'sameManagementPeriod', 'predecessorCustodyPreserved', 'actualInventoryMatchesLatest', 'ownedEnrollmentCleanupRegistered', 'noDateOrJournalOverrides')
            strings = {'scope': 'two-real-default-interval-worker-native-adcs-renewals', 'renewalProtocol': 'fresh-enrollment-with-new-key-and-csr', 'schedulerInvocation': 'actual-production-runner-default-interval'}
            if not isinstance(cycles, dict) or any((cycles.get(key) != expected for key, expected in strings.items())) or any((cycles.get(key) is not True for key in flags)) or (cycles.get('workerIntervalQualified') is not True) or (cycles.get('expiryCleanupQualified') is not False) or (type(cycles.get('successfulAutomationCycles')) is not int) or (cycles['successfulAutomationCycles'] != 2):
                raise ValueError('Invalid native AD CS renewal cycle scope')
            bounded_cycles = {key: cycles[key] for key in (*strings, *flags, 'workerIntervalQualified', 'expiryCleanupQualified', 'successfulAutomationCycles')}
            patterns = {'requestIds': '[1-9][0-9]{0,9}', 'fingerprints': '[a-f0-9]{64}', 'spkiFingerprints': '[a-f0-9]{64}', 'serialNumbers': '[a-f0-9]{1,128}', 'containerNames': 'tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'}
            for key, pattern in patterns.items():
                values = cycles.get(key)
                if not isinstance(values, list) or len(values) != 3 or any((not isinstance(item, str) or not re.fullmatch(pattern, item) for item in values)) or (len(set(values)) != 3):
                    raise ValueError('Invalid native AD CS renewal generation identities')
                bounded_cycles[key] = values
            if any((int(item) > 4294967295 for item in cycles['requestIds'])):
                raise ValueError('Invalid native AD CS request identity')
            for key in ('caRequestCounts', 'expiryEpochs'):
                values = cycles.get(key)
                if not isinstance(values, list) or len(values) != 3 or any((type(item) is not int or not 0 < item <= 9007199254740991 for item in values)):
                    raise ValueError('Invalid native AD CS renewal generation counters')
                bounded_cycles[key] = values
            counts, expiry = (cycles['caRequestCounts'], cycles['expiryEpochs'])
            if counts[2] > 1000 or counts[1] != counts[0] + 1 or counts[2] != counts[1] + 1 or (not expiry[0] < expiry[1] < expiry[2]):
                raise ValueError('Invalid native AD CS renewal generation progression')
            result['nativeAdcsBackgroundRenewals'] = bounded_cycles
            lifecycle = cycles.get('workerLifecycle')
            expected = {'failed': False, 'starts': 1, 'created': 2, 'stops': 1, 'forwarded': True, 'exitCode': 0, 'nativeDrained': True, 'bridgeReady': True}
            if not isinstance(lifecycle, dict) or any((type(lifecycle.get(key)) is not type(want) or lifecycle[key] != want for key, want in expected.items())) or any((type(lifecycle.get(key)) is not int for key in ('ticks', 'finishes', 'summaries', 'firstTickElapsedMs'))) or (not 2 <= lifecycle['ticks'] <= 20) or (not 2 <= lifecycle['finishes'] <= lifecycle['ticks']) or (lifecycle['summaries'] != lifecycle['finishes']) or (not 60000 <= lifecycle['firstTickElapsedMs'] <= 180000):
                raise ValueError('Invalid actual background worker lifecycle')
            result['nativeAdcsBackgroundRenewals']['workerLifecycle'] = {key: lifecycle[key] for key in (*expected, 'ticks', 'finishes', 'summaries', 'firstTickElapsedMs')}
            abandon = value.get('nativeUncertainAbandon')
            flags = ('ownedObserverDrained', 'ownedTransportBlock', 'observedSubmittingTermination', 'actualLeaseExpiry', 'acknowledgedPublicRecovery', 'sameCsrAndKey', 'noAutomaticResubmit', 'publicAbandonAudited', 'unacceptedKeyRemoved', 'originalOrphanPreserved', 'recoveryPolicyUnchanged')
            counts = ('caRequestsAtFault', 'caRequestsAfterRecovery', 'caRequestsAfterAbandon')
            if not isinstance(abandon, dict) or abandon.get('scope') != 'native-zero-request-uncertain-abandon' or abandon.get('resolvedIssuingCaAddress') != '10.64.0.4' or any((abandon.get(key) is not True for key in flags)) or any((type(abandon.get(key)) is not int or abandon[key] != 0 for key in counts)):
                raise ValueError('Invalid native uncertain-abandon evidence')
            result['nativeUncertainAbandon'] = {key: abandon[key] for key in ('scope', 'resolvedIssuingCaAddress', *flags, *counts)}
            timing = ('leaseRemainingAtFaultMs', 'recoveryWaitBudgetMs', 'actualLeaseWaitMs')
            if any((type(abandon.get(key)) is not int or not 0 <= abandon[key] <= 900000 for key in timing)) or abandon['recoveryWaitBudgetMs'] != abandon['leaseRemainingAtFaultMs'] + 90000 or abandon['actualLeaseWaitMs'] + 1000 < abandon['leaseRemainingAtFaultMs']:
                raise ValueError('Invalid actual lease recovery timing')
            result['nativeUncertainAbandon'].update({key: abandon[key] for key in timing})
            ambiguity = value.get('nativeUncertainOperatorAmbiguity')
            ambiguity_flags = ('ownedObserverDrained', 'ownedTransportBlock', 'observedSubmittingTermination', 'actualLeaseExpiry', 'acknowledgedPublicRecovery', 'sameCsrAndKey', 'noAutomaticResubmit', 'originalOrphanPreserved', 'recoveryPolicyUnchanged', 'operatorCreatedSameCsrAmbiguity', 'nativeCaOwnershipVerified', 'automaticAttachmentRefused', 'unacceptedKeyPreserved', 'unrelatedTrustedTlsPreserved', 'publicExplicitReconcileAudited', 'exactSelectedRequestInstalled', 'claimBoundVerification', 'sameProtectedMachineKeyInstalled', 'unusedOwnedRequestRevoked', 'unusedLeafNeverAccepted')
            ambiguity_counts = ('caRequestsAfterOperatorSubmissions', 'caRequestsAfterAmbiguousRecovery', 'caRequestsAfterExplicitRecovery')
            if not isinstance(ambiguity, dict) or ambiguity.get('scope') != 'native-zero-request-uncertainty-with-operator-created-same-csr-ambiguity' or ambiguity.get('fixtureOrigin') != 'operator-created-two-real-system-submissions-of-the-same-public-csr' or (ambiguity.get('resolvedIssuingCaAddress') != '10.64.0.4') or any((ambiguity.get(key) is not True for key in ambiguity_flags)) or (type(ambiguity.get('caRequestsAtFault')) is not int) or (ambiguity['caRequestsAtFault'] != 0) or any((type(ambiguity.get(key)) is not int or ambiguity[key] != 2 for key in ambiguity_counts)):
                raise ValueError('Invalid native operator-created uncertain ambiguity evidence')
            bounded_ambiguity = {key: ambiguity[key] for key in ('scope', 'fixtureOrigin', 'resolvedIssuingCaAddress', 'caRequestsAtFault', *ambiguity_flags, *ambiguity_counts)}
            if any((type(ambiguity.get(key)) is not int or not 0 <= ambiguity[key] <= 900000 for key in timing)) or ambiguity['recoveryWaitBudgetMs'] != ambiguity['leaseRemainingAtFaultMs'] + 90000 or ambiguity['actualLeaseWaitMs'] + 1000 < ambiguity['leaseRemainingAtFaultMs'] + 60000 or (ambiguity['actualLeaseWaitMs'] > ambiguity['recoveryWaitBudgetMs'] + 1000):
                raise ValueError('Invalid native ambiguity actual lease/grace timing')
            bounded_ambiguity.update({key: ambiguity[key] for key in timing})
            for key, pattern in (('enrollmentId', uuid_pattern), ('containerName', 'tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'), ('csrSpkiSha256', '[a-f0-9]{64}'), ('csrSha256', '[a-f0-9]{64}')):
                if not isinstance(ambiguity.get(key), str) or not re.fullmatch(pattern, ambiguity[key]):
                    raise ValueError('Invalid native ambiguity identity')
                bounded_ambiguity[key] = ambiguity[key]
            if ambiguity['containerName'] != 'tokentimer-enr-' + ambiguity['enrollmentId']:
                raise ValueError('Native ambiguity key ownership mismatch')
            floor = ambiguity.get('reconcileSearchFrom')
            if type(floor) is not int or not 1 <= floor <= 4294967295 or type(ambiguity.get('scanWindowSize')) is not int or (ambiguity['scanWindowSize'] != 16):
                raise ValueError('Invalid native ambiguity actual scan window')
            bounded_ambiguity.update({'reconcileSearchFrom': floor, 'scanWindowSize': 16})
            for key, count, pattern in (('requestIds', 2, '[1-9][0-9]{0,9}'), ('fingerprints', 2, '[a-f0-9]{64}'), ('serialNumbers', 2, '[a-f0-9]{1,128}'), ('jobIds', 3, uuid_pattern)):
                items = ambiguity.get(key)
                if not isinstance(items, list) or len(items) != count or any((not isinstance(item, str) or not re.fullmatch(pattern, item) for item in items)) or (len({item.lower() for item in items}) != count):
                    raise ValueError('Invalid native ambiguity distinct identities')
                bounded_ambiguity[key] = list(items)
            if any((not floor <= int(item) < min(floor + 16, 4294967296) for item in ambiguity['requestIds'])):
                raise ValueError('Native ambiguity candidate outside actual default window')
            for key in ('selectedRequestId', 'unusedRequestId'):
                if not isinstance(ambiguity.get(key), str) or ambiguity[key] not in ambiguity['requestIds']:
                    raise ValueError('Native ambiguity selected/unused request mismatch')
                bounded_ambiguity[key] = ambiguity[key]
            if ambiguity['selectedRequestId'] == ambiguity['unusedRequestId']:
                raise ValueError('Native ambiguity selected request cannot be revoked')
            result['nativeUncertainOperatorAmbiguity'] = bounded_ambiguity
            result['nativeUncertainOperatorUnique'] = unique_candidate_fields(value.get('nativeUncertainOperatorUnique'))
            public_foreign = public_foreign_spki_fields(value.get('nativePublicForeignSpki'))
            expected_foreign = {'enrollmentId': bounded_ambiguity['enrollmentId'], 'originalSpkiSha256': bounded_ambiguity['csrSpkiSha256'], 'reconcileSearchFrom': bounded_ambiguity['reconcileSearchFrom'], 'selectedRequestId': bounded_ambiguity['selectedRequestId'], 'selectedFingerprint': bounded_ambiguity['fingerprints'][bounded_ambiguity['requestIds'].index(bounded_ambiguity['selectedRequestId'])]}
            if any((public_foreign[key] != expected for key, expected in expected_foreign.items())) or public_foreign['foreignRequestId'] in bounded_ambiguity['requestIds'] or public_foreign['failedJobId'] in bounded_ambiguity['jobIds']:
                raise ValueError('Public foreign-key refusal must bind actual matching-candidate recovery')
            result['nativePublicForeignSpki'] = public_foreign
            browser = result['nativeBrowserReconcile']
            expected_browser = {'enrollmentId': bounded_ambiguity['enrollmentId'], 'selectedRequestId': bounded_ambiguity['selectedRequestId'], 'unusedRequestId': bounded_ambiguity['unusedRequestId'], 'selectedFingerprint': bounded_ambiguity['fingerprints'][bounded_ambiguity['requestIds'].index(bounded_ambiguity['selectedRequestId'])], 'continuationJobId': bounded_ambiguity['jobIds'][2]}
            if any((browser[key] != expected for key, expected in expected_browser.items())):
                raise ValueError('Browser reconciliation does not match native ownership proof')
            cancellation = value.get('nativeIssuedCancellation')
            if not isinstance(cancellation, dict):
                raise ValueError('Missing native issued cancellation evidence')
            bounded_cancel = {key: cancellation.get(key) is True for key in ('actualCaIssuedBeforeCancel', 'caLeafSignatureAndCsrSpkiVerified', 'controlPlaneStillPendingBeforeCancel', 'nonExportableKeyPresentBeforeCancel', 'signedTerminalCleanupSucceeded', 'exactUnacceptedKeyAbsent', 'certificateNeverAccepted', 'sameRequestSnapshotAndCsrPreserved', 'noAdditionalCaRequest', 'outgoingTrustedTlsUnchanged', 'terminalReconcileRefused', 'unusedIssuedLeafRevoked')}
            for key, pattern in (('requestId', '[1-9][0-9]{0,9}'), ('snapshotSha256', '[a-fA-F0-9]{64}')):
                if not isinstance(cancellation.get(key), str) or not re.fullmatch(pattern, cancellation[key]):
                    raise ValueError('Invalid issued cancellation identity')
                bounded_cancel[key] = cancellation[key]
            if cancellation.get('pollIntervalSeconds') != 900 or cancellation.get('schedulerClock') != 'default-real-now' or cancellation.get('databaseDatesRewritten') is not False or (cancellation.get('journalRewritten') is not False):
                raise ValueError('Invalid issued cancellation clock evidence')
            bounded_cancel.update({'pollIntervalSeconds': 900, 'schedulerClock': 'default-real-now', 'databaseDatesRewritten': False, 'journalRewritten': False})
            result['nativeIssuedCancellation'] = bounded_cancel
            count = value.get('primaryNativePreflightDispatchCount')
            cohorts = value.get('nativePreflightCohorts')
            if type(count) is not int or not 2 <= count <= 20 or count - dispatch['count'] > 18 or (not isinstance(cohorts, list)) or (len(cohorts) > 128):
                raise ValueError('Invalid native preflight budget evidence')
            result['primaryNativePreflightDispatchCount'] = count
            expiry = value.get('nativeValidationExpiry')
            if not isinstance(expiry, dict):
                raise ValueError('Missing native validation deadline evidence')
            bounded_expiry = {key: expiry.get(key) is True for key in ('actualNativeRevocationUnknown', 'actualSignedContinuationExpired', 'persistedDeadlineSurvivedRestartAndPolicyRestoration', 'exactUnacceptedKeyFreed', 'noCertificateAccepted', 'noCaResubmission', 'outgoingTrustedTlsPreserved', 'chainCacheValueRestored')}
            for key in ('configuredTimeoutSeconds', 'defaultTimeoutSeconds', 'storedWindowSeconds', 'monotonicObservedWaitSeconds'):
                if type(expiry.get(key)) not in (int, float) or not 0 <= expiry[key] <= 86400:
                    raise ValueError('Invalid native deadline duration')
                bounded_expiry[key] = expiry[key]
            for key, pattern in (('actualDeadline', '[0-9TZ:.+\\-]{16,40}'), ('requestId', '[1-9][0-9]{0,9}'), ('snapshotSha256', '[a-f0-9]{64}')):
                if not isinstance(expiry.get(key), str) or not re.fullmatch(pattern, expiry[key]):
                    raise ValueError('Invalid native deadline identity')
                bounded_expiry[key] = expiry[key]
            if expiry.get('nativeAndCaClocks') != 'actual' or expiry.get('qualificationScope') != 'configured-five-minute-window-not-default-24-hour-elapsed':
                raise ValueError('Invalid native elapsed deadline scope')
            bounded_expiry.update({'nativeAndCaClocks': 'actual', 'qualificationScope': 'configured-five-minute-window-not-default-24-hour-elapsed'})
            result['nativeValidationExpiry'] = bounded_expiry
            result['nativePreflightCohorts'] = []
            mutations = value.get('nativeTemplateMutations')
            if not isinstance(mutations, list) or len(mutations) > 32:
                raise ValueError('Invalid native template mutation evidence')
            result['nativeTemplateMutations'] = []
            for mutation in mutations:
                if not isinstance(mutation, dict) or any((not isinstance(mutation.get(key), str) or not re.fullmatch(pattern, mutation[key]) for key, pattern in (('caseId', '[a-z0-9-]{1,100}'), ('template', 'TTQualification[A-Za-z0-9]{1,80}'), ('reason', '[A-Za-z0-9_-]{1,100}'), ('preflightVerdict', 'unsafe|unreadable|unknown')))):
                    raise ValueError('Invalid bounded template verdict')
                item = {key: mutation[key] for key in ('caseId', 'template', 'reason', 'preflightVerdict')}
                item.update({key: mutation.get(key) is True for key in ('originalConfirmedIssuerReused', 'actualSignedJobRefused', 'noCaRequestAllocated', 'noKeyGenerated', 'outgoingTrustedTlsPreserved')})
                result['nativeTemplateMutations'].append(item)
            for cohort in cohorts:
                if not isinstance(cohort, dict) or any((not isinstance(cohort.get(key), str) or not re.fullmatch('[a-fA-F0-9-]{36}', cohort[key]) for key in ('workspaceId', 'agentId'))):
                    raise ValueError('Invalid native preflight cohort identity')
                if type(cohort.get('dispatchCount')) is not int or not 1 <= cohort['dispatchCount'] <= 18 or cohort.get('dispatchLimit') != 18 or (cohort.get('nativeIdentity') != 'LocalSystem') or (cohort.get('runtime') != 'candidate-cli'):
                    raise ValueError('Invalid native preflight cohort budget')
                result['nativePreflightCohorts'].append({key: cohort[key] for key in ('workspaceId', 'agentId', 'dispatchCount', 'dispatchLimit', 'nativeIdentity', 'runtime')})
        if 'fixtureSources' in value:
            result['fixtureSources'] = supporting_sources(value['fixtureSources'])
        return result
    if isinstance(value, list) and value and (value[0].get('scope') in scopes):
        keys = ('type', 'name', 'candidateSha', 'scope', 'skip', 'todo', 'fixtureSource', 'qualificationEnvironment', 'artifactQualification', 'qualificationStatus', 'experimental')
        return [{**{key: event[key] for key in keys if key in event}, **({'fixtureSources': supporting_sources(event['fixtureSources'])} if 'fixtureSources' in event else {}), 'file': event.get('fixtureSource', {}).get('file', '')} for event in value]
    return None

def committed_case_names(scope, kind):
    slots = json.loads((ROOT / 'docs/certops/qualification-suites.json').read_text())['slots']
    matching = [slot for slot in slots if slot['kind'] == kind and slot['suite'] == scope]
    if kind == 'database':
        groups = json.loads((ROOT / 'tests/integration/certops-qualification-groups.json').read_text())
        return {(case['file'], case['name']) for slot in matching for case in groups[slot['requiredGroup']]['requiredTests']}
    names = set()
    for slot in matching:
        source = (ROOT / slot['source']).read_text()
        names.update(re.findall('\\bdescribe\\(\\s*["\\\']([^"\\\'\\r\\n]{1,200})["\\\']', source))
        names.update(slot.get('requiredTests', []))
        if 'requiredInventory' in slot:
            names.update(json.loads((ROOT / slot['requiredInventory']).read_text())['requiredTests'])
    return names

def project_case_metadata(result):
    """Retain unknown/failing cases as invalid evidence without their raw names."""
    if isinstance(result, list):
        for event in result:
            known = isinstance(event.get('name'), str) and event['name'] in committed_case_names(event.get('scope'), 'stack')
            if not known:
                event['name'] = '[unrecognized]'
            if event.get('type') not in ('test:pass', 'test:fail') or (not known and event.get('type') == 'test:pass'):
                event['type'] = 'invalid'
            for key in ('skip', 'todo'):
                if key in event and type(event[key]) is not bool:
                    raise ValueError('Invalid stack execution flags')
    elif isinstance(result, dict) and 'tests' in result:
        known = committed_case_names(result.get('scope'), 'database')
        for case in result['tests']:
            recognized = isinstance(case.get('file'), str) and isinstance(case.get('name'), str) and ((case['file'], case['name']) in known)
            if not recognized:
                case['file'] = '[unrecognized]'
                case['name'] = '[unrecognized]'
            if case.get('status') not in ('pass', 'fail', 'pending') or (not recognized and case.get('status') == 'pass'):
                case['status'] = 'invalid'
    return result

def project_common_fields(report, suites, scopes, database_scopes):
    """Validate known scalar fields before collected artifacts are written."""
    enums = {'status': {'passed', 'failed', 'skipped', 'running'}, 'evidenceLevel': {'unit', 'integration', 'real-host', 'e2e'}, 'artifactQualification': {'workflow-checkout-source', 'local-worktree-source-baseline-sha-only'}, 'qualificationStatus': {'qualified', 'not-qualified'}, 'suite': set(suites), 'scope': set(scopes) | set(database_scopes)}
    for key, allowed in enums.items():
        if key in report:
            if not isinstance(report[key], str):
                raise ValueError('Invalid qualification scalar field type')
            if report[key] not in allowed:
                report[key] = 'invalid'
    for key in ('strict', 'experimental'):
        if key in report and type(report[key]) is not bool:
            raise ValueError('Invalid qualification boolean field')
    if 'schemaVersion' in report and (type(report['schemaVersion']) is not int or not 0 <= report['schemaVersion'] <= 100):
        raise ValueError('Invalid qualification schema version')
    if 'candidateSha' in report:
        raw = report['candidateSha']
        if raw is not None and (not isinstance(raw, str)):
            raise ValueError('Invalid qualification candidate identity type')
        if isinstance(raw, str) and (not re.fullmatch('[a-f0-9]{40}', raw)):
            report['candidateSha'] = 'invalid'
    for key in ('startedAt', 'finishedAt'):
        if key not in report:
            continue
        raw = report[key]
        if not isinstance(raw, str):
            raise ValueError('Invalid qualification timestamp type')
        try:
            if not re.fullmatch('[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,6})?Z', raw):
                raise ValueError('Timestamp format')
            datetime.fromisoformat(raw.replace('Z', '+00:00'))
        except ValueError:
            report[key] = 'invalid'
    return report

def sanitized_report(value, suites, scopes, database_scopes=()):
    result = _sanitized_report(value, suites, scopes, database_scopes)
    for report in result if isinstance(result, list) else [result]:
        if not isinstance(report, dict):
            continue
        project_common_fields(report, suites, scopes, database_scopes)
        if 'qualificationEnvironment' in report:
            report['qualificationEnvironment'] = public_environment(report['qualificationEnvironment'])
        if 'fixtureSource' in report:
            report['fixtureSource'] = source_fingerprint(report['fixtureSource'])
        if 'fixtureSources' in report:
            report['fixtureSources'] = supporting_sources(report['fixtureSources'])
    return project_case_metadata(result)

def extract_reports(raw, suites, scopes, database_scopes=(), authenticate_report=None):
    if len(raw) > MAX_ARCHIVE:
        raise ValueError('Artifact archive exceeds the bounded download limit')
    reports = []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if len(entries) > 500 or sum((item.file_size for item in entries)) > 50 * 1024 * 1024:
            raise ValueError('Artifact uncompressed size or entry count exceeds limit')
        for item in entries:
            name = item.filename.replace('\\', '/')
            parts = PurePosixPath(name)
            if parts.is_absolute() or '..' in parts.parts or re.match('^[a-zA-Z]:', name) or stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError('Unsafe artifact archive path')
            if item.is_dir() or parts.suffix not in ('.json', '.jsonl'):
                continue
            if item.file_size > MAX_REPORT:
                raise ValueError('Qualification report exceeds size limit')
            text = archive.read(item).decode('utf-8')
            try:
                value = json.loads(text) if parts.suffix == '.json' else [json.loads(line) for line in text.splitlines() if line.strip()]
            except (ValueError, TypeError, AttributeError):
                raise ValueError('Malformed JSON qualification artifact') from None
            if authenticate_report is not None and (not authenticate_report(value)):
                continue
            try:
                sanitized = sanitized_report(value, suites, scopes, database_scopes)
            except (ValueError, TypeError, AttributeError):
                raise ValueError('Malformed JSON qualification artifact') from None
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
        if not isinstance(target, str) or len(target) > 16384 or '#' in target or any((ord(char) <= 32 or ord(char) == 127 for char in target)):
            raise ValueError('Artifact download URL is invalid')
        try:
            parsed = urllib.parse.urlsplit(target)
            port = parsed.port
        except ValueError:
            raise ValueError('Artifact download URL is invalid') from None
        if parsed.scheme != 'https' or parsed.username is not None or parsed.password is not None or (port not in (None, 443)) or parsed.fragment:
            raise ValueError('Artifact download URL is invalid')
        host = parsed.hostname or ''
        if blob:
            if not re.fullmatch('[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', host) or '..' in host or (not any((host.endswith(suffix) for suffix in ('.blob.core.windows.net', '.githubusercontent.com', '.actions.githubusercontent.com')))):
                raise ValueError('Artifact redirect host is not approved')
        elif host != 'api.github.com':
            raise ValueError('Initial request must stay on GitHub API')

    def request(target, credential=None, blob=False):
        validate(target, blob)
        headers = {'User-Agent': 'certops-qualification-collector'}
        if not blob:
            headers.update({'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
        if credential:
            headers['Authorization'] = 'Bearer ' + credential
        try:
            with urllib.request.build_opener(NoRedirect).open(urllib.request.Request(target, headers=headers), timeout=60) as response:
                raw = response.read(MAX_ARCHIVE + 1)
                if len(raw) > MAX_ARCHIVE:
                    raise ValueError('Bounded download exceeded')
                return raw
        except urllib.error.HTTPError as error:
            if redirect and (not blob) and (error.code == 302):
                location = error.headers.get('Location')
                validate(location, True)
                return request(location, None, True)
            raise ValueError('Qualification API/download request failed') from None
    return request(url, token)

def main(arguments=()):
    profile = qualification_profiles.requested_profile(arguments, os.environ)
    candidate = os.environ.get('CERTOPS_RELEASE_CANDIDATE', '')
    repository = os.environ.get('GITHUB_REPOSITORY', '')
    token = os.environ.get('GITHUB_TOKEN', '')
    run_ids = json.loads(os.environ.get('CERTOPS_RELEASE_RUN_IDS', '[]'))
    if not re.fullmatch('[a-f0-9]{40}', candidate) or not re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or (not token):
        raise ValueError('Explicit candidate, repository and read-only workflow token required')
    matrix = json.loads((ROOT / 'docs/certops/qualification-suites.json').read_text())
    selection = qualification_profiles.select_profile(matrix, profile)
    selected_matrix = selection['specification']
    limits = collection_limits(len(selected_matrix['slots']))
    validate_run_ids(run_ids, limits)
    suites = {slot['suite'] for slot in selected_matrix['slots'] if slot['kind'] == 'host'}
    scopes = {slot['suite'] for slot in selected_matrix['slots'] if slot['kind'] == 'stack'}
    database_scopes = {slot['suite'] for slot in selected_matrix['slots'] if slot['kind'] == 'database'}
    output = ROOT / 'qualification-results/release-collection'
    output.mkdir(parents=True, exist_ok=True)
    files = []
    archive_count = 0
    downloaded_bytes = 0
    coverage = catalog_coverage()
    summary = {'schemaVersion': 1, 'candidateSha': candidate, 'runIds': run_ids, 'status': 'failed', 'mandatoryEnvironments': len(selected_matrix['slots']), 'collectedReports': 0, **qualification_profiles.summary_fields(selection), 'allFeaturesQualified': False, 'catalogCoverage': coverage}
    try:
        for run_id in run_ids:
            endpoint = f'https://api.github.com/repos/{repository}/actions/runs/{run_id}'
            run = json.loads(download(endpoint, token))
            validate_run(run, candidate, repository)
            data = json.loads(download(endpoint + '/artifacts?per_page=100', token))
            if data.get('total_count', 0) > MAX_ARTIFACTS_PER_RUN:
                raise ValueError('Artifact inventory exceeds explicit bound')
            for artifact in data.get('artifacts', []):
                archive_count += 1
                if archive_count > limits['archives']:
                    raise ValueError('Collection artifact count exceeds limit')
                if artifact.get('expired'):
                    raise ValueError('Selected candidate artifact has expired')
                artifact_id = artifact.get('id')
                if type(artifact_id) is not int or artifact.get('size_in_bytes', MAX_ARCHIVE + 1) > MAX_ARCHIVE:
                    raise ValueError('Artifact identity or size is invalid')
                raw = download(f'https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}/zip', token, redirect=True)
                downloaded_bytes += len(raw)
                if downloaded_bytes > MAX_TOTAL_DOWNLOAD:
                    raise ValueError('Collection total download size exceeds limit')
                reports = extract_reports(raw, suites, scopes, database_scopes)
                for suffix, report in reports:
                    issuer_reassignment_proof.verify_workflow(report, run.get('path'))
                    browser_enrollment_proof.verify_workflow(report, run.get('path'))
                    uncertain_abandon_proof.verify_workflow(report, run.get('path'))
                    if len(files) >= limits['reports']:
                        raise ValueError('Collection qualification report count exceeds limit')
                    destination = output / f'report-{run_id}-{artifact_id}-{len(files)}{suffix}'
                    destination.write_text(json.dumps(report) if suffix == '.json' else '\n'.join((json.dumps(item) for item in report)), encoding='utf-8')
                    files.append(str(destination))
        summary['collectedReports'] = len(files)
        if not files:
            raise ValueError('No mandatory qualification reports collected')
        environment = {**os.environ, 'GITHUB_SHA': candidate}
        result = subprocess.run(['node', 'scripts/certops-release-qualification.js', '--profile', profile, candidate, *files], cwd=ROOT, env=environment, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            raise ValueError('Mandatory release matrix qualification failed')
        validate_matrix_summary(json.loads(result.stdout), candidate, len(selected_matrix['slots']), coverage, selection)
        summary['status'] = 'passed'
        summary.update(qualification_profiles.summary_fields(selection, True))
    finally:
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print('Committed mandatory matrix passed; full feature specifications remain separately tracked' if profile == 'full' else f'Declared {profile} profile passed; omitted environments remain unqualified')

def failed_profile_summary(arguments, environment, root=ROOT):
    candidate = environment.get('CERTOPS_RELEASE_CANDIDATE', '')
    result = {'schemaVersion': 1, 'candidateSha': candidate if re.fullmatch('[a-f0-9]{40}', candidate) else None, 'status': 'failed', 'qualificationProfile': 'invalid', 'qualificationScope': 'unverified-profile-failure', 'selectedSlotIds': [], 'omittedSlotIds': [], 'fullMatrixQualified': False, 'allFeaturesQualified': False}
    try:
        profile = qualification_profiles.requested_profile(arguments, environment)
        result['qualificationProfile'] = profile
        matrix = json.loads((root / 'docs/certops/qualification-suites.json').read_text())
        selected = qualification_profiles.select_profile(matrix, profile)
        result.update(qualification_profiles.summary_fields(selected))
        result['mandatoryEnvironments'] = len(selected['selectedSlotIds'])
    except (ValueError, OSError, TypeError, KeyError):
        pass
    return result
if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception as error:
        output = ROOT / 'qualification-results/release-collection'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'summary.json').write_text(json.dumps(failed_profile_summary(sys.argv[1:], os.environ), indent=2) + '\n', encoding='utf-8')
        print(str(error) if isinstance(error, ValueError) else 'Qualification collection failed', file=sys.stderr)
        sys.exit(1)
