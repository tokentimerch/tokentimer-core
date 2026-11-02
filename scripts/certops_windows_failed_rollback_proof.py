"""Closed installed failed-rollback projection; no native execution."""
import re
SCOPE = "installed-public-renewal-absent-predecessor-failed-rollback-and-manual-retry"
FLAGS = ["originalNativeSniAndTrustedTls","exactOwnedShadowAndSiblingAdmission","actualPublicSignedCurrentClaim","actualCaLeafAndProtectedCngAccepted","originalPublicEntryAbsentBeforeRenewal","retainedOriginalCngPossessionWhilePublicEntryAbsent","actualCurrentClaimVerifyFailureAndFailedRollback","nativePredecessorSniAbsentAfterFailedRollback","trustedShadowAndSiblingPreserved","sameOriginalPublicAssociationRestored","holderNaturalExitAndNativeJobDrained","exactShadowRemovedBeforeRetry","freshPublicSignedRetrySucceeded","freshLeafSpkiProtectedKeyAndTrustedTls","profileAndProtectedStatePreserved","failedAcceptedLeafOwnershipRecorded","ownedEndpointCleanupCompleted"]
BASE = ['scope','certificateId','jobIds','claimIds','fingerprints','spkiFingerprints','failedJobStatus','failureCode','rolledBack','retryJobStatus','bindFailureQualified','rollbackFailureQualified','originalOperationAutomaticallyRecovered','transientNewBindingObservationQualified','appIdPreservationQualified']
def fields(report):
    p=report.get('nativeInstalledFailedRollback')
    env=report.get('qualificationEnvironment',{})
    if (not isinstance(p,dict) or report.get('platform')!='win32' or report.get('architecture')!='x64' or env.get('osFamily')!='windows' or env.get('osVersion') not in ('2022','2025') or type(env.get('productType')) is not int or env['productType'] not in (2,3) or env.get('identity')!='LocalSystem' or env.get('nativeLanguage')!='en-US' or env.get('measurement')!='native' or env.get('architecture')!='x64' or report.get('cleanup',{}).get('status')!='passed'):
        raise ValueError('Actual SYSTEM Server failed-rollback environment and cleanup required')
    if set(p)!=set(BASE+FLAGS) or p.get('scope')!=SCOPE or any(p.get(k) is not True for k in FLAGS):
        raise ValueError('Closed native failed-rollback facts required')
    if (p.get('failedJobStatus')!='failed' or p.get('failureCode')!='VERIFY_FAILED' or p.get('rolledBack') is not False or p.get('retryJobStatus')!='succeeded' or p.get('rollbackFailureQualified') is not True or any(p.get(k) is not False for k in ('bindFailureQualified','originalOperationAutomaticallyRecovered','transientNewBindingObservationQualified','appIdPreservationQualified'))):
        raise ValueError('Failed rollback and distinct manual retry required')
    uuid=r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'
    if not isinstance(p.get('certificateId'),str) or not re.fullmatch(uuid,p['certificateId']):
        raise ValueError('Actual public certificate identity required')
    for key,count,pattern in (('jobIds',2,uuid),('claimIds',2,uuid),('fingerprints',3,r'[a-f0-9]{64}'),('spkiFingerprints',3,r'[a-f0-9]{64}')):
        values=p.get(key)
        if not isinstance(values,list) or len(values)!=count or any(not isinstance(x,str) or not re.fullmatch(pattern,x) for x in values) or len(set(values))!=count:
            raise ValueError('Distinct actual public/native identities required')
    return {key:p[key] for key in BASE+FLAGS}
