"""Closed native disabled-profile projection. Offline fixtures are not execution evidence."""
import copy
import re
import certops_acme_bulk_proof as bulk
FIELD="nativeAcmeDisabledProfile"
SCOPE="native-manual-renewal-under-disabled-automatic-profile"
FLAGS="actualOwnedPriorNativeGeneration actualPublicManagementReadd actualPublicDisable productionNowSelectionExcludesDisabled actualPublicManualAdmission actualSignedCurrentClaim actualCaLeafAndNewKey trustedTlsMatchesDeployment currentClaimVerification profileRemainsDisabledAfterSuccess actualPublicReenable productionNowSelectionIncludesEnabled executionPolicyPreserved originalServingPreserved ownedPeriodStopped retainedTlsDrained ownershipGuardReleased".split()
def require(value):
    if not value: raise ValueError("Invalid native disabled-profile manual renewal proof")
def fields(event):
    if event.get("scope")!=bulk.SCOPE or event.get("name")!=bulk.MAIN: return {}
    previous=bulk.fields(event)[bulk.FIELD]
    value=event.get(FIELD)
    require(isinstance(value,dict) and set(value)=={"scope","certificateId","profileId","jobId","claimId","fingerprints","schedulerSweepQualified","backgroundWorkerQualified",*FLAGS})
    require(value["scope"]==SCOPE)
    for key in ("certificateId","profileId","jobId","claimId"): require(isinstance(value[key],str) and re.fullmatch(bulk.UUID,value[key]))
    fingerprints=value["fingerprints"]
    require(isinstance(fingerprints,list) and len(fingerprints)==2 and all(isinstance(x,str) and re.fullmatch(r"[a-f0-9]{64}",x) for x in fingerprints) and len(set(fingerprints))==2)
    require(value["schedulerSweepQualified"] is False and value["backgroundWorkerQualified"] is False)
    for flag in FLAGS: require(value[flag] is True)
    require(value["certificateId"]==previous["certificateIds"][1] and fingerprints[0]==previous["fingerprints"][3])
    require(fingerprints[1] not in previous["fingerprints"]+[previous["originalServingFingerprint"]])
    require(value["jobId"].lower() not in {x.lower() for x in previous["issueJobIds"]+previous["jobIds"]})
    require(value["claimId"].lower() not in {x.lower() for x in previous["claimIds"]})
    return {FIELD:copy.deepcopy(value)}
