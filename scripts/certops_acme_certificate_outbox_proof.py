"""Closed public native certificate outcome/restart projection. Offline fixtures are not native evidence."""
import copy
import re
import certops_acme_bulk_proof as bulk
import certops_acme_native_adoption_proof as adoption
FIELD = "nativeAcmeCertificateOutbox"
SCOPE = "native-certificate-success-result-outbox-and-agent-restart"
FLAGS = "actualSignedCurrentClaim actualNativeSuccessBeforeFixtureStop actualOwnedOutboxPersisted actualResultTransportRefused retainedPidfdOriginalAgentStop actualOriginalAgentClosed sameProtectedStateRestart actualProductionRetryTiming sameClaimSingleAttemptCompleted claimBoundLeafEvidence deployedPairAndTrustedTlsPreserved noAdditionalCaOrderAfterRestart noDeadLetter ownedStateReleased".split()
def require(value):
    if not value:
        raise ValueError("Invalid actual native certificate result restart proof")
def fields(event):
    if event.get("scope") != bulk.SCOPE or event.get("name") != bulk.MAIN:
        return {}
    previous = bulk.fields(event)[bulk.FIELD]
    setup = adoption.fields(event)[adoption.FIELD]
    value = event.get(FIELD)
    require(isinstance(value, dict))
    require(set(value) == {"scope", "certificateId", "jobId", "claimId", "fingerprints", "attemptCount", "extraCaOrdersAfterRestart", "fixtureStopAfterNativeSuccess", "jobCancellationQualified", *FLAGS})
    require(value["scope"] == SCOPE)
    for key in ("certificateId", "jobId", "claimId"):
        require(isinstance(value[key], str) and re.fullmatch(bulk.UUID, value[key]))
    fingerprints = value["fingerprints"]
    require(isinstance(fingerprints, list) and len(fingerprints) == 2 and all(isinstance(x, str) and re.fullmatch(r"[a-f0-9]{64}", x) for x in fingerprints) and len(set(fingerprints)) == 2)
    require(type(value["attemptCount"]) is int and value["attemptCount"] == 1)
    require(type(value["extraCaOrdersAfterRestart"]) is int and value["extraCaOrdersAfterRestart"] == 0)
    require(value["fixtureStopAfterNativeSuccess"] is True and value["jobCancellationQualified"] is False)
    for flag in FLAGS:
        require(value[flag] is True)
    require(fingerprints[0] == previous["originalServingFingerprint"])
    require(value["certificateId"] not in previous["certificateIds"])
    require(fingerprints[1] not in previous["fingerprints"] + setup["fingerprints"])
    jobs = previous["issueJobIds"] + previous["jobIds"] + setup["jobIds"] + [value["jobId"]]
    claims = previous["claimIds"] + setup["claimIds"] + [value["claimId"]]
    require(len({x.lower() for x in jobs}) == len(jobs) and len({x.lower() for x in claims}) == len(claims))
    return {FIELD: copy.deepcopy(value)}
