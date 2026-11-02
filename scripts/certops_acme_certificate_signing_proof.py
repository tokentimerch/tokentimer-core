"""Closed certificate signing-rotation projection. Manual workflow_dispatch only. Not native qualification."""
import copy
import re

SUITE = "native-certificate-signing-rotation"
FIELD = "nativeCertificateSigningRotation"
SCOPE = "isolated-native-certificate-inflight-operator-signing-rotation"
FLAGS = [
    "initialDatabaseEmpty",
    "soleOwnedActiveAgent",
    "originalUnmodifiedV2ClaimObserved",
    "actualOldClaimAuthenticatedBeforeRotation",
    "oldCommandHeldBeforeNativeCa",
    "operatorBeginSupersededOriginalKey",
    "actualHeartbeatPinAcknowledged",
    "nonforceCompleteBeforeOldCommandRelease",
    "oldKeyJobRealCaKeyAndTrustedTls",
    "newKeyJobRealCaKeyAndTrustedTls",
    "currentClaimEvidenceAndSingleDispatch",
    "operatorProfileAndProtectedConfigurationPreserved",
    "originalAgentIdentityPreserved",
    "naturalCommandPidfdDrain",
    "ownedAgentPidfdDrain",
    "ownedTlsAndGatewayDrain",
    "ownedDatabaseAndPrivateCleanup",
]
FALSE_FLAGS = ["sharedFleetQualified", "forcedCompletionQualified", "atomicTreeContainmentQualified"]
UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
DIGEST = re.compile(r"[a-f0-9]{64}")
KEY_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}")


def require(ok):
    if not ok:
        raise ValueError("Invalid certificate signing rotation evidence")


def project_report(report):
    require(isinstance(report, dict) and report.get("suite") == SUITE and report.get("platform") == "linux" and report.get("architecture") == "x64")
    proof = report.get(FIELD)
    require(isinstance(proof, dict) and set(proof) == {"scope", "certificateId", "jobIds", "claimIds", "signingKeyIds", "fingerprints", "spkiFingerprints", "client", "rotatePrivateKey", *FALSE_FLAGS, *FLAGS})
    require(proof["scope"] == SCOPE and proof["client"] == "certbot" and isinstance(proof["rotatePrivateKey"], bool))
    require(isinstance(proof["certificateId"], str) and UUID.fullmatch(proof["certificateId"]))
    for name in ("jobIds", "claimIds"):
        values = proof[name]
        require(isinstance(values, list) and len(values) == 2 and all(isinstance(item, str) and UUID.fullmatch(item) for item in values) and len(set(values)) == 2)
    keys = proof["signingKeyIds"]
    require(isinstance(keys, list) and len(keys) == 2 and all(isinstance(item, str) and KEY_ID.fullmatch(item) for item in keys) and len(set(keys)) == 2)
    for name in ("fingerprints", "spkiFingerprints"):
        values = proof[name]
        require(isinstance(values, list) and len(values) == 2 and all(isinstance(item, str) and DIGEST.fullmatch(item) for item in values))
    require(proof["fingerprints"][0] != proof["fingerprints"][1])
    require((proof["spkiFingerprints"][0] != proof["spkiFingerprints"][1]) is proof["rotatePrivateKey"])
    require(all(proof[name] is False for name in FALSE_FLAGS) and all(proof[name] is True for name in FLAGS))
    environment = report.get("qualificationEnvironment")
    require(isinstance(environment, dict) and environment.get("osFamily") == "linux" and environment.get("distributionId") == "ubuntu" and environment.get("distributionVersion") == "24.04" and environment.get("distribution") == "ubuntu" and environment.get("osVersion") == "24.04" and environment.get("executionSurface") == "host" and environment.get("measurement") == "native")
    return {FIELD: copy.deepcopy(proof)}
