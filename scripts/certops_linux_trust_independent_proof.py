"""Closed public native independent-root proof, never execution qualification."""
import copy
import re

SUITE = "linux-trust-host"
FIELD = "nativeIndependentTrustRoots"
FLAGS = "twoActualIndependentRoots twoActualIssuedLeaves bothInitiallyUntrusted bothNativeDistributionsFinalized bothDefaultDerivedLeafTrustVerified firstActualOwnedRevoke firstLeafNowUntrusted secondSourceBytesAndIdentityUnchanged secondReceiptBytesAndIdentityUnchanged secondDerivedReferencePreserved secondDefaultLeafTrustPreserved secondActualOwnedRevoke bothFinallyUntrusted ownershipGuardReleased".split()
CONFLICT_FIELD = "nativeTrustReceiptConflict"
CONFLICT_FLAGS = "actualSeparateWriterProcesses firstNativeRefreshCompleted secondActualRefreshFinalized actualNativeRefreshesNoOverride wrapperReleaseConsumed losingWriterConflictReported freshDefaultProcessReplay freshDefaultProcessRevoke unrelatedRootSourceAndReceiptUnchanged unrelatedDefaultLeafTrustPreserved ownedRootFinallyUntrusted ownedWorkersClosed ownedInheritedProcessGroupsDrained ownershipGuardReleased".split()


def verify_conflict(p, family):
    require(isinstance(p, dict) and set(p) == {"schemaVersion", "scope", "family", "writerCount", "losingFailureCategory", "firstJobId", "secondJobId", "fingerprints", "serializationQualified", "partialWriteRecoveryQualified", "detachedDescendantContainmentQualified", *CONFLICT_FLAGS})
    require(type(p["schemaVersion"]) is int and p["schemaVersion"] == 1 and p["scope"] == "native-linux-two-process-fixture-wrapped-refresh-receipt-conflict-recovery")
    require(p["family"] == family and type(p["writerCount"]) is int and p["writerCount"] == 2)
    require(p["losingFailureCategory"] == "receipt_finalize_conflict" and p["serializationQualified"] is False and p["partialWriteRecoveryQualified"] is False and p["detachedDescendantContainmentQualified"] is False)
    for name in ("firstJobId", "secondJobId"):
        require(isinstance(p[name], str) and re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", p[name]))
    require(p["firstJobId"] != p["secondJobId"])
    rows = p["fingerprints"]
    require(isinstance(rows, list) and len(rows) == 2 and all(isinstance(row, str) and re.fullmatch(r"[a-f0-9]{64}", row) for row in rows) and len(set(rows)) == 2)
    for flag in CONFLICT_FLAGS:
        require(p[flag] is True)


def require(condition):
    if not condition:
        raise ValueError("Invalid native independent-root evidence")


def project_report(value):
    require(isinstance(value, dict) and value.get("suite") == SUITE and value.get("platform") == "linux" and value.get("architecture") == "x64")
    p, e = value.get(FIELD), value.get("qualificationEnvironment")
    require(isinstance(p, dict) and set(p) == {"schemaVersion", "scope", "family", "derivedReferenceKind", "rootFingerprints", "leafFingerprints", *FLAGS})
    require(type(p["schemaVersion"]) is int and p["schemaVersion"] == 1 and p["scope"] == "native-linux-two-independent-roots-selective-owned-revocation")
    require(p["family"] in ("debian", "rhel"))
    require(p["derivedReferenceKind"] == ("native-source-symlink" if p["family"] == "debian" else "native-derived-certificate"))
    for field in ("rootFingerprints", "leafFingerprints"):
        rows = p[field]
        require(isinstance(rows, list) and len(rows) == 2 and all(isinstance(row, str) and re.fullmatch(r"[a-f0-9]{64}", row) for row in rows) and len(set(rows)) == 2)
    require(len(set(p["rootFingerprints"] + p["leafFingerprints"])) == 4)
    for flag in FLAGS:
        require(p[flag] is True)
    require(isinstance(e, dict) and e.get("measurement") == "native" and e.get("osFamily") == "linux")
    require((p["family"] == "debian" and e.get("distribution") == "ubuntu" and e.get("osVersion") in ("22.04", "24.04") and e.get("executionSurface") == "disposable-vm") or (p["family"] == "rhel" and e.get("distribution") == "almalinux" and e.get("osVersion") == "9.6" and e.get("executionSurface") == "disposable-container"))
    verify_conflict(value.get(CONFLICT_FIELD), p["family"])
    return {FIELD: copy.deepcopy(p), CONFLICT_FIELD: copy.deepcopy(value[CONFLICT_FIELD])}
