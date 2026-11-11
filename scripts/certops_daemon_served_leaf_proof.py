"""Closed public direct-native daemon rollback proof, not signed/API execution."""
import copy
import re

SUITES = {"nginx-host", "apache-host", "haproxy-host"}
FIELD = "nativeDaemonServedLeafMismatch"
FLAGS = "actualTrustedPredecessor actualCandidateDeployedBeforeVerification candidatePairIndependentlyObserved trustedPredecessorStillServedAfterReload actualNativeValidationAndReloadSucceeded productionRollbackRestoredPair actualFingerprintMismatchRefused restoredPairBytesAndPermissions trustedPredecessorAfterRollback exactOwnedConfigurationRestored actualValidationAndReloadRecovered privateStagingPreserved ownershipGuardReleased".split()


def require(condition):
    if not condition:
        raise ValueError("Invalid native consuming-daemon rollback proof")


def project_report(value):
    require(isinstance(value, dict) and value.get("suite") in SUITES and value.get("platform") == "linux" and value.get("architecture") == "x64")
    p, e = value.get(FIELD), value.get("qualificationEnvironment")
    require(isinstance(p, dict) and set(p) == {"schemaVersion", "scope", "service", "evidenceTransport", "fingerprints", *FLAGS})
    require(type(p["schemaVersion"]) is int and p["schemaVersion"] == 1 and p["scope"] == "native-consuming-daemon-production-coordinator-served-leaf-mismatch-rollback")
    require(p["service"] in ("nginx", "apache", "haproxy") and p["service"] + "-host" == value["suite"])
    require(p["evidenceTransport"] == "read-only-local-recorder-not-signed-api")
    original = value.get("nativeDaemonCoordinatorRollback")
    require(isinstance(original, dict) and original.get("service") == p["service"] and original.get("fingerprints") == p["fingerprints"])
    rows = p["fingerprints"]
    require(isinstance(rows, list) and len(rows) == 2 and all(isinstance(row, str) and re.fullmatch(r"[a-f0-9]{64}", row) for row in rows) and len(set(rows)) == 2)
    for flag in FLAGS:
        require(p[flag] is True)
    require(isinstance(e, dict) and e.get("measurement") == "native" and e.get("osFamily") == "linux" and e.get("distributionId") == "ubuntu" and e.get("distributionVersion") in ("22.04", "24.04") and e.get("executionSurface") == "host")
    return {FIELD: copy.deepcopy(p)}
