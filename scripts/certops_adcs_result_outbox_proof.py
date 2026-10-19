"""Closed bounded public observations for actual AD CS result delivery recovery."""
import re

SCOPE = "installed-adcs-native-success-durable-result-production-retry-after-scm-restart"
FLAGS = (
    "actualNativeInstallationBeforeResultDelivery", "originalSignedClaimPreserved",
    "actualDurableRetryDeadline", "ordinaryRetainedHandleServiceStops",
    "sameProtectedConfigurationAndCredential", "sameLeafKeyAndCaRequestAfterRestart",
    "singleConsumedResultNonce", "claimBoundInstalledEvidence", "originalApiRestoredAndHealthy",
    "gatewayAndObserversDrained", "ownedCleanupRegistered",
)
FIELDS = ("scope", "enrollmentId", "jobId", "claimId", "requestId", "fingerprints",
          "caRequestCounts", "recordedAttempts", "retryDelayMs", "atomicTreeContainmentQualified",
          "backgroundTimerQualified", *FLAGS)


def fields(value):
    def require(condition):
        if not condition:
            raise ValueError("Invalid installed AD CS result outbox proof")

    require(isinstance(value, dict) and all(key in value for key in FIELDS))
    require(value["scope"] == SCOPE)
    for key in ("enrollmentId", "jobId", "claimId"):
        require(isinstance(value[key], str) and re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", value[key]))
    require(type(value["requestId"]) is int and 1 <= value["requestId"] <= 0xffffffff)
    fingerprints = value["fingerprints"]
    require(isinstance(fingerprints, list) and len(fingerprints) == 2 and all(isinstance(item, str) and re.fullmatch(r"[a-f0-9]{64}", item) for item in fingerprints) and len(set(fingerprints)) == 2)
    counts = value["caRequestCounts"]
    require(isinstance(counts, list) and len(counts) == 3 and all(type(item) is int and 0 <= item <= 2048 for item in counts))
    require(counts[1] == counts[0] + 1 and counts[2] == counts[1])
    attempts, delay = value["recordedAttempts"], value["retryDelayMs"]
    require(type(attempts) is int and 1 <= attempts <= 5)
    base = 15000 * 2 ** (attempts - 1)
    require(type(delay) is int and base * .8 <= delay <= base * 1.2)
    require(all(value[key] is True for key in FLAGS))
    require(value["atomicTreeContainmentQualified"] is False and value["backgroundTimerQualified"] is False)
    return {key: value[key] for key in FIELDS}
