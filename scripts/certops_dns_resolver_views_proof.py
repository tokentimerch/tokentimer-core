"""Closed public native DNS-view proof. Never runs DNS/provider operations."""
import copy

SUITE = "dns-routing-host"
FIELD = "nativeResolverViews"
FLAGS = "twoIndependentNativeDnsViews unmodifiedDnsQueriesAndResponses realProviderWriteObserved allRefusedReachableDivergence allRecoveredAfterRealSecondViewWrite quorumAcceptedOneRealView bothConfiguredEndpointsActuallyQueried nativeHookCleanupVerified ownedRecordsAbsentFromBothViews ownedUdpSocketsAndChildDrained".split()


def require(condition):
    if not condition:
        raise ValueError("Invalid native configured DNS views proof")


def project_report(value):
    require(isinstance(value, dict) and value.get("suite") == SUITE and value.get("platform") == "linux" and value.get("architecture") == "x64")
    p, e = value.get(FIELD), value.get("qualificationEnvironment")
    require(isinstance(p, dict) and set(p) == {"schemaVersion", "scope", "allAttempts", "recoveryAttempts", "quorumAttempts", "allForwarded", "quorumForwarded", *FLAGS})
    require(type(p["schemaVersion"]) is int and p["schemaVersion"] == 1 and p["scope"] == "native-dns-hook-two-configured-views-all-quorum")
    for name, minimum in (("allAttempts", 2), ("recoveryAttempts", 1), ("quorumAttempts", 1)):
        require(type(p[name]) is int and minimum <= p[name] <= 100)
    for name, minimum in (("allForwarded", 2), ("quorumForwarded", 1)):
        require(isinstance(p[name], list) and len(p[name]) == 2 and all(type(n) is int and minimum <= n <= 1000 for n in p[name]))
    for flag in FLAGS:
        require(p[flag] is True)
    require(isinstance(e, dict) and e.get("measurement") == "native" and e.get("osFamily") == "linux" and e.get("distributionId") == "ubuntu" and e.get("distributionVersion") == "24.04" and e.get("executionSurface") == "host")
    return {FIELD: copy.deepcopy(p)}
