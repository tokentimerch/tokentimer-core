"""Closed public projection of the actual installed native bind-failure lane."""
import hashlib
import json
import re

SCOPE = "installed-public-renewal-native-bind-failure-rollback-and-retry"
UUID = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
FLAGS = ["originalNativeSniAndTrustedTls", "actualPublicSignedCurrentClaim", "actualCaLeafAndProtectedCngAccepted", "claimBoundBindFailureAndRollbackEvidence", "nativePredecessorBindingRestored", "predecessorKeyAndTrustedTlsPreserved", "siblingBindingAndTrustedTlsPreserved", "freshPublicSignedRetrySucceeded", "freshLeafSpkiProtectedKeyAndTrustedTls", "profileAndProtectedStatePreserved", "failedAcceptedLeafOwnershipRecorded", "ownedEndpointCleanupCompleted"]
BASE = ["scope", "certificateId", "jobIds", "claimIds", "fingerprints", "spkiFingerprints", "failedJobStatus", "failureCode", "rolledBack", "retryJobStatus", "bindFailureQualified", "rollbackFailureQualified", "expiryCleanupQualified", "transientNewBindingObservationQualified", "appIdPreservationQualified", "nativeInterposer", "serviceEnvironmentRestored"]
NATIVE = ["jobId", "selector", "candidateThumbprint", "predecessorThumbprint", "candidateFingerprintSha256", "predecessorFingerprintSha256", "seedExitCode", "forwardedExitCode", "nativeErrorCode", "originalArgv", "originalArgvSha256", "systemNetshSha256", "nativeChildrenDrained", "captureOverflow", "drainFailure", "certificateStoreModified"]

def require(condition):
    if not condition:
        raise ValueError("Actual installed native bind failure, rollback, custody and cleanup required")

def match(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None

def fields(report):
    env = report.get("qualificationEnvironment", {})
    require(report.get("platform") == "win32" and report.get("architecture") == "x64" and report.get("cleanup", {}).get("status") == "passed")
    require(env.get("osFamily") == "windows" and env.get("osVersion") in ("2022", "2025") and type(env.get("productType")) is int and env["productType"] in (2, 3))
    require(env.get("identity") == "LocalSystem" and env.get("nativeLanguage") == "en-US" and env.get("measurement") == "native" and env.get("architecture") == "x64")
    p = report.get("nativeInstalledBindFailure")
    require(isinstance(p, dict) and set(p) == set(BASE + FLAGS) and p.get("scope") == SCOPE)
    require(all(p.get(key) is True for key in FLAGS + ["rolledBack", "bindFailureQualified", "serviceEnvironmentRestored"]))
    require(all(p.get(key) is False for key in ["rollbackFailureQualified", "expiryCleanupQualified", "transientNewBindingObservationQualified", "appIdPreservationQualified"]))
    require(p.get("failedJobStatus") == "failed" and p.get("failureCode") == "BIND_FAILED" and p.get("retryJobStatus") == "succeeded" and match(UUID, p.get("certificateId")))
    for key, count, pattern in (("jobIds", 2, UUID), ("claimIds", 2, UUID), ("fingerprints", 3, r"[a-f0-9]{64}"), ("spkiFingerprints", 3, r"[a-f0-9]{64}")):
        values = p.get(key)
        require(isinstance(values, list) and len(values) == count and all(match(pattern, value) for value in values) and len(set(values)) == count)
    n = p.get("nativeInterposer")
    require(isinstance(n, dict) and set(n) == set(NATIVE) and n.get("jobId") == p["jobIds"][0])
    require(n.get("candidateFingerprintSha256") == p["fingerprints"][1] and n.get("predecessorFingerprintSha256") == p["fingerprints"][0])
    require(match(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?:[1-9][0-9]{0,4}", n.get("selector")) and len(n["selector"]) <= 259 and int(n["selector"].rsplit(":", 1)[1]) <= 65535)
    require(all(match(r"[A-F0-9]{40}", n.get(key)) for key in ("candidateThumbprint", "predecessorThumbprint")) and n["candidateThumbprint"] != n["predecessorThumbprint"])
    require(type(n.get("seedExitCode")) is int and n["seedExitCode"] == 0 and type(n.get("forwardedExitCode")) is int and n["forwardedExitCode"] > 0 and n["forwardedExitCode"] != 197 and type(n.get("nativeErrorCode")) is int and n["nativeErrorCode"] == 183)
    require(n.get("nativeChildrenDrained") is True and all(n.get(key) is False for key in ("captureOverflow", "drainFailure", "certificateStoreModified")))
    require(all(match(r"[a-f0-9]{64}", n.get(key)) for key in ("originalArgvSha256", "systemNetshSha256")))
    argv = n.get("originalArgv")
    require(isinstance(argv, list) and 7 <= len(argv) <= 32 and all(isinstance(arg, str) and len(arg) <= 4096 and not re.search(r"[\x00-\x1f]", arg) for arg in argv) and argv[:3] == ["http", "add", "sslcert"])
    require(all(match(r"[a-zA-Z][a-zA-Z0-9]*=.+", arg) for arg in argv[3:]))
    params = [arg.split("=", 1) for arg in argv[3:]]
    require(len({key.lower() for key, _ in params}) == len(params))
    values = {key.lower(): value for key, value in params}
    require(values.get("hostnameport", "").lower() == n["selector"].lower() and values.get("certhash", "").upper() == n["candidateThumbprint"] and values.get("certstorename", "").lower() == "my" and match(r"\{" + UUID + r"\}", values.get("appid", "").lower()))
    require(hashlib.sha256(json.dumps(argv, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest() == n["originalArgvSha256"])
    return {key: p[key] for key in BASE + FLAGS}
