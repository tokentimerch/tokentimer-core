"""Closed public stopped/offline native evidence projection; never executes a clock or reaper."""
import math
import re
from datetime import datetime

SCOPE = "installed-windows-stop-during-dns-default-expiry-offline-reconciliation"
FLAGS = ["realPublicManualRenewalAndSignedClaim","realHeldDnsPostAfterNativeCngJournal","ownedResultDeliveryBarrierBeforeForward","retainedOriginalNativeHandlesBeforeStop","allCapturedDescendantsExited","nativeHandlesAndObserverClosed","sameServingCngBindingAndTrustedTlsWhileStopped","originalPersistedLeaseUnmodified","actualDefaultProductionReaperInvoked","originalAttemptNeverReplayed","actualOriginalJournalOrDurableOutcomePreserved","originalUnacceptedKeyAbsentAfterRestart","freshAuthenticatedRestart","freshPublicManualRenewalSucceeded","freshLeafSpkiProtectedKeyAndTrustedTls","storedProfilePreserved","exactOwnedCleanupCompleted"]
TIMES = ["leaseRenewedAt","leaseExpiresAt","stoppedObservedAt","lastSeenAt","databaseObservedAt","reapedObservedAt","restartedObservedAt","freshRenewalObservedAt"]
FALSE_FLAGS = ["defaultAliveGraceElapsedQualified", "deployedWorkerLoopQualified", "atomicTreeContainmentQualified", "originalOperationAutomaticallyRecovered"]
BASE = ["scope", "originalJobId", "originalClaimId", "freshJobId", "stopOutcome", "capturedProcessCount", "originalAttemptCount", "originalTerminalStatus", "defaultLeaseMs", "defaultOfflineMs", "defaultHardGraceMs", "waitedMonotonicMs", "fingerprints", "spkiFingerprints"]

def epoch(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value):
        raise ValueError("Canonical measured UTC required")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000
    except ValueError as error:
        raise ValueError("Invalid measured UTC") from error

def fields(report):
    p = report.get("nativeWindowsStoppedOffline")
    env = report.get("qualificationEnvironment", {})
    if (not isinstance(p, dict) or report.get("platform") != "win32" or report.get("architecture") != "x64"
            or env.get("osFamily") != "windows" or env.get("osVersion") not in ("2022", "2025")
            or type(env.get("productType")) is not int or env["productType"] not in (2, 3)
            or env.get("identity") != "LocalSystem" or env.get("nativeLanguage") != "en-US"
            or env.get("measurement") != "native" or env.get("architecture") != "x64"
            or report.get("cleanup", {}).get("status") != "passed"):
        raise ValueError("Native Windows stopped/offline environment and cleanup required")
    if p.get("scope") != SCOPE or any(p.get(k) is not True for k in FLAGS) or any(p.get(k) is not False for k in FALSE_FLAGS):
        raise ValueError("Incomplete stopped/offline facts or unsupported promoted claim")
    for key in ("originalJobId", "originalClaimId", "freshJobId"):
        if not isinstance(p.get(key), str) or not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", p[key]):
            raise ValueError("Actual job/claim identity required")
    if (p["originalJobId"] == p["freshJobId"] or p.get("stopOutcome") not in ("graceful-stop-observed", "host-timeout-fallback-observed")
            or type(p.get("capturedProcessCount")) is not int or not 2 <= p["capturedProcessCount"] <= 128
            or type(p.get("originalAttemptCount")) is not int or p["originalAttemptCount"] != 1
            or p.get("originalTerminalStatus") != "orphaned_unknown_effect"):
        raise ValueError("Actual stop and nonreplayed orphan facts required")
    for key, value in (("defaultLeaseMs", 900000), ("defaultOfflineMs", 600000), ("defaultHardGraceMs", 3600000)):
        if type(p.get(key)) is not int or p[key] != value:
            raise ValueError("Unchanged production defaults required")
    t = {key: epoch(p.get(key)) for key in TIMES}
    due = max(t["leaseExpiresAt"], t["lastSeenAt"] + p["defaultOfflineMs"])
    waited = p.get("waitedMonotonicMs")
    if (t["leaseExpiresAt"] - t["leaseRenewedAt"] != p["defaultLeaseMs"]
            or not t["leaseRenewedAt"] <= t["stoppedObservedAt"] <= t["databaseObservedAt"]
            or not t["lastSeenAt"] <= t["databaseObservedAt"] < due <= t["reapedObservedAt"]
            or not t["reapedObservedAt"] <= t["restartedObservedAt"] < t["freshRenewalObservedAt"]
            or type(waited) not in (int, float) or not math.isfinite(waited)
            or not due - t["databaseObservedAt"] - 1000 <= waited < 1200000):
        raise ValueError("Actual default deadline and monotonic wait required")
    for key in ("fingerprints", "spkiFingerprints"):
        values = p.get(key)
        if not isinstance(values, list) or len(values) != 2 or any(not isinstance(x, str) or not re.fullmatch(r"[a-f0-9]{64}", x) for x in values) or len(set(values)) != 2:
            raise ValueError("Independent changed native leaf and SPKI required")
    return {key: p[key] for key in BASE + FALSE_FLAGS + TIMES + FLAGS}
