"""Closed measured alive/default-grace projection; no native execution or clock injection."""
import re
from datetime import datetime
SCOPE = 'installed-windows-alive-agent-default-hard-grace-orphan-classification'
FLAGS = ['actualPublicSignedNativeRenewal', 'actualOwnedCommandBarrier', 'nativeGeneratedKeyBeforeDelegation', 'completedNativeMutationAndTrustedTls', 'exactCurrentClaimDurableSuccessOutbox', 'currentClaimNativeVerificationEvidence', 'actualOriginalResult503BeforeForward', 'originalPersistedLeaseUnmodified', 'authenticatedHeartbeatContinued', 'actualDefaultReaperDeferredBeforeGrace', 'actualDefaultReaperTerminalizedAfterGrace', 'originalOrphanReconciliationPreserved', 'ownedNativeCustodyPreserved', 'storedOperatorProfilePreserved', 'retainedOriginalNativeHandlesDrainedBeforeCleanup', 'exactOwnedCleanupCompleted']
TIMES = ['leaseRenewedAt', 'leaseExpiresAt', 'nativeCompletedAt', 'deferredObservedAt', 'deferredHeartbeatAt', 'terminalObservedAt', 'terminalHeartbeatAt']
FALSE_FLAGS = ["originalOperationAutomaticallyRecovered", "deployedWorkerLoopQualified", "atomicTreeContainmentQualified", "claimPollingAvailabilityQualified"]
BASE = ["scope", "jobId", "claimId", "attemptCount", "terminalStatus", "defaultLeaseMs", "defaultHardGraceMs", "defaultOfflineMs", "waitedMonotonicMs", "heartbeatUptimeSeconds", "fingerprints", "spkiFingerprints"]

def epoch(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value):
        raise ValueError("Canonical measured UTC required")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000
    except ValueError as error:
        raise ValueError("Invalid measured UTC") from error

def fields(report):
    p = report.get("nativeWindowsAliveGrace")
    env = report.get("qualificationEnvironment", {})
    if (not isinstance(p, dict) or report.get("platform") != "win32" or report.get("architecture") != "x64"
            or env.get("osFamily") != "windows" or env.get("osVersion") not in ("2022", "2025")
            or type(env.get("productType")) is not int or env["productType"] not in (2, 3)
            or env.get("identity") != "LocalSystem" or env.get("nativeLanguage") != "en-US"
            or env.get("measurement") != "native" or env.get("architecture") != "x64"
            or report.get("cleanup", {}).get("status") != "passed"):
        raise ValueError("Native Windows alive/default-grace environment and cleanup required")
    if p.get("scope") != SCOPE or any(p.get(k) is not True for k in FLAGS) or any(p.get(k) is not False for k in FALSE_FLAGS):
        raise ValueError("Incomplete alive/default-grace facts or unsupported promoted claim")
    for key in ("jobId", "claimId"):
        if not isinstance(p.get(key), str) or not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", p[key]):
            raise ValueError("Actual job/claim identity required")
    if type(p.get("attemptCount")) is not int or p["attemptCount"] != 1 or p.get("terminalStatus") != "orphaned_unknown_effect":
        raise ValueError("Actual nonreplayed orphan required")
    for key, value in (("defaultLeaseMs",900000),("defaultHardGraceMs",3600000),("defaultOfflineMs",600000)):
        if type(p.get(key)) is not int or p[key] != value:
            raise ValueError("Unchanged production defaults required")
    uptime = p.get("heartbeatUptimeSeconds")
    if (not isinstance(uptime,list) or len(uptime)!=3 or any(type(x) is not int or not 0<=x<=9007199254740991 for x in uptime)
            or not uptime[0]<uptime[1]<uptime[2]):
        raise ValueError("Measured heartbeat-only uptime progression required")
    waited=p.get("waitedMonotonicMs")
    if type(waited) is not int or not 4500000<=waited<=9007199254740991:
        raise ValueError("Real unchanged default elapsed window required")
    t={key:epoch(p.get(key)) for key in TIMES}
    if (t["leaseExpiresAt"]-t["leaseRenewedAt"]!=900000
            or not t["nativeCompletedAt"]<t["leaseExpiresAt"] or t["nativeCompletedAt"]>t["deferredObservedAt"]
            or not t["leaseExpiresAt"]<t["deferredObservedAt"]<=t["leaseExpiresAt"]+3600000
            or not t["terminalObservedAt"]>t["leaseExpiresAt"]+3600000
            or not t["terminalHeartbeatAt"]>t["deferredHeartbeatAt"]):
        raise ValueError("Real default lease/grace chronology required")
    for observed,heartbeat in (("deferredObservedAt","deferredHeartbeatAt"),("terminalObservedAt","terminalHeartbeatAt")):
        if not 0<=t[observed]-t[heartbeat]<600000:
            raise ValueError("Actual fresh heartbeat required")
    for key in ("fingerprints","spkiFingerprints"):
        values=p.get(key)
        if not isinstance(values,list) or len(values)!=2 or any(not isinstance(x,str) or not re.fullmatch(r"[a-f0-9]{64}",x) for x in values) or len(set(values))!=2:
            raise ValueError("Independent changed native leaf and SPKI required")
    return {key:p[key] for key in BASE+FALSE_FLAGS+TIMES+FLAGS}
