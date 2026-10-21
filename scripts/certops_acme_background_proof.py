"""Bounded public projection of actual Linux default-cron ACME renewals.

Only measured public lifecycle/generation facts survive. No worker is launched
and no private path, environment, raw log or key bytes enter collection output.
"""
import re
FIELD = "nativeAcmeBackgroundRenewals"
SCOPE = "real-linux-acme-production-worker-default-minute-cron"
FLAGS = (
    "actualDefaultCron", "defaultSqlNowSelection", "twoAutomaticRealJobs", "claimBoundVerification",
    "distinctCaLeavesAndSerials", "freshSpkiEachGeneration", "advancingActualExpiry", "actualInventoryMatchesLatest", "trustedTlsEachGeneration",
    "protectedLocalKeyEachGeneration", "unchangedStoredProfile", "unchangedManagementPeriod", "isolatedGlobalFixture",
    "ownedJobsRegistered", "workerStoppedAndGroupDrained",
)
LIFECYCLE_FLAGS = ("groupDrained", "closed", "pidfdPinnedBeforeExec", "pidfdSignalUsed", "pidfdClosed", "workerWaited")


def require(value):
    if not value:
        raise ValueError("Incomplete actual Linux worker renewal proof")


def fields(value):
    require(isinstance(value, dict) and value.get("scope") == SCOPE)
    require(value.get("client") in ("certbot", "acme.sh"))
    require(value.get("schedulerInvocation") == "actual-production-runner-default-cron")
    require(type(value.get("successfulAutomationCycles")) is int and value["successfulAutomationCycles"] == 2)
    require(all(value.get(key) is True for key in FLAGS))
    for key, pattern in (("sourceProfileId", r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}"), ("sourceProfileFingerprint", r"[a-f0-9]{64}")):
        require(isinstance(value.get(key), str) and re.fullmatch(pattern, value[key]))
    arrays = {}
    for key, count, pattern in (("jobIds", 2, r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}"), ("fingerprints", 3, r"[a-f0-9]{64}"), ("spkiFingerprints", 3, r"[a-f0-9]{64}"), ("serials", 3, r"[A-F0-9]{1,64}")):
        items = value.get(key)
        require(isinstance(items, list) and len(items) == count)
        require(all(isinstance(item, str) and re.fullmatch(pattern, item) for item in items))
        require(len(set(item.lower() for item in items)) == count)
        arrays[key] = list(items)
    expiry = value.get("expiryEpochs")
    require(isinstance(expiry, list) and len(expiry) == 3 and all(type(item) is int and item > 0 and item <= 9007199254740991 for item in expiry))
    require(expiry[0] < expiry[1] < expiry[2])
    lifecycle = value.get("workerLifecycle")
    require(isinstance(lifecycle, dict) and lifecycle.get("failed") is False)
    require(all(lifecycle.get(key) is True for key in LIFECYCLE_FLAGS))
    for key, expected in (("starts", 1), ("created", 2), ("stops", 1), ("exitCode", 0)):
        require(type(lifecycle.get(key)) is int and lifecycle[key] == expected)
    ticks = lifecycle.get("tickElapsedMs")
    require(isinstance(ticks, list) and 2 <= len(ticks) <= 8)
    require(all(type(item) is int and 0 <= item <= 480000 for item in ticks))
    require(ticks[0] <= 120000 and all(ticks[i] - ticks[i-1] >= 59000 for i in range(1, len(ticks))))
    require(type(lifecycle.get("finishes")) is int and lifecycle["finishes"] == len(ticks))
    require(type(lifecycle.get("summaries")) is int and lifecycle["summaries"] == len(ticks))
    public_lifecycle = {"failed": False, "starts": 1, "created": 2, "stops": 1, "exitCode": 0, "tickElapsedMs": list(ticks), "finishes": len(ticks), "summaries": len(ticks), **dict.fromkeys(LIFECYCLE_FLAGS, True)}
    return {"scope": SCOPE, "client": value["client"], "schedulerInvocation": value["schedulerInvocation"], "successfulAutomationCycles": 2,
            "sourceProfileId": value["sourceProfileId"], "sourceProfileFingerprint": value["sourceProfileFingerprint"], **arrays,
            "expiryEpochs": list(expiry), "workerLifecycle": public_lifecycle, **dict.fromkeys(FLAGS, True)}


SCOPES = ("real-agent-acme-filesystem", "real-agent-acme-eab-filesystem", "real-agent-acmesh-filesystem", "real-agent-acmesh-eab-filesystem", "real-agent-alpine-acmesh")
MAIN = "real ACME: agent discovers public files registers claims issues renews deploys and persists independently verified certificate evidence"


def event_fields(event):
    if event.get("scope") not in SCOPES or event.get("name") != MAIN:
        return {}
    proof = fields(event.get(FIELD))
    reuse = event.get("nativeAcmeKeyReuse")
    require(isinstance(reuse, dict))
    require(proof["client"] == ("acme.sh" if "acmesh" in event["scope"] else "certbot") == reuse.get("client"))
    require(isinstance(reuse.get("fingerprints"), list) and len(reuse["fingerprints"]) == 3)
    require(proof["fingerprints"][2] == reuse["fingerprints"][0])
    require(proof["spkiFingerprints"][2] == reuse.get("spkiFingerprint"))
    require(proof["sourceProfileId"].lower() == str(reuse.get("sourceProfileId")).lower())
    require(isinstance(reuse.get("jobIds"), list) and len(reuse["jobIds"]) == 2 and all(isinstance(item, str) for item in reuse["jobIds"]))
    require(len({item.lower() for item in proof["jobIds"] + reuse["jobIds"]}) == 4)
    return {FIELD: proof}
