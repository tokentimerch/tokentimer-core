"""Closed projection of native public ACME stage transport refusal proof."""
import copy
import re

SCOPES = {"real-agent-acme-filesystem", "real-agent-acme-eab-filesystem", "real-agent-acmesh-filesystem", "real-agent-acmesh-eab-filesystem", "real-agent-alpine-acmesh"}
JOURNEY = "real ACME: agent discovers public files registers claims issues renews deploys and persists independently verified certificate evidence"
FIELD = "nativeAcmeStageFaults"
FLAGS = "actualPublicIssueJobs actualClientReachedBothStages unmodifiedSignedRequests pinnedUpstreamTls ownedOrdersAndAuthorizationsBound noFaultStageForwarded noLeafInstalledOrActivated ownedDnsValuesCleaned realCaIssuanceRecovered trustedPositiveTlsVerified".split()
UUID = r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}"


def require(condition):
    if not condition:
        raise ValueError("Invalid native ACME stage transport refusal proof")


def fields(event):
    if event.get("scope") not in SCOPES or event.get("name") != JOURNEY:
        return {}
    value = event.get(FIELD)
    require(isinstance(value, dict) and set(value) == {"schemaVersion", "scope", "client", "failureOrigin", "cases", "positiveJobId", "positiveFingerprint", *FLAGS})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1)
    require(value["scope"] == "native-public-acme-client-owned-stage-transport-refusal" and value["failureOrigin"] == "owned-proxy-before-upstream-forwarding")
    require(value["client"] == ("acme.sh" if "acmesh" in event["scope"] else "certbot"))
    for flag in FLAGS:
        require(value[flag] is True)
    rows = value["cases"]
    require(isinstance(rows, list) and len(rows) == 2)
    for index, row in enumerate(rows):
        require(isinstance(row, dict) and set(row) == {"stage", "jobId", "certificateId", "refusedRequests", "forwardedFaultRequests", "acceptedAccounts", "acceptedOrders", "authorizationCount", "validAuthorizationCount", "identifiersSha256"})
        require(row["stage"] == ("new-order", "finalize")[index])
        for name in ("jobId", "certificateId"):
            require(isinstance(row[name], str) and re.fullmatch(UUID, row[name]))
        for name in ("refusedRequests", "acceptedAccounts"):
            require(type(row[name]) is int and 1 <= row[name] <= 10000)
        require(type(row["forwardedFaultRequests"]) is int and row["forwardedFaultRequests"] == 0)
        require(isinstance(row["identifiersSha256"], str) and re.fullmatch(r"[a-f0-9]{64}", row["identifiersSha256"]))
        if index == 0:
            for name in ("acceptedOrders", "authorizationCount", "validAuthorizationCount"):
                require(type(row[name]) is int and row[name] == 0)
        else:
            require(type(row["acceptedOrders"]) is int and 1 <= row["acceptedOrders"] <= 32)
            require(type(row["authorizationCount"]) is int and 1 <= row["authorizationCount"] <= 16)
            require(type(row["validAuthorizationCount"]) is int and row["validAuthorizationCount"] == row["authorizationCount"])
    require(rows[0]["certificateId"].lower() != rows[1]["certificateId"].lower())
    require(rows[0]["jobId"].lower() != rows[1]["jobId"].lower() and rows[0]["identifiersSha256"] == rows[1]["identifiersSha256"])
    require(isinstance(value["positiveJobId"], str) and re.fullmatch(UUID, value["positiveJobId"]) and value["positiveJobId"].lower() not in {row["jobId"].lower() for row in rows})
    require(isinstance(value["positiveFingerprint"], str) and re.fullmatch(r"[a-f0-9]{64}", value["positiveFingerprint"]))
    return {FIELD: copy.deepcopy(value)}
