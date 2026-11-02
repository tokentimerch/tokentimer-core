"""Closed native-console projection; no browser or native execution occurs here."""
import copy
import re

SUITE = "linux-native-acme-browser-console"
FIELD = "nativeAcmeBrowserConsole"
FLAGS = "actualSignedNativeClaim actualFirstNativeLineRenderedWhileRunning exactOwnedClientBarrierReleased sameClaimCompletedStream actualCompletionLineRendered zeroBrowserCertOpsWrites zeroLostOrDroppedLines claimBoundVerificationEvidence managedLeafMatchesTrustedTls retainedBrowserClosed".split()


def require(condition):
    if not condition:
        raise ValueError("Invalid native Linux ACME browser-console proof")


def verify_workflow(report, workflow):
    if isinstance(report, dict) and report.get("suite") == SUITE:
        require(workflow == ".github/workflows/certops-acme-native-console.yml")


def fields(data):
    if data.get("suite") != SUITE:
        return {}
    require(data.get("platform") == "linux" and data.get("architecture") == "x64")
    env = data.get("qualificationEnvironment")
    require(isinstance(env, dict) and env.get("osFamily") == "linux" and env.get("measurement") == "native")
    require(env.get("distributionId") == "ubuntu" and env.get("distributionVersion") == "24.04" and env.get("executionSurface") == "host" and env.get("libc") == "glibc")
    value = data.get(FIELD)
    require(isinstance(value, dict) and set(value) == {"schemaVersion", "scope", "client", "jobId", "certificateId", "claimId", "agentId", "fingerprint", "firstLineSha256", "completionLineSha256", "acceptedLines", "browserCertOpsWrites", *FLAGS})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1)
    require(value["scope"] == "browser-console-of-real-linux-acme-agent-claim" and value["client"] == "certbot")
    for name in ("jobId", "certificateId", "claimId", "agentId"):
        require(isinstance(value[name], str) and re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value[name]))
    for name in ("fingerprint", "firstLineSha256", "completionLineSha256"):
        require(isinstance(value[name], str) and re.fullmatch(r"[a-f0-9]{64}", value[name]))
    require(value["firstLineSha256"] != value["completionLineSha256"])
    require(type(value["acceptedLines"]) is int and 2 <= value["acceptedLines"] <= 2000)
    require(type(value["browserCertOpsWrites"]) is int and value["browserCertOpsWrites"] == 0)
    for flag in FLAGS:
        require(value[flag] is True)
    return {FIELD: copy.deepcopy(value)}
