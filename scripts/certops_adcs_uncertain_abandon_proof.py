"""Bounded native zero-request abandonment; never lost-submit response loss."""
import re

SUITE = "adcs-uncertain-abandon"
WORKFLOW = ".github/workflows/certops-enterprise-adcs-qualification.yml"
UUID = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
FLAGS = "ownedObserverDrained ownedTransportBlock observedSubmittingTermination actualLeaseExpiry acknowledgedPublicRecovery sameCsrAndKey noAutomaticResubmit publicAbandonAudited unacceptedKeyRemoved originalOrphanPreserved recoveryPolicyUnchanged".split()
COUNTS = "caRequestsAtFault caRequestsAfterRecovery caRequestsAfterAbandon".split()
TIMING = "leaseRemainingAtFaultMs recoveryWaitBudgetMs actualLeaseWaitMs".split()


def require(condition):
    if not condition:
        raise ValueError("Actual zero-request uncertain abandonment and owned cleanup required")


def fields(report, browser_fields):
    env = report.get("qualificationEnvironment", {})
    require(report.get("platform") == "win32" and report.get("architecture") == "x64" and report.get("cleanup", {}).get("status") == "passed")
    require(all(env.get(k) == v for k, v in dict(osFamily="windows", osVersion="2022", nativeLanguage="en-US", identity="LocalSystem", measurement="native").items()))
    p = report.get("nativeAdcsUncertainAbandon")
    require(isinstance(p, dict) and set(p) == {"scope", "nativeExecutionQualified", "disposableForestRan", "hostCapabilityAbsentIsPass", "responseLossQualified", "parentSuite", "native", "browser", "identity"})
    require(p.get("scope") == "native-zero-request-browser-abandon-and-protected-key-cleanup" and p.get("parentSuite") == "enterprise-adcs-real")
    require(p.get("nativeExecutionQualified") is True and p.get("disposableForestRan") is True and p.get("hostCapabilityAbsentIsPass") is False and p.get("responseLossQualified") is False)
    n = p.get("native")
    require(isinstance(n, dict) and set(n) == set(["scope", "resolvedIssuingCaAddress"] + FLAGS + COUNTS + TIMING))
    require(n.get("scope") == "native-zero-request-uncertain-abandon" and n.get("resolvedIssuingCaAddress") == "10.64.0.4")
    require(all(n.get(k) is True for k in FLAGS) and all(type(n.get(k)) is int and n[k] == 0 for k in COUNTS))
    require(all(type(n.get(k)) is int and 0 <= n[k] <= 900000 for k in TIMING))
    require(n["recoveryWaitBudgetMs"] == n["leaseRemainingAtFaultMs"] + 90000 and n["actualLeaseWaitMs"] + 1000 >= n["leaseRemainingAtFaultMs"])
    identity = p.get("identity")
    require(isinstance(identity, dict) and set(identity) == {"enrollmentId", "originalJobId", "recoveryJobId", "cleanupJobId", "containerName", "csrSha256", "csrSpkiSha256"})
    require(all(isinstance(identity.get(k), str) and re.fullmatch(UUID, identity[k]) for k in ("enrollmentId", "originalJobId", "recoveryJobId", "cleanupJobId")))
    require(len({identity[k] for k in ("originalJobId", "recoveryJobId", "cleanupJobId")}) == 3)
    require(identity.get("containerName") == "tokentimer-enr-" + identity["enrollmentId"])
    require(all(isinstance(identity.get(k), str) and re.fullmatch(r"[a-f0-9]{64}", identity[k]) for k in ("csrSha256", "csrSpkiSha256")))
    browser = browser_fields(p.get("browser"))
    require(browser["enrollmentId"] == identity["enrollmentId"] and browser["cleanupJobId"] == identity["cleanupJobId"])
    require(set(p["browser"]) == set(browser))
    return {**p, "browser": browser}


def verify_workflow(report, workflow):
    if report.get("suite") == SUITE and workflow != WORKFLOW:
        raise ValueError("Native uncertain abandonment requires the comprehensive root-domain workflow")
