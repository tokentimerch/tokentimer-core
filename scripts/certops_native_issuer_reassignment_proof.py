"""Bounded public two-CA evidence projection. Does not execute native tests."""
import re

SUITE = "native-adcs-issuer-reassignment"
WORKFLOW = ".github/workflows/certops-native-issuer-reassignment.yml"
FLAGS = "twoFreshConfirmedIssuers distinctConfirmedCaKeys originNativeInstallation publicSwitchPreservesPolicy singleSwitchAudit manualRenewRefused schedulerSweepNotManualRenew renewalIssuerIsDestination distinctNativeRequests successorLeafSignedByDestination predecessorReplacedOnSameIisCoordinate nonexportableMachineKey predecessorCustodyPreserved noSyntheticDueTime ownedEnrollmentCleanupRegistered".split()
BASE = "scope renewalProtocol schedulerInvocation workerIntervalQualified nativeCell originIssuerId destinationIssuerId originCaKeySha256 destinationCaKeySha256 profileId certificateId requestIds fingerprints spkiFingerprints enrollmentIds jobIds containerNames nativeRequests".split()
CONFIGS = [r"tt-ca.lab.certops.test\TTQualificationRoot", r"tt-ca-switch.lab.certops.test\TTQualificationDestination"]
UUID = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"


def fields(report):
    p = report.get("nativeIssuerReassignment")
    env = report.get("qualificationEnvironment", {})
    if (report.get("nativeCell") != "qualified" or report.get("platform") != "win32"
            or report.get("architecture") != "x64" or report.get("cleanup", {}).get("status") != "passed"
            or any(env.get(k) != v for k, v in {"osFamily": "windows", "osVersion": "2022", "nativeLanguage": "en-US", "identity": "LocalSystem", "measurement": "native"}.items())):
        raise ValueError("Completed SYSTEM Server2022 native issuer-switch evidence required")
    if not isinstance(p, dict) or set(p) != set(BASE + FLAGS) or any(p.get(k) is not True for k in FLAGS):
        raise ValueError("Closed native issuer-switch facts required")
    if (p.get("scope") != "confirmed-adcs-issuer-switch-then-production-scheduler-renewal"
            or p.get("renewalProtocol") != "production-scheduler-sweep-after-public-issuer-switch"
            or p.get("schedulerInvocation") != "qualification-invoked-production-default-sweep"
            or p.get("workerIntervalQualified") is not False or p.get("nativeCell") != "qualified"):
        raise ValueError("Actual scheduler issuer switch required")
    for key, pattern in [(k, UUID) for k in ("originIssuerId", "destinationIssuerId", "profileId", "certificateId")] + [(k, r"[a-f0-9]{64}") for k in ("originCaKeySha256", "destinationCaKeySha256")]:
        if not isinstance(p.get(key), str) or not re.fullmatch(pattern, p[key]):
            raise ValueError("Native issuer-switch identity invalid")
    if p["originIssuerId"] == p["destinationIssuerId"] or p["originCaKeySha256"] == p["destinationCaKeySha256"]:
        raise ValueError("Two distinct confirmed issuers required")
    for key, pattern in [("requestIds", r"[1-9][0-9]{0,9}"), ("fingerprints", r"[a-f0-9]{64}"), ("spkiFingerprints", r"[a-f0-9]{64}"), ("enrollmentIds", UUID), ("jobIds", UUID), ("containerNames", r"tokentimer-enr-" + UUID)]:
        values = p.get(key)
        if (not isinstance(values, list) or len(values) != 2 or any(not isinstance(v, str) or not re.fullmatch(pattern, v) for v in values)
                or (key != "requestIds" and len(set(values)) != 2)):
            raise ValueError("Exact native issuer-switch identities required")
    if any(int(v) > 0xffffffff for v in p["requestIds"]):
        raise ValueError("Native request ID exceeds uint32")
    requests = p.get("nativeRequests")
    if not isinstance(requests, list) or len(requests) != 2:
        raise ValueError("Two independent native CA observations required")
    for i, request in enumerate(requests):
        if p["containerNames"][i] != "tokentimer-enr-" + p["enrollmentIds"][i]:
            raise ValueError("Native container must belong to the exact enrollment")
        if (not isinstance(request, dict) or set(request) != {"caConfig", "caKeySha256", "requestId", "disposition", "subjectRequestCount", "fingerprintSha256"}
                or request.get("caConfig") != CONFIGS[i]
                or request.get("caKeySha256") != p["originCaKeySha256" if i == 0 else "destinationCaKeySha256"]
                or request.get("requestId") != p["requestIds"][i] or request.get("fingerprintSha256") != p["fingerprints"][i]
                or type(request.get("disposition")) is not int or request["disposition"] != 20
                or type(request.get("subjectRequestCount")) is not int or request["subjectRequestCount"] != 1):
            raise ValueError("CA-scoped request observation mismatch")
    return {key: p[key] for key in BASE + FLAGS}


def verify_workflow(report, workflow):
    if report.get("suite") == SUITE and workflow != WORKFLOW:
        raise ValueError("Issuer switch must originate from its dedicated two-CA workflow")
