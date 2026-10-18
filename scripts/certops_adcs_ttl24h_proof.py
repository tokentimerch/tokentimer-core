"""Closed public projection of actual default-24h AD CS native outcomes.

This validates report syntax and scope, never native execution or Azure authority.
The collector authenticates immutable prepare receipts separately before projection.
"""
import copy
from datetime import datetime
import re

SUITE = "windows-domain-adcs-default-ttl24h"
FIELD = "nativeAdcsTtl24h"
SCOPE = "real-default24h-adcs-preflight-and-validation-expiry"
AUTH_FIELDS = "candidateSha prepareRunId prepareRunAttempt nonce vmId nodeSha256 keeperSha256 originalCreatedAt preparedSha256 processId processCreatedAt bootTime taskXmlSha256".split()
ID_FIELDS = "workspaceId agentRowId issuerId installedEnrollmentId deferredEnrollmentId expiredContinuationJobId managedCertificateId profileId freshPreflightJobId freshRenewalJobId freshEnrollmentId".split()
TIMING_FIELDS = "residentStartedAt residentFinishedAt monotonicElapsedMs preDeadlineObservedAt keptObservationCount maximumObservationGapMs".split()
FLAGS = "samePreparedVmBoot noBackgroundSchedulerDuringResident scopedCrlFaultRestoredBeforeResident apiTlsCertificateCoversHardLease staleNativePinRefused staleNativeTemplateRefused apiWaitingForFreshPreflight staleSweepCreatedZero originalDeadlineSurvivedResident defaultDeadlineElapsed exactUnacceptedKeyRemoved incomingCertificateNeverAccepted predecessorCustodyAndTrustedTlsPreserved originalCaRequestNotResubmitted freshPublicPreflightRestoredAdmission freshNativeIssuanceAndCutover noDateOrJournalOverrides".split()
FIELDS = AUTH_FIELDS + ID_FIELDS + TIMING_FIELDS + FLAGS + "scope defaultValidationTimeoutSeconds configuredValidationTimeoutSeconds nativeAndCaClocks schedulerInvocation requestIds fingerprints spkiFingerprints caRequestCounts snapshotSha256 deadlineAt".split()
DAY, HOUR = 86400000, 3600000


def require(condition):
    if not condition:
        raise ValueError("Invalid actual default24h AD CS native proof")


def match(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def epoch(value):
    require(match(value, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,7}Z"))
    try:
        # JavaScript Date retains milliseconds; truncate the native 100ns suffix.
        parsed = datetime.strptime(value[:23] + "Z", "%Y-%m-%dT%H:%M:%S.%fZ")
        delta = parsed - datetime(1970, 1, 1)
        return (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000
    except ValueError:
        raise ValueError("Invalid actual public UTC timestamp") from None


def verify_proof(proof):
    require(isinstance(proof, dict) and set(proof) == set(FIELDS))
    require(proof["scope"] == SCOPE and type(proof["defaultValidationTimeoutSeconds"]) is int and proof["defaultValidationTimeoutSeconds"] == 86400)
    require(proof["configuredValidationTimeoutSeconds"] is None and proof["nativeAndCaClocks"] == "actual" and proof["schedulerInvocation"] == "production-default-clock-stale-then-fresh-sweeps")
    require(match(proof["candidateSha"], r"[a-f0-9]{40}"))
    for key in ("nonce", "nodeSha256", "keeperSha256", "preparedSha256", "taskXmlSha256", "snapshotSha256"):
        require(match(proof[key], r"[a-f0-9]{64}"))
    for key in ("prepareRunId", "prepareRunAttempt"):
        require(match(proof[key], r"[1-9][0-9]{0,19}"))
    for key in ["vmId"] + ID_FIELDS:
        require(match(proof[key], r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"))
    for key in FLAGS:
        require(proof[key] is True)
    require(integer(proof["processId"], 1, 0xffffffff))
    times = {key: epoch(proof[key]) for key in ("originalCreatedAt", "processCreatedAt", "bootTime", "residentStartedAt", "residentFinishedAt", "preDeadlineObservedAt", "deadlineAt")}
    start, finish = times["residentStartedAt"], times["residentFinishedAt"]
    require(times["bootTime"] <= times["processCreatedAt"] <= start and start >= times["originalCreatedAt"] and finish < times["originalCreatedAt"] + 32 * HOUR)
    require(integer(proof["monotonicElapsedMs"], DAY, DAY + HOUR) and abs(finish - start - proof["monotonicElapsedMs"]) <= 5000)
    require(finish > times["deadlineAt"] and start + 23 * HOUR <= times["preDeadlineObservedAt"] < times["deadlineAt"] - 60000)
    require(integer(proof["keptObservationCount"], 24, 26) and integer(proof["maximumObservationGapMs"], 1, HOUR + 300000))
    for key in ("fingerprints", "spkiFingerprints", "requestIds"):
        values = proof[key]
        require(isinstance(values, list) and len(values) == 3 and all(isinstance(item, str) for item in values) and len(set(values)) == 3)
        for item in values:
            require(match(item, r"[1-9][0-9]{0,9}") and int(item) <= 0xffffffff if key == "requestIds" else match(item, r"[a-f0-9]{64}"))
    counts = proof["caRequestCounts"]
    require(isinstance(counts, list) and len(counts) == 4 and all(integer(item, 0, 2048) for item in counts))
    require(all(counts[i] == counts[i - 1] + 1 for i in range(1, 4)))
    for keys in (("installedEnrollmentId", "deferredEnrollmentId", "freshEnrollmentId"), ("expiredContinuationJobId", "freshPreflightJobId", "freshRenewalJobId")):
        require(len({proof[key] for key in keys}) == 3)
    return True


def fields(report):
    """Return only the bounded flat proof after native scope validation."""
    require(isinstance(report, dict) and report.get("suite") == SUITE)
    environment = report.get("qualificationEnvironment")
    require(isinstance(environment, dict))
    expected = {"osFamily": "windows", "osVersion": "2022", "nativeLanguage": "en-US", "identity": "LocalSystem", "measurement": "native", "architecture": "x64"}
    require(all(environment.get(key) == value for key, value in expected.items()))
    require(report.get("platform") == "win32" and report.get("architecture") == "x64")
    require(isinstance(report.get("cleanup"), dict) and report["cleanup"].get("status") == "passed")
    proof = report.get(FIELD)
    verify_proof(proof)
    require(report.get("candidateSha") == proof["candidateSha"])
    return copy.deepcopy(proof)
