"""Closed native single-candidate evidence projection; no host execution."""
import re

FLAGS = "ownedObserverDrained ownedTransportBlock observedSubmittingTermination actualLeaseExpiry acknowledgedPublicRecovery sameCsrAndKey noAutomaticResubmit originalOrphanPreserved recoveryPolicyUnchanged nativeCaOwnershipVerified automaticUniqueAttachmentSucceeded noExplicitRequestIdProposed claimBoundVerification sameProtectedMachineKeyInstalled unrelatedTrustedTlsPreserved".split()

def fields(value):
    fixed = dict(scope="native-operator-single-candidate-acknowledged-automatic-recovery", resolvedIssuingCaAddress="10.64.0.4", caRequestsAtFault=0, caRequestsAfterOperatorSubmission=1, caRequestsAfterRecovery=1, responseLossTimingQualified=False)
    names = set(fixed) | set(FLAGS) | {"leaseRemainingAtFaultMs", "recoveryWaitBudgetMs", "actualLeaseWaitMs", "requestId", "enrollmentId", "containerName", "fingerprint", "csrSha256", "csrSpkiSha256", "jobIds"}
    if not isinstance(value, dict) or set(value) != names or any(type(value.get(k)) is not type(v) or value[k] != v for k, v in fixed.items()) or any(value.get(k) is not True for k in FLAGS):
        raise ValueError("Exact native single-candidate recovery facts required")
    uuid = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    if not isinstance(value["enrollmentId"], str) or not re.fullmatch(uuid, value["enrollmentId"]) or value["containerName"] != "tokentimer-enr-" + value["enrollmentId"]:
        raise ValueError("Native unique-candidate enrollment custody mismatch")
    if not isinstance(value["jobIds"], list) or len(value["jobIds"]) != 2 or any(not isinstance(v, str) or not re.fullmatch(uuid, v) for v in value["jobIds"]) or len(set(value["jobIds"])) != 2:
        raise ValueError("Distinct original/recovery job identities required")
    if not isinstance(value["requestId"], str) or not re.fullmatch(r"[1-9][0-9]{0,9}", value["requestId"]) or int(value["requestId"]) > 0xffffffff or any(not isinstance(value[k], str) or not re.fullmatch(r"[a-f0-9]{64}", value[k]) for k in ("fingerprint", "csrSha256", "csrSpkiSha256")):
        raise ValueError("Native CA request and public CSR identities required")
    remaining, budget, elapsed = (value[k] for k in ("leaseRemainingAtFaultMs", "recoveryWaitBudgetMs", "actualLeaseWaitMs"))
    if any(type(v) is not int or not 0 <= v <= 900000 for v in (remaining, budget, elapsed)) or budget != remaining + 90000 or elapsed + 1000 < remaining + 60000 or elapsed > budget + 1000:
        raise ValueError("Actual native lease and hard grace must elapse")
    return {**value, "jobIds": list(value["jobIds"])}
