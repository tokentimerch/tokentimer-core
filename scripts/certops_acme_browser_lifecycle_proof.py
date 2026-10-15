"""Closed native browser issue/renew projection; never performs qualification."""
import copy
import re

SUITE = "linux-native-acme-browser-lifecycle"
FIELD = "nativeAcmeBrowserLifecycle"
FLAGS = "actualIssueAndRenewForms cancelBothFormsWithoutMutation exactPublicIssueAndRenewAdmission sameOwnedCertificate actualNativeClaimsAndActor claimBoundFingerprintEvidence independentNativeCertificateKeyPairs distinctLeafSerialAndSpki trustedTlsBothGenerations ownedBrowserClosed nativeOperationGuardCleared".split()
DISCOVERY_FLAGS = "actualUnprivilegedAgent noEffectiveCapabilities actualOsEacces fileAndDirectorySymlinksUnfollowed twoActualPositiveScans publicInventoryRegularLocation negativeFingerprintAbsent outsidePublicBytesUnchanged exactAgentClosed ownedInputsRemoved".split()


def require(condition):
    if not condition:
        raise ValueError("Invalid native browser ACME lifecycle proof")


def project_report(value):
    require(isinstance(value, dict) and value.get("suite") == SUITE and value.get("platform") == "linux" and value.get("architecture") == "x64")
    p, e = value.get(FIELD), value.get("qualificationEnvironment")
    require(isinstance(p, dict) and set(p) == {"scope", "jobIds", "certificateId", "fingerprints", "spkiHashes", *FLAGS})
    require(p["scope"] == "actual-browser-issued-and-renewed-native-acme-certificate")
    uuid = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    require(isinstance(p["certificateId"], str) and re.fullmatch(uuid, p["certificateId"], re.I))
    require(isinstance(p["jobIds"], list) and len(p["jobIds"]) == 2 and all(isinstance(v, str) and re.fullmatch(uuid, v, re.I) for v in p["jobIds"]) and len({v.lower() for v in p["jobIds"]}) == 2)
    for name in ("fingerprints", "spkiHashes"):
        require(isinstance(p[name], list) and len(p[name]) == 2 and all(isinstance(v, str) and re.fullmatch(r"[a-f0-9]{64}", v) for v in p[name]) and len(set(p[name])) == 2)
    for flag in FLAGS:
        require(p[flag] is True)
    require(isinstance(e, dict) and e.get("measurement") == "native" and e.get("osFamily") == "linux" and e.get("distributionId") == "ubuntu" and e.get("distributionVersion") == "24.04" and e.get("executionSurface") == "host" and e.get("libc") == "glibc")
    d = value.get("nativeFileDiscoveryRefusals")
    require(isinstance(d, dict) and set(d) == {"scope", "uid", "gid", "positiveFingerprint", "negativeFingerprint", "positiveScanCount", *DISCOVERY_FLAGS})
    require(d["scope"] == "actual-unprivileged-linux-file-discovery-refusals")
    for key in ("uid", "gid"):
        require(type(d[key]) is int and d[key] > 0)
    for key in ("positiveFingerprint", "negativeFingerprint"):
        require(isinstance(d[key], str) and re.fullmatch(r"[a-f0-9]{64}", d[key]))
    require(d["positiveFingerprint"] != d["negativeFingerprint"])
    require(type(d["positiveScanCount"]) is int and 2 <= d["positiveScanCount"] <= 10000)
    require(all(d[flag] is True for flag in DISCOVERY_FLAGS))
    return {FIELD: copy.deepcopy(p), "nativeFileDiscoveryRefusals": copy.deepcopy(d)}


def verify_workflow(value, workflow):
    if value.get("suite") == SUITE:
        require(workflow == ".github/workflows/certops-acme-browser-lifecycle.yml")
