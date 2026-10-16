"""Closed public projection of two genuine bulk-renewed native certificates.

Pure parsing does not execute an agent/CA or qualify an offline fixture.
"""
import copy
import re
FIELD = "nativeAcmeBulkRenewal"
SCOPE = "real-agent-acme-filesystem"
MAIN = "real ACME: agent discovers public files registers claims issues renews deploys and persists independently verified certificate evidence"
FLAGS = "actualPublicOwnedIssuances twoDistinctStoredProfiles bothRotationPoliciesTrue mixedPublicBulkAdmission stablePublicReplay bothCurrentClaimsOwned publicCompletedResultsBound bothRealCaLeavesChanged bothPrivateKeysMatchAndRotate bothTrustedTlsFingerprints claimBoundVerificationEvidence storedProfilesUnchanged ownedDnsCleaned ownedManagementStopped originalServingCertificateUnchanged productionWorkerStopped retainedTlsResourcesDrained ownershipGuardReleased".split()
UUID = r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}"

def require(value):
    if not value:
        raise ValueError("Invalid actual native bulk-renewal proof")

def fields(event):
    if event.get("scope") != SCOPE or event.get("name") != MAIN:
        return {}
    p, e = event.get(FIELD), event.get("qualificationEnvironment")
    require(event.get("type") == "test:pass" and isinstance(p, dict))
    require(set(p) == {"scope", "client", "certificateIds", "issueJobIds", "jobIds", "claimIds", "fingerprints", "serials", "spkiFingerprints", "originalServingFingerprint", "originalServingSpki", "originalServingProfileId", *FLAGS})
    require(p["scope"] == "native-public-bulk-renew-two-agent-local-certificates" and p["client"] == "certbot")
    for flag in FLAGS:
        require(p[flag] is True)
    for key in ("certificateIds", "issueJobIds", "jobIds", "claimIds"):
        rows = p[key]
        require(isinstance(rows, list) and len(rows) == 2 and all(isinstance(row, str) and re.fullmatch(UUID, row) for row in rows) and len({row.lower() for row in rows}) == 2)
    for key in ("fingerprints", "spkiFingerprints"):
        rows = p[key]
        require(isinstance(rows, list) and len(rows) == 4 and all(isinstance(row, str) and re.fullmatch(r"[a-f0-9]{64}", row) for row in rows) and len(set(rows)) == 4)
    serials = p["serials"]
    require(isinstance(serials, list) and len(serials) == 4 and all(isinstance(row, str) and re.fullmatch(r"[a-fA-F0-9]{1,64}", row) for row in serials) and len({int(row, 16) for row in serials}) == 4)
    for key in ("originalServingFingerprint", "originalServingSpki"):
        require(isinstance(p[key], str) and re.fullmatch(r"[a-f0-9]{64}", p[key]))
    require(isinstance(p["originalServingProfileId"], str) and re.fullmatch(UUID, p["originalServingProfileId"]))
    reuse, background = event.get("nativeAcmeKeyReuse"), event.get("nativeAcmeBackgroundRenewals")
    require(isinstance(reuse, dict) and isinstance(background, dict) and reuse.get("client") == "certbot" and background.get("client") == "certbot")
    require(isinstance(reuse.get("fingerprints"), list) and len(reuse["fingerprints"]) == 3 and p["originalServingFingerprint"] == reuse["fingerprints"][2] and p["originalServingSpki"] == reuse.get("spkiFingerprint"))
    require(isinstance(reuse.get("sourceProfileId"), str) and p["originalServingProfileId"].lower() == reuse["sourceProfileId"].lower())
    require(isinstance(reuse.get("jobIds"), list) and len(reuse["jobIds"]) == 2 and isinstance(background.get("jobIds"), list) and len(background["jobIds"]) == 2)
    jobs = p["issueJobIds"] + p["jobIds"] + reuse["jobIds"] + background["jobIds"]
    require(all(isinstance(row, str) and re.fullmatch(UUID, row) for row in jobs) and len({row.lower() for row in jobs}) == 8)
    require(isinstance(e, dict) and e.get("measurement") == "native" and e.get("osFamily") == "linux" and e.get("distributionId") == "ubuntu" and e.get("distributionVersion") == "24.04" and e.get("executionSurface") == "host")
    return {FIELD: copy.deepcopy(p)}
def verify_workflow(report, workflow):
    if isinstance(report, list) and any(isinstance(event, dict) and event.get("scope") == SCOPE for event in report):
        require(workflow == ".github/workflows/certops-real-acme.yml")
