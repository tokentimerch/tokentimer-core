"""Closed public Microsoft OCSP responder evidence; never a native executor."""
import re

SCOPE = "real-installed-adcs-native-microsoft-ocsp-good-unavailable-recovered"
FLAGS = (
    "originalCaAndRoleAbsenceBound", "ownedTemplateAndSignerRequestBound",
    "actualNonexportableSignerAndServiceAcl", "independentDelegatedSignatureAndNoCheck",
    "nativeResponderConfigurationBound", "actualOcspOnlyLeaf",
    "actualPublicRenewalsAndClaimEvidence", "independentNativeRequestIds",
    "originalPublicationRestoredBeforeFault", "actualSignedGoodResponses",
    "actualProgramScopedFirewallFault", "nativeValidUnknownValid",
    "sameCustodyBindingAndTrustedTls", "restoredPublicationReplacementInstalled",
    "originalCachePolicyAndFirewallRestored", "ownedConfigurationAndTemplateRemoved",
    "ownedSignerCertificateAndKeyAbsent", "ownedResponderAndIisStoppedDisabledDrained",
    "ownedGuardReleased", "installedAgentFaultRecoveryQualified",
)
FALSE_FLAGS = (
    "authoritativeRevokedStatusQualified",
    "signedCmcRenewalQualified", "individualFeaturePackageRemovalQualified",
)
FIELDS = (
    "scope", "enrollmentIds", "jobIds", "requestIds", "signerRequestId",
    "leafFingerprints", "signerFingerprint", "issuerKeySha256", "nativeHelperSha256",
    "publicCrlSha256", "responseSha256", "caRequestCounts", "nativeVerdicts", "deferredRecovery",
    *FLAGS, *FALSE_FLAGS,
)


def fields(value):
    def require(condition):
        if not condition:
            raise ValueError("Invalid native Microsoft OCSP evidence")

    require(isinstance(value, dict) and set(value) == set(FIELDS))
    require(value["scope"] == SCOPE)
    require(all(value[key] is True for key in FLAGS))
    require(all(value[key] is False for key in FALSE_FLAGS))
    for key in ("enrollmentIds", "jobIds"):
        rows = value[key]
        require(isinstance(rows, list) and len(rows) == 2)
        require(all(isinstance(row, str) and re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", row) for row in rows))
        require(len({row.lower() for row in rows}) == 2)
    def request_id(row):
        return type(row) is int and 0 < row <= 0xffffffff
    require(request_id(value["signerRequestId"]))
    require(isinstance(value["requestIds"], list) and len(value["requestIds"]) == 2 and all(request_id(row) for row in value["requestIds"]))
    require(len({value["signerRequestId"], *value["requestIds"]}) == 3)
    recovery = value["deferredRecovery"]
    require(isinstance(recovery,dict) and set(recovery) == {"originalJobId","originalClaimId","continuationJobId","continuationClaimId","requestId"})
    require(all(isinstance(recovery[key],str) and re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}",recovery[key]) for key in ("originalJobId","originalClaimId","continuationJobId","continuationClaimId")))
    require(recovery["originalJobId"].lower() not in {row.lower() for row in value["jobIds"]})
    require(recovery["originalClaimId"].lower() != recovery["continuationClaimId"].lower())
    require(recovery["continuationJobId"] == value["jobIds"][0])
    require(request_id(recovery["requestId"]) and recovery["requestId"] == value["requestIds"][0])
    for key, count in (("leafFingerprints", 2), ("responseSha256", 3)):
        require(isinstance(value[key], list) and len(value[key]) == count)
        require(all(isinstance(row, str) and re.fullmatch(r"[a-f0-9]{64}", row) for row in value[key]))
    for key in ("signerFingerprint", "issuerKeySha256", "nativeHelperSha256", "publicCrlSha256"):
        require(isinstance(value[key], str) and re.fullmatch(r"[a-f0-9]{64}", value[key]))
    require(value["leafFingerprints"][0] != value["leafFingerprints"][1])
    require(value["signerFingerprint"] not in value["leafFingerprints"])
    counts = value["caRequestCounts"]
    require(isinstance(counts, list) and len(counts) == 4 and all(type(row) is int and 0 <= row <= 2048 for row in counts))
    require(all(counts[index] - counts[index - 1] == 1 for index in range(1, 4)))
    require(value["nativeVerdicts"] == ["valid", "revocation_unknown", "valid"])
    return {key: value[key] for key in FIELDS}
