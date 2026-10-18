"""Bounded public evidence for actual HTTP-only leaf CRL endpoint availability.

Validation does not execute native enrollment or promote OCSP/CA outage scope.
"""
import re

SCOPE = "real-installed-adcs-http-only-leaf-crl-endpoint-unavailable-and-recovered"
FLAGS = (
    "originalCaPublicationReceiptBound", "actualSignedPinnedPublicCrl", "actualHttpOnlyLeafCdp",
    "publicRenewalInstalled", "currentClaimBoundEvidence", "independentNativeRequestId",
    "exactCaPublicationRestoredBeforeFault", "freshNativeChainValidBefore", "actualOwnedHttp503",
    "freshNativeRevocationUnknown", "sameSignedCrlRecovered", "freshNativeChainValidAfter",
    "sameNonexportableCngCustody", "sameNativeBindingAndTrustedTls", "originalCachePolicyRestored",
    "ownedListenerClosed", "ownedGuardReleased",
    "restoredPublicationLeafInstalledBeforeListenerClose",
    "installedAgentFaultRecoveryQualified",
)
FIELDS = ("scope", "enrollmentId", "jobId", "requestId", "leafFingerprint", "publicCrlSha256",
          "nativeHelperSha256", "originalPublicationSha256", "appliedPublicationSha256",
          "caRequestCounts", "nativeVerdicts", "endpointStatusCodes", "ocspQualified",
          "caOutageQualified", "signedCmcRenewalQualified", "restoredEnrollmentId",
          "restoredJobId", "restoredRequestId", "restoredLeafFingerprint", "deferredRecovery", *FLAGS)


def fields(value):
    def require(condition):
        if not condition:
            raise ValueError("Invalid native HTTP-only leaf CRL evidence")

    require(isinstance(value, dict) and all(key in value for key in FIELDS))
    require(value["scope"] == SCOPE)
    for key in ("enrollmentId", "jobId", "restoredEnrollmentId", "restoredJobId"):
        require(isinstance(value[key], str) and re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", value[key]) is not None)
    require(type(value["requestId"]) is int and 0 < value["requestId"] <= 0xffffffff)
    require(type(value["restoredRequestId"]) is int and 0 < value["restoredRequestId"] <= 0xffffffff)
    require(value["requestId"] != value["restoredRequestId"])
    require(value["enrollmentId"].lower() != value["restoredEnrollmentId"].lower())
    require(value["jobId"].lower() != value["restoredJobId"].lower())
    for key in ("leafFingerprint", "restoredLeafFingerprint", "publicCrlSha256", "nativeHelperSha256", "originalPublicationSha256", "appliedPublicationSha256"):
        require(isinstance(value[key], str) and re.fullmatch(r"[a-f0-9]{64}", value[key]) is not None)
    require(value["originalPublicationSha256"] != value["appliedPublicationSha256"])
    counts = value["caRequestCounts"]
    require(value["leafFingerprint"] != value["restoredLeafFingerprint"])
    require(isinstance(counts, list) and len(counts) == 3 and all(type(count) is int and 0 <= count <= 2048 for count in counts))
    require(counts[1] - counts[0] == 1 and counts[2] - counts[1] == 1)
    require(value["nativeVerdicts"] == ["valid", "revocation_unknown", "valid"])
    require(value["endpointStatusCodes"] == [200, 503, 200] and all(type(code) is int for code in value["endpointStatusCodes"]))
    require(all(value[key] is True for key in FLAGS))
    require(all(value[key] is False for key in ("ocspQualified", "caOutageQualified", "signedCmcRenewalQualified")))
    recovery=value["deferredRecovery"]
    require(isinstance(recovery,dict) and set(recovery)=={"originalJobId","originalClaimId","continuationJobId","continuationClaimId","requestId"})
    require(all(isinstance(recovery[key],str) and re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}",recovery[key]) for key in ("originalJobId","originalClaimId","continuationJobId","continuationClaimId")))
    require(recovery["originalJobId"].lower() not in {value["jobId"].lower(),value["restoredJobId"].lower()})
    require(recovery["originalClaimId"].lower()!=recovery["continuationClaimId"].lower())
    require(recovery["continuationJobId"]==value["jobId"])
    require(type(recovery["requestId"]) is int and recovery["requestId"]==value["requestId"])
    return {key: value[key] for key in FIELDS}
