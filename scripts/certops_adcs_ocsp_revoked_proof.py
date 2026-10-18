"""Projects the closed historical OCSP revoked-status report.

Native lab execution is still pending. This module does not revoke a
certificate or qualify a native responder.
"""
from datetime import datetime
import re
import certops_adcs_ocsp_proof as base_proof

SCOPE = "native-microsoft-ocsp-historical-unserved-leaf-authoritative-revoked"
FLAGS = (
    "historicalLeafUnservedBeforeAndAfter", "currentReplacementCustodyAndTlsPreserved",
    "exactOwnedNativeCaRequestRevoked", "freshSignedCrlAddsHistoricalLeaf",
    "sameOwnedProviderRefreshed", "independentDelegatedRevokedResponse", "actualCryptoApiRevoked",
    "noNewCaRequest", "originalPublicationAndCacheRestored", "activeResponderResourcesDrained",
    "ownedCleanupReleased", "authoritativeRevokedStatusQualified",
)
FALSE_FLAGS = ("installedAgentRevokedLeafRefusalQualified", "authoritativeUnknownStatusQualified")
FIELDS = (
    "scope", "historicalEnrollmentId", "currentEnrollmentId", "historicalRequestId", "currentRequestId",
    "originalCrlSha256", "revokedCrlSha256", "originalCrlNumber", "revokedCrlNumber",
    "historicalFingerprint", "currentFingerprint", "historicalSerial", "revocationTime",
    "responseSha256", "signerFingerprint", "issuerKeySha256", "nativeVerdict", "caRequestCounts",
    *FLAGS, *FALSE_FLAGS,
)


def fields(value, base):
    def require(condition):
        if not condition:
            raise ValueError("Invalid authoritative native OCSP revoked evidence")

    require(isinstance(value, dict) and all(key in value for key in FIELDS))
    require(value["scope"] == SCOPE)
    for key in ("historicalEnrollmentId", "currentEnrollmentId"):
        require(isinstance(value[key], str) and re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", value[key]))
    require(value["historicalEnrollmentId"].lower() != value["currentEnrollmentId"].lower())
    for key in ("historicalRequestId", "currentRequestId"):
        require(type(value[key]) is int and 1 <= value[key] <= 0xffffffff)
    require(value["historicalRequestId"] != value["currentRequestId"])
    for key in ("originalCrlSha256", "revokedCrlSha256", "historicalFingerprint", "currentFingerprint", "responseSha256", "signerFingerprint", "issuerKeySha256"):
        require(isinstance(value[key], str) and re.fullmatch(r"[a-f0-9]{64}", value[key]))
    require(value["originalCrlSha256"] != value["revokedCrlSha256"] and value["historicalFingerprint"] != value["currentFingerprint"])
    for key in ("originalCrlNumber", "revokedCrlNumber"):
        require(isinstance(value[key], str) and re.fullmatch(r"0|[1-9][0-9]{0,48}", value[key]))
    require(int(value["revokedCrlNumber"]) > int(value["originalCrlNumber"]))
    require(isinstance(value["historicalSerial"], str) and re.fullmatch(r"[1-9A-F][A-F0-9]{0,39}", value["historicalSerial"]))
    require(isinstance(value["revocationTime"], str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", value["revocationTime"]))
    datetime.fromisoformat(value["revocationTime"].replace("Z", "+00:00"))
    require(value["nativeVerdict"] == "revoked")
    counts = value["caRequestCounts"]
    require(isinstance(counts, list) and len(counts) == 2 and all(type(item) is int and 0 <= item <= 2048 for item in counts) and counts[0] == counts[1])
    require(all(value[key] is True for key in FLAGS) and all(value[key] is False for key in FALSE_FLAGS))
    original = base_proof.fields(base)
    require(value["historicalEnrollmentId"] == original["enrollmentIds"][0] and value["currentEnrollmentId"] == original["enrollmentIds"][1])
    require(value["historicalRequestId"] == original["requestIds"][0] and value["currentRequestId"] == original["requestIds"][1])
    require(value["historicalFingerprint"] == original["leafFingerprints"][0] and value["currentFingerprint"] == original["leafFingerprints"][1])
    require(value["originalCrlSha256"] == original["publicCrlSha256"] and value["signerFingerprint"] == original["signerFingerprint"] and value["issuerKeySha256"] == original["issuerKeySha256"])
    require(counts[0] == original["caRequestCounts"][-1])
    return {key: value[key] for key in FIELDS}
