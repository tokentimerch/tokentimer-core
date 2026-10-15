"""Bounded public projection for genuine live machine Enroll permission recovery.

Supporting validation never executes LDAP, a CA, certificates, or services.
Private DACL receipts and raw native traces are deliberately not projected.
"""
import re

SCOPE = "real-same-template-machine-enroll-denial-exact-dacl-restore-and-issuance"
FLAGS = ("sameConfirmedIssuerTemplateAndAlgorithm", "actualMachineSidDenied",
         "nativeTemplateDeniedHresult", "deniedKeyAbsentAndJournalRetained",
         "deniedAttemptPreservedNativeCustodyAndTls", "exactDaclRestored",
         "actualCaCacheRestartAndPing", "freshPublicEnrollmentInstalled",
         "independentIssuedCaRequest", "newNonexportableMachineKey",
         "nativeMyAndIisSniCutover", "independentTrustedTls", "claimBoundEvidence",
         "ownedCleanupRegisteredBeforeObservation")
FIELDS = ("scope", "templateGuid", "templateOid", "machineSid", "originalDaclSha256",
          "appliedDaclSha256", "restoredDaclSha256", "deniedCaRequestDelta",
          "caRequestCounts", "enrollmentIds", "jobIds", "fingerprints", "caHresult",
          "preflightRefusalQualified", "signedCmcRenewalQualified", *FLAGS)
UUID = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"


def require(condition):
    if not condition:
        raise ValueError("Invalid live machine Enroll ACL native proof")


def fields(value):
    require(isinstance(value, dict) and all(key in value for key in FIELDS))
    require(value["scope"] == SCOPE)
    for key, pattern in (("templateGuid", UUID), ("templateOid", r"1(?:\.[0-9]+)+"),
                         ("machineSid", r"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+")):
        require(isinstance(value[key], str) and re.fullmatch(pattern, value[key]) is not None)
    for key in ("originalDaclSha256", "appliedDaclSha256", "restoredDaclSha256"):
        require(isinstance(value[key], str) and re.fullmatch(r"[a-f0-9]{64}", value[key]) is not None)
    require(value["originalDaclSha256"] == value["restoredDaclSha256"] != value["appliedDaclSha256"])
    delta, counts = value["deniedCaRequestDelta"], value["caRequestCounts"]
    require(type(delta) is int and delta in (0, 1))
    require(isinstance(counts, list) and len(counts) == 3 and all(type(n) is int and 0 <= n <= 2048 for n in counts))
    require(counts[1] - counts[0] == delta and counts[2] - counts[1] == 1)
    for key in ("enrollmentIds", "jobIds", "fingerprints"):
        rows = value[key]
        pattern = r"[a-f0-9]{64}" if key == "fingerprints" else UUID
        require(isinstance(rows, list) and len(rows) == 2 and all(isinstance(n, str) and re.fullmatch(pattern, n) is not None for n in rows))
        require(len(set(rows)) == 2)
    require(value["caHresult"] == "0x80094012")
    require(all(value[key] is True for key in FLAGS))
    require(value["preflightRefusalQualified"] is False and value["signedCmcRenewalQualified"] is False)
    return {key: value[key] for key in FIELDS}
