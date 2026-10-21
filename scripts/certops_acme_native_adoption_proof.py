"""Closed public projection of actual agent-local native renewal re-setup.

Offline contract fixtures are not agent, CA, TLS or worker execution evidence.
"""
import copy
import re
import certops_acme_bulk_proof as bulk

FIELD = "nativeAcmeRenewalSetup"
SCOPE = "native-agent-local-public-renewal-re-setup"
FLAGS = "actualManualManagementReadd actualSignedDryRun dryRunCustodyUnchanged dryRunCreatesNoIntent actualPublicRealSetup actualCurrentClaims actualNewCaLeafAndKey trustedTlsReplacement claimBoundVerification actualDefaultOutboxDrain exactIntentConfigured publicSetupConfigured executionPolicyPreserved ownedManagementStopped originalServingUnchanged retainedTlsDrained ownershipGuardReleased".split()


def require(value):
    if not value:
        raise ValueError("Invalid actual native renewal-setup proof")


def fields(event):
    if event.get("scope") != bulk.SCOPE or event.get("name") != bulk.MAIN:
        return {}
    previous = bulk.fields(event)[bulk.FIELD]
    value = event.get(FIELD)
    require(isinstance(value, dict))
    require(set(value) == {"scope", "certificateId", "profileId", "jobIds",
                           "claimIds", "fingerprints", "spkiFingerprints", *FLAGS})
    require(value["scope"] == SCOPE)
    for key in ("certificateId", "profileId"):
        require(isinstance(value[key], str) and re.fullmatch(bulk.UUID, value[key]))
    for key in ("jobIds", "claimIds", "fingerprints", "spkiFingerprints"):
        rows = value[key]
        expression = bulk.UUID if key.endswith("Ids") else r"[a-f0-9]{64}"
        require(isinstance(rows, list) and len(rows) == 2 and
                all(isinstance(row, str) and re.fullmatch(expression, row) for row in rows)
                and len({row.lower() for row in rows}) == 2)
    for flag in FLAGS:
        require(value[flag] is True)
    require(value["certificateId"] == previous["certificateIds"][0])
    require(value["fingerprints"][0] == previous["fingerprints"][2])
    require(value["spkiFingerprints"][0] == previous["spkiFingerprints"][2])
    require(value["fingerprints"][1] not in previous["fingerprints"])
    require(value["spkiFingerprints"][1] not in previous["spkiFingerprints"])
    require(value["fingerprints"][1] != previous["originalServingFingerprint"])
    require(value["spkiFingerprints"][1] != previous["originalServingSpki"])
    jobs = value["jobIds"] + previous["issueJobIds"] + previous["jobIds"]
    claims = value["claimIds"] + previous["claimIds"]
    require(len({row.lower() for row in jobs}) == 6 and
            len({row.lower() for row in claims}) == 4)
    return {FIELD: copy.deepcopy(value)}
