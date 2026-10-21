"""Closed native renewal-failure SMTP evidence; offline fixtures are not native runs."""
import copy
import re
import certops_acme_bulk_proof as bulk
import certops_acme_certificate_outbox_proof as outbox

FIELD = "nativeAcmeRenewalAlert"
SCOPE = "native-renewal-transport-refusal-production-outbox-and-smtp"
FLAGS = "actualPublicRenewal actualCurrentClaimFailed actualNonceConsumed actualNativeClientReachedFault faultRequestsNotForwarded noAdditionalCaIssuance originalServingPairPreserved independentTrustedTlsPreserved actualProductionOutboxDrained actualProductionDeliveryWorker independentNewSmtpReceipt exactAlertJobLineage singleSuccessfulEmailDelivery outboxReplayDeduplicated ownershipGuardReleased".split()

def require(value):
    if not value:
        raise ValueError("Invalid native renewal failure SMTP proof")

def fields(event):
    if event.get("scope") != bulk.SCOPE or event.get("name") != bulk.MAIN:
        return {}
    previous = outbox.fields(event)[outbox.FIELD]
    value = event.get(FIELD)
    require(isinstance(value, dict) and set(value) == {"scope", "jobId", "claimId", "certificateId", "alertId", "faultRequestCount", "servingFingerprint", *FLAGS})
    require(value["scope"] == SCOPE)
    for key in ("jobId", "claimId", "certificateId"):
        require(isinstance(value[key], str) and re.fullmatch(bulk.UUID, value[key]))
    require(isinstance(value["alertId"], str) and re.fullmatch(r"[1-9][0-9]*", value["alertId"]))
    require(type(value["faultRequestCount"]) is int and value["faultRequestCount"] > 0)
    fingerprint = value["servingFingerprint"]
    require(isinstance(fingerprint, str) and re.fullmatch(r"[A-F0-9]{2}(?::[A-F0-9]{2}){31}", fingerprint))
    for flag in FLAGS:
        require(value[flag] is True)
    require(value["certificateId"] == previous["certificateId"])
    require(fingerprint.replace(":", "").lower() == previous["fingerprints"][1])
    require(value["jobId"].lower() != previous["jobId"].lower())
    require(value["claimId"].lower() != previous["claimId"].lower())
    return {FIELD: copy.deepcopy(value)}
