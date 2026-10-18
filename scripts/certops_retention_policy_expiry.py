"""Public evidence projection for direct native expiry-wins collector cases.

This validates measured report facts; it neither executes native operations nor
qualifies an installed agent timer or a full 168/720-hour retention window.
"""
import datetime
import math
import re

SCOPE = "native-retention-policy-expiry-wins"
FLAGS = (
    "actualProductionCollectorUsed", "preDeadlineCustodyPreserved",
    "oldCertificateAbsent", "oldKeyAbsent", "immutableHistoryPreserved",
    "replacementCustodyUnchanged", "replacementTrustedTlsVerified",
    "interruptedNativeDeleteRecovered",
)
COUNTS = (
    "successfulCutovers", "predecessorCertificatesRemoved",
    "predecessorKeysRemoved", "lineageRowsFinalized",
)
TIMES = (
    "verifiedCutoverAt", "oldNotAfter", "cleanupDeadline",
    "preDeadlineObservedAt", "cleanupObservedAt", "waitStartedAt", "waitFinishedAt",
)


def _epoch(value):
    if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value):
        raise ValueError("Policy expiry timestamps must be canonical UTC")
    try:
        instant = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("Invalid policy expiry timestamp") from error
    return int(instant.timestamp() * 1000)


INTERRUPTION_FLAGS = ("assignedBeforeResume", "rootExit86", "nativeActiveZero", "nativeHandlesClosed", "wrapperClosed")


def interruption_fields(value):
    if (not isinstance(value, dict) or set(value) != {"scope", *INTERRUPTION_FLAGS}
            or value.get("scope") != "owned-short-retention-native-interruption-drain"
            or any(value.get(flag) is not True for flag in INTERRUPTION_FLAGS)):
        raise ValueError("Incomplete retained native short-retention process drainage")
    return {"scope": value["scope"], **dict.fromkeys(INTERRUPTION_FLAGS, True)}


def fields(value):
    """Require both measured policies and return bounded public fields only."""
    if not isinstance(value, dict) or set(value) != {"168", "720"}:
        raise ValueError("Both native retention policy expiry cases are required")
    result = {}
    for policy in (168, 720):
        item = value[str(policy)]
        if (not isinstance(item, dict) or item.get("scope") != SCOPE
                or type(item.get("configuredRetentionHours")) is not int
                or item["configuredRetentionHours"] != policy
                or item.get("installedServiceTimerQualified") is not False
                or item.get("fullRetentionWindowQualified") is not False
                or any(item.get(field) is not True for field in FLAGS)
                or any(type(item.get(field)) is not int or item[field] != 2 for field in COUNTS)):
            raise ValueError("Incomplete native policy expiry evidence")
        times = {field: _epoch(item.get(field)) for field in TIMES}
        cutover, expiry, deadline = (times[field] for field in TIMES[:3])
        before, after, started, finished = (times[field] for field in TIMES[3:])
        waited = item.get("waitedMonotonicMs")
        if (type(waited) not in (int, float) or not math.isfinite(waited)
                or not 300000 <= waited < 600000
                or not cutover < expiry
                or deadline != expiry + 300000
                or not deadline < cutover + policy * 3600000
                or not cutover <= before < expiry
                or not before <= started < expiry
                or not finished > deadline
                or not after >= finished or not after - finished < 180000
                or abs(finished - started - waited) > 5000):
            raise ValueError("Invalid native policy expiry temporal evidence")
        owned_interruption = interruption_fields(item.get("ownedInterruption"))
        result[str(policy)] = {
            "ownedInterruption": owned_interruption,
            "scope": SCOPE, "configuredRetentionHours": policy,
            **{field: item[field] for field in TIMES},
            "waitedMonotonicMs": waited,
            "installedServiceTimerQualified": False,
            "fullRetentionWindowQualified": False,
            **dict.fromkeys(FLAGS, True), **dict.fromkeys(COUNTS, 2),
        }
    return result
