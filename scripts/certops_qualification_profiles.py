"""Closed evidence profiles; normal hosted collection never implies full qualification."""
import json
from pathlib import Path
DOMAIN = {"enterprise-adcs-real", "enterprise-adcs-hierarchy-real", "native-adcs-issuer-reassignment", "adcs-browser-enrollment", "adcs-install-interruption", "adcs-lost-submit", "adcs-uncertain-abandon", "adcs-cmc-renewal", "adcs-safety-variants", "adcs-crash-experiments"}
EXTENDED = {"enterprise-adcs-elapsed-pending-real", "windows-domain-adcs-retention24h", "windows-domain-adcs-default-ttl24h", "windows-domain-installed-retention-default-timer"}
ADCS_NATIVE = {"enterprise-adcs-real"}
PROFILES = {"full": {"hosted", "domain-adcs", "extended-domain-adcs"}, "standard-hosted": {"hosted"}, "adcs": {"domain-adcs"}, "adcs-native": {"domain-adcs"}, "extended-adcs": {"extended-domain-adcs"}}


def select_profile(matrix, profile="full", capabilities=None):
    if capabilities is None:
        capabilities=json.loads((Path(__file__).resolve().parent.parent / "docs/certops/qualification-suites.json").read_text())["requiredCapabilities"]
    if not isinstance(profile, str) or profile not in PROFILES:
        raise ValueError("Unknown qualification profile")
    slots = matrix.get("slots")
    if not isinstance(slots,list) or not 1 <= len(slots) <= 512:
        raise ValueError("Bounded committed qualification matrix required")
    ids = [slot.get("id") for slot in slots]
    if any(not isinstance(identity,str) or not identity for identity in ids) or len(set(ids)) != len(ids):
        raise ValueError("Unique committed qualification slot IDs required")
    def category(slot):
        if slot.get("suite") in DOMAIN: return "domain-adcs"
        if slot.get("suite") in EXTENDED: return "extended-domain-adcs"
        if "domain" in capabilities.get(slot.get("suite"),[]):
            raise ValueError("Unclassified domain suite cannot enter hosted qualification")
        return "hosted"
    selected = [slot for slot in slots if category(slot) in PROFILES[profile] and (profile != "adcs-native" or slot.get("suite") in ADCS_NATIVE)]
    if not selected:
        raise ValueError("Qualification profile selects no environments")
    selected_ids = [slot["id"] for slot in selected]
    return {"profile":profile,"selectedSlotIds":selected_ids,"omittedSlotIds":[identity for identity in ids if identity not in selected_ids] + [slot["id"] for slot in matrix.get("deferredSlots", [])],"specification":{**matrix,"slots":selected}}


def summary_fields(selection, qualified=False):
    return {"qualificationProfile":selection["profile"],"qualificationScope":"committed-mandatory-matrix" if selection["profile"] == "full" else "declared-profile","selectedSlotIds":selection["selectedSlotIds"][:],"omittedSlotIds":selection["omittedSlotIds"][:],"fullMatrixQualified":qualified is True and selection["profile"] == "full" and not selection["omittedSlotIds"]}


def requested_profile(arguments, environment):
    if arguments:
        if len(arguments) != 2 or arguments[0] != "--profile":
            raise ValueError("Only an explicit --profile name is accepted")
        profile = arguments[1]
        if "CERTOPS_QUALIFICATION_PROFILE" in environment and environment["CERTOPS_QUALIFICATION_PROFILE"] != profile:
            raise ValueError("Qualification profile argument/environment mismatch")
    else:
        profile = environment.get("CERTOPS_QUALIFICATION_PROFILE", "full")
    if profile not in PROFILES:
        raise ValueError("Unknown qualification profile")
    return profile
