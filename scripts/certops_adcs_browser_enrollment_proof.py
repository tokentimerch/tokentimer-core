"""Closed public projection of an executed browser renewal journey; no browser execution."""
import re

SUITE = "adcs-browser-enrollment"
WORKFLOW = ".github/workflows/certops-enterprise-adcs-qualification.yml"
FLAGS = "browserIssuerCreation nativeSafePreflight noEnrollmentBeforeConfirmation browserCaConfirmation postConfirmationNativePreflight browserProfileCreation browserProfileAttachment actualDueSelection defaultSweepCreatedEnrollment automaticSourceAndRealMode claimBoundEvidence installedEnrollment freshLeafAndSpki nativeCaRequestMatched nonexportableMachineCng nativeIisSniMatched independentTrustedTls browserInstalledStateVisible noSyntheticResponses noDateOrJournalOverrides ownedEnrollmentRegistered browserAndTrustCleaned otherProfilePoliciesRestored".split()
FIXED = dict(scope="browser-issuer-profile-default-scheduler-native-adcs", lifecycle="renew-existing-inventory-not-first-issue-or-manual-job", scheduler="production-default-sweep-not-background-worker-loop", browserEngine="chromium")


def journey_fields(browser):
    keys = list(FIXED) + FLAGS + ["browserMutationCount", "successfulEnrollments", "fingerprints", "spkiFingerprints", "enrollmentId", "jobId", "profileId", "issuerId", "requestId"]
    if (not isinstance(browser, dict) or not set(keys).issubset(browser) or any(browser.get(k) != v for k, v in FIXED.items())
            or any(browser.get(k) is not True for k in FLAGS)
            or type(browser.get("browserMutationCount")) is not int or browser["browserMutationCount"] != 6
            or type(browser.get("successfulEnrollments")) is not int or browser["successfulEnrollments"] != 1):
        raise ValueError("Complete native browser lifecycle facts required")
    for key in ("fingerprints", "spkiFingerprints"):
        values = browser.get(key)
        if not isinstance(values, list) or len(values) != 2 or any(not isinstance(v, str) or not re.fullmatch(r"[a-f0-9]{64}", v) for v in values) or len(set(values)) != 2:
            raise ValueError("Distinct native browser certificate identities required")
    for key in ("enrollmentId", "jobId", "profileId", "issuerId"):
        if not isinstance(browser.get(key), str) or not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", browser[key]):
            raise ValueError("Native browser lifecycle identity invalid")
    if not isinstance(browser.get("requestId"), str) or not re.fullmatch(r"[1-9][0-9]{0,9}", browser["requestId"]) or int(browser["requestId"]) > 0xffffffff:
        raise ValueError("Native browser CA request identity invalid")
    return {key: browser[key] for key in keys}


def fields(report):
    p = report.get("nativeAdcsBrowserEnrollment")
    env = report.get("qualificationEnvironment", {})
    if (report.get("platform") != "win32" or report.get("architecture") != "x64" or report.get("cleanup", {}).get("status") != "passed"
            or any(env.get(k) != v for k, v in dict(osFamily="windows", osVersion="2022", nativeLanguage="en-US", identity="LocalSystem", measurement="native").items())):
        raise ValueError("Completed native SYSTEM browser environment required")
    keys = ["scope", "nativeExecutionQualified", "browserLaunched", "disposableForestRan", "hostCapabilityAbsentIsPass", "confirmationBeforeSubmit", "parentSuite", "nativeBrowserJourney"]
    if (not isinstance(p, dict) or set(p) != set(keys) or p.get("scope") != "native-browser-preflight-confirmation-profile-enrollment"
            or p.get("parentSuite") != "enterprise-adcs-real" or p.get("hostCapabilityAbsentIsPass") is not False
            or any(p.get(k) is not True for k in ("nativeExecutionQualified", "browserLaunched", "disposableForestRan", "confirmationBeforeSubmit"))):
        raise ValueError("Native browser execution cannot be replaced by a local contract")
    return {**{key: p[key] for key in keys if key != "nativeBrowserJourney"}, "nativeBrowserJourney": journey_fields(p["nativeBrowserJourney"])}


def verify_workflow(report, workflow):
    if report.get("suite") == SUITE and workflow != WORKFLOW:
        raise ValueError("Browser enrollment must originate from its comprehensive root-domain workflow")
