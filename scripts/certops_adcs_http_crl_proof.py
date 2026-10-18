"""Closed public projection for the actual hierarchy HTTP intermediate CRL fault.

This validates evidence only; it does not run a native chain or create a fault.
"""
import re

SCOPE = "native-hierarchy-http-intermediate-crl-unavailable-and-recovered"
FLAGS = ("actualIntermediateHttpOnlyCdp", "actualPublicHttpCrlFetched",
         "freshNativeChainValidBefore", "exactProgramScopedHttpBlock",
         "httpAvailableOutsideHelper", "issuingCaLdapAvailable",
         "freshNativeRevocationUnknown", "exactFirewallRuleRemoved",
         "freshNativeChainValidAfter", "originalChainCachePolicyRestored",
         "sameNonexportableCngCustody", "sameNativeBindingAndTrustedTls", "ownedGuardReleased")
FIELDS = ("scope", "transport", "revocationTarget", "nativeHelperSha256",
          "publicCrlSha256", "leafFingerprint", "nativeVerdicts",
          "installedAgentQualified", "httpOnlyLeafQualified", "ocspQualified", *FLAGS)


def fields(value):
    def require(condition):
        if not condition:
            raise ValueError("Invalid native hierarchy HTTP CRL evidence")
    require(isinstance(value, dict) and all(key in value for key in FIELDS))
    require(value["scope"] == SCOPE and value["transport"] == "http" and value["revocationTarget"] == "intermediate")
    for key in ("nativeHelperSha256", "publicCrlSha256", "leafFingerprint"):
        require(isinstance(value[key], str) and re.fullmatch(r"[a-f0-9]{64}", value[key]) is not None)
    require(value["nativeVerdicts"] == ["valid", "revocation_unknown", "valid"])
    require(all(value[key] is True for key in FLAGS))
    require(all(value[key] is False for key in ("installedAgentQualified", "httpOnlyLeafQualified", "ocspQualified")))
    return {key: value[key] for key in FIELDS}
