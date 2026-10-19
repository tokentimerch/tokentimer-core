"""Offline projection adversaries; these do not create native evidence."""
import copy
import importlib.util
import pathlib
import unittest

MODULE = pathlib.Path(__file__).with_name("certops_adcs_http_leaf_crl_proof.py")
SPEC = importlib.util.spec_from_file_location("http_leaf_crl", MODULE)
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)


def fixture():
    return {
        "scope": PROOF.SCOPE,
        "enrollmentId": "10000000-0000-4000-8000-000000000001",
        "jobId": "10000000-0000-4000-8000-000000000002", "requestId": 42,
        "restoredEnrollmentId": "10000000-0000-4000-8000-000000000003",
        "restoredJobId": "10000000-0000-4000-8000-000000000004",
        "restoredRequestId": 43, "restoredLeafFingerprint": "6" * 64,
        "leafFingerprint": "1" * 64, "publicCrlSha256": "2" * 64,
        "nativeHelperSha256": "3" * 64, "originalPublicationSha256": "4" * 64,
        "appliedPublicationSha256": "5" * 64, "caRequestCounts": [10, 11, 12],
        "nativeVerdicts": ["valid", "revocation_unknown", "valid"],
        "endpointStatusCodes": [200, 503, 200], "ocspQualified": False,
        "caOutageQualified": False, "signedCmcRenewalQualified": False,
        "deferredRecovery":{"originalJobId":"10000000-0000-4000-8000-000000000005","originalClaimId":"10000000-0000-4000-8000-000000000006","continuationJobId":"10000000-0000-4000-8000-000000000002","continuationClaimId":"10000000-0000-4000-8000-000000000007","requestId":42},
        **{key: True for key in PROOF.FLAGS},
    }


class HttpLeafCrlProjection(unittest.TestCase):
    def test_projection_keeps_only_bounded_public_native_facts(self):
        original = fixture()
        self.assertEqual(PROOF.fields(original), original)
        self.assertEqual(PROOF.fields({**original, "privateReceipt": "discard"}), original)

    def test_missing_false_or_promoted_native_facts_refuse(self):
        for key in PROOF.FIELDS:
            value = fixture()
            del value[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                PROOF.fields(value)
        for key in PROOF.FLAGS:
            for invalid in (False, 1):
                with self.subTest(flag=key, invalid=invalid), self.assertRaises(ValueError):
                    PROOF.fields({**fixture(), key: invalid})
        for key in ("ocspQualified", "caOutageQualified", "signedCmcRenewalQualified"):
            with self.subTest(promotion=key), self.assertRaises(ValueError):
                PROOF.fields({**fixture(), key: True})

    def test_scope_counts_and_uint32_are_not_inferred(self):
        for key, invalid in (("scope", "http-intermediate"), ("requestId", 4294967296),
                             ("requestId", True), ("caRequestCounts", [10, 12]),
                             ("caRequestCounts", [True, 2]),
                             ("nativeVerdicts", ["valid"] * 3),
                             ("endpointStatusCodes", [200, 200, 200])):
            value = copy.deepcopy(fixture())
            value[key] = invalid
            with self.subTest(field=key, invalid=invalid), self.assertRaises(ValueError):
                PROOF.fields(value)

    def test_same_leaf_distinct_claim_continuation_is_required(self):
        for patch in ({"requestId":43},{"requestId":True},{"originalJobId":fixture()["jobId"]},{"continuationJobId":fixture()["restoredJobId"]},{"originalClaimId":fixture()["deferredRecovery"]["continuationClaimId"]},{"rawContainer":"private"}):
            value=copy.deepcopy(fixture())
            value["deferredRecovery"].update(patch)
            with self.subTest(patch=patch),self.assertRaises(ValueError):
                PROOF.fields(value)


if __name__ == "__main__":
    unittest.main()
