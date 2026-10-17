"""Projects the JS OCSP factories into the closed Python reports.

Native lab execution is still pending. Signed-good availability and
authoritative revoked status stay separate reports.
"""
import copy
import json
import pathlib
import subprocess
import unittest

import certops_adcs_ocsp_proof as subject
import certops_adcs_ocsp_revoked_proof as revoked_proof

ROOT = pathlib.Path(__file__).resolve().parent.parent


class OcspProjection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(
            ["node", "-e", "console.log(JSON.stringify(require('./scripts/fixtures/certops-adcs-ocsp.cjs').proof()))"],
            cwd=ROOT, capture_output=True, text=True, timeout=30, check=True,
        )
        cls.proof = json.loads(result.stdout)
        cls.revoked = json.loads(subprocess.check_output(["node", "-e", "console.log(JSON.stringify(require('./scripts/fixtures/certops-adcs-ocsp-revoked.cjs').proof()))"],cwd=ROOT,text=True,timeout=30))

    def test_actual_js_factory_matches_closed_python_projection(self):
        self.assertEqual(subject.fields(self.proof), self.proof)

    def test_all_missing_false_and_unsupported_promotions_refuse(self):
        for key in subject.FIELDS:
            value = copy.deepcopy(self.proof)
            del value[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                subject.fields(value)
        for key in subject.FLAGS:
            for invalid in (False, 1):
                with self.subTest(flag=key, invalid=invalid), self.assertRaises(ValueError):
                    subject.fields({**self.proof, key: invalid})
        for key in subject.FALSE_FLAGS:
            with self.subTest(promotion=key), self.assertRaises(ValueError):
                subject.fields({**self.proof, key: True})

    def test_id_counts_scope_and_private_fields_fail_closed(self):
        for key, invalid in (
            ("signerRequestId", True), ("requestIds", [40, 42]),
            ("caRequestCounts", [39, 40, 42, 43]),
            ("nativeVerdicts", ["valid"] * 3), ("privateReceipt", "forbidden"),
        ):
            value = copy.deepcopy(self.proof)
            value[key] = invalid
            with self.subTest(field=key), self.assertRaises(ValueError):
                subject.fields(value)

    def test_deferred_claim_and_same_leaf_request_crossbinding(self):
        for patch in ({"requestId":42},{"requestId":True},{"originalJobId":self.proof["jobIds"][0]},{"continuationJobId":self.proof["jobIds"][1]},{"originalClaimId":self.proof["deferredRecovery"]["continuationClaimId"]},{"rawContainer":"private"}):
            value=copy.deepcopy(self.proof)
            value["deferredRecovery"].update(patch)
            with self.subTest(patch=patch),self.assertRaises(ValueError):
                subject.fields(value)

    def test_actual_revoked_factory_is_bound_to_the_original_installed_pair(self):
        self.assertEqual(revoked_proof.fields(self.revoked, self.proof), self.revoked)
        self.assertEqual(revoked_proof.fields({**self.revoked, "privatePhase": "discard"}, self.proof), self.revoked)
        for key in revoked_proof.FIELDS:
            value=copy.deepcopy(self.revoked)
            del value[key]
            with self.subTest(missing_revoked=key),self.assertRaises(ValueError):
                revoked_proof.fields(value,self.proof)

    def test_revoked_proof_refuses_false_counts_other_leaf_and_unsupported_scope(self):
        for flag in revoked_proof.FLAGS:
            for invalid in (False,1):
                with self.subTest(revoked_flag=flag,invalid=invalid),self.assertRaises(ValueError):
                    revoked_proof.fields({**self.revoked,flag:invalid},self.proof)
        for patch in ({"currentRequestId":41},{"historicalRequestId":True},{"caRequestCounts":[42,43]},{"revokedCrlNumber":"0"},{"currentFingerprint":"e"*64},{"installedAgentRevokedLeafRefusalQualified":True},{"authoritativeUnknownStatusQualified":True}):
            with self.subTest(revoked_patch=patch),self.assertRaises(ValueError):
                revoked_proof.fields({**self.revoked,**patch},self.proof)
        original=copy.deepcopy(self.proof)
        original["actualSignedGoodResponses"]=False
        with self.assertRaises(ValueError):
            revoked_proof.fields(self.revoked,original)

    def test_revoked_report_stays_separate_from_signed_good_availability(self):
        self.assertFalse(self.proof["authoritativeRevokedStatusQualified"])
        self.assertTrue(self.revoked["authoritativeRevokedStatusQualified"])
        self.assertNotEqual(self.proof["scope"], self.revoked["scope"])
        self.assertEqual(self.revoked["nativeVerdict"], "revoked")
        self.assertNotIn("revoked", self.proof["nativeVerdicts"])
        with self.assertRaises(ValueError):
            subject.fields(self.revoked)
        with self.assertRaises(ValueError):
            revoked_proof.fields(self.proof, self.proof)


if __name__ == "__main__":
    unittest.main()
