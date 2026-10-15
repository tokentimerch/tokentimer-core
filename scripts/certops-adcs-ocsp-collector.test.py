"""Actual JS proof factory to Python projection, with no native execution."""
import copy
import json
import pathlib
import subprocess
import unittest

import certops_adcs_ocsp_proof as subject

ROOT = pathlib.Path(__file__).resolve().parent.parent


class OcspProjection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(
            ["node", "-e", "console.log(JSON.stringify(require('./scripts/fixtures/certops-adcs-ocsp.cjs').proof()))"],
            cwd=ROOT, capture_output=True, text=True, timeout=30, check=True,
        )
        cls.proof = json.loads(result.stdout)

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


if __name__ == "__main__":
    unittest.main()
