"""Offline actual JavaScript/Python projection parity, never CA execution."""
import copy
import json
from pathlib import Path
import subprocess
import unittest
from certops_adcs_unique_candidate_proof import fields, FLAGS

ROOT = Path(__file__).resolve().parent.parent

class UniqueCandidate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.value = json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require('./scripts/fixtures/certops-adcs-unique-candidate.cjs').proof()))"], cwd=ROOT, text=True))

    def test_official_closed_projection_roundtrips_to_native_verifier(self):
        projected = fields(self.value)
        result = subprocess.run(["node", "-e", "const p=JSON.parse(require('node:fs').readFileSync(0,'utf8'));require('./tests/e2e/helpers/certops-adcs-uncertain-operator-unique').verifyProof(p)"], input=json.dumps(projected), cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(projected, self.value)

    def test_missing_coerced_early_and_broader_claims_are_rejected(self):
        for key in self.value:
            value = copy.deepcopy(self.value)
            del value[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                fields(value)
        patches = [{flag: wrong} for flag in FLAGS for wrong in (False, 1, "true")]
        patches += [{"responseLossTimingQualified": True}, {"actualLeaseWaitMs": 60000}, {"caRequestsAfterRecovery": 2}, {"caRequestsAfterOperatorSubmission": True}, {"jobIds": [self.value["jobIds"][0]] * 2}, {"privateKey": "never-public"}]
        for patch in patches:
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                fields({**self.value, **patch})

if __name__ == "__main__":
    unittest.main()
