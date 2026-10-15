"""Offline actual JavaScript producer/Python projection parity, no native run."""
import copy
import json
from pathlib import Path
import subprocess
import unittest
import certops_adcs_result_outbox_proof as proof


def fixture():
    root = Path(__file__).resolve().parent.parent
    return json.loads(subprocess.check_output(["node", "-e", "console.log(JSON.stringify(require('./scripts/fixtures/certops-adcs-result-outbox.cjs').proof()))"], cwd=root, text=True))


class Projection(unittest.TestCase):
    def test_actual_producer_contract_and_private_projection(self):
        value = fixture()
        self.assertEqual(proof.fields({**value, "privateCredential": "discard"}), value)

    def test_missing_invalid_and_promoted_facts_refuse(self):
        original = fixture()
        for key in proof.FIELDS:
            value = copy.deepcopy(original)
            del value[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                proof.fields(value)
        for patch in ({"requestId": True}, {"caRequestCounts": [10, 11, 12]}, {"retryDelayMs": 1}, {"backgroundTimerQualified": True}, {"atomicTreeContainmentQualified": True}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                proof.fields({**original, **patch})
        for flag in proof.FLAGS:
            for wrong in (False, 1):
                with self.subTest(flag=flag, wrong=wrong), self.assertRaises(ValueError):
                    proof.fields({**original, flag: wrong})


if __name__ == "__main__":
    unittest.main()
