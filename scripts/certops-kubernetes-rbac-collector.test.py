"""Offline JS/Python native startup-RBAC projection parity, never cluster execution."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
import certops_kubernetes_rbac_proof as proof

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("kube_rbac_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class NativeStartupRbac(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = "process.stdout.write(JSON.stringify(require('./scripts/test-support/kubernetes-rbac-artifact.cjs').artifact().report))"
        cls.original = json.loads(subprocess.check_output(["node", "-e", source], cwd=ROOT, text=True))

    def test_actual_collector_keeps_only_closed_public_native_facts(self):
        value = copy.deepcopy(self.original)
        value["privateLocalState"] = "must-not-survive"
        result = collector.sanitized_report(value, {"kubernetes-host"}, set())
        self.assertEqual(result[proof.FIELD], value[proof.FIELD])
        self.assertNotIn("must-not-survive", json.dumps(result))
        self.assertEqual(len(result["fixtureSources"]), len(value["fixtureSources"]))

    def test_every_flag_requires_actual_boolean_and_no_missing_native_observation(self):
        for flag in proof.FLAGS:
            for wrong in (False, 1, None, "true"):
                value = copy.deepcopy(self.original)
                value[proof.FIELD][flag] = wrong
                with self.subTest(flag=flag, wrong=wrong), self.assertRaises(ValueError):
                    collector.sanitized_report(value, {"kubernetes-host"}, set())
            value = copy.deepcopy(self.original)
            value[proof.FIELD].pop(flag)
            with self.assertRaises(ValueError):
                proof.project_report(value)

    def test_closed_scope_native403_unique_identity_and_revision_lineage(self):
        for change in ({"schemaVersion": True}, {"scope": "local-contract"}, {"listStatus": "403"}, {"watchStatus": 401}, {"createStatus": 404}, {"createdCertificateUid": self.original[proof.FIELD]["certificateUid"]}, {"missedResourceVersion": "fabricated"}, {"watchedResourceVersion": "100"}, {"watchedResourceVersion": "1" * 21}, {"privateKey": "withheld"}):
            value = copy.deepcopy(self.original)
            value[proof.FIELD].update(change)
            with self.assertRaises(ValueError):
                collector.sanitized_report(value, {"kubernetes-host"}, set())
        value = copy.deepcopy(self.original)
        value.pop(proof.FIELD)
        with self.assertRaises(ValueError):
            proof.project_report(value)


if __name__ == "__main__":
    unittest.main()
