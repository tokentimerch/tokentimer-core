"""Actual JS validator -> closed Python projection; no browser/native run."""
import copy
import json
from pathlib import Path
import subprocess
import unittest
import importlib.util
import certops_acme_native_console_proof as proof

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("native_console_main_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def envelope():
    source = "process.stdout.write(JSON.stringify(require('./scripts/test-support/acme-native-console-proof.cjs').artifact().report))"
    return json.loads(subprocess.check_output(["node", "-e", source], cwd=ROOT, text=True))


class NativeConsoleProjection(unittest.TestCase):
    def test_actual_js_closed_contract_and_outer_privacy(self):
        value = envelope()
        value["privateState"] = "must-not-survive"
        actual = proof.fields(value)
        self.assertEqual(actual[proof.FIELD], value[proof.FIELD])
        self.assertNotIn("must-not-survive", json.dumps(actual))
        projected = collector.sanitized_report(value, {proof.SUITE}, set())
        self.assertEqual(projected[proof.FIELD], value[proof.FIELD])
        self.assertNotIn("must-not-survive", json.dumps(projected))
        actual[proof.FIELD]["acceptedLines"] = 2
        self.assertEqual(value[proof.FIELD]["acceptedLines"], 42)

    def test_missing_or_false_observations_and_wrong_native_scope_refuse(self):
        original = envelope()
        for flag in proof.FLAGS:
            for wrong in (False, None, 1):
                value = copy.deepcopy(original)
                value[proof.FIELD][flag] = wrong
                with self.assertRaises(ValueError):
                    proof.fields(value)
        for key in original[proof.FIELD]:
            value = copy.deepcopy(original)
            del value[proof.FIELD][key]
            with self.assertRaises(ValueError):
                proof.fields(value)
        for patch in ({"acceptedLines": True}, {"acceptedLines": 2001}, {"browserCertOpsWrites": True}, {"browserCertOpsWrites": 1}, {"client": "acme.sh"}, {"privateLog": "secret"}, {"claimId": "foreign"}, {"firstLineSha256": original[proof.FIELD]["completionLineSha256"]}):
            value = copy.deepcopy(original)
            value[proof.FIELD].update(patch)
            with self.assertRaises(ValueError):
                proof.fields(value)
        for field, wrong in (("distributionVersion", "22.04"), ("distributionId", "alpine"), ("executionSurface", "container"), ("measurement", "configured"), ("libc", "musl")):
            value = copy.deepcopy(original)
            value["qualificationEnvironment"][field] = wrong
            with self.assertRaises(ValueError):
                proof.fields(value)
        self.assertEqual(proof.fields({"suite": "browser-agent-console"}), {})

    def test_only_dedicated_authenticated_workflow_can_supply_console_slot(self):
        value = envelope()
        proof.verify_workflow(value, ".github/workflows/certops-acme-native-console.yml")
        self.assertIn(".github/workflows/certops-acme-native-console.yml", collector.WORKFLOWS)
        for workflow in (None, ".github/workflows/certops-real-acme.yml", ".github/workflows/certops-browser-qualification.yml"):
            with self.assertRaises(ValueError):
                proof.verify_workflow(value, workflow)


if __name__ == "__main__":
    unittest.main()
