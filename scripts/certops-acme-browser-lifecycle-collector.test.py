"""Actual JS artifact -> actual collector; no browser/CA execution."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
import certops_acme_browser_lifecycle_proof as proof

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("browser_lifecycle_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def report():
    return json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require('./scripts/test-support/acme-browser-lifecycle-proof.cjs').artifact().report))"], cwd=ROOT, text=True))


class LifecycleProjection(unittest.TestCase):
    def test_actual_js_proof_reaches_real_parser_without_private_outer_state(self):
        value = report()
        value["localPrivateState"] = "must-not-survive"
        result = collector.sanitized_report(value, {proof.SUITE}, set())
        self.assertEqual(result[proof.FIELD], value[proof.FIELD])
        self.assertEqual(result["nativeFileDiscoveryRefusals"], value["nativeFileDiscoveryRefusals"])
        self.assertNotIn("must-not-survive", json.dumps(result))
        proof.verify_workflow(value, ".github/workflows/certops-acme-browser-lifecycle.yml")
        for wrong in (None, ".github/workflows/certops-real-acme.yml", ".github/workflows/certops-acme-native-console.yml"):
            with self.assertRaises(ValueError):
                proof.verify_workflow(value, wrong)

    def test_every_native_observation_is_mandatory_and_extra_state_refused(self):
        original = report()
        for flag in proof.FLAGS:
            for wrong in (False, 1, None):
                value = copy.deepcopy(original)
                value[proof.FIELD][flag] = wrong
                with self.assertRaises(ValueError):
                    collector.sanitized_report(value, {proof.SUITE}, set())
        for change in ({"rawKey": "private"}, {"spkiHashes": ["a" * 64, "a" * 64]}, {"jobIds": ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"]}):
            value = copy.deepcopy(original)
            value[proof.FIELD].update(change)
            with self.assertRaises(ValueError):
                proof.project_report(value)

    def test_native_discovery_is_closed_nonroot_and_requires_all_actual_observations(self):
        original = report()
        for flag in proof.DISCOVERY_FLAGS:
            for wrong in (False, 1, None):
                value = copy.deepcopy(original)
                value["nativeFileDiscoveryRefusals"][flag] = wrong
                with self.assertRaises(ValueError):
                    collector.sanitized_report(value, {proof.SUITE}, set())
        for change in ({"uid": 0}, {"gid": True}, {"positiveScanCount": 1}, {"positiveScanCount": 2.5}, {"positiveFingerprint": "f" * 64}, {"privatePath": "secret"}):
            value = copy.deepcopy(original)
            value["nativeFileDiscoveryRefusals"].update(change)
            with self.assertRaises(ValueError):
                proof.project_report(value)
        value = copy.deepcopy(original)
        del value["nativeFileDiscoveryRefusals"]
        with self.assertRaises(ValueError):
            proof.project_report(value)


if __name__ == "__main__":
    unittest.main()
