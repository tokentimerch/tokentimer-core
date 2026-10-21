"""Offline actual-JS proof parity. Never launches an installed service."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
import certops_linux_installed_discovery_proof as proof

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("installed_discovery_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def fixture():
    return json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require('./scripts/test-support/linux-installed-discovery-proof.cjs').artifact().report))"], cwd=ROOT, text=True))


class InstalledDiscoveryProjection(unittest.TestCase):
    def test_actual_js_proof_parity_closed_native_scope(self):
        value = fixture()
        value["privateConfig"] = "never-persist"
        projected = collector.sanitized_report(value, {proof.SUITE}, set())
        self.assertEqual(projected[proof.FIELD], value[proof.FIELD])
        self.assertNotIn("never-persist", json.dumps(projected))
        for workflow in (".github/workflows/certops-linux-systemd.yml", ".github/workflows/certops-linux-published-upgrade.yml"):
            proof.verify_workflow(value, workflow)
        for wrong in (None, ".github/workflows/certops-real-acme.yml"):
            with self.assertRaises(ValueError):
                proof.verify_workflow(value, wrong)

    def test_every_actual_fact_and_exact_identity_are_mandatory(self):
        original = fixture()
        for flag in proof.FLAGS:
            for wrong in (False, None, 1):
                value = copy.deepcopy(original)
                value[proof.FIELD][flag] = wrong
                with self.assertRaises(ValueError):
                    collector.sanitized_report(value, {proof.SUITE}, set())
        for change in ({"uid": 0}, {"gid": True}, {"positiveScanCount": 1}, {"positiveScanCount": 2.5}, {"privateBackupPath": "must-not-survive"}):
            value = copy.deepcopy(original)
            value[proof.FIELD].update(change)
            with self.assertRaises(ValueError):
                proof.project_report(value)
        for key, wrong in (("platform", "win32"), ("architecture", "arm64")):
            value = copy.deepcopy(original)
            value[key] = wrong
            with self.assertRaises(ValueError):
                proof.project_report(value)


if __name__ == "__main__":
    unittest.main()
