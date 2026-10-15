"""Actual JS artifact through closed native collector; never daemon execution."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
import certops_daemon_coordinator_proof as proof

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("daemon_coordinator_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def report(service="nginx", version="24.04"):
    source = "const f=require('./scripts/test-support/daemon-coordinator-artifact.cjs'),h=require('./scripts/certops-daemon-coordinator-rollback');const a=f.artifact(" + json.dumps(service) + "," + json.dumps(version) + ");h.verifyProof(a.report.nativeDaemonCoordinatorRollback);process.stdout.write(JSON.stringify(a.report));"
    return json.loads(subprocess.check_output(["node", "-e", source], cwd=ROOT, text=True))


class DaemonProjection(unittest.TestCase):
    def test_six_actual_js_artifacts_reach_real_projection_with_private_outer_state_removed(self):
        for service in ("nginx", "apache", "haproxy"):
            for version in ("22.04", "24.04"):
                value = report(service, version)
                value["localPrivateState"] = "must-not-survive"
                result = collector.sanitized_report(value, proof.SUITES, set())
                self.assertEqual(result[proof.FIELD], value[proof.FIELD])
                self.assertEqual(len(result["fixtureSources"]), 13)
                self.assertNotIn("must-not-survive", json.dumps(result))

    def test_every_native_fact_is_mandatory_and_cannot_promote_signed_or_wrong_service_evidence(self):
        original = report()
        for flag in proof.FLAGS:
            for wrong in (False, 1, None):
                value = copy.deepcopy(original)
                value[proof.FIELD][flag] = wrong
                with self.assertRaises(ValueError):
                    collector.sanitized_report(value, proof.SUITES, set())
        for change in ({"service": "apache"}, {"evidenceTransport": "signed-api"}, {"rawKey": "secret"}):
            value = copy.deepcopy(original)
            value[proof.FIELD].update(change)
            with self.assertRaises(ValueError):
                proof.project_report(value)


if __name__ == "__main__":
    unittest.main()
