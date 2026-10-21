"""Offline certificate signing-rotation projection. Manual workflow_dispatch only. Not native qualification."""
import copy
import json
from pathlib import Path
import subprocess
import unittest
import importlib.util
import certops_acme_certificate_signing_proof as proof

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("certificate_signing_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def report():
    value = json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require('./scripts/fixtures/certops-acme-certificate-signing.cjs').fixture()))"], cwd=ROOT, text=True))
    return {
        "suite": proof.SUITE,
        "platform": "linux",
        "architecture": "x64",
        "qualificationEnvironment": {"osFamily": "linux", "distributionId": "ubuntu", "distributionVersion": "24.04", "distribution": "ubuntu", "osVersion": "24.04", "executionSurface": "host", "measurement": "native"},
        proof.FIELD: value,
        "localPrivatePath": "never-public",
    }


class CertificateSigningProjection(unittest.TestCase):
    def test_projects_the_closed_proof_and_drops_private_outer_fields(self):
        value = report()
        projected = proof.project_report(value)
        self.assertEqual(projected[proof.FIELD], value[proof.FIELD])
        self.assertNotIn("never-public", json.dumps(projected))
        actual = collector.sanitized_report(value, {proof.SUITE}, set())
        self.assertEqual(actual[proof.FIELD], value[proof.FIELD])
        self.assertNotIn("never-public", json.dumps(actual))

    def test_refuses_a_forced_completion_or_missing_proof(self):
        forced = report()
        forced[proof.FIELD]["forcedCompletionQualified"] = True
        with self.assertRaises(ValueError):
            proof.project_report(forced)
        missing = report()
        del missing[proof.FIELD]
        with self.assertRaises(ValueError):
            proof.project_report(missing)
        reused = report()
        reused[proof.FIELD]["rotatePrivateKey"] = False
        with self.assertRaises(ValueError):
            proof.project_report(reused)
        for name in proof.FLAGS:
            candidate = copy.deepcopy(report())
            candidate[proof.FIELD][name] = False
            with self.assertRaises(ValueError):
                proof.project_report(candidate)


if __name__ == "__main__":
    unittest.main()
