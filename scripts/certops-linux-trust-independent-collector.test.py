"""Actual JS schema fixture through real collector, never native trust execution."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
import certops_linux_trust_independent_proof as proof

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("trust_independent_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def report(version="24.04"):
    source = "const f=require('./scripts/test-support/linux-trust-independent-artifact.cjs'),h=require('./scripts/certops-linux-trust-independent-roots');const a=f.artifact(" + json.dumps(version) + ");h.verifyProof(a.report.nativeIndependentTrustRoots);process.stdout.write(JSON.stringify(a.report));"
    return json.loads(subprocess.check_output(["node", "-e", source], cwd=ROOT, text=True))


class IndependentTrustProjection(unittest.TestCase):
    def test_actual_js_artifact_reaches_real_collector_on_each_qualified_surface(self):
        for version in ("22.04", "24.04", "9.6"):
            value = report(version)
            value["privateLocalFiles"] = "must-not-survive"
            actual = collector.sanitized_report(value, {proof.SUITE}, set())
            self.assertEqual(actual[proof.FIELD], value[proof.FIELD])
            self.assertEqual(len(actual["fixtureSources"]), 11)
            self.assertNotIn("must-not-survive", json.dumps(actual))

    def test_each_native_observation_is_required_and_private_inner_fields_refuse(self):
        original = report()
        for flag in proof.FLAGS:
            for wrong in (False, 1, None):
                value = copy.deepcopy(original)
                value[proof.FIELD][flag] = wrong
                with self.assertRaises(ValueError):
                    collector.sanitized_report(value, {proof.SUITE}, set())
        for change in ({"family": "rhel"}, {"rawKey": "secret"}, {"derivedReferenceKind": "declared"}, {"rootFingerprints": ["a" * 64, "a" * 64]}):
            value = copy.deepcopy(original)
            value[proof.FIELD].update(change)
            with self.assertRaises(ValueError):
                proof.project_report(value)


if __name__ == "__main__":
    unittest.main()
