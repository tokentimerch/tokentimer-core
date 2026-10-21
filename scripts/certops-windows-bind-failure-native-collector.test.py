"""Offline native bind proof/projection parity. No Windows operations execute."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
import zipfile
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)

class NativeBindProjection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require('./scripts/fixtures/certops-windows-installed-bind-failure-native.cjs').artifact().report))"], cwd=ROOT, text=True, timeout=20))

    def test_exact_projection_matches_actual_js_verifier(self):
        projected = collector.windows_bind_failure_native_proof.fields(self.base)
        self.assertEqual(projected, self.base["nativeInstalledBindFailure"])
        subprocess.run(["node", "-e", "let s='';process.stdin.on('data',b=>s+=b);process.stdin.on('end',()=>require('./tests/e2e/helpers/certops-windows-installed-bind-failure-native').verifyProof(JSON.parse(s)));"], input=json.dumps(projected), text=True, cwd=ROOT, capture_output=True, check=True, timeout=20)

    def test_missing_simulated_overflow_foreign_and_failed_cleanup_refuse(self):
        for key in self.base["nativeInstalledBindFailure"]:
            value = copy.deepcopy(self.base); del value["nativeInstalledBindFailure"][key]
            with self.subTest(missing=key), self.assertRaises(ValueError): collector.windows_bind_failure_native_proof.fields(value)
        for patch in ({"nativeErrorCode": 1312}, {"forwardedExitCode": 197}, {"captureOverflow": True}, {"drainFailure": True}, {"certificateStoreModified": True}, {"originalArgvSha256": "f" * 64}, {"jobId": "-" * 36}):
            value = copy.deepcopy(self.base); value["nativeInstalledBindFailure"]["nativeInterposer"].update(patch)
            with self.subTest(patch=patch), self.assertRaises(ValueError): collector.windows_bind_failure_native_proof.fields(value)
        for patch in ({"cleanup": {"status": "failed"}}, {"architecture": "arm64"}, {"qualificationEnvironment": {**self.base["qualificationEnvironment"], "measurement": "simulated"}}):
            with self.assertRaises(ValueError): collector.windows_bind_failure_native_proof.fields({**self.base, **patch})

    def test_archive_projection_and_dedicated_workflow(self):
        stream = io.BytesIO()
        value = copy.deepcopy(self.base); value["privateOutputCapturePath"] = "must-not-survive"
        with zipfile.ZipFile(stream, "w") as archive: archive.writestr("native.json", json.dumps(value))
        projected = collector.extract_reports(stream.getvalue(), [self.base["suite"]], [])[0][1]
        self.assertEqual(projected["nativeInstalledBindFailure"], self.base["nativeInstalledBindFailure"])
        self.assertNotIn("must-not-survive", json.dumps(projected))
        workflow = ".github/workflows/certops-windows-installed-bind-failure.yml"
        self.assertIn(workflow, collector.WORKFLOWS)
        collector.verify_bind_failure_native_workflow(self.base, workflow)
        for other in (None, ".github/workflows/certops-windows-e2e.yml", ".github/workflows/certops-qualification.yml"):
            with self.assertRaises(ValueError): collector.verify_bind_failure_native_workflow(self.base, other)

if __name__ == "__main__": unittest.main()
