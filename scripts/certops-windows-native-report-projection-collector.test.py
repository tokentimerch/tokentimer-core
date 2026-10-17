"""Offline report projection parity; never executes Windows service scenarios."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("native_projection_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def fixtures():
    source = """const out=[];
for(const version of ['2022','2025']){
 const stop=require('./scripts/test-support/windows-stop-offline.cjs');
 const parent=stop.artifact(version).report;
 out.push(parent,require('./tests/e2e/helpers/certops-windows-interruption-native').createReport(parent,{candidateSha:stop.candidateSha}));
 for(const file of ['./scripts/test-support/windows-alive-grace.cjs','./scripts/test-support/windows-failed-rollback.cjs','./scripts/fixtures/certops-windows-installed-bind-failure-native.cjs'])out.push(require(file).artifact(version).report);
}console.log(JSON.stringify(out));"""
    return json.loads(subprocess.check_output(["node", "-e", source], cwd=ROOT, text=True, timeout=20))


def matrix_errors(reports):
    source = """const fs=require('node:fs'),reports=JSON.parse(fs.readFileSync(0,'utf8'));
const matrix=require('./docs/certops/release-qualification-matrix.json'),verify=require('./scripts/certops-release-qualification').verifyMatrix;
console.log(JSON.stringify(reports.map(report=>{
 const slot=matrix.slots.find(s=>s.suite===report.suite&&s.environment.osVersion===report.qualificationEnvironment.osVersion);
 return verify([{kind:'host',suite:report.suite,environment:slot.environment,report}],{candidateSha:report.candidateSha,specification:{schemaVersion:1,slots:[slot]}});
})));"""
    return json.loads(subprocess.check_output(["node", "-e", source], cwd=ROOT, input=json.dumps(reports), text=True, timeout=20))


class NativeReportProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reports = fixtures()

    def test_official_sanitizer_preserves_validated_native_identity_through_actual_matrix_caller(self):
        projected = []
        for original in self.reports:
            report = copy.deepcopy(original)
            report["privatePath"] = "must-not-survive"
            clean = collector.sanitized_report(report, {report["suite"]}, set())
            self.assertNotIn("must-not-survive", json.dumps(clean))
            projected.append(clean)
        self.assertEqual(matrix_errors(projected), [[] for _ in projected])
        for clean in projected:
            self.assertEqual((clean.get("platform"), clean.get("architecture")), ("win32", "x64"))

    def test_unvalidated_platform_architecture_identity_and_cleanup_are_never_repaired(self):
        for report in self.reports:
            for key, value in (("platform", "linux"), ("architecture", "arm64"), ("cleanup", {"status": "failed"})):
                with self.subTest(suite=report["suite"], key=key), self.assertRaises(ValueError):
                    collector.sanitized_report({**report, key: value}, {report["suite"]}, set())
            for key, value in (("identity", "Administrator"), ("measurement", "simulated")):
                invalid = copy.deepcopy(report)
                invalid["qualificationEnvironment"][key] = value
                with self.subTest(suite=report["suite"], key=key), self.assertRaises(ValueError):
                    collector.sanitized_report(invalid, {report["suite"]}, set())


if __name__ == "__main__":
    unittest.main()
