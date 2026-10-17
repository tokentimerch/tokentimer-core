"""Offline browser sidecar/collector parity; no browser, domain or native test executes."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

import certops_adcs_browser_enrollment_proof as proof

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("browser_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def fixture():
    return json.loads(subprocess.check_output(["node", "-e", "console.log(JSON.stringify(require('./scripts/fixtures/certops-native-browser-enrollment.cjs').nativeReport()))"], cwd=ROOT, text=True))


def js_errors(report):
    source = """const fs=require('node:fs'),report=JSON.parse(fs.readFileSync(0,'utf8'));
const slot=require('./docs/certops/release-qualification-matrix.json').slots.find(row=>row.suite===report.suite);
console.log(JSON.stringify(require('./scripts/certops-release-qualification').verifyMatrix([{kind:'host',suite:report.suite,environment:slot.environment,report}],{candidateSha:report.candidateSha,specification:{schemaVersion:1,slots:[slot]}})));"""
    return json.loads(subprocess.check_output(["node", "-e", source], cwd=ROOT, input=json.dumps(report), text=True))


class BrowserEnrollmentCollectorTests(unittest.TestCase):
    def test_actual_sidecar_factory_roundtrips_official_python_and_js_verifiers(self):
        report = fixture()
        report["privateState"] = "must-not-survive"
        clean = collector.sanitized_report(report, {proof.SUITE}, set())
        self.assertNotIn("must-not-survive", json.dumps(clean))
        self.assertEqual(clean["nativeAdcsBrowserEnrollment"], report["nativeAdcsBrowserEnrollment"])
        self.assertEqual(js_errors(clean), [])
        self.assertEqual(len(clean["scenarios"]), 9)

    def test_local_labels_missing_ui_native_or_cleanup_facts_fail_closed(self):
        report = fixture()
        for key in ("nativeExecutionQualified", "browserLaunched", "disposableForestRan", "confirmationBeforeSubmit"):
            invalid = copy.deepcopy(report)
            invalid["nativeAdcsBrowserEnrollment"][key] = False
            with self.subTest(key=key), self.assertRaises(ValueError):
                proof.fields(invalid)
            self.assertTrue(js_errors(invalid))
        for key in proof.FLAGS:
            invalid = copy.deepcopy(report)
            invalid["nativeAdcsBrowserEnrollment"]["nativeBrowserJourney"][key] = False
            with self.subTest(flag=key), self.assertRaises(ValueError):
                proof.fields(invalid)
        invalid = copy.deepcopy(report)
        invalid["cleanup"]["status"] = "failed"
        with self.assertRaises(ValueError):
            proof.fields(invalid)
        self.assertTrue(js_errors(invalid))

    def test_only_comprehensive_root_workflow_and_all_actual_stages_are_accepted(self):
        report = fixture()
        proof.verify_workflow(report, proof.WORKFLOW)
        for workflow in (".github/workflows/certops-adcs-coverage-variants.yml", ".github/workflows/certops-enterprise-adcs-hierarchy-qualification.yml"):
            with self.assertRaises(ValueError):
                proof.verify_workflow(report, workflow)
        invalid = copy.deepcopy(report)
        invalid["scenarios"].pop()
        self.assertTrue(js_errors(invalid))


if __name__ == "__main__":
    unittest.main()
