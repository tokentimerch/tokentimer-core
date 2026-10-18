"""Offline official collector parity; no native CA, service or key is touched."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
import certops_adcs_uncertain_abandon_proof as proof

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("abandon_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def fixture():
    return json.loads(subprocess.check_output(["node", "-e", "console.log(JSON.stringify(require('./scripts/fixtures/certops-native-uncertain-abandon.cjs').nativeReport()))"], cwd=ROOT, text=True))


def js_errors(report):
    source = """const fs=require('node:fs'),report=JSON.parse(fs.readFileSync(0,'utf8'));
const slot=require('./scripts/certops-qualification-manifest').slots.find(row=>row.suite===report.suite);
console.log(JSON.stringify(require('./scripts/certops-release-qualification').verifyMatrix([{kind:'host',suite:report.suite,environment:slot.environment,report}],{candidateSha:report.candidateSha,specification:{schemaVersion:1,slots:[slot]}})));"""
    return json.loads(subprocess.check_output(["node", "-e", source], cwd=ROOT, input=json.dumps(report), text=True))


class NativeAbandonCollectorTests(unittest.TestCase):
    def test_actual_sidecar_factory_roundtrips_official_python_and_js(self):
        report = fixture()
        report["privateState"] = "must-not-survive"
        clean = collector.sanitized_report(report, {proof.SUITE}, set())
        self.assertNotIn("must-not-survive", json.dumps(clean))
        self.assertEqual(clean["nativeAdcsUncertainAbandon"], report["nativeAdcsUncertainAbandon"])
        self.assertEqual(js_errors(clean), [])
        self.assertEqual(len(clean["scenarios"]), 8)

    def test_native_and_browser_facts_are_mandatory_and_cross_bound(self):
        report = fixture()
        for path, value in (("nativeExecutionQualified", False), ("responseLossQualified", True), ("disposableForestRan", False), ("native.caRequestsAtFault", 1), ("native.actualLeaseWaitMs", 0), ("native.ownedObserverDrained", False), ("browser.exactUnacceptedKeyAbsent", False), ("identity.csrSha256", "wrong"), ("identity.cleanupJobId", report["nativeAdcsUncertainAbandon"]["identity"]["originalJobId"])):
            invalid = copy.deepcopy(report)
            target = invalid["nativeAdcsUncertainAbandon"]
            parts = path.split(".")
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                proof.fields(invalid, collector.browser_abandon_fields)
            self.assertTrue(js_errors(invalid))
        for key in proof.FLAGS:
            invalid = copy.deepcopy(report)
            del invalid["nativeAdcsUncertainAbandon"]["native"][key]
            with self.subTest(flag=key), self.assertRaises(ValueError):
                proof.fields(invalid, collector.browser_abandon_fields)

    def test_only_root_campaign_with_successful_cleanup_and_all_stages(self):
        report = fixture()
        proof.verify_workflow(report, proof.WORKFLOW)
        for workflow in (".github/workflows/certops-adcs-coverage-variants.yml", ".github/workflows/certops-enterprise-adcs-response-loss-experiment.yml"):
            with self.assertRaises(ValueError):
                proof.verify_workflow(report, workflow)
        for key, value in (("platform", "linux"), ("architecture", "arm64"), ("cleanup", {"status": "failed"})):
            invalid = {**report, key: value}
            with self.assertRaises(ValueError):
                proof.fields(invalid, collector.browser_abandon_fields)
            self.assertTrue(js_errors(invalid))
        invalid = copy.deepcopy(report)
        invalid["scenarios"].pop()
        self.assertTrue(js_errors(invalid))


if __name__ == "__main__":
    unittest.main()
