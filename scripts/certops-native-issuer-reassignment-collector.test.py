"""Offline CA-scoped projection/parity regressions; never executes a CA or agent."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

import certops_native_issuer_reassignment_proof as proof

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("issuer_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def fixture():
    uid = lambda digit: f"{digit * 8}-{digit * 4}-{digit * 4}-{digit * 4}-{digit * 12}"
    p = dict(scope="confirmed-adcs-issuer-switch-then-production-scheduler-renewal",
             renewalProtocol="production-scheduler-sweep-after-public-issuer-switch",
             schedulerInvocation="qualification-invoked-production-default-sweep",
             workerIntervalQualified=False, nativeCell="qualified", originIssuerId=uid("1"), destinationIssuerId=uid("2"),
             originCaKeySha256="a" * 64, destinationCaKeySha256="b" * 64, profileId=uid("3"), certificateId=uid("4"),
             requestIds=["17", "17"], fingerprints=["c" * 64, "d" * 64], spkiFingerprints=["e" * 64, "f" * 64],
             enrollmentIds=[uid("5"), uid("6")], jobIds=[uid("7"), uid("8")],
             containerNames=["tokentimer-enr-" + uid("5"), "tokentimer-enr-" + uid("6")],
             **dict.fromkeys(proof.FLAGS, True))
    p["nativeRequests"] = [dict(caConfig=config, caKeySha256=p["originCaKeySha256" if i == 0 else "destinationCaKeySha256"],
                               requestId="17", disposition=20, subjectRequestCount=1, fingerprintSha256=p["fingerprints"][i])
                           for i, config in enumerate(proof.CONFIGS)]
    contract = json.loads((ROOT / "docs/certops/qualification-suites.json").read_text())
    slot = next(x for x in json.loads((ROOT / "docs/certops/release-qualification-matrix.json").read_text())["slots"] if x["suite"] == proof.SUITE)
    digest = lambda file: dict(file=file, sha256=hashlib.sha256((ROOT / file).read_bytes()).hexdigest())
    stamp = "2026-10-18T00:00:00.000Z"
    return dict(schemaVersion=1, suite=proof.SUITE, candidateSha="a" * 40, status="passed", strict=True, evidenceLevel="real-host",
                startedAt=stamp, finishedAt=stamp, requiredScenarios=contract["suites"][proof.SUITE],
                scenarios=[dict(id=id, status="passed", evidenceLevel="real-host", startedAt=stamp, finishedAt=stamp) for id in contract["suites"][proof.SUITE]],
                requiredCapabilities=contract["requiredCapabilities"][proof.SUITE],
                capabilities={name: dict(available=True) for name in contract["requiredCapabilities"][proof.SUITE]},
                missingScenarios=[], missingCapabilities=[], nativeCell="qualified", platform="win32", architecture="x64",
                cleanup=dict(status="passed"), nativeIssuerReassignment=p,
                qualificationEnvironment={**slot["environment"], "measurement": "native"},
                fixtureSource=digest(slot["source"]), fixtureSources=[digest(file) for file in slot["requiredSources"]],
                artifactQualification="workflow-checkout-source")


def js_errors(report):
    program = """const fs=require('node:fs');const report=JSON.parse(fs.readFileSync(0,'utf8'));
const slot=require('./docs/certops/release-qualification-matrix.json').slots.find(s=>s.suite===report.suite);
const errors=require('./scripts/certops-release-qualification').verifyMatrix([{kind:'host',suite:report.suite,environment:slot.environment,report}],{candidateSha:report.candidateSha,specification:{schemaVersion:1,slots:[slot]}});process.stdout.write(JSON.stringify(errors));"""
    return json.loads(subprocess.check_output(["node", "-e", program], input=json.dumps(report), cwd=ROOT, text=True))


class IssuerCollectorTests(unittest.TestCase):
    def test_complete_public_projection_survives_official_collector_and_js_verifier(self):
        report = fixture()
        report["privateToken"] = "must-not-survive"
        clean = collector.sanitized_report(report, {proof.SUITE}, set())
        self.assertEqual(clean["nativeIssuerReassignment"], report["nativeIssuerReassignment"])
        self.assertNotIn("must-not-survive", json.dumps(clean))
        self.assertEqual(js_errors(clean), [])
        self.assertEqual(len(clean["scenarios"]), 6)

    def test_missing_native_fields_or_pending_labels_never_qualify(self):
        for key, value in (("nativeCell", "pending"), ("architecture", "arm64"), ("cleanup", {"status": "failed"})):
            report = fixture()
            report[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                proof.fields(report)
            self.assertTrue(js_errors(report))
        report = fixture()
        del report["nativeIssuerReassignment"]["nativeRequests"]
        with self.assertRaises(ValueError):
            proof.fields(report)
        self.assertTrue(js_errors(report))

    def test_observations_are_bound_to_ca_not_merely_numeric_request_id(self):
        report = fixture()
        self.assertEqual(proof.fields(report)["requestIds"], ["17", "17"])
        for patch in (dict(caConfig=proof.CONFIGS[0]), dict(caKeySha256="a" * 64), dict(requestId="18"),
                      dict(disposition=9), dict(subjectRequestCount=2), dict(subjectRequestCount=True), dict(fingerprintSha256="c" * 64)):
            invalid = copy.deepcopy(report)
            invalid["nativeIssuerReassignment"]["nativeRequests"][1].update(patch)
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                proof.fields(invalid)
            self.assertTrue(js_errors(invalid))

    def test_foreign_workflow_and_incomplete_scenarios_refused(self):
        report = fixture()
        proof.verify_workflow(report, proof.WORKFLOW)
        self.assertIn(proof.WORKFLOW, collector.WORKFLOWS)
        with self.assertRaises(ValueError):
            proof.verify_workflow(report, ".github/workflows/certops-windows-e2e.yml")
        for scenario in report["scenarios"]:
            invalid = copy.deepcopy(report)
            invalid["scenarios"] = [x for x in invalid["scenarios"] if x["id"] != scenario["id"]]
            self.assertTrue(js_errors(invalid))


if __name__ == "__main__":
    unittest.main()
