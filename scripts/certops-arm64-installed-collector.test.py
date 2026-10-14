"""Offline installed ARM64 agent projection/provenance checks; no native actions."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("arm64_installed_collector", Path(__file__).with_name("certops-release-collector.py"))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
SUITE = "windows-arm64-installed-agent"
class Arm64InstalledCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.value = json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require('./scripts/test-support/arm64-installed-artifact.cjs').artifact().report))"], cwd=collector.ROOT, text=True))
    def test_closed_projection_and_private_outer_metadata(self):
        value = copy.deepcopy(self.value); value["privateReceipt"] = "must-not-survive"
        result = collector.sanitized_report(value, {SUITE}, set())
        self.assertEqual(result["nativeArm64InstalledAgent"], value["nativeArm64InstalledAgent"])
        self.assertNotIn("must-not-survive", json.dumps(result))
    def test_every_field_and_scope_is_mandatory(self):
        for key, expected in self.value["nativeArm64InstalledAgent"].items():
            missing = copy.deepcopy(self.value); del missing["nativeArm64InstalledAgent"][key]
            with self.assertRaises(ValueError): collector.sanitized_report(missing, {SUITE}, set())
            wrong = copy.deepcopy(self.value); wrong["nativeArm64InstalledAgent"][key] = not expected if type(expected) is bool else "invalid"
            with self.assertRaises(ValueError): collector.sanitized_report(wrong, {SUITE}, set())
    def test_native_bounds_generations_and_scope_cannot_be_promoted(self):
        changes = [lambda p: p.update(completeMachineWideSurvivorGuardBeforeDeletion=False), lambda p: p.update(exactNativeCertificateAndKeyRemoved=False), lambda p: p.update(retainedOwnedProcessesDrained=False), lambda p: p.update(postgresArchitecture="arm64"), lambda p: p.update(postgresExecution="native"), lambda p: p.update(publicCertificateAdmissionQualified=True), lambda p: p.update(issuanceQualified=True), lambda p: p.update(rawCustody="private"), lambda p: p["jobIds"].__setitem__(1,p["jobIds"][0]), lambda p: p["claimIds"].__setitem__(1,p["claimIds"][0])]
        for change in changes:
            value = copy.deepcopy(self.value); change(value["nativeArm64InstalledAgent"])
            with self.assertRaises(ValueError): collector.sanitized_report(value, {SUITE}, set())
        for field, wrong in (("architecture", "x64"), ("productType", True), ("osVersion", "2025"), ("measurement", "declared")):
            value = copy.deepcopy(self.value); value["qualificationEnvironment"][field] = wrong
            with self.assertRaises(ValueError): collector.sanitized_report(value, {SUITE}, set())
    def test_manual_workflow_has_exact_trusted_candidate_provenance(self):
        candidate = "a" * 40; repository = "example/public-core"
        run = {"status":"completed", "conclusion":"success", "head_sha":candidate, "head_branch":"main", "repository":{"full_name":repository}, "head_repository":{"full_name":repository}, "path":".github/workflows/certops-windows-arm64-agent.yml", "event":"workflow_dispatch"}
        collector.validate_run(run, candidate, repository)
        for key, wrong in (("head_branch","feature"),("event","pull_request"),("conclusion","cancelled"),("head_sha","b"*40),("path",".github/workflows/certops-windows-arm64-host.yml")):
            with self.assertRaises(ValueError): collector.validate_run({**run,key:wrong},candidate,repository)
if __name__ == "__main__": unittest.main()
