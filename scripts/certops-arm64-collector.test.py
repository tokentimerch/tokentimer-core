"""Pure ARM64 collector projections/refusals; no host or workflow qualification."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("arm64_collector", Path(__file__).with_name("certops-release-collector.py"))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
SUITE = "windows-arm64-cng-runtime"
FLAGS = ("csrSignatureVerified", "csrPublicKeyMatchesLeaf", "dnsSanVerified", "keyUsageVerified", "publicLeafSignatureVerified", "nativeAssociationVerified", "nativeSignatureVerified", "protectedExportDenied", "exportableControlSucceeded", "privateBuffersZeroed", "custodyUnchanged", "machineStoreReferenceFound", "exactReferenceExcluded", "ownedArtifactsAbsent")


def report():
    architecture = {"productType": 1, "build": "26200", "cpuArchitectures": [12], "platform": "win32", "nodeArchitecture": "arm64", "powershellArchitecture": "arm64", "goHostArchitecture": "arm64", "goHostOs": "windows", "nodePeMachine": 0xaa64, "powershellPeMachine": 0xaa64, "goPeMachine": 0xaa64, "certreqPeMachine": 0xaa64, "certutilPeMachine": 0xaa64, "administrator": True}
    proof = {"scope": "native-windows11-arm64-cng-public-fixture", "architecture": architecture, "helperPeMachine": 0xaa64, "helperSha256": "b" * 64, "helperExecuted": True, "serverQualified": False, "iisQualified": False, "domainAdcsQualified": False, "privateCaKeyPersisted": False, "cleanupCompleted": True,
             "cases": [{**dict.fromkeys(FLAGS, True), "profile": profile, "chainVerdict": "revocation_unknown", "wrongPinVerdict": "ca_key_changed", "malformedVerdict": "invalid", "storesScanned": 5, "privateExportHResult": -2146893813} for profile in ("rsa-2048", "ec-p256")]}
    metadata = json.loads((collector.ROOT / "docs/certops/qualification-suites.json").read_text())
    return {"suite": SUITE, "platform": "win32", "architecture": "arm64", "nativeArchitectureProbe": copy.deepcopy(architecture), "nativeArm64CngRuntime": proof, "qualificationEnvironment": {"osFamily": "windows", "osVersion": "desktop-26200", "productType": 1, "measurement": "native", "architecture": "arm64"}, "requiredScenarios": metadata["suites"][SUITE], "requiredCapabilities": metadata["requiredCapabilities"][SUITE]}


class Arm64CollectorTests(unittest.TestCase):
    def test_new_manual_workflow_requires_exact_trusted_run_provenance(self):
        candidate = "a" * 40
        repository = "example/public-core"
        run = {"status": "completed", "conclusion": "success", "head_sha": candidate, "head_branch": "main", "repository": {"full_name": repository}, "head_repository": {"full_name": repository}, "path": ".github/workflows/certops-windows-arm64-cng.yml", "event": "workflow_dispatch"}
        collector.validate_run(run, candidate, repository)
        for field, wrong in (("head_branch", "feature"), ("event", "pull_request"), ("conclusion", "cancelled"), ("head_sha", "b" * 40), ("path", ".github/workflows/untrusted.yml")):
            with self.assertRaises(ValueError):
                collector.validate_run({**run, field: wrong}, candidate, repository)

    def test_closed_facts_survive_projection_without_private_metadata(self):
        value = report()
        value["privateReceipt"] = "must not survive"
        projected = collector.sanitized_report(value, {SUITE}, set())
        self.assertEqual(projected["nativeArm64CngRuntime"], value["nativeArm64CngRuntime"])
        self.assertEqual(projected["nativeArchitectureProbe"], value["nativeArchitectureProbe"])
        self.assertEqual(projected["qualificationEnvironment"], value["qualificationEnvironment"])
        self.assertNotIn("privateReceipt", projected)

    def test_each_native_boolean_is_required_as_boolean(self):
        for flag in FLAGS:
            for wrong in (False, 1, None, "true"):
                with self.subTest(flag=flag, wrong=wrong):
                    value = report()
                    value["nativeArm64CngRuntime"]["cases"][0][flag] = wrong
                    with self.assertRaises(ValueError):
                        collector.sanitized_report(value, {SUITE}, set())

    def test_native_architecture_scope_and_inventory_adversaries(self):
        mutations = [lambda value: value.pop("nativeArm64CngRuntime"), lambda value: value["nativeArm64CngRuntime"]["cases"].pop(), lambda value: value["nativeArm64CngRuntime"].update(serverQualified=True), lambda value: value["nativeArm64CngRuntime"].update(privateCaKeyPersisted=True), lambda value: value["nativeArm64CngRuntime"].update(rawInventory=[]), lambda value: value["nativeArm64CngRuntime"]["cases"][0].update(profile=[]), lambda value: value["nativeArm64CngRuntime"]["cases"][0].update(chainVerdict="valid"), lambda value: value["nativeArm64CngRuntime"]["cases"][0].update(storesScanned=True), lambda value: value["nativeArm64CngRuntime"]["architecture"].update(certreqPeMachine=0xa641), lambda value: value["nativeArm64CngRuntime"]["architecture"].update(goHostArchitecture="amd64"), lambda value: value["nativeArchitectureProbe"].update(administrator=1), lambda value: value["qualificationEnvironment"].update(osVersion="2025")]
        for mutate in mutations:
            value = report()
            mutate(value)
            with self.assertRaises(ValueError):
                collector.sanitized_report(value, {SUITE}, set())


if __name__ == "__main__":
    unittest.main()
