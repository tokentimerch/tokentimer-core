"""Pure cross-language native-scope projection adversaries; no host execution."""
import importlib.util
import copy
import json
from pathlib import Path
import subprocess
import unittest
import certops_filesystem_concurrent_proof as proof

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("concurrent_main_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def report():
    source = "process.stdout.write(JSON.stringify(require('./scripts/test-support/filesystem-concurrent-artifact.cjs').artifact().report))"
    return json.loads(subprocess.check_output(["node", "-e", source], cwd=ROOT, text=True))


class PairedFilesystemProof(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = report()

    def test_actual_js_contract_projects_only_closed_public_native_facts(self):
        value = copy.deepcopy(self.original)
        value["privateLocalFiles"] = "must-not-survive"
        projected = proof.project_report(value)
        self.assertEqual(projected, {field: value[field] for field in (proof.FIELD, proof.ALIAS_FIELD, proof.RETENTION_FIELD, proof.ROLLBACK_FIELD)})
        self.assertNotIn("must-not-survive", json.dumps(projected))
        value["platform"] = "win32"
        value[proof.ALIAS_FIELD]["aliasKind"] = "junction"
        value["qualificationEnvironment"] = {"osFamily": "windows", "osVersion": "2025", "productType": 3, "measurement": "native"}
        self.assertEqual(proof.project_report(value)[proof.FIELD], self.original[proof.FIELD])

    def test_actual_js_artifact_reaches_real_collector_without_private_state(self):
        source = "process.stdout.write(JSON.stringify(require('./scripts/test-support/filesystem-concurrent-artifact.cjs').artifact().report))"
        value = json.loads(subprocess.check_output(["node", "-e", source], cwd=ROOT, text=True))
        value["privateLocalFiles"] = "must-not-survive"
        result = collector.sanitized_report(value, {proof.SUITE}, set())
        self.assertEqual(result[proof.FIELD], value[proof.FIELD])
        self.assertEqual(len(result["fixtureSources"]), 14)
        self.assertEqual(result[proof.ROLLBACK_FIELD], value[proof.ROLLBACK_FIELD])
        self.assertNotIn("must-not-survive", json.dumps(result))
        for mutate in (lambda v: v.pop(proof.FIELD), lambda v: v[proof.FIELD].update(nativeListenerClosed=False), lambda v: v[proof.FIELD].update(privateKey="secret")):
            wrong = copy.deepcopy(value)
            mutate(wrong)
            with self.assertRaises(ValueError):
                collector.sanitized_report(wrong, {proof.SUITE}, set())

    def test_every_native_flag_and_closed_scope_is_required(self):
        for flag in proof.FLAGS:
            for wrong in (False, 1, None, "true"):
                value = copy.deepcopy(self.original)
                value[proof.FIELD][flag] = wrong
                with self.subTest(flag=flag, wrong=wrong), self.assertRaises(ValueError):
                    proof.project_report(value)
        for change in ({"completedMutations": True}, {"contenderCount": 1}, {"processScope": "two-processes"}, {"backupNamespaces": "separate-directories"}, {"rawPrivateKey": "must-not-survive"}):
            value = copy.deepcopy(self.original)
            value[proof.FIELD].update(change)
            with self.assertRaises(ValueError):
                proof.project_report(value)

    def test_completion_order_backup_chain_and_final_tls_cannot_be_relabeled(self):
        for mutate in (lambda p: p["completionOrder"].reverse(), lambda p: p["backupPredecessors"].reverse(), lambda p: p.update(servedAfterFingerprint="b" * 64), lambda p: p["fingerprints"].__setitem__(2, p["fingerprints"][1]), lambda p: p["spkiFingerprints"].__setitem__(1, p["spkiFingerprints"][0]), lambda p: p.pop("nativeListenerClosed")):
            value = copy.deepcopy(self.original)
            mutate(value[proof.FIELD])
            with self.assertRaises(ValueError):
                proof.project_report(value)

    def test_alias_requires_exact_native_refusal_recovery_and_no_private_extras(self):
        for flag in proof.ALIAS_FLAGS:
            for wrong in (False, 1, None):
                value = copy.deepcopy(self.original)
                value[proof.ALIAS_FIELD][flag] = wrong
                with self.assertRaises(ValueError):
                    proof.project_report(value)
        for change in ({"refusalStage": "backup-key"}, {"rawKey": "secret"}, {"aliasKind": "junction"}):
            value = copy.deepcopy(self.original)
            value[proof.ALIAS_FIELD].update(change)
            with self.assertRaises(ValueError):
                collector.sanitized_report(value, {proof.SUITE}, set())

    def test_native_retention_requires_all_measured_observations_and_scoped_counts(self):
        for flag in proof.RETENTION_FLAGS:
            value = copy.deepcopy(self.original)
            value[proof.RETENTION_FIELD][flag] = False
            with self.assertRaises(ValueError):
                collector.sanitized_report(value, {proof.SUITE}, set())
        for change in ({"retentionCount": True}, {"targetCount": 1}, {"actualRotations": 3}, {"rawKey": "secret"}):
            value = copy.deepcopy(self.original)
            value[proof.RETENTION_FIELD].update(change)
            with self.assertRaises(ValueError):
                proof.project_report(value)

    def test_unqualified_native_environment_cannot_fill_filesystem_slot(self):
        for change in ({"platform": "darwin"}, {"architecture": "arm64"}, {"suite": "filesystem-linux-backup-dac-host"}):
            value = copy.deepcopy(self.original)
            value.update(change)
            with self.assertRaises(ValueError):
                proof.project_report(value)

        for change in ({"executionSurface": "container"}, {"measurement": "declared"}, {"distributionVersion": "20.04"}):
            value = copy.deepcopy(self.original)
            value["qualificationEnvironment"].update(change)
            with self.assertRaises(ValueError):
                proof.project_report(value)

    def test_paired_rollback_projection_refuses_missing_native_facts_and_private_material(self):
        for flag in proof.ROLLBACK_FLAGS:
            for wrong in (False, 1, None, "true"):
                value = copy.deepcopy(self.original)
                value[proof.ROLLBACK_FIELD][flag] = wrong
                with self.subTest(flag=flag, wrong=wrong), self.assertRaises(ValueError):
                    collector.sanitized_report(value, {proof.SUITE}, set())
            value = copy.deepcopy(self.original)
            value[proof.ROLLBACK_FIELD].pop(flag)
            with self.assertRaises(ValueError):
                proof.project_report(value)
        for change in ({"schemaVersion": True}, {"scope": "local-contract"}, {"fingerprints": ["a" * 64, "a" * 64]}, {"privateKey": "withheld"}):
            value = copy.deepcopy(self.original)
            value[proof.ROLLBACK_FIELD].update(change)
            with self.assertRaises(ValueError):
                collector.sanitized_report(value, {proof.SUITE}, set())
        value = copy.deepcopy(self.original)
        value.pop(proof.ROLLBACK_FIELD)
        with self.assertRaises(ValueError):
            proof.project_report(value)



if __name__ == "__main__":
    unittest.main()
