"""Offline cross-language public proof checks, never Linux/native qualification."""
import copy
import json
import importlib.util
from pathlib import Path
import subprocess
import unittest
import certops_linux_backup_dac_proof as proof

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("linux_dac_main_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def report():
    source = "const h=require('./scripts/certops-linux-filesystem-permission');const p={schemaVersion:1,scope:'native-linux-nonroot-backup-dac-refusal',uid:65534,gid:65534,...Object.fromEntries(h.FLAGS.map(n=>[n,true]))};h.verifyProof(p);process.stdout.write(JSON.stringify(p));"
    value = json.loads(subprocess.check_output(["node", "-e", source], cwd=ROOT, text=True))
    return {"suite": proof.SUITE, "platform": "linux", "architecture": "x64", proof.FIELD: value,
            "qualificationEnvironment": {"osFamily": "linux", "distributionId": "ubuntu", "distributionVersion": "24.04", "measurement": "native", "executionSurface": "disposable-vm"}}


class LinuxBackupDacProjection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = report()

    def test_actual_js_closed_contract_round_trips_without_private_metadata(self):
        value = copy.deepcopy(self.original)
        value["privateFileSnapshots"] = "must-not-survive"
        projected = proof.project_report(value)
        self.assertEqual(projected, {proof.FIELD: value[proof.FIELD]})
        self.assertNotIn("must-not-survive", json.dumps(projected))
        projected[proof.FIELD]["uid"] = 1
        self.assertEqual(value[proof.FIELD]["uid"], 65534)

    def test_actual_js_artifact_reaches_real_collector_projection(self):
        source = "const a=require('./scripts/test-support/linux-backup-dac-artifact.cjs').artifact();require('./scripts/certops-linux-filesystem-permission').verifyProof(a.report.nativeLinuxBackupDac);process.stdout.write(JSON.stringify(a.report));"
        value = json.loads(subprocess.check_output(["node", "-e", source], cwd=ROOT, text=True))
        value["privateFileSnapshots"] = "must-not-survive"
        projected = collector.sanitized_report(value, {proof.SUITE}, set())
        self.assertEqual(projected[proof.FIELD], value[proof.FIELD])
        self.assertEqual(len(projected["fixtureSources"]), 8)
        self.assertNotIn("must-not-survive", json.dumps(projected))
        for mutate in (lambda v: v.pop(proof.FIELD), lambda v: v[proof.FIELD].update(productionBackupRefused=False), lambda v: v[proof.FIELD].update(privateKey="must-not-survive"), lambda v: v.update(platform="win32")):
            wrong = copy.deepcopy(value)
            mutate(wrong)
            with self.assertRaises(ValueError):
                collector.sanitized_report(wrong, {proof.SUITE}, set())

    def test_every_fact_is_required_as_native_true_boolean(self):
        for field in proof.FLAGS:
            for wrong in (False, 1, "true", None):
                value = copy.deepcopy(self.original)
                value[proof.FIELD][field] = wrong
                with self.subTest(field=field, wrong=wrong), self.assertRaises(ValueError):
                    proof.project_report(value)
            value = copy.deepcopy(self.original)
            del value[proof.FIELD][field]
            with self.assertRaises(ValueError):
                proof.project_report(value)

    def test_closed_scope_numeric_identity_and_private_extras_refused(self):
        for change in ({"uid": 0}, {"gid": 0}, {"uid": True}, {"gid": 1.5}, {"uid": 9007199254740992}, {"schemaVersion": True}, {"scope": "signed-service-qualification"}, {"rawKey": "private"}, {"fileSnapshots": []}):
            value = copy.deepcopy(self.original)
            value[proof.FIELD].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                proof.project_report(value)
        value = copy.deepcopy(self.original)
        del value[proof.FIELD]
        with self.assertRaises(ValueError):
            proof.project_report(value)

    def test_windows_container_declared_and_unqualified_distribution_cannot_fill_linux_slot(self):
        for field, wrong in (("platform", "win32"), ("architecture", "arm64"), ("suite", "filesystem-host")):
            value = copy.deepcopy(self.original)
            value[field] = wrong
            with self.assertRaises(ValueError):
                proof.project_report(value)
        for field, wrong in (("osFamily", "windows"), ("distributionId", "almalinux"), ("distributionVersion", "20.04"), ("measurement", "declared"), ("executionSurface", "container")):
            value = copy.deepcopy(self.original)
            value["qualificationEnvironment"][field] = wrong
            with self.assertRaises(ValueError):
                proof.project_report(value)


if __name__ == "__main__":
    unittest.main()
