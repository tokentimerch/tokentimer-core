"""Startup-recovery projection stays a recorded stop or kill."""
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "interruption_collector", ROOT / "scripts/certops-release-collector.py"
)
COLLECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COLLECTOR)

SUITE = "windows-installed-interruption-recovery"
PROOF = {
    "scope": "installed-deterministic-interruption-recovery",
    "evidenceLevel": "host-integration",
    "pointKind": "ledger",
    "interruptionMode": "service-stop",
    "recordedSequence": 1,
    "startupRecovery": True,
    "inUseKeyDeleted": False,
    "powerLossDurabilityQualified": False,
    "realRebootQualified": False,
    "nativeExecutionQualified": False,
    "hostCapabilityAbsentIsPass": False,
}


def project(proof):
    report = {
        "suite": SUITE,
        "cleanup": {"status": "passed"},
        "nativeInstalledInterruption": proof,
    }
    return COLLECTOR.sanitized_report(report, [SUITE], [])


class InstalledInterruptionProjection(unittest.TestCase):
    def test_projects_a_closed_startup_recovery_proof(self):
        projected = project(PROOF)["nativeInstalledInterruption"]
        self.assertEqual(projected, PROOF)
        subprocess.run(
            [
                "node",
                "-e",
                "let s='';process.stdin.on('data',b=>s+=b);process.stdin.on('end',()=>require('./tests/e2e/helpers/certops-windows-installed-interruption').verifyProof(JSON.parse(s)));",
            ],
            input=json.dumps(projected),
            text=True,
            cwd=ROOT,
            check=True,
            capture_output=True,
            timeout=20,
        )

    def test_refuses_power_loss_reboot_and_native_claims(self):
        for field in (
            "powerLossDurabilityQualified",
            "realRebootQualified",
            "nativeExecutionQualified",
            "hostCapabilityAbsentIsPass",
            "inUseKeyDeleted",
        ):
            proof = dict(PROOF)
            proof[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                project(proof)


if __name__ == "__main__":
    unittest.main()
