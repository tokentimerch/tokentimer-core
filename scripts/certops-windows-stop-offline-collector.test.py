"""Offline actual JS fixture/parser parity; never native Windows execution."""
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

class StopOfflineProjection(unittest.TestCase):
    def test_derived_native_interruption_is_narrow_and_refuses_promoted_claims(self):
        report = json.loads(subprocess.check_output(["node", "-e", "const f=require('./scripts/test-support/windows-stop-offline.cjs');process.stdout.write(JSON.stringify(require('./tests/e2e/helpers/certops-windows-interruption-native').createReport(f.artifact().report,{candidateSha:f.candidateSha})))"], cwd=ROOT, text=True, timeout=20))
        self.assertEqual(collector.windows_interruption_native_proof.fields(report), report["nativeInstalledInterruption"])
        for patch in ({"originalOperationAutomaticallyRecovered": True}, {"observedStage": "bind"}, {"interruptionMode": "process-kill"}):
            invalid=copy.deepcopy(report);invalid["nativeInstalledInterruption"].update(patch)
            with self.assertRaises(ValueError):collector.windows_interruption_native_proof.fields(invalid)
        invalid=copy.deepcopy(report);invalid["nativeInstalledInterruption"]["nativeStoppedOffline"]["allCapturedDescendantsExited"]=False
        with self.assertRaises(ValueError):collector.windows_interruption_native_proof.fields(invalid)

    @classmethod
    def setUpClass(cls):
        cls.base = json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require('./scripts/test-support/windows-stop-offline.cjs').artifact().report))"], cwd=ROOT, text=True, timeout=20))

    def test_actual_js_fixture_matches_closed_python_projection_and_back(self):
        projected = collector.windows_stop_offline_proof.fields(self.base)
        self.assertEqual(projected, self.base["nativeWindowsStoppedOffline"])
        subprocess.run(["node", "-e", "let s='';process.stdin.on('data',b=>s+=b);process.stdin.on('end',()=>require('./tests/e2e/helpers/certops-windows-stop-offline-proof').verifyProof(JSON.parse(s)));"], input=json.dumps(projected), text=True, cwd=ROOT, check=True, capture_output=True, timeout=20)

    def test_every_missing_false_promoted_and_out_of_bounds_fact_refuses(self):
        for key in self.base["nativeWindowsStoppedOffline"]:
            value=copy.deepcopy(self.base)
            del value["nativeWindowsStoppedOffline"][key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                collector.windows_stop_offline_proof.fields(value)
        for patch in ({"atomicTreeContainmentQualified":True},{"originalOperationAutomaticallyRecovered":True},{"defaultLeaseMs":60000},{"waitedMonotonicMs":True},{"capturedProcessCount":129},{"exactOwnedCleanupCompleted":False},{"fingerprints":["a"*64,"a"*64]}):
            value=copy.deepcopy(self.base);value["nativeWindowsStoppedOffline"].update(patch)
            with self.subTest(patch=patch), self.assertRaises(ValueError):collector.windows_stop_offline_proof.fields(value)
        for key, val in (("identity","Administrator"),("nativeLanguage","de-DE"),("measurement","simulated"),("osVersion","desktop-26100")):
            value=copy.deepcopy(self.base);value["qualificationEnvironment"][key]=val
            with self.assertRaises(ValueError):collector.windows_stop_offline_proof.fields(value)

    def test_real_archive_parser_strips_private_data_and_requires_cleanup(self):
        def extract(value):
            raw=io.BytesIO()
            with zipfile.ZipFile(raw,"w") as archive:archive.writestr("report.json",json.dumps(value))
            return collector.extract_reports(raw.getvalue(),[self.base["suite"]],[])
        value=copy.deepcopy(self.base);value["nativeWindowsStoppedOffline"]["privatePath"]="private-value"
        result=extract(value)[0][1]
        self.assertEqual(result["nativeWindowsStoppedOffline"],self.base["nativeWindowsStoppedOffline"])
        self.assertNotIn("private-value",json.dumps(result))
        for patch in ({"cleanup":{"status":"failed"}},{"nativeWindowsStoppedOffline":None}):
            with self.assertRaises(ValueError):extract({**self.base,**patch})

    def test_only_the_dedicated_manual_native_workflow_can_supply_this_lane(self):
        collector.verify_stopped_offline_workflow(self.base, ".github/workflows/certops-windows-stop-offline.yml")
        for workflow in (None, ".github/workflows/certops-windows-e2e.yml", ".github/workflows/certops-qualification.yml"):
            with self.assertRaises(ValueError):collector.verify_stopped_offline_workflow(self.base, workflow)

if __name__ == "__main__":unittest.main()
