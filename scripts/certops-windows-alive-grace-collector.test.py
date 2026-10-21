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

class AliveGraceProjection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require('./scripts/test-support/windows-alive-grace.cjs').artifact().report))"], cwd=ROOT, text=True, timeout=20))

    def test_actual_js_fixture_matches_closed_python_projection_and_back(self):
        projected = collector.windows_alive_grace_proof.fields(self.base)
        self.assertEqual(projected, self.base["nativeWindowsAliveGrace"])
        subprocess.run(["node", "-e", "let s='';process.stdin.on('data',b=>s+=b);process.stdin.on('end',()=>require('./tests/e2e/helpers/certops-windows-alive-grace-proof').verifyProof(JSON.parse(s)));"], input=json.dumps(projected), text=True, cwd=ROOT, check=True, capture_output=True, timeout=20)

    def test_every_missing_false_promoted_and_out_of_bounds_fact_refuses(self):
        for key in self.base["nativeWindowsAliveGrace"]:
            value=copy.deepcopy(self.base)
            del value["nativeWindowsAliveGrace"][key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                collector.windows_alive_grace_proof.fields(value)
        for patch in ({"atomicTreeContainmentQualified":True},{"originalOperationAutomaticallyRecovered":True},{"defaultLeaseMs":60000},{"waitedMonotonicMs":True},{"heartbeatUptimeSeconds":[1,1,2]},{"exactOwnedCleanupCompleted":False},{"fingerprints":["a"*64,"a"*64]}):
            value=copy.deepcopy(self.base);value["nativeWindowsAliveGrace"].update(patch)
            with self.subTest(patch=patch), self.assertRaises(ValueError):collector.windows_alive_grace_proof.fields(value)
        for key, val in (("identity","Administrator"),("nativeLanguage","de-DE"),("measurement","simulated"),("osVersion","desktop-26100")):
            value=copy.deepcopy(self.base);value["qualificationEnvironment"][key]=val
            with self.assertRaises(ValueError):collector.windows_alive_grace_proof.fields(value)

    def test_real_archive_parser_strips_private_data_and_requires_cleanup(self):
        def extract(value):
            raw=io.BytesIO()
            with zipfile.ZipFile(raw,"w") as archive:archive.writestr("report.json",json.dumps(value))
            return collector.extract_reports(raw.getvalue(),[self.base["suite"]],[])
        value=copy.deepcopy(self.base);value["nativeWindowsAliveGrace"]["privatePath"]="private-value"
        result=extract(value)[0][1]
        self.assertEqual(result["nativeWindowsAliveGrace"],self.base["nativeWindowsAliveGrace"])
        self.assertNotIn("private-value",json.dumps(result))
        for patch in ({"cleanup":{"status":"failed"}},{"nativeWindowsAliveGrace":None}):
            with self.assertRaises(ValueError):extract({**self.base,**patch})

    def test_only_the_dedicated_manual_native_workflow_can_supply_this_lane(self):
        collector.verify_alive_grace_workflow(self.base, ".github/workflows/certops-windows-alive-grace.yml")
        for workflow in (None, ".github/workflows/certops-windows-e2e.yml", ".github/workflows/certops-qualification.yml"):
            with self.assertRaises(ValueError):collector.verify_alive_grace_workflow(self.base, workflow)

class FailedRollbackProjection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base=json.loads(subprocess.check_output(["node","-e","process.stdout.write(JSON.stringify(require('./scripts/test-support/windows-failed-rollback.cjs').artifact().report))"],cwd=ROOT,text=True,timeout=20))

    def test_actual_js_failed_rollback_matches_python_and_back(self):
        projected=collector.windows_failed_rollback_proof.fields(self.base)
        self.assertEqual(projected,self.base['nativeInstalledFailedRollback'])
        subprocess.run(['node','-e',"let s='';process.stdin.on('data',b=>s+=b);process.stdin.on('end',()=>require('./tests/e2e/helpers/certops-windows-installed-failed-rollback').verifyProof(JSON.parse(s)));"],input=json.dumps(projected),text=True,cwd=ROOT,check=True,capture_output=True,timeout=20)

    def test_failed_rollback_missing_promoted_and_failed_cleanup_refuse(self):
        for key in self.base['nativeInstalledFailedRollback']:
            value=copy.deepcopy(self.base);del value['nativeInstalledFailedRollback'][key]
            with self.subTest(missing=key),self.assertRaises(ValueError):collector.windows_failed_rollback_proof.fields(value)
        for patch in ({'rolledBack':True},{'originalOperationAutomaticallyRecovered':True},{'holderNaturalExitAndNativeJobDrained':False},{'unknown':True},{'jobIds':['a','b']}):
            value=copy.deepcopy(self.base);value['nativeInstalledFailedRollback'].update(patch)
            with self.subTest(patch=patch),self.assertRaises(ValueError):collector.windows_failed_rollback_proof.fields(value)
        for patch in ({'cleanup':{'status':'failed'}},{'platform':'linux'},{'architecture':'arm64'}):
            with self.assertRaises(ValueError):collector.windows_failed_rollback_proof.fields({**self.base,**patch})

    def test_real_failed_rollback_archive_and_workflow_binding(self):
        def extract(value):
            raw=io.BytesIO()
            with zipfile.ZipFile(raw,'w') as archive:archive.writestr('report.json',json.dumps(value))
            return collector.extract_reports(raw.getvalue(),[self.base['suite']],[])
        self.assertEqual(extract(self.base)[0][1]['nativeInstalledFailedRollback'],self.base['nativeInstalledFailedRollback'])
        for value in ({**self.base,'nativeInstalledFailedRollback':None},{**self.base,'cleanup':{'status':'failed'}}):
            with self.assertRaises(ValueError):extract(value)
        collector.verify_failed_rollback_workflow(self.base,'.github/workflows/certops-windows-failed-rollback.yml')
        for workflow in (None,'.github/workflows/certops-windows-e2e.yml','.github/workflows/certops-qualification.yml'):
            with self.assertRaises(ValueError):collector.verify_failed_rollback_workflow(self.base,workflow)

if __name__ == "__main__":unittest.main()
