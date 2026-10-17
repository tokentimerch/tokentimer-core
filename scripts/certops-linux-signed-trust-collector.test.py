"""Offline JS proof parity and public projection. Manual workflow_dispatch only. Not native qualification."""
import copy
import json
from pathlib import Path
import subprocess
import unittest
import importlib.util
import certops_linux_signed_trust_proof as proof
ROOT=Path(__file__).resolve().parent.parent
SPEC=importlib.util.spec_from_file_location('signed_trust_main_collector',ROOT/'scripts/certops-release-collector.py')
collector=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)
def fixture():
    return json.loads(subprocess.check_output(["node","-e","const f=require('./scripts/test-support/linux-signed-trust-artifact.cjs'),h=require('./scripts/certops-linux-signed-trust-proof'),a=f.artifact();h.verifyProof(a.report[h.FIELD]);process.stdout.write(JSON.stringify(a.report));"],cwd=ROOT,text=True))
class SignedTrustProjection(unittest.TestCase):
    def test_actual_js_proof_parity_and_private_outer_fields_dropped(self):
        value=fixture();value['localPrivatePath']='never-public'
        projected=proof.project_report(value)
        self.assertEqual(projected[proof.FIELD],value[proof.FIELD])
        self.assertNotIn('never-public',json.dumps(projected))
        actual=collector.sanitized_report(value,{proof.SUITE},set())
        self.assertEqual(actual[proof.FIELD],value[proof.FIELD])
        self.assertNotIn('never-public',json.dumps(actual))
    def test_every_flag_strict_and_inner_extras_refused(self):
        value=fixture()
        for name in proof.FLAGS:
            for bad in (False,1,None):
                candidate=copy.deepcopy(value);candidate[proof.FIELD][name]=bad
                with self.assertRaises(ValueError):proof.project_report(candidate)
        for patch in ({'privateKey':'no'},{'backgroundReconciliationQualified':True},{'jobIds':[value[proof.FIELD]['jobIds'][0]]*4}):
            candidate=copy.deepcopy(value);candidate[proof.FIELD].update(patch)
            with self.assertRaises(ValueError):proof.project_report(candidate)
    def test_other_host_scope_and_missing_observation_refused(self):
        value=fixture()
        for patch in ({'architecture':'arm64'},{'platform':'win32'},{'qualificationEnvironment':{'osFamily':'linux','distribution':'ubuntu','osVersion':'22.04','measurement':'native','executionSurface':'disposable-vm'}}):
            with self.assertRaises(ValueError):proof.project_report({**value,**patch})
        for key in value[proof.FIELD]:
            candidate=copy.deepcopy(value);del candidate[proof.FIELD][key]
            with self.assertRaises(ValueError):proof.project_report(candidate)
if __name__=='__main__':unittest.main()
