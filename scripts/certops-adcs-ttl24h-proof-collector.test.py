"""Offline synthetic proof parity; these fixtures are never native evidence."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent))
import certops_adcs_ttl24h_proof as proof
ROOT = Path(__file__).resolve().parents[1]

class Ttl24hProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        program = "const h=require('./scripts/certops-adcs-ttl24h-proof'),f=require('./scripts/fixtures/certops-adcs-ttl24h-proof.cjs').fixture();h.verifyProof(f.proof);h.verifyAgainstPrepared(f.proof,f.prepared,f.observed);process.stdout.write(JSON.stringify({proof:f.proof,fields:h.FIELDS,flags:h.FLAGS}));"
        cls.fixture = json.loads(subprocess.check_output(["node", "-e", program], cwd=ROOT, text=True))
        cls.report = {"suite": proof.SUITE, "candidateSha": cls.fixture["proof"]["candidateSha"], "platform": "win32", "architecture": "x64", "qualificationEnvironment": {"osFamily":"windows","osVersion":"2022","nativeLanguage":"en-US","identity":"LocalSystem","measurement":"native","architecture":"x64"}, "cleanup":{"status":"passed"}, proof.FIELD: cls.fixture["proof"]}

    def test_real_js_verified_fixture_and_closed_projection(self):
        self.assertEqual(set(self.fixture["fields"]), set(proof.FIELDS))
        self.assertEqual(self.fixture["flags"], proof.FLAGS)
        value = copy.deepcopy(self.report); value["privateReceipt"] = "must-not-survive"
        projected = proof.fields(value)
        self.assertEqual(projected, self.fixture["proof"])
        self.assertNotIn("must-not-survive", json.dumps(projected))
        projected["requestIds"].append("42")
        self.assertEqual(len(value[proof.FIELD]["requestIds"]), 3)

    def test_every_field_missing_wrong_and_private_fields_rejected(self):
        for key, original in self.fixture["proof"].items():
            with self.subTest(key=key):
                value = copy.deepcopy(self.report); del value[proof.FIELD][key]
                with self.assertRaises(ValueError): proof.fields(value)
                value = copy.deepcopy(self.report); value[proof.FIELD][key] = False if original is True else "invalid"
                with self.assertRaises(ValueError): proof.fields(value)
        value = copy.deepcopy(self.report); value[proof.FIELD]["privateCngContainer"] = "secret"
        with self.assertRaises(ValueError): proof.fields(value)

    def test_timing_native_generation_and_integer_boundaries(self):
        changes = {"monotonicElapsedMs": [True, 86399999, 90000001, 86400000.5], "keptObservationCount": [True,23,27], "maximumObservationGapMs": [0,3900001,True], "processId":[True,0,4294967296], "caRequestCounts":[[0,1,2,4],[0,1,2,True],[-1,0,1,2]], "requestIds":[["1","1","2"],["1","2","4294967296"]], "fingerprints":[["a"*64]*3], "defaultValidationTimeoutSeconds":[True,300], "configuredValidationTimeoutSeconds":[300], "residentFinishedAt":["2026-02-30T00:00:00.000Z"], "preDeadlineObservedAt":[self.fixture["proof"]["deadlineAt"]], "bootTime":[self.fixture["proof"]["residentFinishedAt"]]}
        for key, values in changes.items():
            for wrong in values:
                with self.subTest(key=key, wrong=wrong):
                    value = copy.deepcopy(self.report); value[proof.FIELD][key] = wrong
                    with self.assertRaises(ValueError): proof.fields(value)
        for a,b in (("freshEnrollmentId","installedEnrollmentId"),("freshRenewalJobId","expiredContinuationJobId")):
            value=copy.deepcopy(self.report);value[proof.FIELD][a]=value[proof.FIELD][b]
            with self.assertRaises(ValueError):proof.fields(value)

    def test_native_environment_cleanup_candidate_are_mandatory(self):
        for key in self.report["qualificationEnvironment"]:
            value=copy.deepcopy(self.report);del value["qualificationEnvironment"][key]
            with self.assertRaises(ValueError):proof.fields(value)
            value=copy.deepcopy(self.report);value["qualificationEnvironment"][key]="unsupported"
            with self.assertRaises(ValueError):proof.fields(value)
        for key, wrong in (("suite","windows-adcs-real"),("platform","linux"),("architecture","arm64"),("cleanup",{"status":"failed"}),("cleanup",None),("candidateSha","f"*40)):
            value=copy.deepcopy(self.report);value[key]=wrong
            with self.assertRaises(ValueError):proof.fields(value)

    def test_actual_js_validator_and_python_reject_same_tampered_cases(self):
        cases=[]
        for key, wrong in (("scope","simulated"),("monotonicElapsedMs",86399999),("maximumObservationGapMs",3900001),("configuredValidationTimeoutSeconds",300),("processId",True),("requestIds",["1","2","4294967296"]),("caRequestCounts",[0,1,2,4])):
            value=copy.deepcopy(self.fixture["proof"]);value[key]=wrong;cases.append(value)
        program="const h=require('./scripts/certops-adcs-ttl24h-proof');let s='';process.stdin.on('data',b=>s+=b);process.stdin.on('end',()=>process.stdout.write(JSON.stringify(JSON.parse(s).map(v=>{try{h.verifyProof(v);return true}catch{return false}}))));"
        accepted=json.loads(subprocess.check_output(["node","-e",program],input=json.dumps(cases),text=True,cwd=ROOT))
        self.assertEqual(accepted,[False]*len(cases))
        for value in cases:
            with self.assertRaises(ValueError):proof.verify_proof(value)

if __name__ == "__main__": unittest.main()
