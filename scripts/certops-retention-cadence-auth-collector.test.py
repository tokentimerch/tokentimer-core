"""Offline actual-JS-factory to authenticated GitHub artifact parser controls."""
import base64
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
import zipfile
import certops_retention_cadence_collection as auth
ROOT = Path(__file__).resolve().parents[1]

def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()

def archive(value, member):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(member, encoded(value))
    return out.getvalue()

class CadenceAuthentication(unittest.TestCase):
    def setUp(self):
        self.f = json.loads(subprocess.check_output(["node", "scripts/test-support/retention-cadence-artifact.cjs"], cwd=ROOT))
        self.report = self.f["report"]
        self.run = {"id":16,"run_attempt":1,"path":auth.FINALIZER,"head_sha":"9"*40,"head_branch":"main","event":"schedule","status":"completed","conclusion":"success","repository":{"full_name":"tokentimerch/tokentimer-core"},"head_repository":{"full_name":"tokentimerch/tokentimer-core"}}
        self.routes = {}
        self.base = "https://api.github.com/repos/tokentimerch/tokentimer-core"
        for row in self.report["retentionCadenceProvenance"]["finalizerProvenance"]["controllerSources"]:
            raw=(ROOT/row["file"]).read_bytes()
            self.routes[f"{self.base}/contents/{row['file']}?ref={self.run['head_sha']}"]=encoded({"path":row["file"],"type":"file","encoding":"base64","size":len(raw),"content":base64.b64encode(raw).decode()})
        self.routes[f"{self.base}/actions/runs/12/attempts/1"]=encoded(self.f["run"])
        self.routes[f"{self.base}/actions/runs/12/attempts/1/jobs?per_page=100"]=encoded(self.f["jobs"])
        self.reseal()
    def reseal(self):
        original=archive(self.f["original"],"retention-cadence-original.json")
        original_claim=self.report["retentionCadenceProvenance"]["originalArtifact"]
        original_claim["archiveSha256"]=hashlib.sha256(original).hexdigest()
        self.f["handoff"]["originalArtifact"]=copy.deepcopy(original_claim)
        handoff=archive(self.f["handoff"],"retention-cadence-ownership.json")
        self.report["retentionCadenceProvenance"]["handoffArtifact"]["archiveSha256"]=hashlib.sha256(handoff).hexdigest()
        entries=[]
        for field,raw,at in (("originalArtifact",original,"2026-10-15T00:04:00.000Z"),("handoffArtifact",handoff,"2026-10-15T00:07:00.000Z")):
            item=self.report["retentionCadenceProvenance"][field]
            entries.append({"id":int(item["id"]),"name":item["name"],"size_in_bytes":len(raw),"digest":"sha256:"+item["archiveSha256"],"expired":False,"created_at":at,"workflow_run":{"id":12,"head_sha":"a"*40,"head_branch":"main"}})
            self.routes[f"{self.base}/actions/artifacts/{item['id']}/zip"]=raw
        self.routes[f"{self.base}/actions/runs/12/artifacts?per_page=100"]=encoded({"total_count":2,"artifacts":entries})
    def verify(self):
        return auth.authenticate(self.report,self.run,16,"a"*40,"tokentimerch/tokentimer-core",lambda url,redirect=False:self.routes[url])
    def test_actual_factory_real_archive_parser_auth_and_private_projection(self):
        spec=importlib.util.spec_from_file_location("cadence_real_collector",ROOT/"scripts/certops-release-collector.py")
        collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)
        self.report["privateRawObservation"]="must-not-survive"
        self.report["nativeRetentionCadence"]["privateCngContainer"]="must-not-survive"
        def authenticate(value):
            return auth.authenticate(value,self.run,16,"a"*40,"tokentimerch/tokentimer-core",lambda url,redirect=False:self.routes[url])
        reports=collector.extract_reports(archive(self.report,"qualification.json"),{auth.SUITE},set(),authenticate_report=authenticate)
        self.assertEqual(len(reports),1)
        projected=reports[0][1]
        self.assertEqual(projected["nativeRetentionCadence"],auth.fields(self.report["nativeRetentionCadence"]))
        self.assertNotIn("retentionCadenceProvenance",projected)
        self.assertNotIn("must-not-survive",json.dumps(projected))
        self.assertEqual(projected["platform"],"win32")
        with self.assertRaises(ValueError):collector.validate_run(self.run,"a"*40,"tokentimerch/tokentimer-core")
        self.report["nativeRetentionCadence"]["agentPid"]=999
        with self.assertRaises(ValueError):collector.extract_reports(archive(self.report,"qualification.json"),{auth.SUITE},set(),authenticate_report=authenticate)
    def test_actual_factory_authenticates_original_candidate_across_head_drift(self):
        self.assertTrue(self.verify())
        self.assertNotEqual(self.run["head_sha"],self.report["candidateSha"])
    def test_owner_and_sealed_bytes_tampering_refused(self):
        for field in ("nonce","observerConfigSha256","observerProcessId","agentPid","pendingLedgerFileId","immediateObservedAt"):
            original=self.report["nativeRetentionCadence"][field]
            self.report["nativeRetentionCadence"][field]=999 if isinstance(original,int) else "0"*64
            with self.assertRaises(ValueError):self.verify()
            self.report["nativeRetentionCadence"][field]=original
        url=f"{self.base}/actions/artifacts/14/zip"
        self.routes[url]+=b"changed"
        with self.assertRaises(ValueError):self.verify()
    def test_chronological_approval_and_lease_forgery_refused_even_resealed(self):
        self.f["original"]["azure"]["vmCreatedAt"]="2026-10-14T12:01:00.000Z"
        self.reseal()
        with self.assertRaises(ValueError):self.verify()
    def test_original_native_attestation_cannot_be_missing_or_false(self):
        original=copy.deepcopy(self.f)
        for flag in auth.OBSERVATION_FLAGS:
            self.f=copy.deepcopy(original)
            self.f["original"]["preparation"]["observed"][flag]=False
            self.f["handoff"]["preparation"]=copy.deepcopy(self.f["original"]["preparation"])
            self.f["handoff"]["observed"][flag]=False
            self.reseal()
            with self.assertRaises(ValueError):self.verify()
    def test_creation_after_native_observation_is_impossible_even_resealed(self):
        self.f["original"]["azure"]["vmCreatedAt"]="2026-10-15T00:02:30.000Z"
        self.reseal()
        with self.assertRaises(ValueError):self.verify()
    def test_controller_source_and_foreign_prepare_refused(self):
        self.run["head_repository"]["full_name"]="foreign/core"
        with self.assertRaises(ValueError):self.verify()
        self.run["head_repository"]["full_name"]="tokentimerch/tokentimer-core"
        url=f"{self.base}/actions/runs/12/attempts/1"
        owner=json.loads(self.routes[url]);owner["head_sha"]="8"*40;self.routes[url]=encoded(owner)
        with self.assertRaises(ValueError):self.verify()
    def test_controller_source_bytes_are_authenticated(self):
        row=self.report["retentionCadenceProvenance"]["finalizerProvenance"]["controllerSources"][0]
        url=f"{self.base}/contents/{row['file']}?ref={self.run['head_sha']}"
        response=json.loads(self.routes[url]);response["content"]=base64.b64encode(b"foreign code").decode();response["size"]=12
        self.routes[url]=encoded(response)
        with self.assertRaises(ValueError):self.verify()
    def test_report_environment_and_adjacent_file_identity_contract(self):
        native=copy.deepcopy(self.report["nativeRetentionCadence"])
        native["timerLedgerFileId"]=native["pendingLedgerFileId"]
        self.assertEqual(auth.fields(native)["timerLedgerFileId"],native["pendingLedgerFileId"])
        native["timerLedgerFileId"]=native["immediateLedgerFileId"]
        with self.assertRaises(ValueError):auth.fields(native)
        for key in self.report["qualificationEnvironment"]:
            report=copy.deepcopy(self.report);report["qualificationEnvironment"][key]="unsupported"
            with self.assertRaises(ValueError):auth.report_fields(report)
    def test_projection_strips_private_fields_and_requires_measured_facts(self):
        value=copy.deepcopy(self.report["nativeRetentionCadence"])
        value["privatePath"]="private"
        self.assertNotIn("privatePath",auth.fields(value))
        for key in auth.FLAGS:
            bad={**value,key:False}
            with self.assertRaises(ValueError):auth.fields(bad)
        for key in auth.FALSE_FLAGS:
            with self.assertRaises(ValueError):auth.fields({**value,key:True})
        for elapsed in (0,17280000-300001,25920000+300001,True):
            with self.assertRaises(ValueError):auth.fields({**value,"actualMonotonicIntervalMs":elapsed})

if __name__ == "__main__":unittest.main()
