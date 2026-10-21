"""Offline WebHosting native report projection; no Windows operations execute."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)

def fixture():
    return json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require('./scripts/fixtures/certops-webhosting-retention.cjs').proof()))"], cwd=ROOT, text=True, timeout=20))

class WebHostingProjection(unittest.TestCase):
    def test_actual_js_fixture_and_sanitized_projection_match(self):
        proof = fixture()
        self.assertEqual(collector.webhosting_retention_fields(proof), proof)
        script = "let s='';process.stdin.on('data',b=>s+=b);process.stdin.on('end',()=>require('./packages/agent/scripts/host/retention-webhosting-fixture').verifyProof(JSON.parse(s)));"
        subprocess.run(["node", "-e", script], input=json.dumps(collector.webhosting_retention_fields(proof)), text=True, cwd=ROOT, check=True, capture_output=True, timeout=20)
    def test_missing_false_promoted_or_unbounded_facts_refuse(self):
        base = fixture()
        for field in base:
            proof=copy.deepcopy(base);del proof[field]
            with self.subTest(field=field), self.assertRaises(ValueError):collector.webhosting_retention_fields(proof)
        for section in ("storeReceipt", "borrowedReplacement"):
            for field, value in base[section].items():
                if value is not True:continue
                proof=copy.deepcopy(base);proof[section][field]=False
                with self.subTest(section=section,field=field),self.assertRaises(ValueError):collector.webhosting_retention_fields(proof)
        for elapsed in ({"waitedMonotonicMs":1},{"waitedMonotonicMs":600000},{"waitedMonotonicMs":float('nan')},{"successfulCutovers":True},{"ownedInterruption":None}):
            proof=copy.deepcopy(base);proof['elapsed'].update(elapsed)
            with self.assertRaises(ValueError):collector.webhosting_retention_fields(proof)
    def test_private_native_data_is_stripped_at_every_level(self):
        proof=fixture();proof['privateKey']='secret';proof['storeReceipt']['container']='secret';proof['borrowedReplacement']['nativeName']='secret';proof['elapsed']['path']='secret';proof['elapsed']['ownedInterruption']['argv']='secret'
        self.assertNotIn('secret',json.dumps(collector.webhosting_retention_fields(proof)))
    def test_actual_archive_parser_keeps_proof_and_refuses_missing_or_failed_cleanup(self):
        import io, zipfile
        base={"suite":"windows-webhosting-retention","nativeWebHostingRetention":fixture(),"cleanup":{"status":"passed"},"scenarios":[]}
        def extract(value):
            raw=io.BytesIO()
            with zipfile.ZipFile(raw,"w") as archive:archive.writestr("report.json",json.dumps(value))
            return collector.extract_reports(raw.getvalue(),[base["suite"]],[])
        self.assertEqual(extract(base)[0][1]["nativeWebHostingRetention"],base["nativeWebHostingRetention"])
        for patch in ({"cleanup":{"status":"failed"}},{"nativeWebHostingRetention":None}):
            with self.assertRaises(ValueError):extract({**base,**patch})

    def test_only_dedicated_workflow_can_supply_this_report(self):
        report={'suite':'windows-webhosting-retention'}
        collector.verify_webhosting_retention_workflow(report,'.github/workflows/certops-windows-webhosting-retention.yml')
        with self.assertRaises(ValueError):collector.verify_webhosting_retention_workflow(report,'.github/workflows/certops-qualification.yml')

if __name__=='__main__':unittest.main()
