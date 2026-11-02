"""Actual JS proof validation into real collector parsing, no native execution."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
import certops_acme_bulk_proof as proof
ROOT=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('native_bulk_collector',ROOT/'scripts/certops-release-collector.py')
collector=importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
def events():
    source="const a=require('./scripts/test-support/acme-stage-artifact.cjs').artifact();const e=a.events.find(x=>x.nativeAcmeBulkRenewal);const h=require('./scripts/certops-acme-bulk-report');h.verifyForScope(e.nativeAcmeBulkRenewal,e.scope,e.qualificationEnvironment);h.verifyCrossJourney(e.nativeAcmeBulkRenewal,e.nativeAcmeKeyReuse,e.nativeAcmeBackgroundRenewals);process.stdout.write(JSON.stringify(a.events));"
    return json.loads(subprocess.check_output(['node','-e',source],cwd=ROOT,text=True))
def native(rows):
    return next(row for row in rows if row['name']==proof.MAIN)
class BulkProjection(unittest.TestCase):
    def test_actual_js_factory_real_parser_and_private_outer_state_strip(self):
        rows=events();native(rows)['privateLocalState']='must-not-persist'
        result=collector.sanitized_report(rows,set(),{proof.SCOPE})
        self.assertEqual(native(result)[proof.FIELD],native(rows)[proof.FIELD]);self.assertNotIn('must-not-persist',json.dumps(result))
        proof.verify_workflow(result,'.github/workflows/certops-real-acme.yml')
        for workflow in ('.github/workflows/certops-acme-native-console.yml','.github/workflows/certops-acme-browser-lifecycle.yml','.github/workflows/certops-qualification.yml'):
            with self.assertRaises(ValueError):proof.verify_workflow(result,workflow)
        proof.verify_workflow({'suite':'linux-native-acme-browser-console'},'.github/workflows/certops-acme-native-console.yml')
    def test_missing_native_facts_cannot_qualify(self):
        original=events()
        for flag in proof.FLAGS:
            for invalid in (False,None,1,'true'):
                rows=copy.deepcopy(original);native(rows)[proof.FIELD][flag]=invalid
                with self.assertRaises(ValueError):collector.sanitized_report(rows,set(),{proof.SCOPE})
    def test_private_extra_cross_splice_duplicate_or_foreign_environment_refused(self):
        for mutate in (
            lambda e:e[proof.FIELD].update(privateKey='secret'),
            lambda e:e[proof.FIELD].update(originalServingFingerprint='9'*64),
            lambda e:e[proof.FIELD]['issueJobIds'].__setitem__(0,e['nativeAcmeKeyReuse']['jobIds'][0]),
            lambda e:e[proof.FIELD]['claimIds'].__setitem__(1,e[proof.FIELD]['claimIds'][0].upper()),
            lambda e:e['qualificationEnvironment'].update(executionSurface='container'),
        ):
            rows=events();mutate(native(rows))
            with self.assertRaises(ValueError):collector.sanitized_report(rows,set(),{proof.SCOPE})
if __name__=='__main__':unittest.main()
