"""Actual JS proof validation into real collector parsing, no native execution."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
import certops_acme_certificate_outbox_proof as proof
import certops_acme_bulk_proof as bulk
ROOT=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('native_bulk_collector',ROOT/'scripts/certops-release-collector.py')
collector=importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
def events():
    source="const a=require('./scripts/test-support/acme-stage-artifact.cjs').artifact();const e=a.events.find(x=>x.nativeAcmeBulkRenewal);const h=require('./scripts/certops-acme-bulk-report');h.verifyForScope(e.nativeAcmeBulkRenewal,e.scope,e.qualificationEnvironment);h.verifyCrossJourney(e.nativeAcmeBulkRenewal,e.nativeAcmeKeyReuse,e.nativeAcmeBackgroundRenewals);require('./tests/e2e/helpers/certops-acme-certificate-outbox').verifyAgainstJourney(e.nativeAcmeCertificateOutbox,e.nativeAcmeBulkRenewal,e.nativeAcmeRenewalSetup);process.stdout.write(JSON.stringify(a.events));"
    return json.loads(subprocess.check_output(['node','-e',source],cwd=ROOT,text=True))
def native(rows):
    return next(row for row in rows if row['name']==bulk.MAIN)
class CertificateOutboxProjection(unittest.TestCase):
    def test_actual_js_factory_real_parser_and_private_outer_state_strip(self):
        rows=events();native(rows)['privateLocalState']='must-not-persist'
        result=collector.sanitized_report(rows,set(),{bulk.SCOPE})
        self.assertEqual(native(result)[proof.FIELD],native(rows)[proof.FIELD]);self.assertNotIn('must-not-persist',json.dumps(result))
    def test_missing_native_facts_cannot_qualify(self):
        original=events()
        for flag in proof.FLAGS:
            for invalid in (False,None,1,'true'):
                rows=copy.deepcopy(original);native(rows)[proof.FIELD][flag]=invalid
                with self.assertRaises(ValueError):collector.sanitized_report(rows,set(),{bulk.SCOPE})
    def test_private_extra_cross_splice_duplicate_or_foreign_environment_refused(self):
        for mutate in (
            lambda e:e[proof.FIELD].update(privateKey='secret'),
            lambda e:e[proof.FIELD].update(jobId=e[bulk.FIELD]['jobIds'][0]),
            lambda e:e[proof.FIELD]['fingerprints'].__setitem__(0,'9'*64),
            lambda e:e[proof.FIELD].update(attemptCount=True),
            lambda e:e[proof.FIELD]['fingerprints'].__setitem__(1,e[bulk.FIELD]['fingerprints'][0]),
        ):
            rows=events();mutate(native(rows))
            with self.assertRaises(ValueError):collector.sanitized_report(rows,set(),{bulk.SCOPE})
if __name__=='__main__':unittest.main()
