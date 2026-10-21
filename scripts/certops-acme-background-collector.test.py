"""Offline Node/Python proof parity and privacy checks; no CA or worker runs."""
import copy
import json
import importlib.util
from pathlib import Path
import subprocess
import unittest
import certops_acme_background_proof as helper
ROOT=Path(__file__).resolve().parents[1]
PROGRAM = r"""
const helper = require('./tests/e2e/helpers/certops-acme-background-renewals');
const proof = require('./scripts/test-support/acme-background-proof.cjs').proof();
helper.verifyProof(proof);
process.stdout.write(JSON.stringify({proof,flags:helper.FLAGS}));
"""
class BackgroundProof(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=json.loads(subprocess.check_output(['node','-e',PROGRAM],cwd=ROOT))
    def test_actual_node_verified_shape_and_both_clients(self):
        self.assertEqual(self.fixture['flags'],list(helper.FLAGS))
        for client in ('certbot','acme.sh'):
            value=copy.deepcopy(self.fixture['proof']);value['client']=client
            self.assertEqual(helper.fields(value),value)
    def test_all_fields_required_and_invalid_native_lifecycle_refused(self):
        for key in self.fixture['proof']:
            value=copy.deepcopy(self.fixture['proof']);del value[key]
            with self.subTest(field=key),self.assertRaises(ValueError):helper.fields(value)
        for key in helper.FLAGS:
            value={**self.fixture['proof'],key:False}
            with self.subTest(flag=key),self.assertRaises(ValueError):helper.fields(value)
        for field,wrong in (('pidfdClosed',False),('pidfdSignalUsed',False),('groupDrained',False),('closed',False),('created',1),('starts',True),('tickElapsedMs',[1,2]),('summaries',1)):
            value=copy.deepcopy(self.fixture['proof']);value['workerLifecycle'][field]=wrong
            with self.subTest(lifecycle=field),self.assertRaises(ValueError):helper.fields(value)
        for field,wrong in (('fingerprints',['a'*64]*3),('jobIds',['abcdefab-1234-1234-1234-123456789abc','ABCDEFAB-1234-1234-1234-123456789ABC']),('expiryEpochs',[1,True,3]),('schedulerInvocation','manual-sweep'),('successfulAutomationCycles',1)):
            value=copy.deepcopy(self.fixture['proof']);value[field]=wrong
            with self.subTest(field=field),self.assertRaises(ValueError):helper.fields(value)
    def test_actual_factory_and_collector_bind_all_five_scopes_and_strip_private_data(self):
        spec=importlib.util.spec_from_file_location("background_real_collector",ROOT/"scripts/certops-release-collector.py")
        collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)
        for scope in helper.SCOPES:
            program="process.stdout.write(JSON.stringify(require('./scripts/test-support/acme-stage-artifact.cjs').artifact("+json.dumps(scope)+").events))"
            events=json.loads(subprocess.check_output(['node','-e',program],cwd=ROOT))
            original=next(event for event in events if event['name']==helper.MAIN)
            original[helper.FIELD]['rawLogs']='private-sentinel'
            original[helper.FIELD]['workerLifecycle']['privatePath']='private-sentinel'
            result=collector.sanitized_report(events,set(),{scope})
            main=next(event for event in result if event['name']==helper.MAIN)
            self.assertEqual(main[helper.FIELD],helper.fields(original[helper.FIELD]))
            self.assertNotIn('private-sentinel',json.dumps(result))
            for change in ({'client':'certbot' if 'acmesh' in scope else 'acme.sh'},{'sourceProfileId':'99999999-9999-4999-8999-999999999999'},{'fingerprints':['d'*64,'e'*64,'f'*64]}):
                changed=copy.deepcopy(events)
                event=next(item for item in changed if item['name']==helper.MAIN);event[helper.FIELD].update(change)
                with self.assertRaises(ValueError):collector.sanitized_report(changed,set(),{scope})
            missing=copy.deepcopy(events);del next(item for item in missing if item['name']==helper.MAIN)[helper.FIELD]
            with self.assertRaises(ValueError):collector.sanitized_report(missing,set(),{scope})
    def test_private_fields_are_stripped_and_arrays_are_copied(self):
        value=copy.deepcopy(self.fixture['proof']);value['rawLogs']='private-sentinel';value['workerLifecycle']['privatePath']='private-sentinel'
        result=helper.fields(value);self.assertNotIn('private-sentinel',json.dumps(result));result['jobIds'].append('changed');result['workerLifecycle']['tickElapsedMs'].append(1)
        self.assertEqual(len(value['jobIds']),2);self.assertEqual(len(value['workerLifecycle']['tickElapsedMs']),2)
if __name__=='__main__':unittest.main()
