import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('adoption', Path(__file__).with_name('windows-edition-adoption.py'))
adoption = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adoption)


class AdoptionTests(unittest.TestCase):
    def setUp(self):
        self.archive = b'actual candidate archive'
        self.meta = {'sourceCommit': 'a' * 40, 'editionCommit': 'b' * 40,
                     'editionCoreCommit': 'a' * 40, 'version': '1.2.3', 'architecture': 'amd64',
                     'artifactDigests': {role: 'c' * 64 for role in adoption.ROLES}}
        self.meta['artifactDigests']['archive'] = hashlib.sha256(self.archive).hexdigest()

    def test_matching_bytes_make_bound_record(self):
        raw = adoption.produce(self.meta, self.archive, self.archive)
        self.assertEqual(json.loads(raw), {'caseId': 'same-candidate-bytes', 'status': 'passed', **self.meta})
        self.assertEqual(raw, adoption.produce(self.meta, self.archive, self.archive))

    def test_record_is_accepted_by_existing_binding(self):
        binding_spec = importlib.util.spec_from_file_location('binding', Path(__file__).with_name('windows-release-evidence.py'))
        binding = importlib.util.module_from_spec(binding_spec)
        binding_spec.loader.exec_module(binding)
        records = {}
        for name in binding.required_cases('cloud'):
            records[name] = (adoption.produce(self.meta, self.archive, self.archive) if name == 'same-candidate-bytes' else
                             json.dumps({'caseId': name, 'status': 'passed', **self.meta}).encode())
        report = {'slot': 'cloud', **self.meta, 'cases': [
            {'id': name, 'status': 'passed', 'evidenceSha256': hashlib.sha256(raw).hexdigest()}
            for name, raw in records.items()]}
        binding.validate_case_records(report, records)
        records['same-candidate-bytes'] += b' '
        with self.assertRaises(ValueError): binding.validate_case_records(report, records)

    def test_changed_archive_or_expected_digest_is_rejected(self):
        with self.assertRaises(ValueError): adoption.produce(self.meta, self.archive, self.archive + b'!')
        self.meta['artifactDigests']['archive'] = '0' * 64
        with self.assertRaises(ValueError): adoption.produce(self.meta, self.archive, self.archive)

    def test_invalid_metadata_and_bytes_are_rejected(self):
        for field, value in [('sourceCommit', 'main'), ('editionCoreCommit', 'b' * 40), ('architecture', 'x86'), ('version', 'latest')]:
            bad = dict(self.meta, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError): adoption.produce(bad, self.archive, self.archive)
        for value in (b'', bytearray(self.archive), 'archive'):
            with self.subTest(value=value), self.assertRaises(ValueError): adoption.produce(self.meta, value, value)
        with self.assertRaises(ValueError): adoption.produce(dict(self.meta, extra=True), self.archive, self.archive)


if __name__ == '__main__': unittest.main()
