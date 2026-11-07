// Windows-only cryptographic experiment. These tests establish neither TSA
// nor publisher trust and must never be treated as release qualification.
// The fixtures contain only a self-signed test certificate, signatures and a
// public Microsoft timestamp. They contain no private key or Azure identity.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const fixtures = path.join(__dirname, 'fixtures', 'windows-rfc3161');
const script = fs.readFileSync(path.join(fixtures, 'probe.ps1'), 'utf8');
const signed = fs.readFileSync(path.join(fixtures, 'timestamped.p7'));
const noTimestamp = fs.readFileSync(path.join(fixtures, 'untimestamped.p7'));

function probe(cms, extra = {}) {
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  return spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
    env: { ...process.env, TT_TEST_MUTATE_SIGNATURE: '0', TT_TEST_MUTATE_TIMESTAMP: '0', TT_TEST_CMS: cms.toString('base64'), ...extra }, encoding: 'utf8',
  });
}
const windows = { skip: process.platform !== 'win32' };
test('RFC3161 timestamp is cryptographically bound to the CMS signature', windows, () => {
  const valid = probe(signed);
  assert.equal(valid.status, 0, valid.stderr);
  assert.equal(valid.stdout, '2026-11-04T22:51:19.4370000Z');
  assert.notEqual(probe(signed, { TT_TEST_MUTATE_SIGNATURE: '1' }).status, 0);
  assert.notEqual(probe(signed, { TT_TEST_MUTATE_TIMESTAMP: '1' }).status, 0);
});
test('unsigned timestamp or altered CMS content is rejected', windows, () => {
  assert.notEqual(probe(noTimestamp).status, 0);
  const tampered = Buffer.from(signed);
  const offset = tampered.indexOf(Buffer.from('{"fixture":true}'));
  assert.notEqual(offset, -1, 'fixture must include its known embedded payload');
  tampered[offset + 2] ^= 1;
  assert.notEqual(probe(tampered).status, 0);
  assert.notEqual(probe(Buffer.from('not CMS')).status, 0);
});
