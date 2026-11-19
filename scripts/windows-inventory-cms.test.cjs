const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const windows = { skip: process.platform !== 'win32' };
const fixtures = path.join(__dirname, 'fixtures', 'windows-rfc3161');
const timestamped = fs.readFileSync(path.join(fixtures, 'timestamped.p7'));
const untimestamped = fs.readFileSync(path.join(fixtures, 'untimestamped.p7'));
const inventory = Buffer.from('{"fixture":true}', 'utf8');

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function powershell(script, variables) {
  const command = Buffer.from(script, 'utf16le').toString('base64');
  return spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', command], {
    env: {
      ...process.env,
      TT_CMS_MODULE: path.join(__dirname, 'windows-inventory-cms.psm1'),
      ...variables,
    },
    encoding: 'utf8',
    timeout: 30_000,
  });
}

function inspect(signature, bytes = inventory, expected = digest(bytes)) {
  return powershell(String.raw`
    $ErrorActionPreference = 'Stop'
    $module = Import-Module -Name $env:TT_CMS_MODULE -PassThru
    & $module {
      $inventory = [Convert]::FromBase64String($env:TT_CMS_INVENTORY)
      $signature = [Convert]::FromBase64String($env:TT_CMS_SIGNATURE)
      $proof = Read-WindowsInventoryCms $inventory $signature $env:TT_CMS_EXPECTED
      $proof.Timestamp.UtcDateTime.ToString('o')
    }
  `, {
    TT_CMS_INVENTORY: bytes.toString('base64'),
    TT_CMS_SIGNATURE: signature.toString('base64'),
    TT_CMS_EXPECTED: expected,
  });
}

test('fixture inspection checks the exact inventory and reads its RFC 3161 time', windows, () => {
  const verified = inspect(timestamped);
  assert.equal(verified.status, 0, verified.error?.message || verified.stderr);
  assert.equal(verified.stdout.trim(), '2026-11-04T22:51:19.4370000Z');
  const wrongDigest = inspect(timestamped, inventory, '0'.repeat(64));
  assert.notEqual(wrongDigest.status, 0);
  assert.match(wrongDigest.stderr, /independently expected SHA-256/);
  const differentInventory = inspect(timestamped, Buffer.from('{"fixture":false}'));
  assert.notEqual(differentInventory.status, 0);
  assert.match(differentInventory.stderr, /exact inventory bytes/);
});

test('fixture inspection refuses modified CMS, trailing data and missing timestamps', windows, () => {
  const modified = Buffer.from(timestamped);
  const offset = modified.indexOf(inventory);
  assert.notEqual(offset, -1);
  modified[offset + 2] ^= 1;
  const changedInventory = modified.subarray(offset, offset + inventory.length);
  const invalidSignature = inspect(modified, changedInventory);
  assert.notEqual(invalidSignature.status, 0);
  assert.match(invalidSignature.stderr, /CheckSignature/);

  const extraData = inspect(Buffer.concat([timestamped, Buffer.from([0])]));
  assert.notEqual(extraData.status, 0);
  assert.match(extraData.stderr, /Unexpected bytes after the inventory CMS/);
  const wrongTime = Buffer.from(timestamped);
  const timeOffset = wrongTime.indexOf('20261104225119.437Z', 0, 'ascii');
  assert.notEqual(timeOffset, -1);
  wrongTime[timeOffset + 13] = '8'.charCodeAt(0);
  const tamperedTimestamp = inspect(wrongTime);
  assert.notEqual(tamperedTimestamp.status, 0);
  assert.match(tamperedTimestamp.stderr, /timestamp does not verify/);

  const missingTimestamp = inspect(untimestamped);
  assert.notEqual(missingTimestamp.status, 0);
  assert.match(missingTimestamp.stderr, /Expected exactly one RFC 3161 timestamp/);
});

test('trusted inventory verification refuses the cryptographically valid self-signed fixture', windows, () => {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-inventory-cms-'));
  const inventoryPath = path.join(folder, 'inventory.json');
  try {
    fs.writeFileSync(inventoryPath, inventory);
    const verified = powershell(String.raw`
      $ErrorActionPreference = 'Stop'
      Import-Module -Name $env:TT_CMS_MODULE
      $parameters = @{
        InventoryPath = $env:TT_CMS_INVENTORY_PATH
        SignaturePath = $env:TT_CMS_SIGNATURE_PATH
        ExpectedInventorySha256 = $env:TT_CMS_EXPECTED
        PublisherProfileEku = '1.3.6.1.4.1.311.97.10.20.30.40'
        PublisherIssuerSha256 = 'a' * 64
      }
      Confirm-WindowsInventoryCms @parameters
    `, {
      TT_CMS_INVENTORY_PATH: inventoryPath,
      TT_CMS_SIGNATURE_PATH: path.join(fixtures, 'timestamped.p7'),
      TT_CMS_EXPECTED: digest(inventory),
    });
    assert.notEqual(verified.status, 0);
    assert.match(verified.stderr, /independent Public Trust publisher profile/);
  } finally {
    fs.rmSync(inventoryPath, { force: true });
    fs.rmdirSync(folder);
  }
});

test('cache-only Windows chain policy rejects the untrusted fixture publisher', windows, () => {
  const untrusted = powershell(String.raw`
    $ErrorActionPreference = 'Stop'
    $module = Import-Module -Name $env:TT_CMS_MODULE -PassThru
    & $module {
      $inventory = [Convert]::FromBase64String($env:TT_CMS_INVENTORY)
      $signature = [Convert]::FromBase64String($env:TT_CMS_SIGNATURE)
      $proof = Read-WindowsInventoryCms $inventory $signature $env:TT_CMS_EXPECTED
      Assert-InventoryCertificateChain $proof.Publisher $proof.PublisherCertificates $proof.Timestamp $codeSigningOid
    }
  `, {
    TT_CMS_INVENTORY: inventory.toString('base64'),
    TT_CMS_SIGNATURE: timestamped.toString('base64'),
    TT_CMS_EXPECTED: digest(inventory),
  });
  assert.notEqual(untrusted.status, 0);
  assert.match(untrusted.stderr, /cached revocation is invalid/);
  const status = untrusted.stderr.match(/\b0x([0-9A-F]{8})\b/);
  assert.ok(status, untrusted.error?.message || untrusted.stderr);
  assert.equal(Number.parseInt(status[1], 16) & 0x20, 0x20);
});
