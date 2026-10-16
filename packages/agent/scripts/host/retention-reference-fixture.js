"use strict";
/** Supporting native retention-reference qualification on the existing owned
 * collector fixture. Ledger references are explicit supporting prerequisites,
 * not fabricated enrollment/job outcomes. Real native facts, TLS and clock
 * remain in use. No certificate/key deletion or elapsed-window claim is made. */
const assert = require("node:assert/strict"), path = require("node:path"), { spawnSync } = require("node:child_process");
const ledger = require("../../src/windows-retention");
const scenarios = ["windows-retention-two-open-references-protect", "windows-retention-one-closed-reference-still-protects", "windows-retention-all-closed-respects-real-deadline"];
const requiredSources = ["packages/agent/scripts/host/retention-reference-fixture.js", "packages/agent/scripts/host/retention-fixture.js", "packages/agent/src/windows-retention/index.js", "packages/agent/src/index.js", "packages/agent/src/windows-key-survivors/index.js"];
const fields = ["twoOpenReferencesPersistedAcrossProcess", "bothOpenNativeSweepPreservedCustody", "oneClosedStillProtected", "unknownReferenceDoesNotCloseOwnedReferences", "allClosedStillDeferredByRealDeadline", "nativeCustodyAndTrustedTlsUnchanged"];
function verifyProof(proof) {
  assert.deepEqual(Object.keys(proof).sort(), [...fields, "scope", "elapsed24HourQualified"].sort());
  assert.equal(proof.scope, "native-collector-supporting-ledger-reference-lifecycle"); assert.equal(proof.elapsed24HourQualified, false);
  for (const field of fields) assert.equal(proof[field], true, field);
}
async function qualifyRetentionReferences({ gate, powershell, ledgerDir, oldThumbprint, replacementThumbprint, containerName, sweep, expectReplacementServed }) {
  assert.equal(process.platform, "win32"); assert.ok(gate && typeof gate.scenario === "function");
  const original = ledger.readLedgerRow(ledgerDir, oldThumbprint); assert.ok(original);
  assert.equal(original.ownershipProvenance, "tokentimer_installed"); assert.deepEqual(original.jobOrRollbackJournalRefs, []);
  const refs = [{ ref: "supporting-job:retention-reference-fixture", active: true }, { ref: "supporting-rollback:retention-reference-fixture", active: true }];
  const native = () => powershell(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${oldThumbprint}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if(!$k -or $k.Key.KeyName -ne '${containerName}' -or !$k.Key.IsMachineKey -or $k.Key.Provider.Provider -ne 'Microsoft Software Key Storage Provider' -or [int]$k.Key.ExportPolicy -ne 0){throw 'Owned protected predecessor custody unavailable'};@{thumb=$c.Thumbprint;container=$k.Key.KeyName;public=[Convert]::ToBase64String($c.RawData);policy=[int]$k.Key.ExportPolicy}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`);
  const baseline = native();
  const readFresh = () => {
    const result = spawnSync(process.execPath, ["-e", "const m=require(process.argv[1]);process.stdout.write(JSON.stringify(m.readLedgerRow(process.argv[2],process.argv[3])))", path.resolve(__dirname, "../../src/windows-retention"), ledgerDir, oldThumbprint], { encoding: "utf8", timeout: 10000, maxBuffer: 16384, windowsHide: true });
    assert.ifError(result.error); assert.equal(result.status, 0, "Fresh process must read actual protected ledger"); return JSON.parse(result.stdout);
  };
  const immutable = row => [row.oldThumbprint, row.replacementThumbprint, row.cngKeyContainerId, row.store, row.verifiedCutoverAt, row.oldNotAfter, row.ownershipProvenance];
  const unchanged = async () => { assert.equal(native() === baseline, true, "Exact protected predecessor custody changed"); await expectReplacementServed(replacementThumbprint); assert.deepEqual(immutable(readFresh()), immutable(original)); };
  const deferred = async reason => { const result = await sweep(); assert.equal(result.removed.length, 0); assert.ok(result.deferred.some(row => row.oldThumbprint === oldThumbprint && row.reason === reason)); await unchanged(); };
  await gate.scenario(scenarios[0], async () => {
    ledger.writeLedgerRow(ledgerDir, { ...original, jobOrRollbackJournalRefs: refs }); assert.deepEqual(readFresh().jobOrRollbackJournalRefs, refs);
    await deferred("active_reference_present");
  }, { evidenceLevel: "real-host", oracle: "Two explicit supporting ledger references survive fresh-process read and actual native sweep preserves protected CNG predecessor and trusted replacement" });
  await gate.scenario(scenarios[1], async () => {
    ledger.closeJournalReference(ledgerDir, oldThumbprint, refs[0].ref);
    const expected = [{ ...refs[0], active: false }, refs[1]]; assert.deepEqual(readFresh().jobOrRollbackJournalRefs, expected);
    ledger.closeJournalReference(ledgerDir, oldThumbprint, "supporting-unknown:must-not-close-owned-reference"); assert.deepEqual(readFresh().jobOrRollbackJournalRefs, expected);
    await deferred("active_reference_present");
  }, { evidenceLevel: "real-host", oracle: "Closing one or an unknown reference cannot clear the remaining live rollback reference or delete native custody" });
  await gate.scenario(scenarios[2], async () => {
    ledger.closeJournalReference(ledgerDir, oldThumbprint, refs[1].ref); assert.equal(readFresh().jobOrRollbackJournalRefs.every(ref => ref.active === false), true);
    await deferred("deadline_not_reached");
  }, { evidenceLevel: "real-host", oracle: "Closing both supporting references removes that guard while the unmodified real-clock 24-hour policy still defers; no elapsed qualification implied" });
  const proof = { scope: "native-collector-supporting-ledger-reference-lifecycle", elapsed24HourQualified: false, ...Object.fromEntries(fields.map(field => [field, true])) }; verifyProof(proof); return proof;
}
module.exports = { qualifyRetentionReferences, verifyProof, scenarios, requiredSources, fields };
