"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createRunDnsName, observeCaRequest, observePendingCaRequest, qualifyImmediateStoreRecovery, verifyImmediateRecovery, verifyPendingRecovery } = require("./certops-adcs-store-recovery-proof");

function immediate() {
  const fp = "a".repeat(64), spki = "b".repeat(64);
  const ca = { subjectRequestCount: 1, requestId: 42, fingerprintSha256: fp, serialNumber: "123abc" };
  const fault = { nativeIdentity: "LocalSystem", observedPostAccept: true, nativeProcessDrained: true,
    store: "LocalMachine\\My", iisBindingTouched: false,
    hasPrivateKey: true, nonExportable: true, machineKey: true,
    containerName: "tokentimer-enr-11111111-1111-1111-1111-111111111111", fingerprintSha256: fp,
    csrSpkiSha256: spki, leafSpkiSha256: spki, keySpkiSha256: spki, requestId: null };
  return { dnsName: "certops-adcs-0123456789abcdef-store.example.test", caAtFault: ca, caAfter: { ...ca }, fault,
    recovered: { containerName: fault.containerName, fingerprintSha256: fp, csrSpkiSha256: spki,
      newSubmissions: 0, newKeys: 0, repeatedAccepts: 0 },
    inventory: { provisioningRegistrations: 1, promotions: 1, fingerprintSha256: fp, serviceVerified: false } };
}

test("immediate issuance does not require an agent-recorded RequestId", () => {
  const p = immediate(); assert.equal(verifyImmediateRecovery(p), true);
  p.fault.requestId = "42"; assert.equal(verifyImmediateRecovery(p), true);
  p.fault.requestId = "43"; assert.throws(() => verifyImmediateRecovery(p));
});

test("duplicate requests for the run fail even if the selected leaf matches", () => {
  const p = immediate(); p.caAtFault.subjectRequestCount = 2;
  assert.throws(() => verifyImmediateRecovery(p));
  const q = immediate(); q.caAfter.subjectRequestCount = 2;
  assert.throws(() => verifyImmediateRecovery(q));
});

test("native identity, key custody, recovery and inventory proof are required", () => {
  for (const [part, field, value] of [
    ["fault", "machineKey", false], ["fault", "nonExportable", false],
    ["fault", "iisBindingTouched", true], ["fault", "nativeIdentity", "Administrator"],
    ["fault", "observedPostAccept", false], ["fault", "nativeProcessDrained", false],
    ["fault", "keySpkiSha256", "c".repeat(64)], ["fault", "leafSpkiSha256", "c".repeat(64)],
    ["recovered", "newSubmissions", 1], ["recovered", "newKeys", 1],
    ["recovered", "repeatedAccepts", 1], ["inventory", "promotions", 2],
    ["inventory", "serviceVerified", true], ["caAfter", "serialNumber", "beef"],
  ]) { const p = immediate(); p[part][field] = value; assert.throws(() => verifyImmediateRecovery(p), `${part}.${field}`); }
  const p = immediate(); p.dnsName = "shared.example.test"; assert.throws(() => verifyImmediateRecovery(p));
});

test("qualification uses one fresh DNS name and checks CA before and after recovery", async () => {
  const p = immediate(), calls = [];
  const proof = await qualifyImmediateStoreRecovery({
    inspectAndInterrupt: async ({ dnsName }) => { calls.push(["fault", dnsName]); return p.fault; },
    caObserver: async ({ dnsName }) => { calls.push(["ca", dnsName]); return p.caAtFault; },
    restartAndRecover: async ({ dnsName }) => { calls.push(["recover", dnsName]); return p.recovered; },
    readInventory: async ({ dnsName }) => { calls.push(["inventory", dnsName]); return p.inventory; },
  });
  assert.deepEqual(calls.map(([name]) => name), ["fault", "ca", "recover", "ca", "inventory"]);
  assert.ok(calls.every(([, name]) => name === proof.dnsName));
});

test("pending approval resumes the same recorded RequestId and key", () => {
  const p = { originalRequestId: 42, afterRestartRequestId: "42", retrievedRequestId: 42, newSubmissions: 0, sameKey: true,
    caPending: { requestId: 42, disposition: 9, subjectRequestCount: 1 },
    caIssued: { requestId: 42, disposition: 20, subjectRequestCount: 1 } };
  assert.equal(verifyPendingRecovery(p), true);
  for (const change of [{ afterRestartRequestId: 43 }, { retrievedRequestId: null }, { newSubmissions: 1 }, { sameKey: false }]) {
    assert.throws(() => verifyPendingRecovery({ ...p, ...change }));
  }
  assert.throws(() => verifyPendingRecovery({ ...p, caPending: { ...p.caPending, subjectRequestCount: 2 } }));
  assert.throws(() => verifyPendingRecovery({ ...p, caIssued: { ...p.caIssued, disposition: 9 } }));
});

test("native pending observer reads only the original request and counts all matching rows", async () => {
  const dnsName = createRunDnsName();
  const result = await observePendingCaRequest({ dnsName, id: 42, execFileImpl: async (program, argv) => {
    assert.equal(program, "powershell.exe");
    assert.equal(argv[argv.indexOf("-CommonName") + 1], dnsName);
    assert.equal(argv[argv.indexOf("-RequestId") + 1], "42");
    return { stdout: JSON.stringify({ requestId: 42, subjectRequestCount: 1, disposition: 9 }) };
  } });
  assert.equal(result.disposition, 9);
  await assert.rejects(observePendingCaRequest({ dnsName, id: 42, execFileImpl: async () => ({
    stdout: JSON.stringify({ requestId: 42, subjectRequestCount: 2, disposition: 9 }),
  }) }));
});

test("native CA observer scopes the complete request count to a fresh run", async () => {
  const dnsName = createRunDnsName(), fingerprintSha256 = "a".repeat(64);
  assert.notEqual(dnsName, createRunDnsName());
  let invoked = false;
  const result = await observeCaRequest({ dnsName, fingerprintSha256, execFileImpl: async (program, argv, options) => {
    invoked = true;
    assert.equal(program, "powershell.exe");
    assert.equal(argv[argv.indexOf("-CommonName") + 1], dnsName);
    assert.equal(argv[argv.indexOf("-FingerprintSha256") + 1], fingerprintSha256);
    assert.equal(options.windowsHide, true);
    return { stdout: JSON.stringify({ fingerprintSha256, subjectRequestCount: 1, requestId: 12, serialNumber: "ab12" }) };
  } });
  assert.equal(invoked, true);
  assert.equal(result.subjectRequestCount, 1);
  await assert.rejects(observeCaRequest({ dnsName, fingerprintSha256, execFileImpl: async () => ({
    stdout: JSON.stringify({ fingerprintSha256, subjectRequestCount: 2, requestId: 12, serialNumber: "ab12" }),
  }) }));
  await assert.rejects(observeCaRequest({ dnsName: "shared.example.test", fingerprintSha256, execFileImpl: async () => { throw Error("must not query"); } }));
});
