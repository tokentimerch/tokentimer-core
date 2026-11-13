"use strict";

// Assertions shared by the no-IIS native recovery driver. Its caller must
// obtain the CA rows from the qualification operator, and the store/key facts
// independently from the interrupted LocalSystem agent host. These assertions
// do not themselves constitute a native qualification run.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const DNS = /^certops-adcs-[a-f0-9]{16,32}-store\.example\.test$/;
const SHA256 = /^[a-f0-9]{64}$/;
const REQUEST_ID = /^[1-9][0-9]{0,9}$/;

function createRunDnsName() {
  return `certops-adcs-${crypto.randomBytes(16).toString("hex")}-store.example.test`;
}

// Read the CA's complete request count for this run's unique name. The
// existing lab-only helper performs this query as the separate qualification
// officer, never using or granting CA database privileges to the agent.
async function observeCaRequest({ dnsName, fingerprintSha256, execFileImpl = promisify(execFile) }) {
  assert.match(dnsName, DNS);
  assert.match(fingerprintSha256, SHA256);
  const script = path.resolve(__dirname, "../../../infra/certops-adcs/owned-issued-request.ps1");
  const result = await execFileImpl("powershell.exe", [
    "-NoProfile", "-NonInteractive", "-File", script,
    "-CommonName", dnsName, "-FingerprintSha256", fingerprintSha256,
  ], { windowsHide: true, timeout: 60000, maxBuffer: 16384 });
  const observed = JSON.parse(result.stdout);
  assert.equal(observed.fingerprintSha256, fingerprintSha256);
  assert.equal(observed.subjectRequestCount, 1, "Expected exactly one CA request for this run");
  requestId(observed.requestId);
  assert.match(observed.serialNumber, /^[a-fA-F0-9]+$/);
  return observed;
}

async function observePendingCaRequest({ dnsName, id, execFileImpl = promisify(execFile) }) {
  assert.match(dnsName, DNS);
  const expectedId = requestId(id);
  const script = path.resolve(__dirname, "../../../infra/certops-adcs/owned-request-observation.ps1");
  const result = await execFileImpl("powershell.exe", [
    "-NoProfile", "-NonInteractive", "-File", script,
    "-CommonName", dnsName, "-RequestId", expectedId,
  ], { windowsHide: true, timeout: 60000, maxBuffer: 16384 });
  const observed = JSON.parse(result.stdout);
  assert.equal(observed.subjectRequestCount, 1, "Expected exactly one CA request for this run");
  assert.equal(requestId(observed.requestId), expectedId);
  return observed;
}

function requestId(value) {
  const id = String(value ?? "");
  assert.match(id, REQUEST_ID);
  assert.ok(Number(id) <= 2147483647);
  return id;
}

function verifyImmediateRecovery({ dnsName, caAtFault, caAfter, fault, recovered, inventory }) {
  assert.match(dnsName, DNS, "Each run needs its own scoped qualification DNS name");
  for (const ca of [caAtFault, caAfter]) {
    // The officer query counts every request for this unique CN, not just
    // the request whose certificate matches the observed leaf.
    assert.equal(ca.subjectRequestCount, 1, "Duplicate CA requests must fail the run");
    assert.match(ca.fingerprintSha256, SHA256);
    assert.match(ca.serialNumber, /^[a-fA-F0-9]+$/);
    requestId(ca.requestId);
  }
  assert.equal(String(caAfter.requestId), String(caAtFault.requestId));
  assert.equal(caAfter.fingerprintSha256, caAtFault.fingerprintSha256);
  assert.equal(caAfter.serialNumber, caAtFault.serialNumber);
  assert.equal(fault.nativeIdentity, "LocalSystem");
  assert.equal(fault.observedPostAccept, true);
  assert.equal(fault.nativeProcessDrained, true);
  assert.equal(fault.store, "LocalMachine\\My");
  assert.equal(fault.iisBindingTouched, false);
  assert.equal(fault.hasPrivateKey, true);
  assert.equal(fault.nonExportable, true);
  assert.equal(fault.machineKey, true);
  assert.match(fault.containerName, /^tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  for (const hash of [fault.fingerprintSha256, fault.csrSpkiSha256, fault.leafSpkiSha256, fault.keySpkiSha256]) assert.match(hash, SHA256);
  assert.equal(fault.fingerprintSha256, caAtFault.fingerprintSha256);
  assert.equal(fault.leafSpkiSha256, fault.csrSpkiSha256);
  assert.equal(fault.keySpkiSha256, fault.csrSpkiSha256);
  // Immediate issuance may not expose a RequestId in the agent journal.
  if (fault.requestId != null && fault.requestId !== "") {
    assert.equal(requestId(fault.requestId), requestId(caAtFault.requestId));
  }
  assert.equal(recovered.containerName, fault.containerName);
  assert.equal(recovered.fingerprintSha256, fault.fingerprintSha256);
  assert.equal(recovered.csrSpkiSha256, fault.csrSpkiSha256);
  assert.equal(recovered.newSubmissions, 0);
  assert.equal(recovered.newKeys, 0);
  assert.equal(recovered.repeatedAccepts, 0);
  assert.equal(inventory.provisioningRegistrations, 1);
  assert.equal(inventory.promotions, 1);
  assert.equal(inventory.fingerprintSha256, fault.fingerprintSha256);
  assert.equal(inventory.serviceVerified, false);
  return true;
}

// The driver must perform its own native post-accept fault and inspection;
// this coordinator supplies a unique request identity and independent CA
// observations around the recovery. No result is a release qualification
// until a real no-IIS driver is wired and run on the candidate artifact.
async function qualifyImmediateStoreRecovery({ inspectAndInterrupt, restartAndRecover, readInventory, caObserver = observeCaRequest }) {
  for (const fn of [inspectAndInterrupt, restartAndRecover, readInventory, caObserver]) {
    assert.equal(typeof fn, "function");
  }
  const dnsName = createRunDnsName();
  const fault = await inspectAndInterrupt({ dnsName });
  const caAtFault = await caObserver({ dnsName, fingerprintSha256: fault.fingerprintSha256 });
  const recovered = await restartAndRecover({ dnsName, fault });
  const caAfter = await caObserver({ dnsName, fingerprintSha256: fault.fingerprintSha256 });
  const inventory = await readInventory({ dnsName, fault, recovered });
  verifyImmediateRecovery({ dnsName, caAtFault, caAfter, fault, recovered, inventory });
  return { dnsName, caAtFault, caAfter, fault, recovered, inventory };
}

function verifyPendingRecovery({ originalRequestId, afterRestartRequestId, retrievedRequestId, caPending, caIssued, newSubmissions, sameKey }) {
  const id = requestId(originalRequestId);
  assert.equal(requestId(afterRestartRequestId), id);
  assert.equal(requestId(retrievedRequestId), id);
  for (const ca of [caPending, caIssued]) {
    assert.equal(ca.subjectRequestCount, 1);
    assert.equal(requestId(ca.requestId), id);
  }
  assert.equal(caPending.disposition, 9);
  assert.equal(caIssued.disposition, 20);
  assert.equal(newSubmissions, 0);
  assert.equal(sameKey, true);
  return true;
}

module.exports = { createRunDnsName, observeCaRequest, observePendingCaRequest, qualifyImmediateStoreRecovery, verifyImmediateRecovery, verifyPendingRecovery };
