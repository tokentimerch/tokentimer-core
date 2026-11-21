"use strict";

// Qualification coordinator, not a native fixture. Its independent CA and
// process observers must be supplied by a disposable Windows lab. Never infer
// zero new orders or keys from the agent journal or job status alone.
// A Pebble fixture can use createPebbleCaObserver({ proxy, inspectIsolation })
// for observeCa. The fixture still owns DNS preparation, fault injection,
// service restart, native operation capture and inventory inspection.
const assert = require("node:assert/strict");
const { createHash, randomBytes } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const HASH = /^[a-f0-9]{64}$/;
const CAPTURE = /^[a-f0-9]{32}$/;
const CONTAINER = /^tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const PHASES = ["after-finalization-before-save", "after-save-upload-lost"];

function createRunDnsName(zone) {
  assert.match(zone, /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/);
  return `tt-acme-${randomBytes(12).toString("hex")}.${zone}`;
}

function readCandidateArchive(archivePath, expectedSha256) {
  assert.ok(path.isAbsolute(archivePath), "A local candidate archive path is required");
  assert.match(expectedSha256, HASH, "The immutable agent archive digest is required");
  const actual = createHash("sha256").update(fs.readFileSync(archivePath)).digest("hex");
  assert.equal(actual, expectedSha256, "Agent archive does not match the candidate");
  return actual;
}

function validateCounter(before, fault, after) {
  for (const counter of [before, fault, after]) {
    assert.equal(counter?.coverageComplete, true, "Independent capture must cover the whole run");
    assert.match(counter.captureId, CAPTURE);
    for (const key of ["orders", "keygens", "accepts"]) {
      assert.ok(Number.isSafeInteger(counter[key]) && counter[key] >= 0, `Invalid ${key} count`);
    }
  }
  assert.equal(before.captureId, fault.captureId);
  assert.equal(before.captureId, after.captureId);
  assert.equal(fault.orders - before.orders, 1, "The initial attempt must create exactly one order");
  assert.equal(fault.keygens - before.keygens, 1, "The initial attempt must create exactly one key");
  assert.equal(fault.accepts, before.accepts, "These interruptions occur before native acceptance");
  assert.equal(after.orders, fault.orders, "Recovery must not create another order");
  assert.equal(after.keygens, fault.keygens, "Recovery must not create another key");
  assert.ok(after.accepts >= fault.accepts, "Native counts cannot go backwards");
}

function verifyCrashRecovery({ phase, dnsName, candidateSha256, before, atFault, after, caAtFault, caAfter, fault, recovered, inventory }) {
  assert.ok(PHASES.includes(phase));
  assert.match(dnsName, /^tt-acme-[a-f0-9]{24}\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/);
  assert.match(candidateSha256, HASH);
  validateCounter(before, atFault, after);
  for (const ca of [caAtFault, caAfter]) {
    assert.ok(["independent-ca", "isolated-ca-proxy"].includes(ca?.source));
    assert.equal(ca.coverageComplete, true, "CA observation must have complete independently verified coverage");
    assert.match(ca.coverageId, CAPTURE);
    assert.equal(ca.dnsName, dnsName);
    assert.equal(ca.ordersForDns, 1, "Count all CA orders for this unique DNS name");
    assert.equal(ca.finalizedOrdersForDns, 1);
    assert.ok(typeof ca.orderId === "string" && ca.orderId.length > 0);
    assert.match(ca.fingerprintSha256, HASH, "The CA must independently identify the issued leaf");
  }
  assert.equal(caAtFault.orderId, caAfter.orderId);
  assert.equal(caAtFault.fingerprintSha256, caAfter.fingerprintSha256);
  assert.equal(caAtFault.source, caAfter.source);
  assert.equal(caAtFault.coverageId, caAfter.coverageId);
  assert.equal(fault?.phase, phase);
  assert.equal(fault.candidateSha256, candidateSha256);
  assert.equal(fault.nativeIdentity, "LocalSystem");
  assert.equal(fault.noIis, true);
  assert.equal(fault.nativeProcessDrained, true);
  assert.equal(fault.caFinalizationObserved, true);
  assert.match(fault.containerName, CONTAINER);
  assert.match(fault.csrSpkiSha256, HASH);
  assert.equal(fault.keySpkiSha256, fault.csrSpkiSha256);
  assert.equal(fault.machineKey, true);
  assert.equal(fault.nonExportable, true);
  assert.equal(fault.keyPossessionVerified, true);
  assert.equal(fault.leafDurable, phase === "after-save-upload-lost");
  assert.equal(fault.evidenceUploadDropped, phase === "after-save-upload-lost");
  if (fault.leafDurable) {
    assert.match(fault.fingerprintSha256, HASH);
    assert.equal(fault.fingerprintSha256, caAtFault.fingerprintSha256);
    assert.equal(fault.leafSpkiSha256, fault.csrSpkiSha256);
  }
  assert.equal(recovered?.containerName, fault.containerName);
  assert.equal(recovered.csrSpkiSha256, fault.csrSpkiSha256);
  assert.equal(recovered.keySpkiSha256, fault.csrSpkiSha256);
  assert.equal(recovered.machineKey, true);
  assert.equal(recovered.nonExportable, true);
  assert.equal(recovered.keyPossessionVerified, true);
  assert.ok(["installed", "uncertain"].includes(recovered.outcome));
  if (phase === "after-save-upload-lost") assert.equal(recovered.outcome, "installed");
  assert.equal(inventory?.serviceVerified, false);
  assert.equal(inventory.provisioningRegistrations, 1);
  if (recovered.outcome === "installed") {
    assert.match(recovered.fingerprintSha256, HASH);
    assert.equal(recovered.leafSpkiSha256, fault.csrSpkiSha256);
    assert.equal(recovered.store, "LocalMachine\\My");
    assert.equal(recovered.fingerprintSha256, caAfter.fingerprintSha256);
    if (fault.leafDurable) assert.equal(recovered.fingerprintSha256, fault.fingerprintSha256);
    assert.equal(inventory.promotions, 1);
    assert.equal(inventory.fingerprintSha256, recovered.fingerprintSha256);
    assert.equal(after.accepts - atFault.accepts, 1, "Recovery must accept the original leaf once");
  } else {
    assert.equal(phase, "after-finalization-before-save");
    assert.equal(recovered.outcomeVisible, true);
    assert.equal(inventory.promotions, 0);
    assert.equal(after.accepts, atFault.accepts, "An uncertain outcome must not install a leaf");
  }
  return true;
}

async function qualifyCrashRecovery({ fixture, archivePath, archiveSha256, zone }) {
  assert.equal(process.platform, "win32", "A real Windows member is required");
  assert.equal(process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST, "1", "A disposable lab host is required");
  for (const key of ["inspectHost", "prepareRun", "startCapture", "issueAndInterrupt", "observeCa", "restartAndRecover", "readInventory"]) {
    assert.equal(typeof fixture?.[key], "function", `Missing native lab hook: ${key}`);
  }
  const candidateSha256 = readCandidateArchive(archivePath, archiveSha256);
  const host = await fixture.inspectHost({ candidateSha256 });
  assert.equal(host?.nativeIdentity, "LocalSystem");
  assert.equal(host.noIis, true);
  assert.equal(host.agentArchiveSha256, candidateSha256);
  assert.equal(host.storeOnlyAcmeCapability, true, "The candidate must declare the qualification capability");
  const results = [];
  for (const phase of PHASES) {
    const dnsName = createRunDnsName(zone);
    await fixture.prepareRun({ phase, dnsName, candidateSha256 });
    const capture = await fixture.startCapture({ phase, dnsName });
    assert.equal(typeof capture?.read, "function", "Native operation capture is required");
    assert.equal(typeof capture?.stop, "function", "Native capture cleanup is required");
    try {
      const before = await capture.read();
      const fault = await fixture.issueAndInterrupt({ phase, dnsName, candidateSha256 });
      const atFault = await capture.read();
      const caAtFault = await fixture.observeCa({ phase, dnsName });
      const recovered = await fixture.restartAndRecover({ phase, dnsName, fault });
      const after = await capture.read();
      const caAfter = await fixture.observeCa({ phase, dnsName });
      const inventory = await fixture.readInventory({ phase, dnsName, fault, recovered });
      const evidence = { phase, dnsName, candidateSha256, before, atFault, after, caAtFault, caAfter, fault, recovered, inventory };
      verifyCrashRecovery(evidence);
      results.push(evidence);
    } finally { await capture.stop(); }
  }
  return results;
}

module.exports = { PHASES, createRunDnsName, readCandidateArchive, validateCounter, verifyCrashRecovery, qualifyCrashRecovery };
