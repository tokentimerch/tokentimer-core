"use strict";

// Qualification coordinator, not a native fixture. Its independent CA and
// process observers must be supplied by a disposable Windows lab. Never infer
// zero new orders or keys from the agent journal or job status alone.
// A Pebble fixture can use createPebbleCaObserver({ proxy, inspectIsolation })
// as the CA observation's read hook. The fixture creates that observation
// without side effects; its start hook owns resource creation. Both the CA
// observation and native capture expose stop hooks with drainage receipts.
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

function validateCaptureBaseline(counter) {
  assert.equal(counter?.coverageComplete, true, "Independent capture must cover the whole run");
  assert.match(counter.captureId, CAPTURE);
  for (const key of ["orders", "keygens", "accepts"]) {
    assert.ok(Number.isSafeInteger(counter[key]) && counter[key] >= 0, "Invalid " + key + " count");
  }
}

function validateCaBaseline(ca, dnsName) {
  assert.ok(["independent-ca", "isolated-ca-proxy"].includes(ca?.source));
  assert.equal(ca.coverageComplete, true, "CA observation must cover the whole run");
  assert.match(ca.coverageId, CAPTURE);
  assert.equal(ca.dnsName, dnsName);
  assert.equal(ca.ordersForDns, 0, "The run DNS must not have an earlier CA order");
  assert.equal(ca.finalizedOrdersForDns, 0);
}

function validateCaCheckpoint(ca, baseline, dnsName) {
  assert.equal(ca?.source, baseline.source);
  assert.equal(ca.coverageComplete, true, "CA observation must have complete independently verified coverage");
  assert.match(ca.coverageId, CAPTURE);
  assert.equal(ca.coverageId, baseline.coverageId);
  assert.equal(ca.dnsName, dnsName);
  assert.equal(ca.ordersForDns, 1, "Count all CA orders for this unique DNS name");
  assert.equal(ca.finalizedOrdersForDns, 1);
  assert.ok(typeof ca.orderId === "string" && ca.orderId.length > 0);
  assert.match(ca.fingerprintSha256, HASH, "The CA must independently identify the issued leaf");
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

function validateFault(phase, fault, candidateSha256, caAtFault) {
  assert.equal(fault?.phase, phase);
  assert.equal(fault.candidateSha256, candidateSha256);
  assert.equal(fault.nativeIdentity, "LocalSystem");
  assert.equal(fault.noIis, true);
  assert.equal(fault.nativeProcessDrained, true, "Native process drainage must be confirmed before recovery");
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
}

function verifyCrashRecovery({ phase, dnsName, candidateSha256, before, atFault, after, caBefore, caAtFault, caAfter, fault, recovered, inventory }) {
  assert.ok(PHASES.includes(phase));
  assert.match(dnsName, /^tt-acme-[a-f0-9]{24}\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/);
  assert.match(candidateSha256, HASH);
  validateCounter(before, atFault, after);
  validateCaBaseline(caBefore, dnsName);
  for (const ca of [caAtFault, caAfter]) validateCaCheckpoint(ca, caBefore, dnsName);
  assert.equal(caAtFault.orderId, caAfter.orderId);
  assert.equal(caAtFault.fingerprintSha256, caAfter.fingerprintSha256);
  assert.equal(caAtFault.source, caAfter.source);
  assert.equal(caAtFault.coverageId, caAfter.coverageId);
  assert.equal(caBefore.source, caAtFault.source);
  assert.equal(caBefore.coverageId, caAtFault.coverageId);
  validateFault(phase, fault, candidateSha256, caAtFault);
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

// Records contain only explicitly selected public identity and status facts.
function publicFacts(value) {
  const out = {};
  if (!value || typeof value !== "object") return out;
  for (const key of ["candidateSha256", "csrSpkiSha256", "keySpkiSha256", "fingerprintSha256", "leafSpkiSha256"]) {
    if (typeof value[key] === "string" && HASH.test(value[key])) out[key] = value[key];
  }
  for (const key of ["coverageComplete", "noIis", "nativeProcessDrained", "caFinalizationObserved", "machineKey", "nonExportable", "keyPossessionVerified", "leafDurable", "evidenceUploadDropped", "outcomeVisible", "serviceVerified"]) {
    if (typeof value[key] === "boolean") out[key] = value[key];
  }
  for (const key of ["orders", "keygens", "accepts", "ordersForDns", "finalizedOrdersForDns", "provisioningRegistrations", "promotions"]) {
    if (Number.isSafeInteger(value[key]) && value[key] >= 0) out[key] = value[key];
  }
  for (const key of ["captureId", "coverageId"]) {
    if (typeof value[key] === "string" && CAPTURE.test(value[key])) out[key] = value[key];
  }
  if (PHASES.includes(value.phase)) out.phase = value.phase;
  if (typeof value.dnsName === "string" && /^tt-acme-[a-f0-9]{24}\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value.dnsName)) out.dnsName = value.dnsName;
  if (typeof value.containerName === "string" && CONTAINER.test(value.containerName)) out.containerName = value.containerName;
  if (typeof value.orderId === "string" && /^[a-zA-Z0-9_-]{1,128}$/.test(value.orderId)) out.orderId = value.orderId;
  if (["independent-ca", "isolated-ca-proxy"].includes(value.source)) out.source = value.source;
  if (["installed", "uncertain"].includes(value.outcome)) out.outcome = value.outcome;
  if (value.nativeIdentity === "LocalSystem") out.nativeIdentity = value.nativeIdentity;
  if (value.store === "LocalMachine\\My") out.store = value.store;
  return out;
}

// Observer signals must abort as soon as coverage is lost. The native fixture
// must terminate and drain its external work when that happens.
async function runObservedAction(fixture, signal, action, options) {
  assert.equal(signal.aborted, false, "Observation coverage was lost before the action");
  let onAbort;
  const aborted = new Promise(resolve => {
    onAbort = () => resolve({ aborted: true });
    signal.addEventListener("abort", onAbort, { once: true });
  });
  const settled = Promise.resolve().then(() => action({ ...options, signal })).then(
    value => ({ value }),
    reason => ({ error: reason instanceof Error ? reason : new Error("Observed action rejected", { cause: reason }) }),
  );
  try {
    const result = await Promise.race([settled, aborted]);
    if (result.aborted || signal.aborted || result.error) {
      const coverageLost = result.aborted || signal.aborted;
      const errors = coverageLost ? [new Error("Observation coverage was lost during the action")] : [result.error];
      let drainTimer, drainageProven = false;
      try {
        const drainTimeout = new Promise((_, reject) => {
          drainTimer = setTimeout(() => reject(new Error("Interrupted action drainage timed out")), 5000);
        });
        const drain = await Promise.race([Promise.resolve().then(() => fixture.abortAndDrainAction(options)), drainTimeout]);
        assert.equal(drain?.drained, true, "Interrupted action drainage must be confirmed");
        drainageProven = true;
      } catch (error) { errors.push(error); }
      finally { clearTimeout(drainTimer); }
      let settleTimer;
      const timeout = new Promise(resolve => { settleTimer = setTimeout(() => resolve({ timeout: true }), 5000); });
      const stopped = await Promise.race([settled, timeout]);
      clearTimeout(settleTimer);
      if (stopped.timeout) errors.push(new Error("Interrupted action did not settle after drainage"));
      else if (stopped.error && stopped.error !== result.error) errors.push(stopped.error);
      const failure = new AggregateError(errors, coverageLost ? "Observation coverage lost during action" : "Observed action failed");
      // A timeout or unproven termination is not evidence that work stopped.
      // The caller must retain the observers and require operator intervention.
      failure.preserveObservers = !drainageProven || Boolean(stopped.timeout);
      throw failure;
    }
    return result.value;
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

async function exerciseSyntheticCoordinator({ fixture, archivePath, archiveSha256, zone }) {
  assert.equal(process.platform, "win32", "A real Windows member is required");
  assert.equal(process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST, "1", "A disposable lab host is required");
  for (const key of ["inspectHost", "prepareRun", "createCapture", "issueAndInterrupt", "createCaObservation",
    "restartAndRecover", "readInventory", "persistEvidence", "readEvidence", "abortAndDrainAction"]) {
    assert.equal(typeof fixture?.[key], "function", "Missing native lab hook: " + key);
  }
  const candidateSha256 = readCandidateArchive(archivePath, archiveSha256);
  const host = await fixture.inspectHost({ candidateSha256 });
  assert.equal(host?.nativeIdentity, "LocalSystem");
  assert.equal(host.noIis, true);
  assert.equal(host.agentArchiveSha256, candidateSha256);
  assert.equal(host.storeOnlyAcmeCapability, true, "The candidate must declare the qualification capability");
  const results = [], receiptIds = new Set();
  for (const phase of PHASES) {
    const dnsName = createRunDnsName(zone);
    let capture, captureCreated = false, captureId, caObservation, caCreated = false, caId, bodyError;
    let lastCounter, lastCa, caBefore, pendingResult, finalCounter, finalCa, preserveObservers = false;
    let point = "starting";
    // Actual flush and independent readback must be verified in the native
    // fixture; these interface assertions alone are not qualification proof.
    const persist = async (stage, facts = {}) => {
      const recordJson = JSON.stringify({ schema: 1, phase, dnsName, candidateSha256, stage, ...facts });
      const sha256 = createHash("sha256").update(recordJson, "utf8").digest("hex");
      const saved = await fixture.persistEvidence({ recordJson, sha256 });
      assert.equal(saved?.flushed, true, "Evidence flush must be confirmed");
      assert.match(saved.receiptId, CAPTURE);
      assert.equal(receiptIds.has(saved.receiptId), false, "Evidence receipt was reused");
      receiptIds.add(saved.receiptId);
      const readback = await fixture.readEvidence({ receiptId: saved.receiptId });
      assert.equal(typeof readback, "string", "Evidence must be independently read back");
      assert.equal(readback, recordJson, "Evidence readback differs");
      assert.equal(createHash("sha256").update(readback, "utf8").digest("hex"), sha256);
    };
    try {
      await persist("starting");
      point = "capture-start";
      // Factories must be side-effect-free; resource creation belongs in start.
      capture = await fixture.createCapture({ phase, dnsName, candidateSha256 });
      captureCreated = true;
      assert.equal(typeof capture?.start, "function", "Native capture start is required");
      assert.equal(typeof capture?.read, "function", "Native operation capture is required");
      assert.equal(typeof capture?.stop, "function", "Native capture cleanup is required");
      point = "ca-start";
      caObservation = await fixture.createCaObservation({ phase, dnsName, candidateSha256 });
      caCreated = true;
      assert.equal(typeof caObservation?.start, "function", "CA observation start is required");
      assert.equal(typeof caObservation?.read, "function", "CA observation read is required");
      assert.equal(typeof caObservation?.stop, "function", "CA observation cleanup is required");
      await caObservation.start();
      caBefore = await caObservation.read({ phase, dnsName, boundary: "before-capture" });
      caId = typeof caBefore?.coverageId === "string" && CAPTURE.test(caBefore.coverageId) ? caBefore.coverageId : null;
      validateCaBaseline(caBefore, dnsName);
      lastCa = caBefore;
      point = "capture-start";
      await capture.start();
      assert.ok(capture.signal instanceof AbortSignal && caObservation.signal instanceof AbortSignal, "Independent observation loss signals are required");
      const observationSignal = AbortSignal.any([capture.signal, caObservation.signal]);
      assert.equal(observationSignal.aborted, false, "Observation coverage lost during startup");
      const before = await capture.read();
      captureId = typeof before?.captureId === "string" && CAPTURE.test(before.captureId) ? before.captureId : null;
      validateCaptureBaseline(before);
      for (const key of ["orders", "keygens", "accepts"]) assert.equal(before[key], 0, "Native capture baseline must be empty");
      lastCounter = before;
      const caReady = await caObservation.read({ phase, dnsName, boundary: "after-capture-start" });
      validateCaBaseline(caReady, dnsName);
      assert.equal(caReady.source, caBefore.source);
      assert.equal(caReady.coverageId, caBefore.coverageId, "CA observation changed during capture startup");
      lastCa = caReady;
      await persist("baseline", { capture: publicFacts(before), ca: publicFacts(caReady) });
      point = "prepare";
      await runObservedAction(fixture, observationSignal, fixture.prepareRun, { phase, dnsName, candidateSha256 });
      const prepared = await capture.read();
      validateCaptureBaseline(prepared);
      assert.equal(prepared.captureId, before.captureId, "Native capture changed during preparation");
      lastCounter = prepared;
      for (const key of ["orders", "keygens", "accepts"]) {
        assert.equal(prepared[key], before[key], "Native operations occurred during preparation");
      }
      const caPrepared = await caObservation.read({ phase, dnsName, boundary: "after-prepare" });
      validateCaBaseline(caPrepared, dnsName);
      assert.equal(caPrepared.source, caBefore.source, "CA source changed during preparation");
      assert.equal(caPrepared.coverageId, caBefore.coverageId, "CA observation changed during preparation");
      lastCa = caPrepared;
      await persist("prepared", { capture: publicFacts(prepared), ca: publicFacts(caPrepared) });
      point = "issue";
      const fault = await runObservedAction(fixture, observationSignal, fixture.issueAndInterrupt, { phase, dnsName, candidateSha256 });
      await persist("fault-observed", { fault: publicFacts(fault) });
      point = "fault-check";
      const atFault = await capture.read();
      validateCounter(before, atFault, atFault);
      lastCounter = atFault;
      const caAtFault = await caObservation.read({ phase, dnsName });
      validateCaCheckpoint(caAtFault, caBefore, dnsName);
      lastCa = caAtFault;
      validateFault(phase, fault, candidateSha256, caAtFault);
      await persist("fault-verified", { capture: publicFacts(atFault), ca: publicFacts(caAtFault), fault: publicFacts(fault) });
      point = "recovery-check";
      const beforeRecovery = await capture.read();
      validateCounter(before, atFault, beforeRecovery);
      assert.equal(beforeRecovery.accepts, atFault.accepts, "Unexpected acceptance before recovery");
      lastCounter = beforeRecovery;
      const caBeforeRecovery = await caObservation.read({ phase, dnsName, boundary: "before-recovery" });
      validateCaCheckpoint(caBeforeRecovery, caBefore, dnsName);
      assert.equal(caBeforeRecovery.orderId, caAtFault.orderId, "CA order changed before recovery");
      assert.equal(caBeforeRecovery.fingerprintSha256, caAtFault.fingerprintSha256, "CA leaf changed before recovery");
      lastCa = caBeforeRecovery;
      point = "recover";
      const recovered = await runObservedAction(fixture, observationSignal, fixture.restartAndRecover, { phase, dnsName, fault });
      await persist("recovery-observed", { recovered: publicFacts(recovered) });
      point = "verify";
      const after = await capture.read();
      const caAfter = await caObservation.read({ phase, dnsName });
      const inventory = await fixture.readInventory({ phase, dnsName, fault, recovered });
      const evidence = { phase, dnsName, candidateSha256, before, atFault, after, caBefore, caAtFault, caAfter, fault, recovered, inventory };
      verifyCrashRecovery(evidence);
      lastCounter = after;
      lastCa = caAfter;
      await persist("pre-drain-validated", { capture: publicFacts(after), ca: publicFacts(caAfter),
        recovered: publicFacts(recovered), inventory: publicFacts(inventory) });
      pendingResult = { phase, dnsName, candidateSha256, before: publicFacts(before), atFault: publicFacts(atFault),
        after: publicFacts(after), caBefore: publicFacts(caBefore), caAtFault: publicFacts(caAtFault),
        caAfter: publicFacts(caAfter), fault: publicFacts(fault), recovered: publicFacts(recovered),
        inventory: publicFacts(inventory) };
      assert.equal(observationSignal.aborted, false, "Observation coverage lost before drainage");
      point = "cleanup";
    } catch (error) {
      preserveObservers = error?.preserveObservers === true;
      bodyError = error;
      try { await persist("failed", { point, code: "QUALIFICATION_FAILED" }); }
      catch (persistError) { bodyError = new AggregateError([error, persistError], "Qualification and failure evidence persistence failed"); }
      throw bodyError;
    } finally {
      const errors = [];
      if (preserveObservers) {
        try { await persist("observers-preserved", { code: "OPERATOR_INTERVENTION_REQUIRED" }); }
        catch (error) { throw new AggregateError([bodyError, error], "Observers retained; intervention evidence persistence failed"); }
      } else {
      // Keep the CA observer active until the native capture has drained.
      if (captureCreated) {
        try {
          assert.equal(typeof capture?.stop, "function", "Native capture cleanup is required");
          const receipt = await capture.stop();
          assert.equal(receipt?.drained, true, "Native capture drainage must be confirmed");
          assert.match(receipt.captureId, CAPTURE);
          if (captureId) assert.equal(receipt.captureId, captureId, "Native capture changed during cleanup");
          finalCounter = receipt.finalCounter;
          if (!bodyError) {
            validateCaptureBaseline(finalCounter);
            assert.equal(finalCounter.captureId, lastCounter.captureId);
            for (const key of ["orders", "keygens", "accepts"]) {
              assert.equal(finalCounter[key], lastCounter[key], "Native operations occurred during drainage");
            }
          }
        } catch (error) { errors.push(error); }
      }
      if (caCreated) {
        try {
          assert.equal(typeof caObservation?.stop, "function", "CA observation cleanup is required");
          const receipt = await caObservation.stop();
          assert.equal(receipt?.drained, true, "CA observation drainage must be confirmed");
          assert.match(receipt.coverageId, CAPTURE);
          if (caId) assert.equal(receipt.coverageId, caId, "CA observation changed during cleanup");
          finalCa = receipt.finalObservation;
          if (!bodyError) {
            validateCaCheckpoint(finalCa, caBefore, dnsName);
            assert.equal(finalCa.orderId, lastCa.orderId, "CA order changed during drainage");
            assert.equal(finalCa.fingerprintSha256, lastCa.fingerprintSha256, "CA leaf changed during drainage");
          }
        } catch (error) { errors.push(error); }
      }
      try {
        if (errors.length || bodyError) {
          await persist("cleanup-failed", { code: errors.length ? "OBSERVER_CLEANUP_FAILED" : "QUALIFICATION_FAILED",
            capture: publicFacts(finalCounter), ca: publicFacts(finalCa) });
        } else {
          await persist("completed", { code: "OBSERVERS_DRAINED", capture: publicFacts(finalCounter), ca: publicFacts(finalCa) });
        }
      } catch (error) { errors.push(error); }
      if (errors.length) {
        if (bodyError) errors.unshift(bodyError);
        if (errors.length === 1) throw errors[0];
        throw new AggregateError(errors, "Qualification and observer cleanup failed");
      }
      }
    }
    results.push(pendingResult);
  }
  return results;
}

// Deliberately closed until the real fixture proves continuous independent
// capture, interruption and drainage, and persistent evidence with independent
// readback. It must also independently compare installed files and runtime
// against the candidate archive and verify the service process token SID is
// S-1-5-18; the synthetic inspectHost assertions do not establish these facts.
// Before stopping either observer after recovery, the real fixture must also
// independently prove the agent service is quiescent: no active work remains
// and the service cannot dispatch another operation during final drainage.
// Settlement or drainage of a JavaScript hook does not establish quiescence.
async function qualifyCrashRecovery() {
  throw new Error("Native ACME qualification is unavailable: real observation and action drainage are not qualified");
}

module.exports = { PHASES, createRunDnsName, readCandidateArchive, validateCounter, verifyCrashRecovery, qualifyCrashRecovery };
