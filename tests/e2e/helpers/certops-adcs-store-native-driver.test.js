"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { PassThrough } = require("node:stream");
const { startNativeStoreObserver, verifyNativeFault } = require("./certops-adcs-store-native-observer");
const { qualifyNativeStoreRecovery, validateNativeCounts, validateInitialNativeCounts, validateCaptureStart, stopNativeCapture, validateCaObservationStart, validateCaObservationWindow, stopCaObservation, drainQualificationResources, verifyRecoveryCheckpoint, validateCaBaselineWindow, verifyPreIssueCheckpoint, createPublicEvidenceRecorder, verifyCandidateHost, requireActiveObservationInterruption } = require("./certops-adcs-store-native-driver");

function makeEvidenceHooks() {
  const values = new Map();
  let next = 0;
  return {
    candidateArchiveSha256: "f".repeat(64),
    async writeEvidence({ json }) { const receiptId = (++next).toString(16).padStart(32, "0"); values.set(receiptId, json); return { receiptId, flushCompleted: true }; },
    async readEvidence({ receiptId }) { return values.get(receiptId); },
    async inspectEvidenceDurability() { return { independentReader: true, flushVerified: true, persistentStore: true, continuityProven: true, storeId: "e".repeat(64) }; },
  };
}
test("native observer starts only the scoped lab script and refuses unproven drainage", async () => {
  const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => {};
  const observer = startNativeStoreObserver({ workDir: "owned", configDir: "config", root: "root", nodeExecutable: "node.exe",
    spawnImpl(program, args, options) {
      assert.equal(program, "powershell.exe");
      assert.match(args[3], /store-accept-phase-fault\.ps1$/);
      assert.equal(args[args.indexOf("-OwnedDirectory") + 1], "owned");
      assert.equal(options.windowsHide, true);
      return child;
    } });
  child.stdout.write("CERTOPS_STORE_ACCEPT_READY\n"); await observer.ready;
  child.emit("close", 1);
  await assert.rejects(observer.result, /not proven/);
  await observer.stopAndDrain();
  assert.equal(observer.hasLiveChild(), true);
});

test("native proof fails before journal inspection when key possession or drainage is missing", () => {
  assert.throws(() => verifyNativeFault({ nativeIdentity: "LocalSystem", observedPostAccept: true,
    nativeProcessDrained: false, keyPossessionVerified: true }, { configDir: "unused" }));
  assert.throws(() => verifyNativeFault({ nativeIdentity: "LocalSystem", observedPostAccept: true,
    nativeProcessDrained: true, keyPossessionVerified: false }, { configDir: "unused" }));
});

test("native driver refuses to run without an independent operation counter", async () => {
  if (process.platform !== "win32") return;
  const previous = process.env.CERTOPS_ADCS_DISPOSABLE_LAB;
  try {
    process.env.CERTOPS_ADCS_DISPOSABLE_LAB = "1";
    await assert.rejects(qualifyNativeStoreRecovery({ serviceOwned: true, ps() {}, until() {}, jobFinished() {} }), /Independent native and CA observation hooks/);
  } finally {
    if (previous === undefined) delete process.env.CERTOPS_ADCS_DISPOSABLE_LAB;
    else process.env.CERTOPS_ADCS_DISPOSABLE_LAB = previous;
  }
});

test("native operation counts require continuous complete capture", () => {
  const before = { captureId: "a".repeat(32), coverageComplete: true, submissions: 1, keygens: 1, accepts: 1 };
  assert.equal(validateNativeCounts({ ...before }, before).captureId, before.captureId);
  for (const change of [{ coverageComplete: false }, { captureId: "b".repeat(32) }, { keygens: 0 }, { accepts: null }]) {
    assert.throws(() => validateNativeCounts({ ...before, ...change }, before));
  }
});

test("native capture must count the one initial key, request and acceptance", () => {
  const counts = { captureId: "a".repeat(32), coverageComplete: true, submissions: 1, keygens: 1, accepts: 1 };
  assert.equal(validateInitialNativeCounts(counts, counts.captureId), counts);
  for (const changed of [{ keygens: 2 }, { accepts: 2 }, { submissions: 2 }, { captureId: "b".repeat(32) }]) {
    assert.throws(() => validateInitialNativeCounts({ ...counts, ...changed }, counts.captureId));
  }
});


test("capture baseline is complete, empty, bound and has verified drainage", async () => {
  const id = "a".repeat(32);
  const baseline = { captureId: id, coverageComplete: true, submissions: 0, keygens: 0, accepts: 0 };
  const valid = { started: true, captureId: id, baseline, async read() { return baseline; }, async stop() { return { captureId: id, drained: true }; } };
  assert.equal(validateCaptureStart(valid), baseline);
  await stopNativeCapture(valid);
  for (const invalid of [
    { ...valid, started: false }, { ...valid, baseline: { ...baseline, coverageComplete: false } },
    { ...valid, baseline: { ...baseline, captureId: "b".repeat(32) } },
    { ...valid, baseline: { ...baseline, submissions: 1 } }, { ...valid, stop: undefined }, { ...valid, read: undefined },
  ]) assert.throws(() => validateCaptureStart(invalid));
  await assert.rejects(stopNativeCapture({ ...valid, async stop() { return { captureId: id, drained: false }; } }));
  await assert.rejects(stopNativeCapture({ ...valid, async stop() { return { captureId: "b".repeat(32), drained: true }; } }));
});


test("CA baseline and full window reject gaps, purge, restore, duplicate requests and changed identities", async () => {
  const id = "a".repeat(32), key = "b".repeat(64), fingerprint = "c".repeat(64);
  const start = { started: true, observationId: id, coverageComplete: true, startedBeforeBaseline: true, lossFree: true,
    noPurgeProven: true, noRestoreProven: true, caPublicKeySha256: key, baselineRequestId: 2,
    async readBaseline() {}, async stop() { return { drained: true, observationId: id, finalWindow: window }; } };
  const window = { coverageComplete: true, observationId: id, caPublicKeySha256: key, baselineRequestId: 2,
    lossFree: true, noPurgeProven: true, noRestoreProven: true, globalCount: 1, matchingIssuedCount: 1,
    unknownIssuedCount: 0, subjectRequestCount: 1, fingerprintSha256: fingerprint, requestId: "3" };
  assert.equal(validateCaObservationStart(start, key), start);
  assert.equal(validateCaObservationWindow(window, start, fingerprint), window);
  await stopCaObservation(start, window);
  for (const change of [{ coverageComplete: false }, { startedBeforeBaseline: false }, { lossFree: false },
    { noPurgeProven: false }, { noRestoreProven: false }, { caPublicKeySha256: "d".repeat(64) }, { baselineRequestId: -1 }]) {
    assert.throws(() => validateCaObservationStart({ ...start, ...change }, key));
  }
  for (const change of [{ coverageComplete: false }, { observationId: "d".repeat(32) }, { baselineRequestId: 1 },
    { lossFree: false }, { noPurgeProven: false }, { noRestoreProven: false }, { globalCount: 2 },
    { matchingIssuedCount: 0 }, { unknownIssuedCount: 1 }, { fingerprintSha256: "d".repeat(64) }, { requestId: "2" }]) {
    assert.throws(() => validateCaObservationWindow({ ...window, ...change }, start, fingerprint));
  }
  await assert.rejects(stopCaObservation({ ...start, async stop() { return { drained: true, observationId: id, finalWindow: { ...window, globalCount: 2 } }; } }, window));
});

test("drainage preserves the original error and attempts every cleanup", async () => {
  const original = new Error("qualification failed"), calls = [];
  await assert.rejects(drainQualificationResources({ primaryError: original,
    observer: { async stopAndDrain() { calls.push("observer"); }, hasLiveChild() { return false; } },
    caObservation: { observationId: "a".repeat(32), async stop() { calls.push("ca"); throw new Error("ca failed"); } },
    capture: { captureId: "b".repeat(32), async stop() { calls.push("native"); return { captureId: "b".repeat(32), drained: true }; } },
  }), error => error instanceof AggregateError && error.errors[0] === original && error.errors.length === 2);
  assert.deepEqual(calls, ["observer", "native", "ca"]);
});

test("recovery checkpoint rejects capture loss, extra operations and changed CA state", async () => {
  const captureId = "a".repeat(32), observationId = "b".repeat(32), key = "c".repeat(64), fingerprint = "d".repeat(64);
  const counts = { captureId, coverageComplete: true, submissions: 1, keygens: 1, accepts: 1 };
  const observation = { observationId, caPublicKeySha256: key, baselineRequestId: 1 };
  const window = { coverageComplete: true, observationId, caPublicKeySha256: key, baselineRequestId: 1,
    lossFree: true, noPurgeProven: true, noRestoreProven: true, globalCount: 1, matchingIssuedCount: 1,
    unknownIssuedCount: 0, subjectRequestCount: 1, fingerprintSha256: fingerprint, requestId: "2" };
  const dnsName = "certops-adcs-0123456789abcdef-store.example.test";
  const args = { dnsName, beforeCounts: counts, observation, lastWindow: window, fingerprintSha256: fingerprint,
    async readNativeOperationCounts() { return counts; }, async readIndependentCaObservation(input) { assert.equal(input.dnsName, dnsName); return window; } };
  await verifyRecoveryCheckpoint(args);
  await assert.rejects(verifyRecoveryCheckpoint({ ...args, dnsName: undefined }));
  await assert.rejects(verifyRecoveryCheckpoint({ ...args, async readNativeOperationCounts() { return { ...counts, coverageComplete: false }; } }));
  await assert.rejects(verifyRecoveryCheckpoint({ ...args, async readNativeOperationCounts() { return { ...counts, keygens: 2 }; } }));
  await assert.rejects(verifyRecoveryCheckpoint({ ...args, async readIndependentCaObservation() { return { ...window, noRestoreProven: false }; } }));
  await assert.rejects(verifyRecoveryCheckpoint({ ...args, async readIndependentCaObservation() { return { ...window, requestId: "3" }; } }));
});


test("baseline checkpoint rejects changed identity, loss and requests before issuance", async () => {
  const id = "a".repeat(32), key = "b".repeat(64);
  const observation = { observationId: id, caPublicKeySha256: key, baselineRequestId: 2 };
  const window = { coverageComplete: true, observationId: id, caPublicKeySha256: key, baselineRequestId: 2,
    lossFree: true, noPurgeProven: true, noRestoreProven: true, globalCount: 0, maxRequestId: 2 };
  validateCaBaselineWindow(window, observation);
  for (const change of [{ coverageComplete: false }, { observationId: "c".repeat(32) }, { lossFree: false },
    { noPurgeProven: false }, { noRestoreProven: false }, { globalCount: 1 }, { maxRequestId: 3 }]) {
    assert.throws(() => validateCaBaselineWindow({ ...window, ...change }, observation));
  }
  const captureId = "d".repeat(32);
  const baseline = { captureId, coverageComplete: true, submissions: 0, keygens: 0, accepts: 0 };
  await verifyPreIssueCheckpoint({ baseline, async read() { return baseline; } },
    { ...observation, async readBaseline() { return window; } });
});

test("public evidence requires independent readback and stable verified durability", async () => {
  const hooks = makeEvidenceHooks();
  const record = createPublicEvidenceRecorder(hooks);
  const first = await record("baseline", { candidateSha256: hooks.candidateArchiveSha256, submissions: 0 });
  assert.match(first.sha256, /^[a-f0-9]{64}$/);
  await record("failure", { candidateSha256: hooks.candidateArchiveSha256, stage: "issuing", code: "QUALIFICATION_FAILED" });
  const invalidCases = [
    { ...hooks, writeEvidence: hooks.readEvidence },
    { ...hooks, async writeEvidence() { return { receiptId: "a".repeat(32), flushCompleted: false }; } },
    { ...hooks, async readEvidence() { return "different"; } },
    { ...hooks, async inspectEvidenceDurability() { return { independentReader: true, flushVerified: false, persistentStore: true, continuityProven: true, storeId: "e".repeat(64) }; } },
  ];
  assert.throws(() => createPublicEvidenceRecorder(invalidCases[0]));
  for (const invalid of invalidCases.slice(1)) {
    const failing = createPublicEvidenceRecorder(invalid);
    await assert.rejects(failing("baseline", { submissions: 0 }));
    await assert.rejects(failing("failure", { stage: "issuing", code: "QUALIFICATION_FAILED" }), /permanently invalidated/);
  }
  const badField = createPublicEvidenceRecorder(makeEvidenceHooks());
  await assert.rejects(badField("baseline", { privateKey: "must-not-write" }), /not public/);
});


function makeCandidateHooks() {
  const candidateArchiveSha256 = require("node:crypto").createHash("sha256").update(require("node:fs").readFileSync(__filename)).digest("hex");
  const expectedRuntimeSha256 = "e".repeat(64);
  return { archivePath: __filename, candidateArchiveSha256, expectedRuntimeSha256,
    async inspectCandidateHost() { return { inspectionIndependent: true, archiveBytesVerified: true,
      installedFilesMatchArchive: true, protectedInstallation: true, serviceOwned: true, serviceIdentity: "LocalSystem",
      processTokenSid: "S-1-5-18", noIis: true, storeOnlyAdcsCapability: true,
      agentArchiveSha256: candidateArchiveSha256, runtimeSha256: expectedRuntimeSha256 }; } };
}

test("candidate inspection rejects absent or mismatched archive and installed service", async () => {
  const candidate = makeCandidateHooks();
  await verifyCandidateHost(candidate);
  await assert.rejects(verifyCandidateHost({ ...candidate, archivePath: undefined }));
  await assert.rejects(verifyCandidateHost({ ...candidate, candidateArchiveSha256: "0".repeat(64) }), /digest mismatch/);
  const host = await candidate.inspectCandidateHost();
  await assert.rejects(verifyCandidateHost({ ...candidate, async inspectCandidateHost() { return { ...host, installedFilesMatchArchive: false }; } }));
  await assert.rejects(verifyCandidateHost({ ...candidate, async inspectCandidateHost() { return { ...host, processTokenSid: "S-1-5-19" }; } }));
});

test("qualification blocks factories and issue jobs without active loss interruption", async () => {
  assert.throws(requireActiveObservationInterruption, /active observation-loss interruption is not implemented/);
  if (process.platform !== "win32") return;
  const previous = process.env.CERTOPS_ADCS_DISPOSABLE_LAB;
  let operations = 0, posts = 0, writes = 0;
  try {
    process.env.CERTOPS_ADCS_DISPOSABLE_LAB = "1";
    await assert.rejects(qualifyNativeStoreRecovery({
      ...makeEvidenceHooks(), ...makeCandidateHooks(), serviceOwned: true,
      async writeEvidence() { writes++; }, workDir: require("node:os").tmpdir(),
      configDir: "unused", api: "/unused", fixture: { pool: { query() { operations++; } }, request() { posts++; } },
      ps() {}, until() {}, jobFinished() {}, async prepareRun() { operations++; },
      async createNativeOperationCapture() { operations++; }, async createIndependentCaObservation() { operations++; },
      async readNativeOperationCounts() {}, async readIndependentCaObservation() {},
    }), /active observation-loss interruption is not implemented/);
    assert.equal(operations, 0); assert.equal(posts, 0); assert.equal(writes, 0);
  } finally {
    if (previous === undefined) delete process.env.CERTOPS_ADCS_DISPOSABLE_LAB;
    else process.env.CERTOPS_ADCS_DISPOSABLE_LAB = previous;
  }
});
test("CA drainage detects a submission during native capture drainage", async () => {
  const captureId = "a".repeat(32), observationId = "b".repeat(32), key = "c".repeat(64), fingerprint = "d".repeat(64);
  const counts = { captureId, coverageComplete: true, submissions: 1, keygens: 1, accepts: 1 };
  const window = { coverageComplete: true, observationId, caPublicKeySha256: key, baselineRequestId: 1,
    lossFree: true, noPurgeProven: true, noRestoreProven: true, globalCount: 1, matchingIssuedCount: 1,
    unknownIssuedCount: 0, subjectRequestCount: 1, fingerprintSha256: fingerprint, requestId: "2" };
  const calls = []; let lateSubmission = false;
  await assert.rejects(drainQualificationResources({ lastCounts: counts, lastWindow: window,
    capture: { captureId, async stop() { calls.push("native"); lateSubmission = true; return { drained: true, captureId, finalCounts: counts }; } },
    caObservation: { observationId, caPublicKeySha256: key, baselineRequestId: 1,
      async stop() { calls.push("ca"); return { drained: true, observationId, finalWindow: { ...window, globalCount: lateSubmission ? 2 : 1 } }; } },
  }), AggregateError);
  assert.deepEqual(calls, ["native", "ca"]);
});

test("failed observer drainage preserves both live observations for intervention", async () => {
  for (const mode of ["throws", "child"]) {
    const calls = [], original = new Error("qualification failed");
    await assert.rejects(drainQualificationResources({ primaryError: original,
      observer: { async stopAndDrain() { calls.push("observer"); if (mode === "throws") throw new Error("stop failed"); },
        hasLiveChild() { return mode === "child"; } },
      capture: { async stop() { calls.push("native"); } },
      caObservation: { async stop() { calls.push("ca"); } },
    }), error => error instanceof AggregateError && error.errors[0] === original && /operator intervention/.test(error.message));
    assert.deepEqual(calls, ["observer"]);
  }
});

test("failed native capture drainage preserves the CA observer", async () => {
  for (const mode of ["throws", "unproven"]) {
    const calls = [], original = new Error("qualification failed");
    await assert.rejects(drainQualificationResources({ primaryError: original,
      capture: { captureId: "a".repeat(32), async stop() { calls.push("native"); if (mode === "throws") throw new Error("stop failed"); return { drained: false, captureId: "a".repeat(32) }; } },
      caObservation: { async stop() { calls.push("ca"); } },
    }), error => error instanceof AggregateError && error.errors[0] === original && /preserve live CA observation/.test(error.message));
    assert.deepEqual(calls, ["native"]);
  }
});
