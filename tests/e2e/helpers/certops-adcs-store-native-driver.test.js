"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { PassThrough } = require("node:stream");
const { CANDIDATE_SHA256, nativeCounts } = require("./certops-adcs-store-native-cng.fixture");
const { startNativeStoreObserver, verifyNativeFault } = require("./certops-adcs-store-native-observer");
const { qualifyInstalledStoreRecovery, qualifyNativeStoreRecovery, validateNativeCounts, validateInitialNativeCounts, validateCaptureStart, stopNativeCapture, validateCaObservationStart, validateCaObservationWindow, stopCaObservation, drainQualificationResources, verifyRecoveryCheckpoint, validateCaBaselineWindow, verifyPreIssueCheckpoint, createPublicEvidenceRecorder, verifyCandidateHost, requireActiveObservationInterruption } = require("./certops-adcs-store-native-driver");
const { validateObservedServiceStart, validateSeparateStoreRecoveryEvidence } = require("./certops-adcs-store-native-driver");

function makeEvidenceHooks() {
  const values = new Map();
  let next = 0;
  return {
    candidateArchiveSha256: CANDIDATE_SHA256,
    async writeEvidence({ json }) { const receiptId = (++next).toString(16).padStart(32, "0"); values.set(receiptId, json); return { receiptId, flushCompleted: true }; },
    async readEvidence({ receiptId }) { return values.get(receiptId); },
    async inspectEvidenceDurability() { return { independentReader: true, flushVerified: true, persistentStore: true, continuityProven: true, storeId: "e".repeat(64) }; },
  };
}

test("the evidence recorder rejects a different candidate before writing that phase", async () => {
  const hooks = makeEvidenceHooks();
  let writes = 0;
  const record = createPublicEvidenceRecorder({
    ...hooks,
    async writeEvidence(entry) {
      writes++;
      return hooks.writeEvidence(entry);
    },
  });
  const candidateSha256 = hooks.candidateArchiveSha256;
  const otherCandidate = "a".repeat(64);
  await record("baseline", { candidateSha256, submissions: 0 });
  await assert.rejects(record("post-accept", { candidateSha256: otherCandidate }), /candidate/i);
  assert.equal(writes, 1);
  await assert.rejects(record("post-accept", { candidateSha256 }), /permanently invalidated/);
  await assert.rejects(createPublicEvidenceRecorder(hooks)("baseline", {}), /candidate/i);
  await assert.rejects(createPublicEvidenceRecorder(hooks)("baseline", { candidateSha256: otherCandidate }), /candidate/i);
  assert.throws(() => createPublicEvidenceRecorder({ ...hooks, candidateArchiveSha256: undefined }), /candidate/i);
});

test("named Store public receipts preserve approved launcher and independent phase identities", async () => {
  const { NAMED_STORE_SCOPE } = require("./certops-adcs-store-named-observation");
  const hooks = makeEvidenceHooks();
  const launcherSha256 = "b".repeat(64);
  const options = { ...hooks, expectedLauncherSha256: launcherSha256 };
  const fields = { candidateSha256: CANDIDATE_SHA256, launcherSha256, captureId: "a".repeat(32),
    observationScope: NAMED_STORE_SCOPE, ephemeralCng: "not-qualified", namedStoreEvidenceSha256: "c".repeat(64),
    phaseEvidenceReceiptId: "d".repeat(32), phaseEvidenceSha256: "e".repeat(64) };
  const saved = await createPublicEvidenceRecorder(options)("post-accept", fields);
  const row = JSON.parse(await hooks.readEvidence(saved));
  assert.equal(row.launcherSha256, launcherSha256);
  assert.equal(row.phaseEvidenceReceiptId, fields.phaseEvidenceReceiptId);
  assert.equal(row.phaseEvidenceSha256, fields.phaseEvidenceSha256);
  await assert.rejects(createPublicEvidenceRecorder(options)("post-accept", { ...fields, launcherSha256: "0".repeat(64) }), /another launcher/);
  const { phaseEvidenceReceiptId, ...missingId } = fields;
  await assert.rejects(createPublicEvidenceRecorder(options)("post-accept", missingId), /receipt ID and digest/);
});

test("the evidence recorder rejects a different capture of the same candidate", async () => {
  const hooks = makeEvidenceHooks();
  const record = createPublicEvidenceRecorder(hooks);
  const candidateSha256 = hooks.candidateArchiveSha256;
  await record("baseline", { candidateSha256, captureId: "a".repeat(32) });
  await assert.rejects(record("post-accept", { candidateSha256, captureId: "b".repeat(32) }), /captureId/);
  const recordCa = createPublicEvidenceRecorder(makeEvidenceHooks());
  await recordCa("baseline", { candidateSha256, observationId: "a".repeat(32) });
  await assert.rejects(recordCa("ca-at-fault", { candidateSha256, observationId: "b".repeat(32) }), /observationId/);
});

test("public key counts require a digest and a capture identity", async () => {
  const candidateSha256 = CANDIDATE_SHA256;
  const captureId = "a".repeat(32);
  const cngEvidenceSha256 = "1".repeat(64);
  const makeRecord = () => createPublicEvidenceRecorder(makeEvidenceHooks());
  const fields = { candidateSha256, keygens: 0 };
  await makeRecord()("baseline", { ...fields, captureId, cngEvidenceSha256 });
  await assert.rejects(makeRecord()("baseline", { ...fields, captureId }), /capture ID and digest/);
  await assert.rejects(makeRecord()("baseline", { ...fields, cngEvidenceSha256 }), /capture ID and digest/);
});

test("pending restart and final drainage receipts stay bound to the same durable capture", async () => {
  const hooks = makeEvidenceHooks();
  const record = createPublicEvidenceRecorder(hooks);
  const evidence = { candidateSha256: CANDIDATE_SHA256, requestId: "8",
    captureId: "a".repeat(32), observationId: "b".repeat(32),
    keygens: 1, cngEvidenceSha256: "c".repeat(64) };
  for (const phase of ["pending-before-restart", "pending-after-restart"]) {
    const saved = await record(phase, evidence);
    assert.deepEqual(JSON.parse(await hooks.readEvidence(saved)), { schema: 1, phase, ...evidence });
  }
  await assert.rejects(record("observations-drained", { ...evidence, serviceDrainageSha256: "invalid" }));
});

test("paired Store recovery evidence requires separate capture and receipt identities", () => {
  const postAccept = {
    dnsName: "certops-adcs-0000000000000011-store.example.test", candidateArchiveSha256: CANDIDATE_SHA256,
    captureId: "1".repeat(32), observationId: "2".repeat(32), initialObservationRunId: "3".repeat(32),
    observationRunId: "4".repeat(32), evidenceReceiptId: "5".repeat(32), evidenceReceiptSha256: "6".repeat(64),
  };
  const pending = {
    dnsName: "certops-adcs-0000000000000022-store.example.test", candidateArchiveSha256: CANDIDATE_SHA256,
    captureId: "7".repeat(32), observationId: "8".repeat(32), initialObservationRunId: "9".repeat(32),
    observationRunId: "a".repeat(32), evidenceReceiptId: "b".repeat(32), evidenceReceiptSha256: "c".repeat(64),
  };
  const verify = (evidence) => validateSeparateStoreRecoveryEvidence(postAccept, evidence, CANDIDATE_SHA256);
  assert.doesNotThrow(() => verify(pending));
  for (const field of ["dnsName", "captureId", "observationId", "evidenceReceiptId", "evidenceReceiptSha256"]) {
    assert.throws(() => verify({ ...pending, [field]: postAccept[field] }), { message: `Recovery scenarios reused ${field}` });
  }
  assert.throws(() => verify({ ...pending, initialObservationRunId: postAccept.observationRunId }), /fresh observation run/);
  assert.throws(() => verify({ ...pending, observationRunId: pending.initialObservationRunId }), /fresh observation run/);
  assert.throws(() => verify({ ...pending, evidenceReceiptId: undefined }));
  assert.throws(() => verify({ ...pending, candidateArchiveSha256: "0".repeat(64) }), /different signed package/);
});

test("named Store observation counts independently observed persistent-key and install evidence", () => {
  const { NAMED_STORE_SCOPE, verifyNamedStoreIdentity } = require("./certops-adcs-store-named-observation");
  const { captureEvidenceDetails } = require("./certops-adcs-store-native-driver");
  const captureId = "a".repeat(32);
  const containerName = "tokentimer-enr-00000000-0000-0000-0000-000000000001";
  const evidence = { captureId, candidateSha256: CANDIDATE_SHA256, calibrationSha256: "b".repeat(64),
    sourceLoss: { ca: 0, key: 0, process: 0 }, events: [] };
  const base = { scope: NAMED_STORE_SCOPE, captureId, submissions: 0, keygens: 0, accepts: 0, namedEvidence: evidence };
  const capture = { started: true, captureId, baseline: base, async read() {}, async stop() {} };
  assert.throws(() => validateCaptureStart(capture, CANDIDATE_SHA256), /scope/);
  const previous = validateCaptureStart(capture, CANDIDATE_SHA256, NAMED_STORE_SCOPE);
  const events = [
    { sequence: 1, kind: "named-key-create", recordId: "17", containerName },
    { sequence: 2, kind: "ca-submission", recordId: "8", requestId: "21" },
    { sequence: 3, kind: "certreq-accept-start", recordId: "12", pid: 1490, createdFileTime: "0000000000000001" },
    { sequence: 4, kind: "certreq-accept-exit", recordId: "13", pid: 1490, createdFileTime: "0000000000000001", exitCode: 0 },
  ];
  const issued = { ...base, submissions: 1, keygens: 1, accepts: 1, namedEvidence: { ...evidence, events } };
  const checked = validateInitialNativeCounts(issued, previous);
  verifyNamedStoreIdentity(checked, { containerName, requestId: "21", requireSuccessfulAccept: true });
  const running = validateNativeCounts({ ...issued, namedEvidence: { ...issued.namedEvidence, events: events.slice(0, 3) } });
  assert.throws(() => verifyNamedStoreIdentity(running, { requireSuccessfulAccept: true }), /certreq success/);
  assert.throws(() => validateNativeCounts({ ...issued, namedEvidence: { ...issued.namedEvidence,
    events: [...events.slice(0, 3), { ...events[3], pid: 1491 }] } }), /certreq exit must match/);
  const failed = validateNativeCounts({ ...issued, namedEvidence: { ...issued.namedEvidence,
    events: [...events.slice(0, 3), { ...events[3], exitCode: 1 }] } });
  assert.throws(() => verifyNamedStoreIdentity(failed, { requireSuccessfulAccept: true }), /certreq success/);
  assert.throws(() => verifyNamedStoreIdentity(checked, { containerName: "different" }), /another key container/);
  assert.throws(() => verifyNamedStoreIdentity(checked, { requestId: "22" }), /another CA RequestId/);
  const report = captureEvidenceDetails(checked, "b".repeat(64));
  assert.equal(report.launcherSha256, "b".repeat(64));
  assert.equal(report.observationScope, NAMED_STORE_SCOPE);
  assert.equal(report.ephemeralCng, "not-qualified");
  assert.match(report.namedStoreEvidenceSha256, /^[a-f0-9]{64}$/);
  assert.equal(report.cngEvidenceSha256, undefined);
  assert.throws(() => validateNativeCounts({ ...issued, coverageComplete: true }), /exhaustive CNG/);
  assert.throws(() => validateNativeCounts({ ...issued, accepts: 0 }), /differs from observed certreq/);
  assert.throws(() => validateNativeCounts({ ...issued, namedEvidence: { ...issued.namedEvidence,
    sourceLoss: { ca: 0, key: 0, process: 1 } } }), /reported loss/);
  assert.throws(() => validateNativeCounts({ ...issued, namedEvidence: { ...issued.namedEvidence,
    events: [events[0], { ...events[1], requestId: "22" }, ...events.slice(2)] } }, checked), /rewrote a previous checkpoint/);
  assert.throws(() => validateNativeCounts(nativeCounts(0, 0, 0), previous), /scope changed/);
});

test("named Store interruption requires a bound external loss observer and an unfinished durable install", async () => {
  const { NAMED_STORE_SCOPE } = require("./certops-adcs-store-named-observation");
  const { armStoreAcceptObserver, verifyNamedPostAcceptWindow } = require("./certops-adcs-store-native-driver");
  const context = { observationScope: NAMED_STORE_SCOPE, candidateArchiveSha256: CANDIDATE_SHA256,
    expectedLauncherSha256: "b".repeat(64), async readNamedStorePhaseEvidence() {} };
  const binding = { captureId: "c".repeat(32), observationRunId: "d".repeat(32),
    serviceProcess: { pid: 21, sid: "S-1-5-18", created: "2026-11-23T10:30:00.000Z" } };
  await assert.rejects(armStoreAcceptObserver(context, binding), /Independent Store loss observer is required/);
  const observer = { ready: Promise.resolve(), result: Promise.resolve(),
    bindTarget() {}, readDrainage() {}, stopAndDrain() {}, hasLiveChild() { return false; } };
  assert.equal(await armStoreAcceptObserver({ ...context, createNamedStoreAcceptObserver(actual) {
    assert.deepEqual(actual, { ...binding, candidateArchiveSha256: CANDIDATE_SHA256, launcherSha256: context.expectedLauncherSha256 });
    return observer;
  } }, binding), observer);

  const fault = { ...binding, phaseEvidenceSha256: "e".repeat(64), phaseEvidenceReceiptId: "f".repeat(32), jobId: "job-1", containerName: "owned" };
  const receipt = { jobId: fault.jobId, containerName: fault.containerName, status: "generated",
    acceptedThumbprint: null, acceptedStore: null, acceptedAt: null };
  assert.equal(verifyNamedPostAcceptWindow(fault, binding, receipt), fault.phaseEvidenceSha256);
  assert.throws(() => verifyNamedPostAcceptWindow({ ...fault, phaseEvidenceSha256: undefined }, binding, receipt), /phase evidence/);
  assert.throws(() => verifyNamedPostAcceptWindow(fault, binding, { ...receipt, status: "enrolled_by_agent" }), /already committed/);
  assert.throws(() => verifyNamedPostAcceptWindow(fault, binding, { ...receipt, acceptedStore: "My" }), /already committed/);
  assert.throws(() => verifyNamedPostAcceptWindow(fault, binding, { ...receipt, jobId: "another-job" }));
});

test("named Store phase readback binds the exact certreq lifetime, input and enrolled target", () => {
  const { createHash } = require("node:crypto");
  const { MAX_PHASE_EVIDENCE_BYTES, verifyNamedStorePhaseEvidence } = require("./certops-adcs-store-phase-evidence");
  const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
  const launcherSha256 = "b".repeat(64);
  const serviceDrainageSha256 = "c".repeat(64);
  const certificateSha256 = "d".repeat(64);
  const configDir = "C:\\Owned Store\\state";
  const argv = ["certreq.exe", "-q", "-machine", "-accept",
    configDir + "\\windows-cert-store-work\\accept-fdea58b1.cer"];
  const observation = { captureId: "e".repeat(32), observationRunId: "f".repeat(32),
    serviceProcess: { pid: 20, sid: "S-1-5-18", created: "2026-11-23T10:30:00.000Z" } };
  const enrollmentId = "a0000000-0000-0000-0000-000000000001";
  const target = { jobId: "b0000000-0000-0000-0000-000000000002", enrollmentId,
    containerName: "tokentimer-enr-" + enrollmentId, snapshotSha256: "6".repeat(64),
    domain: "certops-adcs-0000000000000001-store.example.test" };
  const start = { kind: "certreq-accept-start", pid: 300, createdFileTime: "00000000000000aa",
    parentPid: 22, parentCreatedFileTime: "0000000000000099", parentProcessSequence: "33",
    recordId: "129", auditRecordId: "17", argvSha256: hash(JSON.stringify(argv)), certificateSha256 };
  const exit = { kind: "certreq-accept-exit", pid: 300, createdFileTime: "00000000000000aa", recordId: "130", exitCode: 0 };
  const common = { target, observation, fault: { fingerprintSha256: certificateSha256 },
    candidateArchiveSha256: CANDIDATE_SHA256, launcherSha256, serviceDrainageSha256, configDir };
  const counts = (events) => ({ accepts: 1, namedEvidence: { events } });
  const phase = { schema: 1, candidateArchiveSha256: CANDIDATE_SHA256, launcherSha256,
    ...observation, serviceDrainageSha256, target: { ...target, certificateSha256 }, certreq: {
      pid: start.pid, createdFileTime: start.createdFileTime, parentPid: start.parentPid,
      parentCreatedFileTime: start.parentCreatedFileTime, parentProcessSequence: start.parentProcessSequence,
      auditRecordId: start.auditRecordId, startRecordId: start.recordId, exitRecordId: exit.recordId, argv,
    } };
  function verify(value, events = [start, exit], expectedSha256) {
    const raw = Buffer.isBuffer(value) ? value : Buffer.from(JSON.stringify(value));
    return verifyNamedStorePhaseEvidence({ ...common, raw, expectedSha256: expectedSha256 ?? hash(raw), counts: counts(events) });
  }
  assert.equal(verify(phase), hash(JSON.stringify(phase)));
  assert.throws(() => verify(phase, [start, exit], "0".repeat(64)), /digest mismatch/);
  assert.throws(() => verify(Buffer.alloc(MAX_PHASE_EVIDENCE_BYTES + 1)), /bounded UTF-8/);
  assert.throws(() => verify(Buffer.from(JSON.stringify(phase).replace('"schema":1', '"schema":2,"schema":1'))), /does not match/);
  const anotherChild = [{ ...start, pid: 301 }, { ...exit, pid: 301 }];
  assert.throws(() => verify(phase, anotherChild), /does not match/);
  assert.throws(() => verify(phase, [start, { ...exit, createdFileTime: "00000000000000ab" }]), /another process lifetime/);
  assert.throws(() => verify({ ...phase, target: { ...phase.target, enrollmentId: "foreign" } }), /does not match/);
  assert.throws(() => verify({ ...phase, launcherSha256: "0".repeat(64) }), /does not match/);
  assert.throws(() => verify(phase, [{ ...start, certificateSha256: "0".repeat(64) }, exit]), /differs from the enrolled certificate/);
  assert.throws(() => verify(phase, [{ ...start, argvSha256: "0".repeat(64) }, exit]), /argv differs/);
});

test("a service restart requires a fresh armed observation run in the same live capture", () => {
  const target = {
    candidateArchiveSha256: CANDIDATE_SHA256, captureId: "a".repeat(32), previousObservationRunId: "b".repeat(32),
    serviceProcess: { pid: 21, sid: "S-1-5-18", created: "2026-11-23T10:30:00.000Z" },
  };
  const proof = {
    candidateArchiveSha256: CANDIDATE_SHA256, captureId: target.captureId,
    independentReader: true, captureContinued: true, runArmedBeforeStart: true,
    observationRunId: "c".repeat(32), process: { pid: 22, sid: "S-1-5-18", created: "2026-11-23T10:31:00.000Z" },
    evidenceSha256: "d".repeat(64),
  };
  assert.deepEqual(validateObservedServiceStart(proof, target), {
    process: proof.process, observationRunId: proof.observationRunId, serviceStartSha256: proof.evidenceSha256,
  });
  for (const change of [
    { observationRunId: target.previousObservationRunId }, { observationRunId: undefined },
    { captureContinued: false }, { runArmedBeforeStart: false }, { independentReader: false },
    { captureId: "e".repeat(32) }, { process: target.serviceProcess }, { evidenceSha256: undefined },
  ]) {
    assert.throws(() => validateObservedServiceStart({ ...proof, ...change }, target), JSON.stringify(change));
  }
});

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

test("native operation counts cannot claim coverage with counters alone", () => {
  const counts = { captureId: "a".repeat(32), coverageComplete: true, submissions: 0, keygens: 0, accepts: 0 };
  assert.throws(() => validateNativeCounts(counts), /raw CNG evidence/i);
});

test("native operation counts require continuous complete capture", () => {
  const before = nativeCounts();
  assert.equal(validateNativeCounts({ ...before }, before).captureId, before.captureId);
  for (const change of [{ coverageComplete: false }, { captureId: "b".repeat(32) }, { keygens: 0 }, { accepts: null }]) {
    assert.throws(() => validateNativeCounts({ ...before, ...change }, before));
  }
});

test("ephemeral CNG coverage requires matching raw create and finalize events for both providers", () => {
  const baseline = nativeCounts({ submissions: 0, keygens: 0, accepts: 0 });
  assert.deepEqual(validateNativeCounts(baseline), baseline);
  const wrongCapture = structuredClone(baseline);
  wrongCapture.cngEvidence.captureId = "b".repeat(32);
  assert.throws(() => validateNativeCounts(wrongCapture), /another capture/);

  const ncryptOnly = structuredClone(baseline);
  ncryptOnly.cngEvidence.events = ncryptOnly.cngEvidence.events
    .filter(event => !event.evidence?.payload.operation.startsWith("bcrypt-"))
    .map((event, index) => ({ ...event, sequence: index + 1 }));
  assert.throws(() => validateNativeCounts(ncryptOnly), /ephemeral NCrypt and BCrypt/);

  const named = structuredClone(baseline);
  named.cngEvidence.events[0].evidence.payload.nameKind = "non-null";
  assert.throws(() => validateNativeCounts(named), /must use an ephemeral key/);
  const wrongHandle = structuredClone(baseline);
  wrongHandle.cngEvidence.events.find(event => event.kind === "cng-api-return" &&
    event.evidence.payload.operation === "bcrypt-finalize").evidence.payload.handleCorrelation = "2".repeat(64);
  assert.throws(() => validateNativeCounts(wrongHandle), /unobserved or released key/);
  const unrelatedReturn = structuredClone(baseline);
  unrelatedReturn.cngEvidence.events[1].evidence.pid++;
  assert.throws(() => validateNativeCounts(unrelatedReturn), /does not match/);
});

test("CNG checkpoints reject missing calls, altered history and a mismatched key count", () => {
  const supplied = nativeCounts();
  const before = validateNativeCounts(supplied);
  assert.deepEqual(validateNativeCounts(nativeCounts({ keygens: 2 }), before), nativeCounts({ keygens: 2 }));
  assert.throws(() => validateNativeCounts({ ...supplied, keygens: 0 }), /do not match raw CNG/);

  const unfinished = structuredClone(supplied);
  unfinished.cngEvidence.events.pop();
  assert.throws(() => validateNativeCounts(unfinished), /unfinished calls/);
  const missing = structuredClone(supplied);
  missing.cngEvidence.events.splice(1, 1);
  assert.throws(() => validateNativeCounts(missing), /gap or duplicate/);
  const failed = structuredClone(supplied);
  failed.cngEvidence.events.findLast(event => event.kind === "cng-api-return" &&
    event.evidence.payload.operation === "ncrypt-finalize").evidence.payload.status = "80090009";
  assert.throws(() => validateNativeCounts(failed), /generation call failed/);

  supplied.cngEvidence.events[0].evidence.payload.invocationFingerprint = "2".repeat(64);
  supplied.cngEvidence.events[1].evidence.payload.invocationFingerprint = "2".repeat(64);
  assert.doesNotThrow(() => validateNativeCounts(supplied));
  assert.throws(() => validateNativeCounts(supplied, before), /rewrote a previous checkpoint/);
  const newCandidate = nativeCounts();
  newCandidate.cngEvidence.candidateSha256 = "1".repeat(64);
  assert.throws(() => validateNativeCounts(newCandidate, before), /candidate changed/);
});

test("CNG cannot finalize an ephemeral key after the handle was freed", () => {
  const counts = nativeCounts({ submissions: 0, keygens: 0, accepts: 0 });
  const events = counts.cngEvidence.events;
  const { pid, createdFileTime } = events[0].evidence;
  const payload = {
    tid: 42, callId: 900, operation: "ncrypt-free",
    invocationFingerprint: "3".repeat(64), handleCorrelation: "1".repeat(64),
  };
  events.splice(2, 0, { kind: "cng-api-entry", evidence: { pid, createdFileTime, payload } },
    { kind: "cng-api-return", evidence: { pid, createdFileTime, payload: { ...payload, status: "00000000" } } });
  events.forEach((event, index) => { event.sequence = index + 1; });
  assert.throws(() => validateNativeCounts(counts), /released a key before finalization/);
});

test("native capture must count the one initial key, request and acceptance", () => {
  const counts = nativeCounts();
  const baseline = nativeCounts({ submissions: 0, keygens: 0, accepts: 0 });
  assert.deepEqual(validateInitialNativeCounts(counts, baseline), counts);
  for (const changed of [{ keygens: 2 }, { accepts: 2 }, { submissions: 2 }, { captureId: "b".repeat(32) }]) {
    assert.throws(() => validateInitialNativeCounts({ ...counts, ...changed }, baseline));
  }
});


test("capture baseline is complete, empty, bound and has verified drainage", async () => {
  const id = "a".repeat(32);
  const baseline = nativeCounts({ captureId: id, submissions: 0, keygens: 0, accepts: 0 });
  const valid = { started: true, captureId: id, baseline, async read() { return baseline; }, async stop() { return { captureId: id, drained: true }; } };
  assert.deepEqual(validateCaptureStart(valid, CANDIDATE_SHA256), baseline);
  assert.throws(() => validateCaptureStart(valid, "1".repeat(64)), /another candidate/);
  await stopNativeCapture(valid);
  for (const invalid of [
    { ...valid, started: false }, { ...valid, baseline: { ...baseline, coverageComplete: false } },
    { ...valid, baseline: { ...baseline, captureId: "b".repeat(32) } },
    { ...valid, baseline: { ...baseline, submissions: 1 } }, { ...valid, stop: undefined }, { ...valid, read: undefined },
  ]) assert.throws(() => validateCaptureStart(invalid, CANDIDATE_SHA256));
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
  const counts = nativeCounts({ captureId });
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
  const baseline = nativeCounts({ captureId, submissions: 0, keygens: 0, accepts: 0 });
  await verifyPreIssueCheckpoint({ baseline, async read() { return baseline; } },
    { ...observation, async readBaseline() { return window; } }, baseline);
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
  const serviceProcess = { pid: 123, sid: "S-1-5-18", created: "2026-10-01T00:00:00.000Z" };
  return { archivePath: __filename, candidateArchiveSha256, expectedRuntimeSha256,
    async ps() { return JSON.stringify(serviceProcess); },
    async inspectCandidateHost() { return { inspectionIndependent: true, archiveBytesVerified: true,
      installedFilesMatchArchive: true, protectedInstallation: true, serviceOwned: true, serviceIdentity: "LocalSystem",
      processTokenSid: "S-1-5-18", noIis: true, storeOnlyAdcsCapability: true,
      agentArchiveSha256: candidateArchiveSha256, runtimeSha256: expectedRuntimeSha256, serviceProcess }; } };
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

test("named Store package inspection binds the exact signed launcher bytes", async () => {
  const { NAMED_STORE_SCOPE } = require("./certops-adcs-store-named-observation");
  const candidate = makeCandidateHooks();
  const host = await candidate.inspectCandidateHost();
  const launcherPath = require.resolve("./certops-adcs-store-native-cng.fixture");
  const launcherSha256 = require("node:crypto").createHash("sha256").update(require("node:fs").readFileSync(launcherPath)).digest("hex");
  const scoped = { ...candidate, observationScope: NAMED_STORE_SCOPE, launcherPath, expectedLauncherSha256: launcherSha256 };
  await assert.rejects(verifyCandidateHost({ ...scoped, launcherPath: undefined }), /launcher path is required/);
  await assert.rejects(verifyCandidateHost({ ...scoped, expectedLauncherSha256: "0".repeat(64) }), /launcher digest mismatch/);
  await assert.rejects(verifyCandidateHost(scoped), /another launcher/);
  const inspected = await verifyCandidateHost({ ...scoped, async inspectCandidateHost(approved) {
    assert.equal(approved.launcherSha256, launcherSha256);
    return { ...host, launcherSha256 };
  } });
  assert.equal(inspected.launcherSha256, launcherSha256);
});

test("candidate inspection is bound to the running SCM service lifetime", async () => {
  const candidate = makeCandidateHooks();
  const healthy = await candidate.inspectCandidateHost();
  const { serviceProcess } = healthy;
  assert.deepEqual((await verifyCandidateHost(candidate)).serviceProcess, serviceProcess);
  for (const changed of [
    { ...serviceProcess, pid: serviceProcess.pid + 1 },
    { ...serviceProcess, created: "2026-10-01T00:00:01.000Z" },
    { ...serviceProcess, sid: "S-1-5-19" },
    {},
  ]) {
    await assert.rejects(verifyCandidateHost({
      ...candidate,
      async ps() { return JSON.stringify(changed); },
    }), /service process|S-1-5-18/);
  }
  await assert.rejects(verifyCandidateHost({
    ...candidate, async inspectCandidateHost() { return { ...healthy, serviceProcess: undefined }; },
  }), /service process/i);
});

test("both native recovery entries fail before inspecting the host or starting either scenario", async () => {
  const context = new Proxy({}, { get() { assert.fail("The closed native gate accessed the lab context"); } });
  const reason = /active observation-loss interruption is not implemented/;
  assert.throws(requireActiveObservationInterruption, reason);
  for (const qualify of [qualifyNativeStoreRecovery, qualifyInstalledStoreRecovery]) {
    await assert.rejects(qualify(context), reason);
  }
});

test("CA drainage detects a submission during native capture drainage", async () => {
  const captureId = "a".repeat(32), observationId = "b".repeat(32), key = "c".repeat(64), fingerprint = "d".repeat(64);
  const counts = nativeCounts({ captureId });
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
