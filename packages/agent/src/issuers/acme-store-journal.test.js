"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { generateCsr } = require("../keys");
const { issueStoreCertificateOnce, readStoreEnrollment, prepareStoreEnrollment, saveStoreCsr, markStoreInstallation, runAcmeStoreOperation, runAcmeStoreOperationForJob, isAcmeStoreContainerProtected, diskStorage } = require("./acme-store-journal");
const fixtures = path.join(__dirname, "../verify/fixtures");
const csrPem = generateCsr({ keyPath: path.join(fixtures, "leaf.key.pem"), subject: { commonName: "example.com" } }).csrPem;
const certificatePem = fs.readFileSync(path.join(fixtures, "leaf.crt.pem"), "utf8");

function scenario() {
  let stored = null, calls = 0;
  const storage = { read: () => stored && structuredClone(stored), write: (value) => { stored = structuredClone(value); } };
  const args = { jobId: "job-one", agentId: "agent-one",
    csrPem, domains: ["example.com"], requestSha256: "a".repeat(64), storage, assertLock() {},
    beforeSubmit: async () => {}, submit: async () => { calls++; return { outcome: "issued", certificatePem }; } };
  args.containerName = prepareStoreEnrollment(args).record.containerName;
  saveStoreCsr(args);
  return { args, storage, calls: () => calls, state: () => stored };
}

test("save the issued leaf before upload, then replay it without another order", async () => {
  const item = scenario();
  assert.equal((await issueStoreCertificateOnce(item.args)).outcome, "issued");
  assert.equal(item.state().state, "issued");
  assert.equal(readStoreEnrollment(item.args).containerName, item.args.containerName);
  // A caller's subsequent evidence upload may fail; replay reads the saved leaf.
  const replay = await issueStoreCertificateOnce(item.args);
  assert.equal(replay.recovered, true);
  assert.equal(replay.certificatePem, certificatePem);
  assert.equal(item.calls(), 1);
});

test("lost finalization response or interrupted durable save never creates another order", async () => {
  const lost = scenario();
  lost.args.submit = async () => { throw new Error("lost response after finalization"); };
  assert.equal((await issueStoreCertificateOnce(lost.args)).outcome, "uncertain");
  assert.equal(readStoreEnrollment(lost.args).state, "submitting");
  lost.args.submit = async () => { throw new Error("must not submit again"); };
  assert.equal((await issueStoreCertificateOnce(lost.args)).outcome, "uncertain");
  const interrupted = scenario();
  const write = interrupted.storage.write;
  interrupted.storage.write = value => { if (value.state === "issued") throw new Error("crash before save"); write(value); };
  await assert.rejects(issueStoreCertificateOnce(interrupted.args), /crash before save/);
  assert.equal((await issueStoreCertificateOnce(interrupted.args)).outcome, "uncertain");
  assert.equal(interrupted.calls(), 1);
});

test("identity conflict or foreign certificate is never retried or accepted", async () => {
  const item = scenario();
  item.args.submit = async () => ({ outcome: "issued", certificatePem: fs.readFileSync(path.join(fixtures, "wrong-san.crt.pem"), "utf8") });
  assert.equal((await issueStoreCertificateOnce(item.args)).outcome, "uncertain");
  await assert.rejects(issueStoreCertificateOnce({ ...item.args, agentId: "agent-two" }), /invalid durable/);
  assert.equal((await issueStoreCertificateOnce(item.args)).outcome, "uncertain");
});

test("protected disk journal survives reconstruction", async () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "acme-store-journal-"));
  try {
    const item = scenario();
    item.args.storage = diskStorage(stateDir, item.args.jobId);
    item.args.stateDir = stateDir;
    item.args.containerName = prepareStoreEnrollment(item.args).record.containerName;
    saveStoreCsr(item.args);
    assert.equal((await issueStoreCertificateOnce(item.args)).outcome, "issued");
    assert.equal(isAcmeStoreContainerProtected({ stateDir, jobId: item.args.jobId, containerName: item.args.containerName }), true);
    item.args.storage = diskStorage(stateDir, item.args.jobId);
    assert.equal(readStoreEnrollment(item.args).state, "issued");
    assert.equal((await issueStoreCertificateOnce(item.args)).recovered, true);
    assert.equal(item.calls(), 1);
  } finally { fs.rmSync(stateDir, { recursive: true, force: true }); }
});

test("installation intent survives an interruption and never repeats the order", async () => {
  const item = scenario();
  await issueStoreCertificateOnce(item.args);
  markStoreInstallation(item.args);
  assert.equal(readStoreEnrollment(item.args).state, "installing");
  assert.equal((await issueStoreCertificateOnce(item.args)).recovered, true);
  markStoreInstallation({ ...item.args, completed: true });
  assert.equal(readStoreEnrollment(item.args).state, "installed");
  assert.equal(item.calls(), 1);
});

test("interrupted key generation retains the original intent and never submits", async () => {
  const item = scenario();
  let stored = null;
  item.args.storage = { read: () => stored, write: value => { stored = structuredClone(value); } };
  const initial = prepareStoreEnrollment(item.args);
  const replay = prepareStoreEnrollment(item.args);
  assert.equal(initial.created, true);
  assert.equal(replay.created, false);
  assert.equal(replay.record.state, "keygen_intent");
  await assert.rejects(issueStoreCertificateOnce(item.args), /identity conflicts|not been durably prepared/);
  assert.equal(item.calls(), 0);
});

test("orchestration recovers a saved issued leaf after a lost upload without keygen or resubmission", async () => {
  let state = null, keygens = 0, orders = 0, installs = 0, reports = 0;
  const storage = { read: () => state && structuredClone(state), write: value => { state = structuredClone(value); } };
  const lock = { assertHeld() {}, async run(fn) { return fn(new AbortController().signal); }, release() {} };
  const args = { stateDir: "unused", jobId: "job-two", enrollmentId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", agentId: "agent-one", domains: ["valid.example.com"], requestSha256: "a".repeat(64), storage,
    acquireLock: () => lock, recordContainer: async () => {},
    generateCsr: async ({ containerName }) => { keygens++; return { ok: true, containerName, csrPem }; },
    submit: async () => { orders++; return { outcome: "issued", certificatePem }; },
    reportReceipt: async () => {}, reportIssuance: async () => { reports++; if (reports === 1) throw new Error("upload failed"); },
    install: async () => { installs++; return { status: "succeeded", storeProof: { status: "complete", fingerprintSha256: new (require("node:crypto").X509Certificate)(certificatePem).fingerprint256.replace(/:/g, "").toLowerCase() } }; } };
  await assert.rejects(runAcmeStoreOperation(args), /upload failed/);
  assert.equal(state.state, "issued");
  assert.equal((await runAcmeStoreOperation(args)).status, "succeeded");
  assert.equal(state.state, "installed");
  assert.deepEqual({ keygens, orders, installs, reports }, { keygens: 1, orders: 1, installs: 1, reports: 2 });
});

test("failed submission acknowledgement never calls the CA and recovery never opens a replacement order", async () => {
  let state = null, orders = 0;
  const storage = { read: () => state && structuredClone(state), write: value => { state = structuredClone(value); } };
  const lock = { assertHeld() {}, async run(fn) { return fn(new AbortController().signal); }, release() {} };
  let failAck = true;
  const args = { stateDir: "unused", jobId: "ack-job", enrollmentId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", agentId: "agent-one",
    domains: ["example.com"], requestSha256: "a".repeat(64), storage, acquireLock: () => lock, recordContainer: async () => {},
    generateCsr: async ({ containerName }) => ({ ok: true, containerName, csrPem }),
    submit: async () => { orders++; return { outcome: "issued", certificatePem }; },
    reportReceipt: async ({ state }) => { if (state === "submitting" && failAck) throw new Error("ack lost"); },
    reportIssuance: async () => {}, install: async () => { throw new Error("must not install"); } };
  await assert.rejects(runAcmeStoreOperation(args), /ack lost/);
  assert.equal(state.state, "submitting"); assert.equal(orders, 0);
  failAck = false;
  assert.equal((await runAcmeStoreOperation(args)).outcome, "uncertain");
  assert.equal(orders, 0);
});

test("a leaf for the CSR key but wrong DNS name is never installed or promoted", async () => {
  let state = null, installs = 0, issuedReceipts = 0;
  const storage = { read: () => state && structuredClone(state), write: value => { state = structuredClone(value); } };
  const lock = { assertHeld() {}, async run(fn) { return fn(new AbortController().signal); }, release() {} };
  const args = { stateDir: "unused", jobId: "wrong-dns", enrollmentId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", agentId: "agent-one",
    domains: ["wrong.example.com"], requestSha256: "a".repeat(64), storage, acquireLock: () => lock, recordContainer: async () => {},
    generateCsr: async ({ containerName }) => ({ ok: true, containerName, csrPem }),
    submit: async () => ({ outcome: "issued", certificatePem }), reportReceipt: async item => { if (item.state === "issued") issuedReceipts++; },
    reportIssuance: async () => { throw new Error("invalid leaf must not be reported"); }, install: async () => { installs++; } };
  const result = await runAcmeStoreOperation(args);
  assert.equal(result.status, "failed"); assert.match(result.errorMessage, /SAN_MISMATCH/);
  assert.equal(state.state, "issued"); assert.equal(installs, 0); assert.equal(issuedReceipts, 0);
  const replay = await runAcmeStoreOperation({ ...args, recoveryOnly: true });
  assert.equal(replay.status, "failed"); assert.equal(installs, 0);
});

test("crash after CA finalization before durable leaf keeps the original key and creates no replacement order", async () => {
  let state = null, orders = 0, keygens = 0, failSave = true;
  const receipts = [];
  const storage = { read: () => state && structuredClone(state), write: value => {
    if (value.state === "issued" && failSave) throw new Error("crash before durable leaf");
    state = structuredClone(value);
  } };
  const lock = { assertHeld() {}, async run(fn) { return fn(new AbortController().signal); }, release() {} };
  const args = { stateDir: "unused", jobId: "crash-job", enrollmentId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", agentId: "agent-one",
    domains: ["example.com"], requestSha256: "a".repeat(64), storage, acquireLock: () => lock, recordContainer: async () => {},
    generateCsr: async ({ containerName }) => { keygens++; return { ok: true, containerName, csrPem }; },
    submit: async () => { orders++; return { outcome: "issued", certificatePem }; },
    reportReceipt: async receipt => receipts.push(receipt.state), reportIssuance: async () => {},
    install: async () => { throw new Error("must not install"); } };
  await assert.rejects(runAcmeStoreOperation(args), /crash before durable leaf/);
  const originalContainer = state.containerName;
  failSave = false;
  assert.equal((await runAcmeStoreOperation(args)).outcome, "uncertain");
  assert.equal(state.containerName, originalContainer); assert.equal(keygens, 1); assert.equal(orders, 1);
  assert.equal(receipts.at(-1), "uncertain");
});

test("operator continuation never creates a key or submits an order, even without a saved leaf", async () => {
  const item = scenario();
  let mutations = 0;
  const lock = { assertHeld() {}, async run(fn) { return fn(new AbortController().signal); }, release() {} };
  const result = await runAcmeStoreOperation({ ...item.args, enrollmentId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", recoveryOnly: true,
    acquireLock: () => lock, recordContainer: async () => { mutations++; }, generateCsr: async () => { mutations++; },
    reportReceipt: async () => {}, reportIssuance: async () => {}, install: async () => { mutations++; } });
  assert.equal(result.outcome, "uncertain"); assert.equal(mutations, 0); assert.equal(item.calls(), 0);
});

test("uncertain submission and repeated operator continuations stay recoverable without another key or order", async () => {
  let state = null, keygens = 0, orders = 0;
  const storage = { read: () => state && structuredClone(state), write: value => { state = structuredClone(value); } };
  const lock = { assertHeld() {}, async run(fn) { return fn(new AbortController().signal); }, release() {} };
  const args = { stateDir: "unused", jobId: "ambiguous-order", enrollmentId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", agentId: "agent-one",
    domains: ["example.com"], requestSha256: "a".repeat(64), storage, acquireLock: () => lock,
    recordContainer: async () => {}, generateCsr: async ({ containerName }) => { keygens++; return { ok: true, containerName, csrPem }; },
    submit: async () => { orders++; throw new Error("connection lost after finalization"); }, reportReceipt: async () => {},
    reportIssuance: async () => {}, install: async () => { throw new Error("must not install"); } };
  for (const recoveryOnly of [false, true, true]) {
    const result = await runAcmeStoreOperationForJob({ ...args, recoveryOnly });
    assert.equal(result.status, "orphaned_unknown_effect");
    assert.match(result.errorMessage, /needsOperatorReconciliation=true/);
    assert.equal(state.state, "submitting");
  }
  assert.equal(keygens, 1); assert.equal(orders, 1);
});

test("lost acknowledgement after issuance keeps the job eligible for operator recovery", async () => {
  let state = null, keygens = 0, orders = 0;
  const storage = { read: () => state && structuredClone(state), write: value => { state = structuredClone(value); } };
  const lock = { assertHeld() {}, async run(fn) { return fn(new AbortController().signal); }, release() {} };
  const args = { stateDir: "unused", jobId: "lost-upload", enrollmentId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", agentId: "agent-one",
    domains: ["valid.example.com"], requestSha256: "a".repeat(64), storage, acquireLock: () => lock,
    recordContainer: async () => {}, generateCsr: async ({ containerName }) => { keygens++; return { ok: true, containerName, csrPem }; },
    submit: async () => { orders++; return { outcome: "issued", certificatePem }; }, reportReceipt: async () => {},
    reportIssuance: async () => { throw new Error("upload lost"); }, install: async () => { throw new Error("must not install"); } };
  const result = await runAcmeStoreOperationForJob(args);
  assert.equal(result.status, "orphaned_unknown_effect");
  assert.match(result.errorMessage, /needsOperatorReconciliation=true/);
  assert.equal(state.state, "issued"); assert.equal(keygens, 1); assert.equal(orders, 1);
});

test("an invalid issued leaf remains visible for operator recovery and is never installed", async () => {
  let state = null, orders = 0, installs = 0;
  const storage = { read: () => state && structuredClone(state), write: value => { state = structuredClone(value); } };
  const lock = { assertHeld() {}, async run(fn) { return fn(new AbortController().signal); }, release() {} };
  const args = { stateDir: "unused", jobId: "invalid-leaf", enrollmentId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", agentId: "agent-one",
    domains: ["wrong.example.com"], requestSha256: "a".repeat(64), storage, acquireLock: () => lock,
    recordContainer: async () => {}, generateCsr: async ({ containerName }) => ({ ok: true, containerName, csrPem }),
    submit: async () => { orders++; return { outcome: "issued", certificatePem }; }, reportReceipt: async () => {},
    reportIssuance: async () => {}, install: async () => { installs++; } };
  for (const recoveryOnly of [false, true]) {
    const result = await runAcmeStoreOperationForJob({ ...args, recoveryOnly });
    assert.equal(result.status, "orphaned_unknown_effect");
    assert.match(result.errorMessage, /SAN_MISMATCH/);
    assert.match(result.errorMessage, /needsOperatorReconciliation=true/);
  }
  assert.equal(state.state, "issued"); assert.equal(orders, 1); assert.equal(installs, 0);
});

test("installed receipt acknowledgement loss replays proof without another key, order or acceptance", async () => {
  let state = null, keygens = 0, orders = 0, accepts = 0, reports = 0;
  const storage = { read: () => state && structuredClone(state), write: value => { state = structuredClone(value); } };
  const lock = { assertHeld() {}, async run(fn) { return fn(new AbortController().signal); }, release() {} };
  const fingerprint = new (require("node:crypto").X509Certificate)(certificatePem).fingerprint256.replace(/:/g, "").toLowerCase();
  const args = { stateDir: "unused", jobId: "installed-lost-ack", enrollmentId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", agentId: "agent-one",
    domains: ["valid.example.com"], requestSha256: "a".repeat(64), storage, acquireLock: () => lock,
    recordContainer: async () => {}, generateCsr: async ({ containerName }) => { keygens++; return { ok: true, containerName, csrPem }; },
    submit: async () => { orders++; return { outcome: "issued", certificatePem }; },
    reportReceipt: async receipt => { if (receipt.state === "installed" && reports++ === 0) throw new Error("ack lost"); },
    reportIssuance: async () => {}, install: async ({ recovery }) => {
      if (!recovery) accepts++;
      return { status: "succeeded", storeProof: { status: "complete", fingerprintSha256: fingerprint } };
    } };
  assert.equal((await runAcmeStoreOperationForJob(args)).status, "orphaned_unknown_effect");
  assert.equal(state.state, "installed");
  const replay = await runAcmeStoreOperationForJob({ ...args, recoveryOnly: true });
  assert.equal(replay.status, "succeeded");
  assert.deepEqual({ keygens, orders, accepts, reports }, { keygens: 1, orders: 1, accepts: 1, reports: 2 });
});

test("enrollment lock loss aborts the active order and continuation never creates a replacement", async () => {
  let state = null, keygens = 0, orders = 0, installed = 0;
  const controller = new AbortController();
  const storage = { read: () => state && structuredClone(state), write: value => { state = structuredClone(value); } };
  const lock = { assertHeld() { if (controller.signal.aborted) throw Object.assign(new Error("lock lost"), { code: "STORE_LOCK_LOST" }); }, async run(fn) { return fn(controller.signal); }, release() {} };
  const args = { stateDir: "unused", jobId: "lock-loss", enrollmentId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", agentId: "agent-one", domains: ["example.com"], requestSha256: "a".repeat(64), storage,
    acquireLock: () => lock, recordContainer: async () => {}, generateCsr: async ({ containerName }) => { keygens++; return { ok: true, containerName, csrPem }; },
    submit: async ({ signal }) => { orders++; assert.strictEqual(signal, controller.signal); controller.abort(); assert.equal(signal.aborted, true); throw new Error("child aborted"); },
    reportReceipt: async () => {}, reportIssuance: async () => {}, install: async () => { installed++; } };
  assert.equal((await runAcmeStoreOperationForJob(args)).status, "orphaned_unknown_effect");
  const originalContainer = state.containerName;
  const freshLock = { assertHeld() {}, async run(fn) { return fn(new AbortController().signal); }, release() {} };
  for (let i = 0; i < 2; i++) assert.equal((await runAcmeStoreOperationForJob({ ...args, acquireLock: () => freshLock, recoveryOnly: true })).status, "orphaned_unknown_effect");
  assert.equal(state.state, "submitting"); assert.equal(state.containerName, originalContainer);
  assert.deepEqual({ keygens, orders, installed }, { keygens: 1, orders: 1, installed: 0 });
});
