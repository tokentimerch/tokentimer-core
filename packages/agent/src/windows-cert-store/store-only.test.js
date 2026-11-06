"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { X509Certificate } = require("node:crypto");
const { createHash } = require("node:crypto");
const { inspectStoreOnlyCertificate, inspectPendingStoreRequest, observeStoreOnlyPredecessor, installStoreOnlyCertificate } = require("./store-only");
const { storeSnapshotTargetError } = require("../adcs-windows-iis");

const certificatePem = fs.readFileSync(path.join(__dirname, "../verify/fixtures/selfsigned.crt.pem"), "utf8");
const cert = new X509Certificate(certificatePem);
const containerName = "tokentimer-enr-11111111-1111-1111-1111-111111111111";
const now = (Date.parse(cert.validFrom) + Date.parse(cert.validTo)) / 2;
function facts() {
  return { present: true, fingerprintSha256: cert.fingerprint256.replace(/:/g, "").toLowerCase(),
    thumbprint: cert.fingerprint.replace(/:/g, ""), hasPrivateKey: true,
    machineKey: true, nonExportable: true, containerMatches: true, keyPossessionVerified: true,
    notBefore: cert.validFrom, notAfter: cert.validTo, serialNumber: cert.serialNumber };
}
function exec(response, error = null) {
  return (file, args, options, cb) => {
    assert.equal(file, "powershell.exe");
    assert.equal(args[2], "-Command");
    assert.match(args[3], new RegExp(`-Container '${containerName}'`));
    assert.equal(options.windowsHide, true);
    cb(error, typeof response === "string" ? response : JSON.stringify(response), "");
    return {};
  };
}
function inspect(response, error) {
  return inspectStoreOnlyCertificate({ certificatePem, containerName, now, execFileImpl: exec(response, error) });
}

test("native store proof requires the exact certificate and protected machine key", async () => {
  assert.equal((await inspect(facts())).status, "complete");
  for (const [field, value] of [["fingerprintSha256", "f".repeat(64)], ["thumbprint", "bad"], ["hasPrivateKey", false],
    ["machineKey", false], ["nonExportable", false], ["containerMatches", false], ["keyPossessionVerified", false], ["notAfter", "invalid"], ["serialNumber", ""]]) {
    assert.equal((await inspect({ ...facts(), [field]: value })).status, "error", field);
  }
});

test("absent is distinct from unreadable or malformed store state", async () => {
  assert.equal((await inspect({ present: false })).status, "absent");
  assert.equal((await inspect("not-json")).status, "error");
  assert.equal((await inspect({})).status, "error");
  assert.equal((await inspect("", Object.assign(new Error("unavailable"), { code: 1 }))).status, "error");
});

test("invalid input is refused without invoking native commands", async () => {
  let calls = 0;
  const execFileImpl = () => { calls++; };
  assert.equal((await inspectStoreOnlyCertificate({ certificatePem, containerName: "foreign", execFileImpl })).status, "error");
  assert.equal((await inspectStoreOnlyCertificate({ certificatePem: "broken", containerName, execFileImpl })).status, "error");
  assert.equal(calls, 0);
});

test("pending request observation binds the issued leaf to the journaled CSR key without authorizing acceptance", async () => {
  const csrSpkiSha256 = createHash("sha256").update(cert.publicKey.export({ type: "spki", format: "der" })).digest("hex");
  let assertions = 0;
  const options = { certificatePem, containerName, csrSpkiSha256, assertHeld: () => { assertions++; }, execFileImpl: exec({ matchingRequests: 1, verified: true }) };
  assert.deepEqual(await inspectPendingStoreRequest(options), { status: "observed", matchingRequests: 1, keyMatches: true, safeToAccept: false });
  assert.equal(assertions, 2);
  for (const response of [{ matchingRequests: 2, verified: true }, { matchingRequests: 0, verified: true }, {}, "not-json"]) {
    assert.deepEqual(await inspectPendingStoreRequest({ ...options, execFileImpl: exec(response) }), { status: "unavailable", safeToAccept: false });
  }
  assert.deepEqual(await inspectPendingStoreRequest({ ...options, execFileImpl: exec({ matchingRequests: 0, verified: false }) }),
    { status: "observed", matchingRequests: 0, keyMatches: false, safeToAccept: false });
});

test("pending request inspection refuses a foreign CSR key or lost authority", async () => {
  const csrSpkiSha256 = createHash("sha256").update(cert.publicKey.export({ type: "spki", format: "der" })).digest("hex");
  let calls = 0;
  const execFileImpl = (...args) => { calls++; return exec({ matchingRequests: 1, verified: true })(...args); };
  const options = { certificatePem, containerName, csrSpkiSha256, assertHeld() {}, execFileImpl };
  assert.deepEqual(await inspectPendingStoreRequest({ ...options, csrSpkiSha256: "0".repeat(64) }), { status: "unavailable", safeToAccept: false });
  assert.equal(calls, 0);
  let assertions = 0;
  assert.deepEqual(await inspectPendingStoreRequest({ ...options, assertHeld() { if (++assertions === 2) throw new Error("lost"); } }),
    { status: "unavailable", safeToAccept: false });
  assert.equal(calls, 1);
  const controller = new AbortController(); controller.abort();
  assert.deepEqual(await inspectPendingStoreRequest({ ...options, signal: controller.signal }), { status: "unavailable", safeToAccept: false });
  assert.equal(calls, 1);
});

test("predecessor lookup requires the exact signed fingerprint and a readable key", async () => {
  let calls = 0;
  const fingerprintSha256 = "a".repeat(64);
  const run = (record) => async (value = fingerprintSha256) => observeStoreOnlyPredecessor({ fingerprintSha256: value,
    execFileImpl: (file, args, opts, cb) => { calls++; assert.equal(file, "powershell.exe");
      assert.match(args[3], new RegExp(fingerprintSha256)); cb(null, JSON.stringify(record), ""); return {}; } });
  const good = { fingerprintSha256, hasPrivateKey: true, serialNumber: "AB12", notAfter: cert.validTo };
  assert.deepEqual(await run(good)(), { existingNotAfter: cert.validTo, existingSerialHex: "AB12" });
  for (const change of [{ fingerprintSha256: "b".repeat(64) }, { hasPrivateKey: false }, { serialNumber: "" }, { notAfter: "invalid" }]) {
    assert.ok((await run({ ...good, ...change })()).error);
  }
  const before = calls;
  assert.deepEqual(await run(good)(null), { existingNotAfter: null, existingSerialHex: null });
  assert.ok((await observeStoreOnlyPredecessor({})).error);
  assert.equal(calls, before);
});

test("the signed store snapshot prevents destination or predecessor tampering", () => {
  const target = { type: "windows-cert-store", reference: "host.example.test", store: "My" };
  const destinationSha256 = createHash("sha256").update(JSON.stringify(target)).digest("hex");
  const snapshot = { destinationType: "windows-cert-store", predecessorFingerprintSha256: null, destinationSha256, authorizedDnsNames: ["HOST.EXAMPLE.TEST"] };
  assert.equal(storeSnapshotTargetError(snapshot, target), null);
  assert.equal(storeSnapshotTargetError({ ...snapshot, predecessorFingerprintSha256: "a".repeat(64) }, target), null);
  for (const next of [{ ...target, reference: "other.example.test" }, { ...target, store: "Root" }, { type: "windows-iis" }]) {
    assert.ok(storeSnapshotTargetError(snapshot, next));
  }
  assert.ok(storeSnapshotTargetError({ ...snapshot, predecessorFingerprintSha256: "invalid" }, target));
  assert.ok(storeSnapshotTargetError({ ...snapshot, authorizedDnsNames: ["other.example.test"] }, target));
  assert.ok(storeSnapshotTargetError({ destinationType: "windows-cert-store", destinationSha256 }, target));
  assert.equal(storeSnapshotTargetError({}, { type: "windows-iis" }), null);
});

function installation(overrides = {}) {
  const calls = [];
  const thumbprint = cert.fingerprint.replace(/:/g, "");
  const fingerprintSha256 = cert.fingerprint256.replace(/:/g, "").toLowerCase();
  const complete = { status: "complete", thumbprint, fingerprintSha256 };
  const lock = { assertHeld() {}, async run(fn) { return fn(new AbortController().signal); }, release() { calls.push("release"); } };
  return { calls, complete, options: {
    certificatePem, containerName, stateDir: "state", workDir: "work", mode: "initial", certificateValidated: true,
    onBeforeMutation: step => calls.push(step), onInstallStep: async step => calls.push(`journal:${step}`),
    acquireLockImpl: (_dir, store) => { assert.equal(store, "My"); return lock; },
    inspectImpl: async () => { calls.push("inspect"); return calls.filter(x => x === "inspect").length === 1 ? { status: "absent" } : complete; },
    acceptImpl: async ({ store }) => { assert.equal(store, "My"); calls.push("accept"); return { ok: true, thumbprint }; },
    readReceiptImpl: () => null, markReceiptImpl: () => { calls.push("receipt"); return true; }, ...overrides,
  } };
}

test("store installation journals before accept and verifies exact key after it", async () => {
  const item = installation();
  const result = await installStoreOnlyCertificate(item.options);
  assert.equal(result.status, "succeeded");
  assert.deepEqual(item.calls, ["inspect", "store-accept", "journal:accept", "accept", "inspect", "store-acceptance-receipt", "receipt", "release"]);
});

test("recovery never repeats accept when a certificate is absent or already installed", async () => {
  const absent = installation({ mode: "recovery", inspectImpl: async () => ({ status: "absent" }) });
  assert.equal((await installStoreOnlyCertificate(absent.options)).status, "failed");
  assert.equal(absent.calls.includes("accept"), false);
  const present = installation({ mode: "recovery" });
  present.options.inspectImpl = async () => present.complete;
  assert.equal((await installStoreOnlyCertificate(present.options)).status, "succeeded");
  assert.equal(present.calls.includes("accept"), false);
});

test("receipt failures require reconciliation and recovery does not accept again", async () => {
  for (const fail of [() => false, () => { throw new Error("write failed"); }]) {
    let attempts = 0;
    const item = installation({ markReceiptImpl: () => { attempts++; return attempts === 1 ? fail() : true; } });
    const result = await installStoreOnlyCertificate(item.options);
    assert.equal(result.status, "failed");
    assert.equal(result.retryableInterrupt, true);
    assert.match(result.errorMessage, /ownership receipt requires reconciliation/);
    assert.equal(item.calls.filter((call) => call === "accept").length, 1);
    item.options.mode = "recovery";
    item.options.inspectImpl = async () => item.complete;
    const recovered = await installStoreOnlyCertificate(item.options);
    assert.equal(recovered.status, "succeeded");
    assert.equal(item.calls.filter((call) => call === "accept").length, 1);
    assert.equal(attempts, 2);
  }
});

test("lease or enrollment-lock loss before accept never starts native mutation", async () => {
  const controller = new AbortController();
  let accepts = 0;
  const item = installation({ signal: controller.signal,
    onInstallStep: async () => { controller.abort(); },
    acceptImpl: async () => { accepts++; return { ok: true }; } });
  const result = await installStoreOnlyCertificate(item.options);
  assert.equal(result.status, "failed");
  assert.equal(result.retryableInterrupt, true);
  assert.equal(accepts, 0);
  assert.equal(item.calls.includes("receipt"), false);
});

test("lease loss during accept aborts the native call and preserves the key for reconciliation", async () => {
  const controller = new AbortController();
  const item = installation({ signal: controller.signal,
    acceptImpl: async ({ signal }) => {
      controller.abort();
      assert.equal(signal.aborted, true);
      return { ok: false, reason: "aborted" };
    } });
  const result = await installStoreOnlyCertificate(item.options);
  assert.equal(result.status, "failed");
  assert.equal(result.retryableInterrupt, true);
  assert.equal(item.calls.includes("receipt"), false);
});

test("AD CS deployment forwards cancellation and reports an uncertain installation for recovery", async () => {
  const store = require("./store-only");
  const original = store.installStoreOnlyCertificate;
  const controller = new AbortController();
  try {
    store.installStoreOnlyCertificate = async ({ signal }) => {
      assert.strictEqual(signal, controller.signal);
      controller.abort();
      return { status: "failed", retryableInterrupt: true, errorMessage: "acceptance aborted" };
    };
    const result = await require("../index").runWindowsIisDeployTail({
      target: { type: "windows-cert-store", reference: "app.example.com", store: "My" },
      storeEnrollmentId: "enrollment", storeDestinationSha256: "a".repeat(64), signal: controller.signal,
    });
    assert.equal(result.status, "orphaned_unknown_effect");
    assert.equal(result.retryableInterrupt, true);
    assert.match(result.errorMessage, /needsOperatorReconciliation=true/);
  } finally {
    store.installStoreOnlyCertificate = original;
  }
});

test("AD CS store proof serializes the active claim with the evidence", async () => {
  const store = require("./store-only");
  const original = store.installStoreOnlyCertificate;
  const fingerprintSha256 = cert.fingerprint256.replace(/:/g, "").toLowerCase();
  let body;
  try {
    store.installStoreOnlyCertificate = async () => ({ status: "succeeded", storeProof: { fingerprintSha256 } });
    const result = await require("../index").runWindowsIisDeployTail({
      jobId: "job-1", client: { async reportEvidence(value) { body = value; } }, certificatePem,
      target: { type: "windows-cert-store", reference: "app.example.com", store: "My" },
      storeEnrollmentId: "enrollment", storeDestinationSha256: "a".repeat(64), leaseOpts: { claimId: "claim-1" },
    });
    assert.equal(result.status, "succeeded");
    assert.equal(body.claimId, "claim-1");
    assert.equal(body.evidenceItems[0].fingerprintSha256, fingerprintSha256);
  } finally {
    store.installStoreOnlyCertificate = original;
  }
});

test("failed acceptance, mismatched proof and accepted receipt cannot delete or reaccept a key", async () => {
  const failed = installation({ acceptImpl: async () => ({ ok: false }) });
  assert.equal((await installStoreOnlyCertificate(failed.options)).retryableInterrupt, true);
  assert.equal(failed.calls.includes("receipt"), false);
  const conflict = installation({ readReceiptImpl: () => ({ containerName, status: "enrolled_by_agent", acceptedThumbprint: "F".repeat(40) }) });
  assert.equal((await installStoreOnlyCertificate(conflict.options)).status, "failed");
  assert.equal(conflict.calls.includes("accept"), false);
  const untrusted = installation({ inspectImpl: async () => ({ status: "complete", thumbprint: "F".repeat(40), fingerprintSha256: "a".repeat(64) }) });
  assert.equal((await installStoreOnlyCertificate(untrusted.options)).status, "failed");
  assert.equal(untrusted.calls.includes("receipt"), false);
  const recoveryMismatch = installation({ mode: "recovery", inspectImpl: async () => ({ status: "error", error: "machine key mismatch" }) });
  assert.equal((await installStoreOnlyCertificate(recoveryMismatch.options)).status, "failed");
  assert.equal(recoveryMismatch.calls.includes("accept"), false);
  assert.equal(recoveryMismatch.calls.includes("receipt"), false);
});

test("lease loss after installation keeps the result recoverable without a second accept", async () => {
  const store = require("./store-only");
  const original = store.installStoreOnlyCertificate;
  const certificatePem = fs.readFileSync(path.join(__dirname, "../verify/fixtures/leaf.crt.pem"), "utf8");
  const fingerprintSha256 = new (require("node:crypto").X509Certificate)(certificatePem).fingerprint256.replace(/:/g, "").toLowerCase();
  let accepts = 0, renewals = 0, evidence = 0, installed = false;
  try {
    store.installStoreOnlyCertificate = async ({ mode }) => {
      if (!installed) { assert.equal(mode, "initial"); accepts++; installed = true; }
      else assert.equal(mode, "recovery");
      return { status: "succeeded", storeProof: { fingerprintSha256 } };
    };
    const args = { jobId: "job-1", client: { async reportEvidence() { evidence++; } }, certificatePem,
      target: { type: "windows-cert-store", reference: "app.example.com", store: "My" }, storeEnrollmentId: "enrollment", storeDestinationSha256: "a".repeat(64),
      leaseOpts: { claimId: "claim-1", leaseClient: { async renewLease() { renewals++; return renewals === 2 ? { ok: false, status: 409 } : { ok: true }; } } } };
    const first = await require("../index").runWindowsIisDeployTail(args);
    assert.equal(first.status, "orphaned_unknown_effect"); assert.match(first.errorMessage, /needsOperatorReconciliation=true/); assert.equal(evidence, 0);
    const recovery = await require("../index").runWindowsIisDeployTail({ ...args, storeRecovery: true });
    assert.equal(recovery.status, "succeeded"); assert.equal(accepts, 1); assert.equal(evidence, 1);
  } finally { store.installStoreOnlyCertificate = original; }
});
