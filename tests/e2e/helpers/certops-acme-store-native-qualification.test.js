"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { createRunDnsName, readCandidateArchive, verifyCrashRecovery, qualifyCrashRecovery } = require("./certops-acme-store-native-qualification");
// Expose private functions only inside this test module. The loadable
// qualification module offers no entry point for passing real fixtures.
const isolated = { exports: {} };
const testSource = fs.readFileSync(path.join(__dirname, "certops-acme-store-native-qualification.js"), "utf8");
new Function("require", "module", "exports", testSource + "\nmodule.exports = { exerciseSyntheticCoordinator, runObservedAction };")(require, isolated, isolated.exports);
const { exerciseSyntheticCoordinator, runObservedAction } = isolated.exports;

test("a rejection without a reason still aborts and drains the action", async () => {
  let drains = 0;
  const fixture = { abortAndDrainAction: async () => {
    drains += 1;
    return { drained: true };
  } };
  await assert.rejects(
    runObservedAction(fixture, new AbortController().signal, () => Promise.reject(), {}),
    error => error instanceof AggregateError && error.preserveObservers === false,
  );
  assert.equal(drains, 1);
});

// Unit-test adapter: the real fixture must create its observer without
// side effects and return matching independently verified drainage evidence.
function withCaLifecycle(fixture) {
  const records = new Map();
  return { ...fixture,
    abortAndDrainAction: async () => ({ drained: true }),
    createCapture: async options => {
      const actual = await fixture.startCapture(options);
      let lastCounter;
      return {
        signal: new AbortController().signal,
        start: async () => {},
        read: typeof actual?.read === "function" ? async () => { lastCounter = await actual.read(); return lastCounter; } : undefined,
        stop: async () => ({ ...(await actual.stop()), finalCounter: lastCounter }),
      };
    },
    createCaObservation: fixture.createCaObservation || (async () => {
      let lastCa;
      return { signal: new AbortController().signal, start: async () => {}, read: async options => { lastCa = await fixture.observeCa(options); return lastCa; },
        stop: async () => ({ drained: true, coverageId: "f".repeat(32), finalObservation: lastCa }) };
    }),
    persistEvidence: async ({ recordJson, sha256 }) => {
      if (fixture.onEvidence) await fixture.onEvidence(JSON.parse(recordJson), recordJson);
      const receiptId = sha256.slice(0, 32);
      records.set(receiptId, recordJson);
      return { flushed: true, receiptId };
    },
    readEvidence: async ({ receiptId }) => records.get(receiptId),
  };
}

function sample(phase) {
  const fp = "a".repeat(64), spki = "b".repeat(64), archive = "c".repeat(64);
  const dnsName = "tt-acme-0123456789abcdef01234567.example.test";
  const containerName = "tokentimer-enr-11111111-1111-1111-1111-111111111111";
  const counter = (orders, keygens, accepts) => ({ captureId: "d".repeat(32), coverageComplete: true, orders, keygens, accepts });
  const ca = { source: "independent-ca", coverageComplete: true, coverageId: "f".repeat(32), dnsName, orderId: "order-1", ordersForDns: 1, finalizedOrdersForDns: 1, fingerprintSha256: fp };
  const saved = phase === "after-save-upload-lost";
  return {
    phase, dnsName, candidateSha256: archive, before: counter(0, 0, 0), atFault: counter(1, 1, 0),
    after: counter(1, 1, saved ? 1 : 0), caBefore: { ...ca, orderId: null, ordersForDns: 0, finalizedOrdersForDns: 0, fingerprintSha256: null }, caAtFault: { ...ca }, caAfter: { ...ca },
    fault: { phase, candidateSha256: archive, nativeIdentity: "LocalSystem", noIis: true,
      nativeProcessDrained: true, caFinalizationObserved: true, containerName,
      csrSpkiSha256: spki, keySpkiSha256: spki, machineKey: true, nonExportable: true,
      keyPossessionVerified: true, leafDurable: saved, evidenceUploadDropped: saved,
      ...(saved ? { fingerprintSha256: fp, leafSpkiSha256: spki } : {}) },
    recovered: { outcome: saved ? "installed" : "uncertain", containerName, csrSpkiSha256: spki,
      keySpkiSha256: spki, machineKey: true, nonExportable: true, keyPossessionVerified: true,
      ...(saved ? { fingerprintSha256: fp, leafSpkiSha256: spki, store: "LocalMachine\\My" } : { outcomeVisible: true }) },
    inventory: { provisioningRegistrations: 1, promotions: saved ? 1 : 0, serviceVerified: false,
      fingerprintSha256: saved ? fp : null },
  };
}

test("both interruption boundaries require a continuous independent trace", () => {
  assert.equal(verifyCrashRecovery(sample("after-finalization-before-save")), true);
  assert.equal(verifyCrashRecovery(sample("after-save-upload-lost")), true);
  for (const [section, key, value] of [
    ["atFault", "orders", 2], ["after", "orders", 2], ["after", "keygens", 2],
    ["before", "coverageComplete", false], ["after", "captureId", "e".repeat(32)],
    ["caAfter", "ordersForDns", 2], ["caAfter", "orderId", "different"],
    ["caAfter", "coverageComplete", false], ["caAfter", "coverageId", "e".repeat(32)],
    ["caBefore", "coverageComplete", false], ["caBefore", "coverageId", "e".repeat(32)], ["caBefore", "ordersForDns", 1],
    ["fault", "nativeProcessDrained", false], ["fault", "noIis", false],
    ["fault", "keySpkiSha256", "e".repeat(64)], ["fault", "evidenceUploadDropped", false],
    ["recovered", "outcome", "uncertain"], ["inventory", "promotions", 2],
  ]) {
    const proof = sample("after-save-upload-lost"); proof[section][key] = value;
    assert.throws(() => verifyCrashRecovery(proof), `${section}.${key}`);
  }
});

test("pre-save uncertainty retains the original key and performs no acceptance", () => {
  const proof = sample("after-finalization-before-save");
  assert.equal(verifyCrashRecovery(proof), true);
  for (const [section, key, value] of [
    ["fault", "leafDurable", true], ["recovered", "outcomeVisible", false],
    ["after", "accepts", 1], ["inventory", "promotions", 1],
    ["recovered", "containerName", "tokentimer-enr-22222222-2222-2222-2222-222222222222"],
  ]) {
    const mutated = structuredClone(proof); mutated[section][key] = value;
    assert.throws(() => verifyCrashRecovery(mutated), `${section}.${key}`);
  }
});

test("a proxy-based CA observation requires the same verified isolation interval", () => {
  const proof = sample("after-save-upload-lost");
  for (const ca of [proof.caBefore, proof.caAtFault, proof.caAfter]) {
    ca.source = "isolated-ca-proxy"; ca.coverageComplete = true; ca.coverageId = "f".repeat(32);
  }
  assert.equal(verifyCrashRecovery(proof), true);
  proof.caAfter.coverageId = "e".repeat(32);
  assert.throws(() => verifyCrashRecovery(proof));
  proof.caAfter.coverageId = proof.caAtFault.coverageId;
  proof.caAfter.coverageComplete = false;
  assert.throws(() => verifyCrashRecovery(proof));
});

test("run names are unique and candidate archive digest is independently checked", () => {
  assert.notEqual(createRunDnsName("example.test"), createRunDnsName("example.test"));
  assert.throws(() => createRunDnsName("example.test;unsafe"));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "acme-candidate-"));
  try {
    const archive = path.join(dir, "agent.zip");
    fs.writeFileSync(archive, "candidate");
    const sha = createHash("sha256").update("candidate").digest("hex");
    assert.equal(readCandidateArchive(archive, sha), sha);
    assert.throws(() => readCandidateArchive(archive, "0".repeat(64)));
    assert.throws(() => readCandidateArchive("relative.zip", sha));
  } finally { fs.unlinkSync(path.join(dir, "agent.zip")); fs.rmdirSync(dir); }
});

// skip-reason: platform
test("incomplete capture or CA baseline prevents key generation and orders", { skip: process.platform !== "win32" }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "acme-baseline-"));
  const archive = path.join(dir, "agent.zip");
  const previous = process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
  const sha = createHash("sha256").update("candidate").digest("hex");
  try {
    fs.writeFileSync(archive, "candidate");
    process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = "1";
    for (const failing of ["capture", "ca"]) {
      let submissions = 0, stopped = 0;
      const fixture = {
        inspectHost: async () => ({ nativeIdentity: "LocalSystem", noIis: true, agentArchiveSha256: sha, storeOnlyAcmeCapability: true }),
        prepareRun: async () => {},
        startCapture: async () => ({ read: async () => ({ coverageComplete: failing !== "capture", captureId: "d".repeat(32), orders: 0, keygens: 0, accepts: 0 }), stop: async () => { stopped++; return { drained: true, captureId: "d".repeat(32) }; } }),
        observeCa: async ({ dnsName }) => ({ source: "independent-ca", coverageComplete: failing !== "ca", coverageId: "f".repeat(32), dnsName, ordersForDns: 0, finalizedOrdersForDns: 0 }),
        issueAndInterrupt: async () => { submissions++; }, restartAndRecover: async () => {}, readInventory: async () => {},
      };
      await assert.rejects(exerciseSyntheticCoordinator({ fixture: withCaLifecycle(fixture), archivePath: archive, archiveSha256: sha, zone: "example.test" }), /cover the whole run/);
      assert.equal(submissions, 0);
      assert.equal(stopped, 1);
    }
  } finally {
    if (previous === undefined) delete process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
    else process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = previous;
    if (fs.existsSync(archive)) fs.unlinkSync(archive);
    fs.rmdirSync(dir);
  }
});

// skip-reason: platform
test("failed capture drainage is reported alongside the original refusal", { skip: process.platform !== "win32" }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "acme-drain-"));
  const archive = path.join(dir, "agent.zip");
  const previous = process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
  const sha = createHash("sha256").update("candidate").digest("hex");
  try {
    fs.writeFileSync(archive, "candidate");
    process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = "1";
    let submissions = 0;
    const fixture = {
      inspectHost: async () => ({ nativeIdentity: "LocalSystem", noIis: true, agentArchiveSha256: sha, storeOnlyAcmeCapability: true }),
      prepareRun: async () => {},
      startCapture: async () => ({ read: async () => ({ coverageComplete: false }), stop: async () => ({ drained: false }) }),
      observeCa: async ({ dnsName }) => ({ source: "independent-ca", coverageComplete: true, coverageId: "f".repeat(32), dnsName, ordersForDns: 0, finalizedOrdersForDns: 0 }), issueAndInterrupt: async () => { submissions++; },
      restartAndRecover: async () => {}, readInventory: async () => {},
    };
    await assert.rejects(exerciseSyntheticCoordinator({ fixture: withCaLifecycle(fixture), archivePath: archive, archiveSha256: sha, zone: "example.test" }),
      error => error instanceof AggregateError && error.errors.some(e => /Independent capture/.test(e.message)) &&
        error.errors.some(e => /drainage/.test(e.message)));
    assert.equal(submissions, 0);
  } finally {
    if (previous === undefined) delete process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
    else process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = previous;
    if (fs.existsSync(archive)) fs.unlinkSync(archive);
    fs.rmdirSync(dir);
  }
});

// skip-reason: platform
test("the CA baseline is taken before either native issue attempt", { skip: process.platform !== "win32" }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "acme-order-"));
  const archive = path.join(dir, "agent.zip");
  const previous = process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
  const sha = createHash("sha256").update("candidate").digest("hex");
  try {
    fs.writeFileSync(archive, "candidate");
    process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = "1";
    const calls = [];
    const fixture = {
      inspectHost: async () => ({ nativeIdentity: "LocalSystem", noIis: true, agentArchiveSha256: sha, storeOnlyAcmeCapability: true }),
      prepareRun: async ({ phase }) => { calls.push([phase, "prepare"]); },
      startCapture: async ({ phase }) => {
        let read = 0;
        const proof = sample(phase);
        return {
          read: async () => [proof.before, proof.before, proof.atFault, proof.atFault, proof.after][read++],
          stop: async () => ({ drained: true, captureId: proof.before.captureId }),
        };
      },
      observeCa: async ({ phase, dnsName, boundary }) => {
        const proof = sample(phase);
        const event = boundary === "before-capture" ? "baseline" : boundary === "after-capture-start" ? "ready" : boundary === "after-prepare" ? "prepared" : boundary === "before-recovery" ? "recovery-ready" : calls.some(([p, e]) => p === phase && e === "recover") ? "after" : "fault";
        calls.push([phase, event]);
        return { ...(["baseline", "ready", "prepared"].includes(event) ? proof.caBefore : ["fault", "recovery-ready"].includes(event) ? proof.caAtFault : proof.caAfter), dnsName };
      },
      issueAndInterrupt: async ({ phase }) => {
        calls.push([phase, "issue"]);
        return { ...sample(phase).fault, candidateSha256: sha };
      },
      restartAndRecover: async ({ phase }) => { calls.push([phase, "recover"]); return sample(phase).recovered; },
      readInventory: async ({ phase }) => sample(phase).inventory,
    };
    const results = await exerciseSyntheticCoordinator({ fixture: withCaLifecycle(fixture), archivePath: archive, archiveSha256: sha, zone: "example.test" });
    assert.equal(results.length, 2);
    for (const result of results) {
      assert.equal(result.fault.phase, result.phase);
      assert.equal(result.caBefore.dnsName, result.dnsName);
      assert.equal(result.caAtFault.dnsName, result.dnsName);
      assert.equal(result.caAfter.dnsName, result.dnsName);
      assert.equal(verifyCrashRecovery(JSON.parse(JSON.stringify(result))), true);
    }
    for (const phase of ["after-finalization-before-save", "after-save-upload-lost"]) {
      assert.deepEqual(calls.filter(([p]) => p === phase).map(([, e]) => e), ["baseline", "ready", "prepare", "prepared", "issue", "fault", "recovery-ready", "recover", "after"]);
    }
  } finally {
    if (previous === undefined) delete process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
    else process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = previous;
    if (fs.existsSync(archive)) fs.unlinkSync(archive);
    fs.rmdirSync(dir);
  }
});

// skip-reason: platform
test("partially initialized capture is drained before refusing to issue", { skip: process.platform !== "win32" }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "acme-partial-"));
  const archive = path.join(dir, "agent.zip");
  const previous = process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
  const sha = createHash("sha256").update("candidate").digest("hex");
  let submissions = 0, stopped = 0;
  try {
    fs.writeFileSync(archive, "candidate");
    process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = "1";
    const fixture = {
      inspectHost: async () => ({ nativeIdentity: "LocalSystem", noIis: true, agentArchiveSha256: sha, storeOnlyAcmeCapability: true }),
      prepareRun: async () => {},
      startCapture: async () => ({ stop: async () => { stopped++; return { drained: true, captureId: "d".repeat(32) }; } }),
      observeCa: async () => {}, issueAndInterrupt: async () => { submissions++; },
      restartAndRecover: async () => {}, readInventory: async () => {},
    };
    await assert.rejects(exerciseSyntheticCoordinator({ fixture: withCaLifecycle(fixture), archivePath: archive, archiveSha256: sha, zone: "example.test" }), /Native operation capture/);
    assert.equal(stopped, 1);
    assert.equal(submissions, 0);
  } finally {
    if (previous === undefined) delete process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
    else process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = previous;
    if (fs.existsSync(archive)) fs.unlinkSync(archive);
    fs.rmdirSync(dir);
  }
});

// skip-reason: platform
test("invalid fault checkpoints do not restart the agent", { skip: process.platform !== "win32" }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "acme-fault-"));
  const archive = path.join(dir, "agent.zip");
  const previous = process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
  const sha = createHash("sha256").update("candidate").digest("hex");
  try {
    fs.writeFileSync(archive, "candidate");
    process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = "1";
    for (const failing of ["capture", "ca", "drain"]) {
      let reads = 0, observations = 0, recoveries = 0, stopped = 0;
      const fixture = {
        inspectHost: async () => ({ nativeIdentity: "LocalSystem", noIis: true, agentArchiveSha256: sha, storeOnlyAcmeCapability: true }),
        prepareRun: async () => {},
        startCapture: async () => ({
          read: async () => ({ coverageComplete: ++reads < 3 || failing !== "capture", captureId: "d".repeat(32), orders: reads < 3 ? 0 : 1, keygens: reads < 3 ? 0 : 1, accepts: 0 }),
          stop: async () => { stopped++; return { drained: true, captureId: "d".repeat(32) }; },
        }),
        observeCa: async ({ dnsName }) => {
          const count = observations++;
          return { source: "independent-ca", coverageComplete: count < 3 || failing !== "ca", coverageId: "f".repeat(32), dnsName,
            ordersForDns: count < 3 ? 0 : 1, finalizedOrdersForDns: count < 3 ? 0 : 1,
            orderId: "order", fingerprintSha256: "a".repeat(64) };
        },
        issueAndInterrupt: async ({ phase }) => ({ ...sample(phase).fault, candidateSha256: sha, nativeProcessDrained: failing !== "drain" }),
        restartAndRecover: async () => { recoveries++; }, readInventory: async () => {},
      };
      await assert.rejects(exerciseSyntheticCoordinator({ fixture: withCaLifecycle(fixture), archivePath: archive, archiveSha256: sha, zone: "example.test" }), /coverage|cover the whole run|drainage/);
      assert.equal(recoveries, 0);
      assert.equal(stopped, 1);
    }
  } finally {
    if (previous === undefined) delete process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
    else process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = previous;
    if (fs.existsSync(archive)) fs.unlinkSync(archive);
    fs.rmdirSync(dir);
  }
});

// skip-reason: platform
test("preparation cannot create native operations or replace either observation", { skip: process.platform !== "win32" }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "acme-prepare-"));
  const archive = path.join(dir, "agent.zip");
  const previous = process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
  const sha = createHash("sha256").update("candidate").digest("hex");
  try {
    fs.writeFileSync(archive, "candidate");
    process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = "1";
    for (const change of ["key", "order", "capture", "ca", "caOrder"]) {
      let reads = 0, observations = 0, submissions = 0, stopped = 0;
      const fixture = {
        inspectHost: async () => ({ nativeIdentity: "LocalSystem", noIis: true, agentArchiveSha256: sha, storeOnlyAcmeCapability: true }),
        prepareRun: async () => {},
        startCapture: async () => ({
          read: async () => { reads++; return { coverageComplete: true, captureId: reads > 1 && change === "capture" ? "e".repeat(32) : "d".repeat(32),
            orders: reads > 1 && change === "order" ? 1 : 0, keygens: reads > 1 && change === "key" ? 1 : 0, accepts: 0 }; },
          stop: async () => { stopped++; return { drained: true, captureId: "d".repeat(32) }; },
        }),
        observeCa: async ({ dnsName }) => { observations++; return { source: "independent-ca", coverageComplete: true,
          coverageId: observations > 2 && change === "ca" ? "e".repeat(32) : "f".repeat(32), dnsName,
          ordersForDns: observations > 2 && change === "caOrder" ? 1 : 0, finalizedOrdersForDns: 0 }; },
        issueAndInterrupt: async () => { submissions++; }, restartAndRecover: async () => {}, readInventory: async () => {},
      };
      await assert.rejects(exerciseSyntheticCoordinator({ fixture: withCaLifecycle(fixture), archivePath: archive, archiveSha256: sha, zone: "example.test" }));
      assert.equal(submissions, 0);
      assert.equal(stopped, 1);
    }
  } finally {
    if (previous === undefined) delete process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
    else process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = previous;
    if (fs.existsSync(archive)) fs.unlinkSync(archive);
    fs.rmdirSync(dir);
  }
});

// skip-reason: platform
test("a CA start failure drains both observers and preserves all cleanup errors", { skip: process.platform !== "win32" }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "acme-ca-cleanup-"));
  const archive = path.join(dir, "agent.zip");
  const previous = process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
  const sha = createHash("sha256").update("candidate").digest("hex");
  try {
    fs.writeFileSync(archive, "candidate");
    process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = "1";
    for (const failCleanup of [false, true]) {
      let nativeStopped = 0, caStopped = 0, submissions = 0;
      const fixture = {
        inspectHost: async () => ({ nativeIdentity: "LocalSystem", noIis: true, agentArchiveSha256: sha, storeOnlyAcmeCapability: true }),
        prepareRun: async () => {},
        startCapture: async () => ({
          read: async () => ({ coverageComplete: true, captureId: "d".repeat(32), orders: 0, keygens: 0, accepts: 0 }),
          stop: async () => { nativeStopped++; if (failCleanup) throw new Error("native cleanup failed"); return { drained: true, captureId: "d".repeat(32) }; },
        }),
        createCaObservation: async () => ({
          start: async () => { throw new Error("CA start failed"); },
          read: async () => {},
          stop: async () => { caStopped++; if (failCleanup) throw new Error("CA cleanup failed"); return { drained: true, coverageId: "f".repeat(32) }; },
        }),
        issueAndInterrupt: async () => { submissions++; }, restartAndRecover: async () => {}, readInventory: async () => {},
      };
      const adapted = withCaLifecycle(fixture);
      adapted.createCapture = async () => ({
        start: async () => { throw new Error("native capture must not start before CA"); },
        read: async () => {},
        stop: async () => { nativeStopped++; if (failCleanup) throw new Error("native cleanup failed"); return { drained: true, captureId: "d".repeat(32) }; },
      });
      await assert.rejects(exerciseSyntheticCoordinator({ fixture: adapted, archivePath: archive, archiveSha256: sha, zone: "example.test" }), error => {
        if (!failCleanup) return /CA start failed/.test(error.message);
        return error instanceof AggregateError && error.errors.length === 3 &&
          error.errors.some(e => /CA start failed/.test(e.message)) &&
          error.errors.some(e => /CA cleanup failed/.test(e.message)) &&
          error.errors.some(e => /native cleanup failed/.test(e.message));
      });
      assert.equal(caStopped, 1);
      assert.equal(nativeStopped, 1);
      assert.equal(submissions, 0);
    }
  } finally {
    if (previous === undefined) delete process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
    else process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = previous;
    if (fs.existsSync(archive)) fs.unlinkSync(archive);
    fs.rmdirSync(dir);
  }
});

// skip-reason: platform
test("evidence readback or flush failure blocks issue or recovery without saving secrets", { skip: process.platform !== "win32" }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "acme-evidence-"));
  const archive = path.join(dir, "agent.zip");
  const previous = process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
  const sha = createHash("sha256").update("candidate").digest("hex");
  try {
    fs.writeFileSync(archive, "candidate");
    process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = "1";
    for (const failure of ["readback", "fault-flush"]) {
      let currentStage, submissions = 0, recoveries = 0, nativeStopped = 0, caStopped = 0;
      const records = [];
      const fixture = {
        inspectHost: async () => ({ nativeIdentity: "LocalSystem", noIis: true, agentArchiveSha256: sha, storeOnlyAcmeCapability: true }),
        prepareRun: async () => {},
        startCapture: async () => ({
          read: async () => ({ coverageComplete: true, captureId: "d".repeat(32), orders: 0, keygens: 0, accepts: 0 }),
          stop: async () => { nativeStopped++; return { drained: true, captureId: "d".repeat(32) }; },
        }),
        createCaObservation: async () => ({
          signal: new AbortController().signal,
          start: async () => {},
          read: async ({ dnsName }) => ({ source: "independent-ca", coverageComplete: true, coverageId: "f".repeat(32), dnsName, ordersForDns: 0, finalizedOrdersForDns: 0 }),
          stop: async () => { caStopped++; return { drained: true, coverageId: "f".repeat(32) }; },
        }),
        issueAndInterrupt: async ({ phase }) => {
          submissions++;
          return { ...sample(phase).fault, candidateSha256: sha, privateKeyPem: "SENTINEL_PRIVATE_KEY", rawPayload: "SENTINEL_PAYLOAD" };
        },
        restartAndRecover: async () => { recoveries++; }, readInventory: async () => {},
        onEvidence: async (record, raw) => {
          currentStage = record.stage;
          records.push(raw);
          if (failure === "fault-flush" && record.stage === "fault-observed") throw new Error("SENTINEL_PRIVATE_ERROR");
        },
      };
      const adapted = withCaLifecycle(fixture);
      const read = adapted.readEvidence;
      adapted.readEvidence = async options => {
        const result = await read(options);
        return failure === "readback" && currentStage === "prepared" ? "tampered" : result;
      };
      await assert.rejects(exerciseSyntheticCoordinator({ fixture: adapted, archivePath: archive, archiveSha256: sha, zone: "example.test" }));
      assert.equal(submissions, failure === "fault-flush" ? 1 : 0);
      assert.equal(recoveries, 0);
      assert.equal(nativeStopped, 1);
      assert.equal(caStopped, 1);
      assert.ok(records.some(raw => JSON.parse(raw).stage === "failed"));
      assert.ok(records.every(raw => !raw.includes("SENTINEL_")));
    }
  } finally {
    if (previous === undefined) delete process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
    else process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = previous;
    if (fs.existsSync(archive)) fs.unlinkSync(archive);
    fs.rmdirSync(dir);
  }
});

// skip-reason: platform
test("a native capture start failure is drained and recorded", { skip: process.platform !== "win32" }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "acme-native-start-"));
  const archive = path.join(dir, "agent.zip");
  const previous = process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
  const sha = createHash("sha256").update("candidate").digest("hex");
  try {
    fs.writeFileSync(archive, "candidate");
    process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = "1";
    let stopped = 0, submissions = 0;
    const records = [];
    const fixture = withCaLifecycle({
      inspectHost: async () => ({ nativeIdentity: "LocalSystem", noIis: true, agentArchiveSha256: sha, storeOnlyAcmeCapability: true }),
      prepareRun: async () => {}, startCapture: async () => {}, observeCa: async ({ dnsName }) => ({ source: "independent-ca", coverageComplete: true, coverageId: "f".repeat(32), dnsName, ordersForDns: 0, finalizedOrdersForDns: 0 }),
      issueAndInterrupt: async () => { submissions++; }, restartAndRecover: async () => {}, readInventory: async () => {},
      onEvidence: async record => { records.push(record); },
    });
    fixture.createCapture = async () => ({
      start: async () => { throw new Error("private start message"); },
      read: async () => {}, stop: async () => { stopped++; return { drained: true, captureId: "d".repeat(32) }; },
    });
    await assert.rejects(exerciseSyntheticCoordinator({ fixture, archivePath: archive, archiveSha256: sha, zone: "example.test" }), /private start message/);
    assert.equal(stopped, 1);
    assert.equal(submissions, 0);
    assert.ok(records.some(record => record.stage === "failed" && record.point === "capture-start"));
    assert.ok(!JSON.stringify(records).includes("private start message"));
  } finally {
    if (previous === undefined) delete process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
    else process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = previous;
    if (fs.existsSync(archive)) fs.unlinkSync(archive);
    fs.rmdirSync(dir);
  }
});


// skip-reason: platform
test("drainage refuses late activity and reused evidence receipts", { skip: process.platform !== "win32" }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "acme-final-drain-"));
  const archive = path.join(dir, "agent.zip");
  const previous = process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
  const sha = createHash("sha256").update("candidate").digest("hex");
  try {
    fs.writeFileSync(archive, "candidate");
    process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = "1";
    for (const change of ["native", "ca", "receipt", "before-recovery"]) {
      let recovery = false, reads = 0, submissions = 0, nativeStopped = 0, caStopped = 0;
      const stages = [];
      const raw = {
        inspectHost: async () => ({ nativeIdentity: "LocalSystem", noIis: true, agentArchiveSha256: sha, storeOnlyAcmeCapability: true }),
        prepareRun: async () => {},
        startCapture: async ({ phase }) => {
          const proof = sample(phase);
          return { read: async () => {
            const counter = [proof.before, proof.before, proof.atFault, proof.atFault, proof.after][reads++];
            return change === "before-recovery" && reads === 4 ? { ...counter, keygens: 2 } : counter;
          }, stop: async () => { nativeStopped++; return { drained: true, captureId: proof.before.captureId }; } };
        },
        observeCa: async ({ phase, dnsName, boundary }) => {
          const proof = sample(phase);
          return { ...(["before-capture", "after-capture-start", "after-prepare"].includes(boundary) ? proof.caBefore : recovery ? proof.caAfter : proof.caAtFault), dnsName };
        },
        issueAndInterrupt: async ({ phase }) => { submissions++; return { ...sample(phase).fault, candidateSha256: sha }; },
        restartAndRecover: async ({ phase }) => { recovery = true; return sample(phase).recovered; },
        readInventory: async ({ phase }) => sample(phase).inventory,
        onEvidence: async record => stages.push(record.stage),
      };
      const fixture = withCaLifecycle(raw);
      const captureFactory = fixture.createCapture;
      fixture.createCapture = async options => {
        const capture = await captureFactory(options);
        const stop = capture.stop;
        capture.stop = async () => {
          const result = await stop();
          return change === "native" ? { ...result, finalCounter: { ...result.finalCounter, keygens: 2 } } : result;
        };
        return capture;
      };
      const caFactory = fixture.createCaObservation;
      fixture.createCaObservation = async options => {
        const ca = await caFactory(options);
        const stop = ca.stop;
        ca.stop = async () => {
          caStopped++;
          const result = await stop();
          return change === "ca" ? { ...result, finalObservation: { ...result.finalObservation, ordersForDns: 2 } } : result;
        };
        return ca;
      };
      if (change === "receipt") {
        const save = fixture.persistEvidence;
        let first;
        fixture.persistEvidence = async data => { const result = await save(data); first ||= result.receiptId; return { ...result, receiptId: first }; };
      }
      await assert.rejects(exerciseSyntheticCoordinator({ fixture, archivePath: archive, archiveSha256: sha, zone: "example.test" }));
      assert.ok(!stages.includes("completed"));
      if (change === "receipt") assert.equal(submissions, 0);
      else {
        assert.equal(submissions, 1);
        assert.equal(nativeStopped, 1);
        assert.equal(caStopped, 1);
        if (change === "before-recovery") assert.equal(recovery, false);
      }
    }
  } finally {
    if (previous === undefined) delete process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
    else process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = previous;
    if (fs.existsSync(archive)) fs.unlinkSync(archive);
    fs.rmdirSync(dir);
  }
});

test("the real qualification entry point remains closed", async () => {
  await assert.rejects(qualifyCrashRecovery(), /not qualified/);
});

test("observation loss interrupts and drains the in-flight action", async () => {
  for (const failDrain of [false, true]) {
    const controller = new AbortController();
    let aborted = false, drains = 0;
    const fixture = { abortAndDrainAction: async () => { drains++; return { drained: !failDrain }; } };
    const action = ({ signal }) => new Promise((resolve, reject) => {
      signal.addEventListener("abort", () => { aborted = true; reject(new Error("action stopped")); }, { once: true });
      queueMicrotask(() => controller.abort());
    });
    await assert.rejects(runObservedAction(fixture, controller.signal, action, {}), error =>
      error instanceof AggregateError && error.errors.some(item => /coverage was lost/.test(item.message)) &&
      (!failDrain || error.errors.some(item => /drainage/.test(item.message))));
    assert.equal(aborted, true);
    assert.equal(drains, 1);
  }
});

test("a stuck action-drain hook times out and preserves the coverage-loss error", async () => {
  const controller = new AbortController();
  let drains = 0;
  const fixture = { abortAndDrainAction: async () => { drains++; return new Promise(() => {}); } };
  const action = ({ signal }) => new Promise((_, reject) => {
    signal.addEventListener("abort", () => reject(new Error("action stopped")), { once: true });
    queueMicrotask(() => controller.abort());
  });
  await assert.rejects(runObservedAction(fixture, controller.signal, action, {}), error =>
    error instanceof AggregateError && error.errors.some(item => /coverage was lost/.test(item.message)) &&
    error.errors.some(item => /drainage timed out/.test(item.message)) &&
    error.errors.some(item => /action stopped/.test(item.message)));
  assert.equal(drains, 1);
});

// skip-reason: platform
test("undrained in-flight action retains observers and requires intervention", { skip: process.platform !== "win32" }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "acme-retain-observers-"));
  const archive = path.join(dir, "agent.zip");
  const previous = process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
  const sha = createHash("sha256").update("candidate").digest("hex");
  try {
    fs.writeFileSync(archive, "candidate");
    process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = "1";
    const controller = new AbortController();
    let nativeStopped = 0, caStopped = 0, recoveries = 0;
    const stages = [];
    const raw = {
      inspectHost: async () => ({ nativeIdentity: "LocalSystem", noIis: true, agentArchiveSha256: sha, storeOnlyAcmeCapability: true }),
      prepareRun: async () => {},
      startCapture: async () => ({
        read: async () => ({ coverageComplete: true, captureId: "d".repeat(32), orders: 0, keygens: 0, accepts: 0 }),
        stop: async () => { nativeStopped++; return { drained: true, captureId: "d".repeat(32) }; },
      }),
      observeCa: async ({ dnsName }) => ({ source: "independent-ca", coverageComplete: true, coverageId: "f".repeat(32), dnsName, ordersForDns: 0, finalizedOrdersForDns: 0 }),
      issueAndInterrupt: async ({ signal }) => new Promise((_, reject) => {
        signal.addEventListener("abort", () => reject(new Error("action stopped")), { once: true });
        queueMicrotask(() => controller.abort());
      }),
      restartAndRecover: async () => { recoveries++; }, readInventory: async () => {},
      onEvidence: async record => stages.push(record.stage),
    };
    const fixture = withCaLifecycle(raw);
    const captureFactory = fixture.createCapture;
    fixture.createCapture = async options => ({ ...await captureFactory(options), signal: controller.signal });
    const caFactory = fixture.createCaObservation;
    fixture.createCaObservation = async options => {
      const observer = await caFactory(options), stop = observer.stop;
      observer.stop = async () => { caStopped++; return stop(); };
      return observer;
    };
    fixture.abortAndDrainAction = async () => ({ drained: false });
    await assert.rejects(exerciseSyntheticCoordinator({ fixture, archivePath: archive, archiveSha256: sha, zone: "example.test" }), /coverage lost/);
    assert.equal(nativeStopped, 0);
    assert.equal(caStopped, 0);
    assert.equal(recoveries, 0);
    assert.ok(stages.includes("observers-preserved"));
    assert.ok(!stages.includes("completed"));
  } finally {
    if (previous === undefined) delete process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
    else process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = previous;
    if (fs.existsSync(archive)) fs.unlinkSync(archive);
    fs.rmdirSync(dir);
  }
});

test("a rejected action must drain before observers can be stopped", async () => {
  for (const drained of [true, false]) {
    let drains = 0;
    const fixture = { abortAndDrainAction: async () => { drains++; return { drained }; } };
    const signal = new AbortController().signal;
    await assert.rejects(runObservedAction(fixture, signal, async () => { throw new Error("child launch failed"); }, {}), error =>
      error instanceof AggregateError && error.errors.some(item => /child launch failed/.test(item.message)) &&
      error.preserveObservers === !drained &&
      (drained || error.errors.some(item => /drainage/.test(item.message))));
    assert.equal(drains, 1);
  }
});
