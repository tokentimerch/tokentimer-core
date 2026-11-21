"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { createRunDnsName, readCandidateArchive, verifyCrashRecovery } = require("./certops-acme-store-native-qualification");

function sample(phase) {
  const fp = "a".repeat(64), spki = "b".repeat(64), archive = "c".repeat(64);
  const dnsName = "tt-acme-0123456789abcdef01234567.example.test";
  const containerName = "tokentimer-enr-11111111-1111-1111-1111-111111111111";
  const counter = (orders, keygens, accepts) => ({ captureId: "d".repeat(32), coverageComplete: true, orders, keygens, accepts });
  const ca = { source: "independent-ca", coverageComplete: true, coverageId: "f".repeat(32), dnsName, orderId: "order-1", ordersForDns: 1, finalizedOrdersForDns: 1, fingerprintSha256: fp };
  const saved = phase === "after-save-upload-lost";
  return {
    phase, dnsName, candidateSha256: archive, before: counter(0, 0, 0), atFault: counter(1, 1, 0),
    after: counter(1, 1, saved ? 1 : 0), caAtFault: { ...ca }, caAfter: { ...ca },
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
  for (const ca of [proof.caAtFault, proof.caAfter]) {
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
