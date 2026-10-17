"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const journey = require("../tests/e2e/helpers/certops-acme-key-reuse");
const contract = journey.variants;

const ROOT = path.resolve(__dirname, "..");

function registration() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "_registration", "cross-coverage.json"), "utf8"));
}

test("registration stays partial and does not promote catalog rows", () => {
  const body = registration();
  assert.equal(body.status, "partial");
  assert.equal(body.promotesCatalogRows, false);
  assert.equal(body.claimsQualification, false);
  assert.equal(body.hostCapabilityAbsentIsPass, false);
  const suite = body.suites.find((item) => item.id === contract.SUITE);
  assert.equal(suite.status, "partial");
  assert.equal(suite.evidenceLevel, "integration");
  assert.equal(suite.proofEvidenceLevel, "script");
  assert.equal(suite.qualified, false);
  assert.deepEqual(suite.scenarios, [...contract.SCENARIOS]);
  assert.deepEqual(suite.catalogIds, [...contract.CATALOG_IDS]);
  assert.deepEqual(suite.requiredSources, [...contract.REQUIRED_SOURCES]);
});

test("positive CSR reuse verifier stays separate from the local gate", () => {
  assert.equal(typeof journey.qualifyKeyReuse, "function");
  assert.equal(journey.scope, "real-linux-manual-and-default-scheduler-csr-key-reuse");
  const proof = {
    scope: journey.scope,
    client: "certbot",
    ...Object.fromEntries(journey.fields.map((field) => [field, true])),
    fingerprints: ["a", "b", "c"].map((value) => value.repeat(64)),
    serials: ["A1", "B2", "C3"],
    spkiFingerprint: "d".repeat(64),
    jobIds: [crypto.randomUUID(), crypto.randomUUID()],
    sourceProfileId: crypto.randomUUID(),
    sourceProfileFingerprint: "e".repeat(64),
  };
  assert.equal(journey.verifyProof(proof), true);
  assert.throws(() => journey.verifyProof(contract.localProof({
    keyReuseRefused: true,
    outsidePathRefused: true,
    inUseKeyPreserved: true,
  })));
});

test("reused SPKI and an outside client path fail closed", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "acme-key-"));
  try {
    const client = path.join(root, "bin", "certbot");
    fs.mkdirSync(path.dirname(client), { recursive: true });
    fs.writeFileSync(client, "");
    const keyPath = path.join(root, "keys", "account.key");
    fs.mkdirSync(path.dirname(keyPath), { recursive: true });
    const state = contract.createRun(root);
    contract.registerKey(state, "account", keyPath, "in-use-key-bytes");
    const { publicKey } = crypto.generateKeyPairSync("ed25519");
    const spki = contract.spkiOf(publicKey);
    const outside = path.join(path.dirname(root), "certbot-outside");
    assert.throws(() => contract.submitOrder(state, { clientPath: outside, spki }), { code: "CLIENT_PATH" });
    assert.equal(state.spkis.has(spki), false);
    const accepted = contract.submitOrder(state, { clientPath: client, spki });
    assert.equal(accepted.nativeExecutionQualified, false);
    assert.equal(accepted.sharedFleetQualified, false);
    assert.equal(accepted.liveCertbot, "pending");
    assert.throws(() => contract.submitOrder(state, { clientPath: client, spki }), { code: "KEY_REUSE" });
    assert.throws(() => contract.submitOrder(state, {
      clientPath: client,
      spki: "ab".repeat(32),
      sharedFleet: true,
    }), { code: "SHARED_FLEET" });
    assert.equal(state.sharedFleetQualified, false);
    assert.throws(() => contract.submitOrder(state, {
      clientPath: client,
      spki: "cd".repeat(32),
      cleanupCommand: "netsh http reset",
    }), { code: "BLANKET_NETSH_RESET" });
    assert.throws(() => contract.deleteKey(state, "account"), { code: "KEY_IN_USE" });
    assert.equal(fs.readFileSync(keyPath, "utf8"), "in-use-key-bytes");
    const proof = contract.localProof({
      keyReuseRefused: true,
      outsidePathRefused: true,
      inUseKeyPreserved: true,
    });
    assert.equal(proof.liveCertbot, "pending");
    assert.equal(proof.hostCapabilityAbsentIsPass, false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("missing lab fails closed without qualifying certbot", () => {
  const reportPath = path.join(os.tmpdir(), `acme-key-reuse-${crypto.randomUUID()}.json`);
  const report = contract.run({ env: {}, reportPath, write: true });
  assert.equal(report.status, "failed");
  assert.equal(report.qualified, false);
  assert.equal(report.claimsQualification, false);
  assert.equal(report.nativeExecutionQualified, false);
  assert.equal(report.sharedFleetQualified, false);
  assert.equal(report.liveCertbot, "pending");
  assert.equal(report.hostCapabilityAbsentIsPass, false);
  assert.equal(report.inUseKeyDeleted, false);
  assert.equal(report.blanketNetshReset, false);
  assert.equal(report.evidenceLevel, "integration");
  const spawned = spawnSync(process.execPath, ["scripts/certops-acme-key-reuse.js"], {
    cwd: ROOT,
    env: { ...process.env, [contract.REPORT_ENV]: reportPath },
    encoding: "utf8",
  });
  assert.equal(spawned.status, 1);
  const written = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  assert.equal(written.status, "failed");
  assert.equal(written.liveCertbot, "pending");
  fs.rmSync(reportPath, { force: true });
});

test("coverage workflow is manual dispatch only", () => {
  const source = fs.readFileSync(path.join(ROOT, ".github", "workflows", "certops-cross-coverage-variants.yml"), "utf8");
  assert.match(source, /^on:\r?\n {2}workflow_dispatch:\r?\n/m);
  assert.equal(/^\s*push:/m.test(source), false);
  assert.equal(/^\s*pull_request:/m.test(source), false);
  assert.match(source, /contents:\s*read/);
  assert.match(source, /exit 1\s*$/);
});
