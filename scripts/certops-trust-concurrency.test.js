"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const contract = require("../tests/e2e/helpers/certops-trust-concurrency");

const ROOT = path.resolve(__dirname, "..");

function registration() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "_registration", "cross-coverage.json"), "utf8"));
}

test("registration keeps the public signed-trust cell separate", () => {
  const body = registration();
  assert.equal(body.status, "partial");
  assert.equal(body.promotesCatalogRows, false);
  const suite = body.suites.find((item) => item.id === contract.SUITE);
  assert.equal(suite.status, "partial");
  assert.equal(suite.evidenceLevel, "integration");
  assert.equal(suite.proofEvidenceLevel, "host-integration");
  assert.deepEqual(suite.catalogIds, [...contract.CATALOG_IDS]);
  assert.deepEqual(suite.separateCatalogIds, [...contract.SEPARATE_CATALOG_IDS]);
  assert.equal(suite.qualified, false);
  assert.notEqual(suite.id, contract.PUBLIC_SIGNED_TRUST_SUITE);
});

test("one writer commits and partial recovery restores the previous store", () => {
  const first = fs.mkdtempSync(path.join(os.tmpdir(), "trust-lock-"));
  const second = fs.mkdtempSync(path.join(os.tmpdir(), "trust-recover-"));
  try {
    const store = contract.createStore(first, "previous-store");
    fs.writeFileSync(path.join(first, "unrelated.txt"), "leave-me");
    contract.commit(store, "writer-a", "writer-a-bytes");
    assert.throws(() => contract.commit(store, "writer-b", "writer-b-bytes"), { code: "CONCURRENT_COMMIT" });
    assert.equal(store.commits, 1);
    assert.equal(fs.readFileSync(path.join(first, "store.bin"), "utf8"), "writer-a-bytes");
    assert.equal(fs.readFileSync(path.join(first, "unrelated.txt"), "utf8"), "leave-me");
    const recovery = contract.createStore(second, "previous-store");
    fs.writeFileSync(path.join(second, "unrelated.txt"), "leave-me");
    contract.crashPartial(recovery, "PARTIAL-SECRET");
    assert.equal(contract.recover(recovery).toString(), "previous-store");
    assert.equal(fs.existsSync(path.join(second, "store.bin.partial")), false);
    assert.equal(fs.readFileSync(path.join(second, "unrelated.txt"), "utf8"), "leave-me");
    contract.assertSeparate(contract.SUITE);
    assert.throws(() => contract.assertSeparate(contract.PUBLIC_SIGNED_TRUST_SUITE));
    const proof = contract.localProof();
    assert.equal(proof.publicSignedTrustQualified, false);
    assert.equal(proof.publicSignedTrustSeparate, true);
  } finally {
    fs.rmSync(first, { recursive: true, force: true });
    fs.rmSync(second, { recursive: true, force: true });
  }
});

test("missing trust lab fails closed", () => {
  const reportPath = path.join(os.tmpdir(), `trust-concurrency-${crypto.randomUUID()}.json`);
  const report = contract.run({ env: {}, reportPath, write: true });
  assert.equal(report.status, "failed");
  assert.equal(report.publicSignedTrustSeparate, true);
  assert.equal(report.publicSignedTrustQualified, false);
  assert.equal(report.qualified, false);
  assert.equal(report.hostCapabilityAbsentIsPass, false);
  const spawned = spawnSync(process.execPath, ["scripts/certops-trust-concurrency.js"], {
    cwd: ROOT,
    env: { ...process.env, [contract.REPORT_ENV]: reportPath },
    encoding: "utf8",
  });
  assert.equal(spawned.status, 1);
  fs.rmSync(reportPath, { force: true });
});
