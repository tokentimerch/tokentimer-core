"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const contract = require("../tests/e2e/helpers/certops-fs-symlink-rollback");

const ROOT = path.resolve(__dirname, "..");

function registration() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "_registration", "cross-coverage.json"), "utf8"));
}

test("registration stays an integration contract", () => {
  const body = registration();
  assert.equal(body.status, "partial");
  assert.equal(body.promotesCatalogRows, false);
  const suite = body.suites.find((item) => item.id === contract.SUITE);
  assert.equal(suite.status, "partial");
  assert.equal(suite.evidenceLevel, "integration");
  assert.equal(suite.proofEvidenceLevel, "host-integration");
  assert.deepEqual(suite.catalogIds, [...contract.CATALOG_IDS]);
  assert.deepEqual(suite.scenarios, [...contract.SCENARIOS]);
});

test("symlink escape, permission denial, and rollback stay inside the owned root", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "fs-root-"));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "fs-out-"));
  const link = path.join(root, "escape");
  try {
    fs.writeFileSync(path.join(outside, "secret.txt"), "outside-bytes");
    fs.symlinkSync(outside, link, process.platform === "win32" ? "junction" : "dir");
    assert.throws(() => contract.readContained(root, "escape"), { code: "SYMLINK_ESCAPE" });
    assert.throws(() => contract.readContained(root, path.join("escape", "secret.txt")), { code: "SYMLINK_ESCAPE" });
    assert.equal(fs.readFileSync(path.join(outside, "secret.txt"), "utf8"), "outside-bytes");
    const file = path.join(root, "leaf.pem");
    fs.writeFileSync(file, "previous-bytes");
    contract.writeOwned(file, "next-bytes");
    assert.equal(fs.readFileSync(file, "utf8"), "next-bytes");
    contract.rollbackOwned(file, "previous-bytes");
    assert.equal(fs.readFileSync(file, "utf8"), "previous-bytes");
    const denied = {
      lstatSync() {
        return { isSymbolicLink: () => false };
      },
      writeFileSync() {
        const error = new Error("denied");
        error.code = "EACCES";
        throw error;
      },
    };
    assert.throws(() => contract.writeOwned(file, "blocked-bytes", denied), { code: "PERMISSION_DENIED" });
    assert.equal(fs.readFileSync(file, "utf8"), "previous-bytes");
    assert.throws(() => contract.rollbackOwned(link, "previous-bytes"), { code: "SYMLINK_ESCAPE" });
    assert.equal(fs.readFileSync(path.join(outside, "secret.txt"), "utf8"), "outside-bytes");
    contract.verifyProof(contract.localProof());
  } finally {
    fs.rmSync(link, { force: true });
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test("missing filesystem lab fails closed", () => {
  const reportPath = path.join(os.tmpdir(), `fs-symlink-${crypto.randomUUID()}.json`);
  const report = contract.run({ env: {}, reportPath, write: true });
  assert.equal(report.status, "failed");
  assert.equal(report.followedSymlink, false);
  assert.equal(report.qualified, false);
  assert.equal(report.hostCapabilityAbsentIsPass, false);
  assert.equal(report.inUseKeyDeleted, false);
  const spawned = spawnSync(process.execPath, ["scripts/certops-fs-symlink-rollback.js"], {
    cwd: ROOT,
    env: { ...process.env, [contract.REPORT_ENV]: reportPath },
    encoding: "utf8",
  });
  assert.equal(spawned.status, 1);
  fs.rmSync(reportPath, { force: true });
});
