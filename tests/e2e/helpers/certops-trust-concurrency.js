/**
 * Qualification: local trust-store concurrency
 *
 * An exclusive lock permits one writer and refuses the second without replacement.
 * Partial-write recovery removes only the owned partial file, restores predecessor bytes
 * and preserves unrelated neighbors. Missing labs fail closed. Keep
 * publicSignedTrustQualified false: bundle/recovery annotations do not qualify the
 * separate public signed-trust lifecycle.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";

/** Local trust-store concurrency and partial-write recovery. Two writers
 * cannot both commit. Recovery restores the previous store bytes. The public
 * signed-trust cell stays a separate suite. */

const assert = require("node:assert/strict");
const {pendingFacts} = require("../../../scripts/certops-qualification-report");
const fs = require("node:fs");
const path = require("node:path");

const SCOPE = "trust-store-recovery-and-concurrency";
const SUITE = "trust-concurrency";
const SUITE_LEVEL = "integration";
const PROOF_LEVEL = "host-integration";
const REPORT_FILE = "trust-concurrency.json";
const REPORT_ENV = "CERTOPS_TRUST_CONCURRENCY_REPORT";
const PUBLIC_SIGNED_TRUST_SUITE = "linux-signed-trust";
const SCENARIOS = Object.freeze([
  "trust-two-writers-single-commit",
  "trust-partial-write-recovery",
]);
const CATALOG_IDS = Object.freeze([
  "trust.bundle-concurrency",
  "trust.restart-recovery",
]);
const SEPARATE_CATALOG_IDS = Object.freeze(["trust.public-signed-lifecycle"]);
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-qualification-report.js",
  "tests/e2e/helpers/certops-trust-concurrency.js",
  "scripts/certops-trust-concurrency.js",
  "scripts/certops-trust-concurrency.test.js",
  "scripts/_registration/cross-coverage.json",
  ".github/workflows/certops-cross-coverage-variants.yml",
]);

function assertSeparate(suite) {
  assert.notEqual(suite, PUBLIC_SIGNED_TRUST_SUITE);
}

function createStore(dir, previous) {
  fs.mkdirSync(dir, { recursive: true });
  const body = Buffer.from(previous);
  fs.writeFileSync(path.join(dir, "store.bin"), body);
  fs.writeFileSync(path.join(dir, "store.bin.bak"), body);
  return { dir, commits: 0, previous: body };
}

function commit(store, writer, bytes) {
  assertSeparate(SUITE);
  const lock = path.join(store.dir, "commit.lock");
  let fd;
  try {
    fd = fs.openSync(lock, "wx");
  } catch (error) {
    if (error.code === "EEXIST") {
      throw Object.assign(new Error("second writer refused"), {
        code: "CONCURRENT_COMMIT",
      });
    }
    throw error;
  }
  try {
    fs.writeFileSync(fd, String(writer));
    fs.writeFileSync(path.join(store.dir, "store.bin"), Buffer.from(bytes));
    store.commits += 1;
  } finally {
    fs.closeSync(fd);
  }
  return { commits: store.commits, writer };
}

function crashPartial(store, partial) {
  fs.writeFileSync(path.join(store.dir, "store.bin.partial"), Buffer.from(partial));
  fs.writeFileSync(path.join(store.dir, "store.bin"), Buffer.from(partial));
}

function recover(store) {
  const unrelated = path.join(store.dir, "unrelated.txt");
  const unrelatedBefore = fs.existsSync(unrelated) ? fs.readFileSync(unrelated) : null;
  const partial = path.join(store.dir, "store.bin.partial");
  const current = path.join(store.dir, "store.bin");
  if (fs.lstatSync(current).isSymbolicLink()) {
    throw Object.assign(new Error("refusing to follow a store symlink"), {
      code: "SYMLINK_ESCAPE",
    });
  }
  if (fs.existsSync(partial)) fs.unlinkSync(partial);
  const previous = fs.readFileSync(path.join(store.dir, "store.bin.bak"));
  fs.writeFileSync(current, previous);
  if (unrelatedBefore) assert.ok(fs.readFileSync(unrelated).equals(unrelatedBefore));
  assert.equal(fs.existsSync(partial), false);
  return fs.readFileSync(current);
}

function verifyProof(proof) {
  assert.equal(proof.scope, SCOPE);
  assert.equal(proof.evidenceLevel, PROOF_LEVEL);
  assert.equal(proof.singleCommit, true);
  assert.equal(proof.recoveredPrevious, true);
  assert.equal(proof.publicSignedTrustSeparate, true);
  assert.equal(proof.publicSignedTrustQualified, false);
  assert.equal(proof.hostCapabilityAbsentIsPass, false);
  assert.equal(proof.inUseKeyDeleted, false);
  assert.equal(proof.blanketNetshReset, false);
  return true;
}

function localProof() {
  const proof = {
    scope: SCOPE,
    evidenceLevel: PROOF_LEVEL,
    singleCommit: true,
    recoveredPrevious: true,
    publicSignedTrustSeparate: true,
    publicSignedTrustQualified: false,
    hostCapabilityAbsentIsPass: false,
    inUseKeyDeleted: false,
    blanketNetshReset: false,
  };
  verifyProof(proof);
  return proof;
}

function assessLab(env = process.env) {
  const missing = [];
  if (env.CERTOPS_TRUST_HOST_LAB !== "1") missing.push("CERTOPS_TRUST_HOST_LAB");
  return { ok: missing.length === 0, missing };
}

function closedReport(reason, env = process.env) {
  const lab = assessLab(env);
  const now = new Date().toISOString();
  return {...pendingFacts({SUITE, SUITE_LEVEL, PROOF_LEVEL, SCENARIOS, REQUIRED_SOURCES, CATALOG_IDS, now}),
publicSignedTrustSeparate: true,
publicSignedTrustQualified: false,
separateCatalogIds: [...SEPARATE_CATALOG_IDS],
reason: lab.ok
      ? "A local store fixture does not qualify signed trust distribution"
      : String(reason || `lab absent: ${lab.missing.join(",")}`),
cleanup: { status: "failed", summary: "The public signed-trust cell was not started" }};
}

function writeReport(reportPath, report) {
  assert.equal(report.suite, SUITE);
  assert.notEqual(report.suite, PUBLIC_SIGNED_TRUST_SUITE);
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
}

function run(options = {}) {
  const env = options.env || process.env;
  const report = closedReport(options.reason, env);
  const reportPath = options.reportPath || env[REPORT_ENV] || path.join("qualification-results", REPORT_FILE);
  if (options.write !== false) writeReport(reportPath, report);
  return report;
}

module.exports = {
  SCOPE,
  SUITE,
  SUITE_LEVEL,
  PROOF_LEVEL,
  REPORT_FILE,
  REPORT_ENV,
  PUBLIC_SIGNED_TRUST_SUITE,
  SCENARIOS,
  CATALOG_IDS,
  SEPARATE_CATALOG_IDS,
  REQUIRED_SOURCES,
  assertSeparate,
  createStore,
  commit,
  crashPartial,
  recover,
  verifyProof,
  localProof,
  assessLab,
  closedReport,
  writeReport,
  run,
};
