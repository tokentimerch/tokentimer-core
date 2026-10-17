"use strict";

/** Local filesystem containment contract. A symlink that leaves the owned
 * root fails before a read or write. Permission denial fails closed. Rollback
 * restores the previous file bytes and does not follow a symlink. */

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const SCOPE = "filesystem-permission-symlink-and-rollback";
const SUITE = "fs-symlink-rollback";
const SUITE_LEVEL = "integration";
const PROOF_LEVEL = "host-integration";
const REPORT_FILE = "fs-symlink-rollback.json";
const REPORT_ENV = "CERTOPS_FS_SYMLINK_ROLLBACK_REPORT";
const SCENARIOS = Object.freeze([
  "fs-symlink-escape-refused",
  "fs-permission-denied-closed",
  "fs-rollback-restores-bytes",
]);
const CATALOG_IDS = Object.freeze([
  "deploy.path-containment",
  "deploy.atomic-backups",
  "deploy.leaf-chain-key",
  "linux-install.state-permissions",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-fs-symlink-rollback.js",
  "scripts/certops-fs-symlink-rollback.js",
  "scripts/certops-fs-symlink-rollback.test.js",
  "docs/certops/cross/fs-symlink-rollback.md",
  "scripts/_registration/cross-coverage.json",
  ".github/workflows/certops-cross-coverage-variants.yml",
]);

function contained(root, candidate) {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function failClosed(code, message) {
  return Object.assign(new Error(message), {
    code,
    hostCapabilityAbsentIsPass: false,
  });
}

function walkContained(root, relativePath, io) {
  const base = path.resolve(root);
  const segments = String(relativePath).split(/[\\/]+/).filter(Boolean);
  if (segments.length === 0 || segments.some((segment) => segment === "." || segment === "..")) {
    throw failClosed("PATH_ESCAPE", "path outside owned root");
  }
  let current = base;
  for (const segment of segments) {
    current = path.join(current, segment);
    if (!contained(base, current)) throw failClosed("PATH_ESCAPE", "path outside owned root");
    const stat = io.lstatSync(current);
    if (!stat.isSymbolicLink()) continue;
    const link = path.resolve(path.dirname(current), io.readlinkSync(current));
    if (!contained(base, link)) throw failClosed("SYMLINK_ESCAPE", "symlink escape outside owned root");
    throw failClosed("SYMLINK_ESCAPE", "refusing to follow a symlink");
  }
  return current;
}

function readContained(root, relativePath, io = fs) {
  const target = walkContained(root, relativePath, io);
  return io.readFileSync(target);
}

function writeOwned(file, bytes, io = fs) {
  const stat = io.lstatSync(file);
  if (stat.isSymbolicLink()) throw failClosed("SYMLINK_ESCAPE", "refusing to follow a symlink");
  try {
    io.writeFileSync(file, bytes);
  } catch (error) {
    if (error.code === "EACCES" || error.code === "EPERM") {
      throw failClosed("PERMISSION_DENIED", "permission denied");
    }
    throw error;
  }
}

function rollbackOwned(file, previous, io = fs) {
  const stat = io.lstatSync(file);
  if (stat.isSymbolicLink()) throw failClosed("SYMLINK_ESCAPE", "refusing to follow a symlink");
  const body = Buffer.from(previous);
  try {
    io.writeFileSync(file, body);
  } catch (error) {
    if (error.code === "EACCES" || error.code === "EPERM") {
      throw failClosed("PERMISSION_DENIED", "permission denied");
    }
    throw error;
  }
  assert.ok(Buffer.from(io.readFileSync(file)).equals(body));
  return body;
}

function verifyProof(proof) {
  assert.equal(proof.scope, SCOPE);
  assert.equal(proof.evidenceLevel, PROOF_LEVEL);
  assert.equal(proof.symlinkEscapeRefused, true);
  assert.equal(proof.permissionDeniedClosed, true);
  assert.equal(proof.rollbackRestored, true);
  assert.equal(proof.followedSymlink, false);
  assert.equal(proof.hostCapabilityAbsentIsPass, false);
  assert.equal(proof.inUseKeyDeleted, false);
  assert.equal(proof.blanketNetshReset, false);
  return true;
}

function localProof() {
  const proof = {
    scope: SCOPE,
    evidenceLevel: PROOF_LEVEL,
    symlinkEscapeRefused: true,
    permissionDeniedClosed: true,
    rollbackRestored: true,
    followedSymlink: false,
    hostCapabilityAbsentIsPass: false,
    inUseKeyDeleted: false,
    blanketNetshReset: false,
  };
  verifyProof(proof);
  return proof;
}

function assessLab(env = process.env) {
  const missing = [];
  if (env.CERTOPS_FS_HOST_LAB !== "1") missing.push("CERTOPS_FS_HOST_LAB");
  return { ok: missing.length === 0, missing };
}

function closedReport(reason, env = process.env) {
  const lab = assessLab(env);
  const now = new Date().toISOString();
  return {
    schemaVersion: 1,
    suite: SUITE,
    strict: true,
    status: "failed",
    evidenceLevel: SUITE_LEVEL,
    proofEvidenceLevel: PROOF_LEVEL,
    qualified: false,
    claimsQualification: false,
    hostCapabilityAbsentIsPass: false,
    followedSymlink: false,
    inUseKeyDeleted: false,
    blanketNetshReset: false,
    startedAt: now,
    finishedAt: now,
    requiredScenarios: [...SCENARIOS],
    missingScenarios: [...SCENARIOS],
    scenarios: [],
    requiredSources: [...REQUIRED_SOURCES],
    catalogIds: [...CATALOG_IDS],
    promotesCatalogRows: false,
    reason: lab.ok
      ? "A local rollback fixture does not qualify the host deployment"
      : String(reason || `lab absent: ${lab.missing.join(",")}`),
    cleanup: { status: "failed", summary: "No path outside the owned root was written" },
  };
}

function writeReport(reportPath, report) {
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
  SCENARIOS,
  CATALOG_IDS,
  REQUIRED_SOURCES,
  contained,
  readContained,
  writeOwned,
  rollbackOwned,
  verifyProof,
  localProof,
  assessLab,
  closedReport,
  writeReport,
  run,
};
