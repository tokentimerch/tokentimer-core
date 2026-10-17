"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const contract = require("../tests/e2e/helpers/certops-browser-audit-redaction");

const ROOT = path.resolve(__dirname, "..");

function registration() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "_registration", "cross-coverage.json"), "utf8"));
}

function secretText() {
  return [
    "diagnostic before storage",
    "-----BEGIN PRIVATE KEY-----",
    "AAAA",
    "-----END PRIVATE KEY-----",
    "Authorization: Bearer abcdefghijklmnop",
    "password=s3cret",
  ].join("\n");
}

test("registration stays an integration contract", () => {
  const body = registration();
  assert.equal(body.status, "partial");
  assert.equal(body.promotesCatalogRows, false);
  const suite = body.suites.find((item) => item.id === contract.SUITE);
  assert.equal(suite.status, "partial");
  assert.equal(suite.evidenceLevel, "integration");
  assert.equal(suite.proofEvidenceLevel, "script");
  assert.deepEqual(suite.scenarios, [...contract.SCENARIOS]);
  assert.deepEqual(suite.catalogIds, [...contract.CATALOG_IDS]);
});

test("redaction, anonymous replay, and local labels fail closed", () => {
  const raw = secretText();
  const stored = [];
  assert.throws(() => contract.recordAudit(stored, {
    actor: "anonymous",
    action: "console.replay",
    detail: raw,
  }), { code: "ANONYMOUS_REPLAY" });
  assert.equal(stored.length, 0);
  contract.recordAudit(stored, { actor: "owner", action: "diagnostic.store", detail: raw });
  assert.equal(contract.containsSecret(stored[0].diagnostic), false);
  assert.equal(stored[0].diagnostic.includes("BEGIN "), false);
  assert.equal(stored[0].diagnostic.includes("Bearer"), false);
  assert.equal(stored[0].diagnostic.includes("password="), false);
  assert.throws(() => contract.replayCompletedConsole({
    completed: true,
    actor: "anonymous",
    jobId: "job-1",
  }), { code: "ANONYMOUS_REPLAY" });
  const allowed = contract.replayCompletedConsole({
    completed: true,
    actor: "admin",
    jobId: "job-1",
  });
  assert.equal(allowed.allowed, true);
  assert.equal(allowed.browserQualified, false);
  const labels = contract.checkAccessibility(contract.ACCESSIBILITY_FIXTURE);
  assert.deepEqual(labels.labels, [...contract.LABELS]);
  assert.equal(labels.liveBrowser, false);
  assert.equal(labels.browserQualified, false);
  assert.throws(() => contract.checkAccessibility(
    contract.ACCESSIBILITY_FIXTURE.replace('aria-label="Audit history"', 'aria-label="Missing history"'),
  ), { code: "A11Y_LABEL" });
  contract.verifyProof(contract.localProof());
});

test("missing browser fails closed", () => {
  const reportPath = path.join(os.tmpdir(), `browser-audit-${crypto.randomUUID()}.json`);
  const report = contract.run({
    env: {},
    probe: { missing: true, browser: false },
    reportPath,
    write: true,
  });
  assert.equal(report.status, "failed");
  assert.equal(report.reason, "browser absent");
  assert.equal(report.browserQualified, false);
  assert.equal(report.liveBrowser, false);
  assert.equal(report.qualified, false);
  assert.equal(report.hostCapabilityAbsentIsPass, false);
  const spawned = spawnSync(process.execPath, ["scripts/certops-browser-audit-redaction.js"], {
    cwd: ROOT,
    env: { ...process.env, [contract.REPORT_ENV]: reportPath },
    encoding: "utf8",
  });
  assert.equal(spawned.status, 1);
  const written = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  assert.equal(written.reason, "browser absent");
  fs.rmSync(reportPath, { force: true });
});
