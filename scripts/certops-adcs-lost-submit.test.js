"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const subject = require("../tests/e2e/helpers/certops-adcs-lost-submit");

const root = path.resolve(__dirname, "..");
const owned = {
  owner: "owned-run",
  subject: "CN=owned.example.test",
  csrSha256: "ab".repeat(32),
  requestId: "99",
};

function candidate(requestId, extra = {}) {
  return {
    owned: true,
    owner: owned.owner,
    subject: owned.subject,
    csrSha256: owned.csrSha256,
    requestId,
    ...extra,
  };
}

test("zero candidates are a clean miss and do not invent a request id", () => {
  const result = subject.reconcileLostSubmit([], owned);
  assert.equal(result.requestId, null);
  assert.equal(result.chosen, false);
  assert.equal(result.proof.status, "clean-miss");
  assert.equal(result.proof.requestId, null);
  assert.equal(result.proof.nativeExecutionQualified, false);
  assert.equal(result.proof.hostCapabilityAbsentIsPass, false);
  assert.equal(result.proof.localParserResult, true);
  assert.throws(() => subject.verifyProof({ ...result.proof, requestId: "1" }));
});

test("two or more candidates fail closed with no chosen request", () => {
  assert.throws(() => subject.reconcileLostSubmit([candidate("4"), candidate("5")], owned), (error) => {
    assert.equal(error.chosen, false);
    assert.equal(error.requestId, null);
    assert.match(error.message, /Ambiguous/);
    return true;
  });
  assert.throws(() => subject.reconcileLostSubmit([candidate("4"), candidate("5"), candidate("6")], owned), (error) => {
    assert.equal(error.requestId, null);
    return true;
  });
  assert.throws(() => subject.verifyProof({
    scope: subject.SCOPE,
    evidenceLevel: "integration",
    status: "ambiguous",
    requestId: "4",
    chosen: true,
    candidateCount: 2,
    localParserResult: true,
    disposableForestRan: false,
    nativeExecutionQualified: false,
    hostCapabilityAbsentIsPass: false,
  }));
});

test("exactly one owned candidate is only a local parser result", () => {
  const result = subject.reconcileLostSubmit([candidate("17")], owned);
  subject.verifyProof(result.proof);
  assert.equal(result.requestId, "17");
  assert.equal(result.proof.chosen, true);
  assert.equal(result.proof.nativeExecutionQualified, false);
  assert.equal(result.proof.disposableForestRan, false);
  assert.throws(() => subject.reconcileLostSubmit([candidate("18", { owned: false, owner: "foreign" })], owned));
  assert.throws(() => subject.reconcileLostSubmit([candidate("0")], owned));
  assert.equal(subject.assessLab({}, "win32").passed, false);
  assert.throws(() => subject.qualifyLostSubmit({ env: {}, platform: "win32" }), /Disposable AD CS forest is required/);
});

test("command entry writes a failed report", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "adcs-lost-"));
  const reportPath = path.join(dir, "report.json");
  try {
    const env = { ...process.env, CERTOPS_ADCS_LOST_SUBMIT_REPORT: reportPath };
    delete env.CERTOPS_ADCS_DISPOSABLE_LAB;
    const result = spawnSync(process.execPath, [path.join(root, "scripts/certops-adcs-lost-submit.js")], { encoding: "utf8", env });
    assert.equal(result.status, 1);
    const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    assert.equal(report.status, "failed");
    assert.equal(report.requestId, null);
    assert.equal(report.chosen, false);
    assert.equal(report.nativeExecutionQualified, false);
    assert.equal(report.hostCapabilityAbsentIsPass, false);
    assert.equal(report.disposableForestRan, false);
    assert.equal(report.evidenceLevel, "integration");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  for (const rel of subject.REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
});
