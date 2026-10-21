"use strict";
/**
 * Qualification notes: local abandonment contract
 *
 * Local success requires submission_uncertain, no in-use-key deletion and no foreign request
 * mutation. Native/absent-host-as-pass flags stay false and missing lab fails closed. The real
 * forest journey lives in tests/e2e/helpers/certops-adcs-uncertain-abandon.js; local contracts do
 * not replace it or claim native execution.
 *
 * Shared setup, evidence and cleanup policy: docs/certops/e2e-qualification.md.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const subject = require("./certops-adcs-uncertain-abandon");

const root = path.resolve(__dirname, "..");

function ownedAction(extra = {}) {
  return {
    state: "submission_uncertain",
    inUseKeyDeleted: false,
    foreignRequestTouched: false,
    ownedRequestId: "17",
    requestId: "17",
    key: { container: "tt-adcs-key-owned", inUse: true },
    commands: [],
    ...extra,
  };
}

test("uncertain abandon succeeds only without key deletion or a foreign request", () => {
  const result = subject.abandonUncertain(ownedAction());
  subject.verifyProof(result.proof);
  assert.equal(result.abandoned, true);
  assert.equal(result.proof.state, "submission_uncertain");
  assert.equal(result.proof.inUseKeyDeleted, false);
  assert.equal(result.proof.foreignRequestTouched, false);
  assert.equal(result.proof.nativeExecutionQualified, false);
  assert.equal(result.proof.hostCapabilityAbsentIsPass, false);
  assert.equal(result.proof.disposableForestRan, false);
  assert.throws(() => subject.abandonUncertain(ownedAction({ state: "pending" })), /uncertain state/);
  assert.throws(() => subject.abandonUncertain(ownedAction({ inUseKeyDeleted: true })), /in-use key/);
  assert.throws(() => subject.abandonUncertain(ownedAction({ deleteKey: true })), /in-use key/);
  assert.throws(() => subject.abandonUncertain(ownedAction({
    commands: [{ file: "certutil.exe", args: ["-delkey", "tt-adcs-key-owned"] }],
  })), /in-use key/);
  assert.throws(() => subject.abandonUncertain(ownedAction({ foreignRequestTouched: true })), /foreign request/);
  assert.throws(() => subject.abandonUncertain(ownedAction({ requestId: "18" })), /foreign request/);
  assert.throws(() => subject.verifyProof({ ...result.proof, nativeExecutionQualified: true }));
});

test("the forest helper remains the native journey", () => {
  const native = require("../tests/e2e/helpers/certops-adcs-uncertain-abandon");
  assert.equal(typeof native.qualifyUncertainAbandon, "function");
  assert.equal(typeof native.assertProof, "function");
  assert.equal(native.localContract.abandonUncertain, subject.abandonUncertain);
  assert.notEqual(native.qualifyUncertainAbandon, subject.qualifyUncertainAbandon);
  assert.throws(() => native.assertProof({ scope: "native-zero-request-uncertain-abandon", nativeExecutionQualified: true }));
});

test("a missing lab fails closed", () => {
  assert.equal(subject.assessLab({}, "win32").passed, false);
  assert.equal(subject.assessLab({}, "win32").hostCapabilityAbsentIsPass, false);
  assert.throws(() => subject.qualifyUncertainAbandon({ env: {}, platform: "linux" }), /Disposable AD CS forest is required/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "adcs-abandon-"));
  const reportPath = path.join(dir, "report.json");
  try {
    const env = { ...process.env, CERTOPS_ADCS_UNCERTAIN_ABANDON_REPORT: reportPath };
    delete env.CERTOPS_ADCS_DISPOSABLE_LAB;
    const result = spawnSync(process.execPath, [path.join(root, "scripts/certops-adcs-uncertain-abandon.js")], { encoding: "utf8", env });
    assert.equal(result.status, 1);
    const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    assert.equal(report.status, "failed");
    assert.equal(report.nativeExecutionQualified, false);
    assert.equal(report.hostCapabilityAbsentIsPass, false);
    assert.equal(report.disposableForestRan, false);
    assert.equal(report.inUseKeyDeleted, false);
    assert.equal(report.foreignRequestTouched, false);
    assert.equal(report.evidenceLevel, "integration");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  for (const rel of subject.REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
});
