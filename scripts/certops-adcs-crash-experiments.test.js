"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const subject = require("../tests/e2e/helpers/certops-adcs-crash-experiments");

const root = path.resolve(__dirname, "..");
const ready = {
  CERTOPS_ADCS_DISPOSABLE_LAB: "1",
  CERTOPS_ADCS_API_URL: "https://lab.example.test",
};

test("crash experiment proofs are rejected for release qualification", () => {
  assert.deepEqual([...subject.EXPERIMENTS], ["response-loss", "journal-phase", "key-generation"]);
  for (const experiment of subject.EXPERIMENTS) {
    const proof = subject.buildExperimentProof(experiment);
    assert.equal(subject.verifyProof(proof), true);
    assert.equal(proof.releaseQualificationSatisfied, false);
    assert.equal(proof.nativeExecutionQualified, false);
    assert.equal(proof.hostCapabilityAbsentIsPass, false);
    assert.equal(proof.disposableForestRan, false);
    assert.equal(proof.evidenceLevel, "integration");
    assert.throws(() => subject.verifyProof({ ...proof, releaseQualificationSatisfied: true }), new RegExp(subject.REJECTED));
    assert.throws(() => subject.verifyProof({ ...proof, qualified: true }), new RegExp(subject.REJECTED));
    assert.throws(() => subject.treatAsQualified(proof), new RegExp(subject.REJECTED));
  }
  assert.throws(() => subject.qualifyCrashExperiment({ env: {}, platform: "win32" }), /Disposable AD CS forest is required/);
  assert.throws(() => subject.qualifyCrashExperiment({ env: ready, platform: "win32" }), new RegExp(subject.REJECTED));
  assert.equal(subject.assessLab(ready, "win32").passed, false);
  assert.equal(subject.assessLab(ready, "win32").hostCapabilityAbsentIsPass, false);
});

test("command entry retains failed diagnostic evidence without publishing a release", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "adcs-crash-"));
  const reportPath = path.join(dir, "report.json");
  try {
    const env = { ...process.env, CERTOPS_ADCS_CRASH_EXPERIMENTS_REPORT: reportPath };
    delete env.CERTOPS_ADCS_DISPOSABLE_LAB;
    const result = spawnSync(process.execPath, [path.join(root, "scripts/certops-adcs-crash-experiments.js")], { encoding: "utf8", env });
    assert.equal(result.status, 1);
    const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    assert.equal(report.status, "failed");
    assert.equal(report.releaseQualificationSatisfied, false);
    assert.equal(report.nativeExecutionQualified, false);
    assert.equal(report.hostCapabilityAbsentIsPass, false);
    assert.equal(report.disposableForestRan, false);
    assert.throws(() => subject.treatAsQualified(report), new RegExp(subject.REJECTED));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const workflow = fs.readFileSync(path.join(root, ".github/workflows/certops-adcs-coverage-variants.yml"), "utf8");
  assert.match(workflow, /^on:\r?\n {2}workflow_dispatch:\r?\n/m);
  assert.doesNotMatch(workflow, /pull_request:/);
  assert.doesNotMatch(workflow, /\npush:/);
  assert.match(workflow, /contents: read/);
  assert.match(workflow, /process\.exit\(1\)/);
  assert.doesNotMatch(workflow, /softprops\/action-gh-release|provision-lab|bicep/);
  assert.match(workflow, /if: always\(\)\s+uses: actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02/);
  assert.match(workflow, /retention-days: 7\s+if-no-files-found: error/);
  assert.match(workflow, /qualification-results\/adcs-crash-experiments\.json/);
  const registration = JSON.parse(fs.readFileSync(path.join(root, "scripts/_registration/adcs-coverage.json"), "utf8"));
  assert.equal(registration.catalogStatus, "partial");
  assert.equal(registration.disposableForestRan, false);
  const suite = registration.suites.find((item) => item.id === subject.SUITE);
  assert.equal(suite.evidenceLevel, "integration");
  assert.deepEqual(suite.scenarios, [...subject.REQUIRED_SCENARIOS]);
  for (const rel of subject.REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
});
