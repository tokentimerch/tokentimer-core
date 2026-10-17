"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const subject = require("../tests/e2e/helpers/certops-adcs-browser-enrollment");

const root = path.resolve(__dirname, "..");
const ready = {
  CERTOPS_ADCS_DISPOSABLE_LAB: "1",
  CERTOPS_ADCS_API_URL: "https://lab.example.test",
};
const browser = { browser: true, ownedPage: true, confirmationControl: true };

function journey() {
  return [{ step: "preflight" }, { step: "confirmation" }, { step: "enrollment" }];
}

test("journey order requires confirmation before enrollment", () => {
  const proof = subject.acceptJourney(journey());
  subject.verifyProof(proof);
  assert.deepEqual(proof.journey, ["preflight", "confirmation", "enrollment"]);
  assert.equal(proof.confirmationBeforeSubmit, true);
  assert.equal(proof.browserLaunched, false);
  assert.equal(proof.nativeExecutionQualified, false);
  assert.equal(proof.hostCapabilityAbsentIsPass, false);
  assert.equal(proof.disposableForestRan, false);
  assert.throws(() => subject.assertJourney([{ step: "confirmation" }, { step: "preflight" }, { step: "enrollment" }]), /order required/);
  assert.throws(() => subject.assertJourney([{ step: "enrollment" }, { step: "confirmation" }, { step: "preflight" }]), /Confirmation is required before submit/);
  assert.throws(() => subject.assertJourney([{ step: "preflight" }, { step: "submit" }]), /Confirmation is required before submit/);
  assert.throws(() => subject.assertJourney([{ step: "preflight" }, { step: "enrollment" }]), /Confirmation is required before submit/);
  for (const flag of ["browserLaunched", "nativeExecutionQualified", "hostCapabilityAbsentIsPass", "disposableForestRan"]) {
    assert.throws(() => subject.verifyProof({ ...proof, [flag]: true }));
  }
  assert.throws(() => subject.verifyProof({ ...proof, confirmationBeforeSubmit: false }));
});

test("a missing browser fails closed and no browser is launched", () => {
  const absent = subject.assessBrowser(null);
  assert.equal(absent.available, false);
  assert.equal(absent.passed, false);
  assert.equal(absent.nativeQualified, false);
  assert.equal(absent.hostCapabilityAbsentIsPass, false);
  assert.equal(subject.assessLab({}, "linux").passed, false);
  assert.throws(() => subject.qualifyBrowserEnrollment({ env: ready, platform: "win32" }), /Browser is required/);
  assert.throws(() => subject.qualifyBrowserEnrollment({ env: ready, platform: "win32", browser }), /does not launch a browser/);
  assert.throws(() => subject.qualifyBrowserEnrollment({ env: {}, platform: "win32", browser }), /Disposable AD CS forest is required/);
  const source = fs.readFileSync(path.join(root, subject.SOURCE), "utf8");
  assert.doesNotMatch(source, /playwright|puppeteer|chrome\.exe|msedge\.exe/);
});

test("command entry writes a failed report and the workflow stays manual", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "adcs-browser-"));
  const reportPath = path.join(dir, "report.json");
  try {
    const env = { ...process.env, CERTOPS_ADCS_BROWSER_ENROLLMENT_REPORT: reportPath };
    delete env.CERTOPS_ADCS_DISPOSABLE_LAB;
    const result = spawnSync(process.execPath, [path.join(root, "scripts/certops-adcs-browser-enrollment.js")], { encoding: "utf8", env });
    assert.equal(result.status, 1);
    const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    assert.equal(report.status, "failed");
    assert.equal(report.evidenceLevel, "integration");
    assert.equal(report.nativeExecutionQualified, false);
    assert.equal(report.hostCapabilityAbsentIsPass, false);
    assert.equal(report.disposableForestRan, false);
    assert.equal(report.browserLaunched, false);
    assert.equal(report.suite, subject.SUITE);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const workflow = fs.readFileSync(path.join(root, ".github/workflows/certops-adcs-coverage-variants.yml"), "utf8");
  assert.match(workflow, /^on:\n {2}workflow_dispatch:\n/m);
  assert.doesNotMatch(workflow, /pull_request:/);
  assert.doesNotMatch(workflow, /\npush:/);
  assert.match(workflow, /contents: read/);
  assert.match(workflow, /process\.exit\(1\)/);
  assert.doesNotMatch(workflow, /provision-lab|az deployment|bicep|softprops\/action-gh-release/);
  assert.match(workflow, /if: always\(\)\s+uses: actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02/);
  assert.match(workflow, /retention-days: 7\s+if-no-files-found: error/);
  assert.match(workflow, /qualification-results\/adcs-browser-enrollment\.json/);
  const registration = fs.readFileSync(path.join(root, "scripts/_registration/adcs-coverage.json"), "utf8");
  assert.doesNotMatch(registration, /"implemented"/);
  const catalog = JSON.parse(registration);
  const suite = catalog.suites.find((item) => item.id === subject.SUITE);
  assert.equal(suite.evidenceLevel, "integration");
  assert.deepEqual(suite.scenarios, [...subject.REQUIRED_SCENARIOS]);
  assert.equal(suite.catalogIds.some((item) => item.catalogStatus === "implemented"), false);
  for (const rel of subject.REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
});
