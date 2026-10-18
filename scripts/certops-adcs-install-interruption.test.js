"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const subject = require("../tests/e2e/helpers/certops-adcs-install-interruption");

const root = path.resolve(__dirname, "..");
const RUN = "ab".repeat(16);
const ready = {
  CERTOPS_ADCS_DISPOSABLE_LAB: "1",
  CERTOPS_ADCS_API_URL: "https://lab.example.test",
};

function recorded(phase, sequence) {
  return subject.recordPhase({
    phase,
    runId: RUN,
    sequence,
    payload: Buffer.from(`${phase}-${RUN}`),
  });
}

test("each installation phase restarts the same owned target and keeps the key", () => {
  assert.deepEqual([...subject.PHASES], ["role-install", "ca-config", "template-publish", "acl-grant", "iis-enroll-site"]);
  for (const [index, phase] of subject.PHASES.entries()) {
    const point = recorded(phase, index + 1);
    assert.equal(point.point.key.inUse, true);
    const commands = subject.buildRestartPlan(point.point);
    assert.equal(commands[0].args[1], point.point.target);
    assert.equal(commands[1].args[1], point.point.target);
    const result = subject.recover({ point: point.point, bytes: point.bytes, commands });
    subject.verifyProof(result.proof);
    assert.equal(result.keyDeleted, false);
    assert.equal(result.proof.restartedTarget, result.proof.target);
    assert.equal(result.proof.powerLossDurabilityQualified, false);
    assert.equal(result.proof.realRebootQualified, false);
    assert.equal(result.proof.nativeExecutionQualified, false);
    assert.equal(result.proof.hostCapabilityAbsentIsPass, false);
    assert.equal(result.proof.blanketNetshReset, false);
    const changed = Buffer.from(point.bytes);
    changed[0] ^= 0xff;
    assert.throws(() => subject.recover({ point: point.point, bytes: changed, commands }), /Preserve unresolved installation point/);
  }
});

test("reboot, power loss, key deletion, and blanket netsh reset are refused", () => {
  const point = recorded("acl-grant", 4);
  assert.throws(() => subject.buildRestartPlan({ ...point.point, mode: "reboot" }), /real reboot/);
  assert.throws(() => subject.buildRestartPlan({ ...point.point, mode: "power-loss" }), /power loss/);
  assert.throws(() => subject.assertSafeCommands(point.point, [{ file: "certutil.exe", args: ["-delkey", point.point.key.container] }]), /in-use key/);
  assert.throws(() => subject.assertSafeCommands(point.point, [{ file: "netsh.exe", args: ["int", "ip", "reset"] }]), /blanket netsh reset/);
  assert.equal(subject.assessLab(ready, "win32").passed, false);
  assert.throws(() => subject.qualifyInstallInterruption({ env: {}, platform: "linux" }), /Disposable AD CS forest is required/);
  assert.throws(() => subject.qualifyInstallInterruption({ env: ready, platform: "win32" }), /do not restart an owned target/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "adcs-install-"));
  try {
    subject.writePoint(dir, point);
    const loaded = subject.readPoint(dir);
    const result = subject.recover({ point: loaded.point, bytes: loaded.bytes, commands: subject.buildRestartPlan(loaded.point) });
    assert.equal(result.proof.phase, "acl-grant");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("command entry writes a failed report and does not claim a forest", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "adcs-install-report-"));
  const reportPath = path.join(dir, "report.json");
  try {
    const env = { ...process.env, CERTOPS_ADCS_INSTALL_INTERRUPTION_REPORT: reportPath };
    delete env.CERTOPS_ADCS_DISPOSABLE_LAB;
    const result = spawnSync(process.execPath, [path.join(root, "scripts/certops-adcs-install-interruption.js")], { encoding: "utf8", env });
    assert.equal(result.status, 1);
    const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    assert.equal(report.status, "failed");
    assert.equal(report.disposableForestRan, false);
    assert.equal(report.nativeExecutionQualified, false);
    assert.equal(report.hostCapabilityAbsentIsPass, false);
    assert.equal(report.powerLossDurabilityQualified, false);
    assert.equal(report.realRebootQualified, false);
    assert.equal(report.inUseKeyDeleted, false);
    assert.equal(report.blanketNetshReset, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const workflow = fs.readFileSync(path.join(root, ".github/workflows/certops-adcs-coverage-variants.yml"), "utf8");
  assert.match(workflow, /^on:\r?\n {2}workflow_dispatch:\r?\n/m);
  assert.doesNotMatch(workflow, /pull_request:/);
  assert.doesNotMatch(workflow, /\npush:/);
  assert.doesNotMatch(workflow, /provision-lab|bicep|softprops\/action-gh-release/);
  assert.match(workflow, /if: always\(\)\s+uses: actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02/);
  assert.match(workflow, /retention-days: 7\s+if-no-files-found: error/);
  assert.match(workflow, /qualification-results\/adcs-install-interruption\.json/);
  for (const rel of subject.REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
});
