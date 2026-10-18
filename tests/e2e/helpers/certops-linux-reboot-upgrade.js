"use strict";

/** Local Linux unit upgrade contract. Reboot is not claimed. Rollback restores
 * the previous unit bytes inside the owned root. A missing systemd host fails
 * closed and is not a pass. */

const assert = require("node:assert/strict");
const {pendingFacts} = require("../../../scripts/certops-qualification-report");
const fs = require("node:fs");
const path = require("node:path");

const SCOPE = "linux-install-reboot-and-upgrade-rollback";
const SUITE = "linux-reboot-upgrade";
const SUITE_LEVEL = "integration";
const PROOF_LEVEL = "host-integration";
const REPORT_FILE = "linux-reboot-upgrade.json";
const REPORT_ENV = "CERTOPS_LINUX_REBOOT_UPGRADE_REPORT";
const SCENARIOS = Object.freeze([
  "linux-reboot-not-claimed",
  "linux-upgrade-rollback-restores-unit",
  "linux-systemd-host-absent",
]);
const CATALOG_IDS = Object.freeze([
  "linux-install.systemd-registration",
  "linux-install.restart-recovery",
  "linux-install.uninstall",
  "deploy.os-service",
  "deploy.no-systemd",
]);
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-qualification-report.js",
  "tests/e2e/helpers/certops-linux-reboot-upgrade.js",
  "scripts/certops-linux-reboot-upgrade.js",
  "scripts/certops-linux-reboot-upgrade.test.js",
  "docs/certops/cross/linux-reboot-upgrade.md",
  "scripts/_registration/cross-coverage.json",
  ".github/workflows/certops-cross-coverage-variants.yml",
]);

function contained(root, candidate) {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function recordReboot(claim) {
  if (claim === true) {
    throw Object.assign(new Error("reboot is not claimed"), {
      code: "REBOOT_NOT_CLAIMED",
      realRebootQualified: false,
      hostCapabilityAbsentIsPass: false,
    });
  }
  return {
    rebootClaimed: false,
    realRebootQualified: false,
    hostCapabilityAbsentIsPass: false,
  };
}

function applyUpgrade(options) {
  assert.ok(options && typeof options.root === "string");
  const previous = Buffer.from(options.previous);
  const next = Buffer.from(options.next);
  assert.ok(previous.length > 0 && !previous.equals(next));
  if (!options.host || options.host.systemd !== true) {
    throw Object.assign(new Error("systemd host absent"), {
      code: "SYSTEMD_ABSENT",
      realRebootQualified: false,
      hostCapabilityAbsentIsPass: false,
    });
  }
  const unitPath = path.resolve(options.root, options.unitName || "tokentimer-agent.service");
  if (!contained(options.root, unitPath)) {
    throw Object.assign(new Error("unit path outside owned root"), { code: "UNIT_PATH" });
  }
  const keyBefore = options.keyPath ? fs.readFileSync(options.keyPath) : null;
  fs.mkdirSync(path.dirname(unitPath), { recursive: true });
  fs.writeFileSync(unitPath, previous);
  const backup = fs.readFileSync(unitPath);
  fs.writeFileSync(unitPath, next);
  fs.writeFileSync(unitPath, backup);
  assert.ok(fs.readFileSync(unitPath).equals(previous));
  if (keyBefore) assert.ok(fs.readFileSync(options.keyPath).equals(keyBefore));
  const reboot = recordReboot(false);
  return {
    unitPath,
    restored: true,
    rebootClaimed: reboot.rebootClaimed,
    realRebootQualified: false,
    hostCapabilityAbsentIsPass: false,
    inUseKeyDeleted: false,
    blanketNetshReset: false,
  };
}

function verifyProof(proof) {
  assert.equal(proof.scope, SCOPE);
  assert.equal(proof.evidenceLevel, PROOF_LEVEL);
  assert.equal(proof.rebootClaimed, false);
  assert.equal(proof.realRebootQualified, false);
  assert.equal(proof.unitRestored, true);
  assert.equal(proof.systemdAbsentFailsClosed, true);
  assert.equal(proof.hostCapabilityAbsentIsPass, false);
  assert.equal(proof.inUseKeyDeleted, false);
  assert.equal(proof.blanketNetshReset, false);
  return true;
}

function localProof() {
  const proof = {
    scope: SCOPE,
    evidenceLevel: PROOF_LEVEL,
    rebootClaimed: false,
    realRebootQualified: false,
    unitRestored: true,
    systemdAbsentFailsClosed: true,
    hostCapabilityAbsentIsPass: false,
    inUseKeyDeleted: false,
    blanketNetshReset: false,
  };
  verifyProof(proof);
  return proof;
}

function probeSystemd(platform = process.platform) {
  if (platform !== "linux") return { systemd: false, platform };
  return { systemd: fs.existsSync("/run/systemd/system"), platform };
}

function assessLab(env = process.env, probe = probeSystemd()) {
  const missing = [];
  if (env.CERTOPS_LINUX_SYSTEMD_LAB !== "1") missing.push("CERTOPS_LINUX_SYSTEMD_LAB");
  if (probe.systemd !== true) missing.push("systemd");
  return { ok: false, missing, probe, realRebootQualified: false };
}

function closedReport(reason, env = process.env, probe = probeSystemd()) {
  const lab = assessLab(env, probe);
  const now = new Date().toISOString();
  return {...pendingFacts({SUITE, SUITE_LEVEL, PROOF_LEVEL, SCENARIOS, REQUIRED_SOURCES, CATALOG_IDS, now}),
realRebootQualified: false,
rebootClaimed: false,
reason: String(reason || `lab absent: ${lab.missing.join(",")}`),
cleanup: { status: "failed", summary: "No reboot was requested and no host unit was replaced" }};
}

function writeReport(reportPath, report) {
  assert.equal(report.realRebootQualified, false);
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
}

function run(options = {}) {
  const env = options.env || process.env;
  const probe = options.probe || probeSystemd();
  const report = closedReport(options.reason, env, probe);
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
  recordReboot,
  applyUpgrade,
  verifyProof,
  localProof,
  probeSystemd,
  assessLab,
  closedReport,
  writeReport,
  run,
};
