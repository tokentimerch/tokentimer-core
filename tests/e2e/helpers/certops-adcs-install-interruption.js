"use strict";

/** Local contract for recovery across remaining AD CS installation phases.
 * The same owned target restarts. An in-use key is never deleted. This is
 * a service restart of that target. Power-loss durability stays false. A
 * real reboot stays false. A blanket netsh reset is refused.
 */

const assert = require("node:assert/strict");
const {assessLab, createClosedReport, writeReport} = require("../../../scripts/certops-adcs-lab-contract");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const SUITE = "adcs-install-interruption";
const SOURCE = "tests/e2e/helpers/certops-adcs-install-interruption.js";
const EVIDENCE_LEVEL = "integration";
const SCOPE = "adcs-install-phase-owned-target-restart";
const DEFAULT_REPORT = "qualification-results/adcs-install-interruption.json";
const PHASES = Object.freeze([
  "role-install",
  "ca-config",
  "template-publish",
  "acl-grant",
  "iis-enroll-site",
]);
const REQUIRED_SCENARIOS = Object.freeze(PHASES.map((phase) => `adcs-install-interruption-${phase}`));
const REQUIRED_CAPABILITIES = Object.freeze(["windows", "domain", "api", "qualifiedBuild"]);
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-adcs-lab-contract.js",
  SOURCE,
  "scripts/certops-adcs-install-interruption.js",
  "docs/certops/adcs/install-interruption.md",
  ".github/workflows/certops-adcs-coverage-variants.yml",
]);
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "phase",
  "target",
  "restartedTarget",
  "inUseKeyDeleted",
  "blanketNetshReset",
  "powerLossDurabilityQualified",
  "realRebootQualified",
  "disposableForestRan",
  "nativeExecutionQualified",
  "hostCapabilityAbsentIsPass",
]);
const KEY_DELETE = /delkey|certutil|cngkey|remove-item|shutdown|reboot|restart-computer|stop-computer/i;
const NETSH_RESET = /netsh(\.exe)?\b.*\breset\b/i;



function assertRunId(runId) {
  assert.match(runId, /^[a-f0-9]{32}$/);
}

function recordPhase({ phase, runId, sequence, payload }) {
  assert.ok(PHASES.includes(phase), "installation phase required");
  assertRunId(runId);
  assert.ok(Number.isInteger(sequence) && sequence > 0);
  const bytes = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload || ""));
  assert.ok(bytes.length > 0, "installation phase needs recorded bytes");
  const target = `tt-adcs-install-${runId}`;
  const point = {
    phase,
    runId,
    sequence,
    mode: "service-restart",
    target,
    digest: crypto.createHash("sha256").update(bytes).digest("hex"),
    key: { container: `tt-adcs-key-${runId}`, inUse: true },
  };
  return { point, bytes };
}

function assertSafeCommands(point, commands) {
  assert.equal(point.key.inUse, true, "recovery requires the recorded in-use key");
  for (const command of commands) {
    const joined = [command.file, ...(command.args || [])].join(" ");
    if (NETSH_RESET.test(joined)) throw new Error("Refusing blanket netsh reset");
    if (KEY_DELETE.test(joined)) throw new Error("Refusing to delete an in-use key");
    if (/delete/i.test(joined) && joined.includes(point.key.container)) {
      throw new Error("Refusing to delete an in-use key");
    }
  }
}

function buildRestartPlan(point) {
  if (point.mode === "reboot") throw new Error("real reboot is not this case");
  if (point.mode === "power-loss") throw new Error("power loss is not this case");
  assert.equal(point.mode, "service-restart");
  assert.ok(PHASES.includes(point.phase));
  assert.match(point.target, /^tt-adcs-install-[a-f0-9]{32}$/);
  assert.equal(point.key.container, `tt-adcs-key-${point.runId}`);
  const commands = [
    { step: "interrupt", file: "sc.exe", args: ["stop", point.target] },
    { step: "restart", file: "sc.exe", args: ["start", point.target] },
  ];
  assertSafeCommands(point, commands);
  assert.equal(commands[0].args[1], commands[1].args[1]);
  return commands;
}

function recover({ point, bytes, commands }) {
  const digest = crypto.createHash("sha256").update(bytes).digest("hex");
  if (digest !== point.digest) {
    const error = new Error("Preserve unresolved installation point");
    error.passed = false;
    error.nativeQualified = false;
    throw error;
  }
  assertSafeCommands(point, commands);
  const restart = commands.filter((command) => command.step === "restart");
  assert.equal(restart.length, 1);
  assert.deepEqual(restart[0].args, ["start", point.target]);
  const interrupt = commands.filter((command) => command.step === "interrupt");
  assert.equal(interrupt.length, 1);
  assert.equal(interrupt[0].args[1], point.target);
  const proof = {
    scope: SCOPE,
    evidenceLevel: EVIDENCE_LEVEL,
    phase: point.phase,
    target: point.target,
    restartedTarget: point.target,
    inUseKeyDeleted: false,
    blanketNetshReset: false,
    powerLossDurabilityQualified: false,
    realRebootQualified: false,
    disposableForestRan: false,
    nativeExecutionQualified: false,
    hostCapabilityAbsentIsPass: false,
  };
  verifyProof(proof);
  return { restarted: true, keyDeleted: false, proof };
}

function writePoint(dir, record) {
  const file = path.join(dir, "install-interruption-point.json");
  fs.writeFileSync(file, `${JSON.stringify({ point: record.point, payload: record.bytes.toString("base64") })}\n`);
  return file;
}

function readPoint(dir) {
  const parsed = JSON.parse(fs.readFileSync(path.join(dir, "install-interruption-point.json"), "utf8"));
  return { point: parsed.point, bytes: Buffer.from(parsed.payload, "base64") };
}

function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...PROOF_KEYS].sort());
  assert.equal(value.scope, SCOPE);
  assert.equal(value.evidenceLevel, EVIDENCE_LEVEL);
  assert.ok(PHASES.includes(value.phase));
  assert.match(value.target, /^tt-adcs-install-[a-f0-9]{32}$/);
  assert.equal(value.restartedTarget, value.target);
  assert.equal(value.inUseKeyDeleted, false);
  assert.equal(value.blanketNetshReset, false);
  assert.equal(value.powerLossDurabilityQualified, false);
  assert.equal(value.realRebootQualified, false);
  assert.equal(value.disposableForestRan, false);
  assert.equal(value.nativeExecutionQualified, false);
  assert.equal(value.hostCapabilityAbsentIsPass, false);
  return true;
}

function qualifyInstallInterruption(context = {}) {
  const lab = assessLab(context.env, context.platform);
  if (!lab.ok) throw new Error(`Disposable AD CS forest is required: ${lab.missing.join(",")}`);
  throw new Error("Installation interruption markers do not restart an owned target");
}

const buildClosedReport = createClosedReport({SUITE, EVIDENCE_LEVEL, REQUIRED_CAPABILITIES, REQUIRED_SCENARIOS}, {powerLossDurabilityQualified: false, realRebootQualified: false, inUseKeyDeleted: false, blanketNetshReset: false}, {});



function dispatch(options = {}) {
  const env = options.env || process.env;
  const platform = options.platform || process.platform;
  const lab = assessLab(env, platform);
  const reportPath = options.reportPath || env.CERTOPS_ADCS_INSTALL_INTERRUPTION_REPORT || DEFAULT_REPORT;
  const reason = lab.ok
    ? "Installation interruption markers do not restart an owned target"
    : `Disposable AD CS forest is required: ${lab.missing.join(",")}`;
  writeReport(reportPath, buildClosedReport(reason));
  console.error(reason);
  return 1;
}

if (require.main === module) process.exitCode = dispatch();

module.exports = {
  SUITE,
  SOURCE,
  SCOPE,
  EVIDENCE_LEVEL,
  PHASES,
  REQUIRED_SCENARIOS,
  REQUIRED_CAPABILITIES,
  REQUIRED_SOURCES,
  PROOF_KEYS,
  DEFAULT_REPORT,
  assessLab,
  recordPhase,
  buildRestartPlan,
  assertSafeCommands,
  recover,
  writePoint,
  readPoint,
  verifyProof,
  qualifyInstallInterruption,
  buildClosedReport,
  dispatch,
};
