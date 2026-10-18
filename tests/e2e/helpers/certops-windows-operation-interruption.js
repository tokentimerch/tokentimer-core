"use strict";
const {assessHostProbe} = require("../../../scripts/certops-qualification-report");

/** Host-integration contract for service interruption at certificate-operation
 * stages beyond a single recorded point. Each stage records a point and
 * recovers by starting the same owned target. An in-use key is never deleted.
 * This is a service stop or a process kill. It is not power loss and it is
 * not a reboot. */

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const SCOPE = "certificate-operation-stage-interruption";
const SCENARIO = "windows-operation-interruption-stages";
const EVIDENCE_LEVEL = "host-integration";
const SUITE_ID = "windows-operation-interruption-contract";
const SUITE_LEVEL = "integration";
const REPORT_FIELD = "operationInterruption";
const WORKFLOW = ".github/workflows/certops-windows-coverage-variants.yml";
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-qualification-report.js",
  "tests/e2e/helpers/certops-windows-operation-interruption.js",
  "scripts/certops-windows-operation-interruption.js",
  "scripts/certops-windows-operation-interruption.test.js",
  "docs/certops/windows/operation-interruption.md",
  WORKFLOW,
]);
const STAGES = Object.freeze(["key-generation", "submit", "install", "bind"]);
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "runId",
  "stage",
  "pointKind",
  "interruptionMode",
  "recordedSequence",
  "startupRecovery",
  "sameOwnedTarget",
  "nativeExecutionQualified",
  "hostCapabilityAbsentIsPass",
  "powerLossDurabilityQualified",
  "realRebootQualified",
  "inUseKeyDeleted",
  "blanketNetshReset",
]);
const CLOSED = Object.freeze([
  "nativeExecutionQualified",
  "hostCapabilityAbsentIsPass",
  "powerLossDurabilityQualified",
  "realRebootQualified",
  "inUseKeyDeleted",
  "blanketNetshReset",
]);
const KEY_DELETE =
  /delkey|certutil|cngkey|remove-item|shutdown|reboot|restart-computer|stop-computer/i;
const DENIED =
  /reset|shutdown|reboot|restart-computer|stop-computer|delkey|0\.0\.0\.0|\[::\]/i;

function assertRunId(runId) {
  assert.match(runId, /^[a-f0-9]{32}$/);
}

function normalizeRoot(root) {
  return String(root).replaceAll("/", "\\").replace(/\\+$/, "");
}

function assertRunRoot(root, runId) {
  const normalized = normalizeRoot(root);
  assert.ok(normalized.includes(runId), "run root must contain the run id");
  assert.ok(normalized.split("\\").length >= 3, "run root must be a nested directory");
  assert.equal(/^C:\\Windows(\\|$)/i.test(normalized), false, "refusing a Windows directory");
  return normalized;
}

function createRunManifest({ runId, root }) {
  assertRunId(runId);
  const normalized = assertRunRoot(root, runId);
  const port = 49152 + (Number.parseInt(runId.slice(0, 4), 16) % 8000);
  const host = `p-${runId}.opint.local`;
  const serviceName = `tt-op-${runId}`;
  return {
    runId,
    root: normalized,
    evidenceLevel: EVIDENCE_LEVEL,
    nativeExecutionQualified: false,
    serviceName,
    key: {
      container: serviceName,
      provider: "Microsoft Software Key Storage Provider",
      inUse: true,
    },
    site: {
      name: `tt-op-${runId}`,
      physicalPath: `${normalized}\\tt-op-${runId}`,
      binding: {
        kind: "hostnameport",
        host,
        address: "127.0.0.1",
        port,
        selector: `hostnameport=${host}:${port}`,
        store: "My",
      },
    },
  };
}

function recordPoint({ manifest, stage, kind, sequence, payload, mode, pid, image }) {
  assert.ok(manifest && manifest.serviceName);
  assert.ok(STAGES.includes(stage), "stage must be a certificate operation");
  assert.ok(kind === "ledger" || kind === "cng");
  assert.ok(mode === "service-stop" || mode === "process-kill");
  assertRunId(manifest.runId);
  assert.ok(Number.isInteger(sequence) && sequence > 0);
  const bytes = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload));
  assert.ok(bytes.length > 0, "recorded point needs the ledger or CNG bytes");
  const point = {
    stage,
    kind,
    runId: manifest.runId,
    sequence,
    digest: crypto.createHash("sha256").update(bytes).digest("hex"),
    mode,
    key: manifest.key,
    serviceName: manifest.serviceName,
    root: manifest.root,
    binding: manifest.site.binding.selector,
  };
  if (mode === "process-kill") {
    assert.ok(Number.isInteger(pid) && pid > 4 && pid <= 0xffffffff);
    const normalizedImage = normalizeRoot(image);
    assert.equal(normalizedImage.startsWith(`${point.root}\\`), true);
    point.pid = pid;
    point.image = normalizedImage;
  }
  return { point, bytes };
}

function assertNoInUseKeyDeletion(point, commands) {
  assert.equal(point.key.inUse, true, "recovery requires the recorded in-use key");
  for (const command of commands) {
    const joined = [command.file, ...(command.args || [])].join(" ");
    if (KEY_DELETE.test(joined) || DENIED.test(joined)) {
      throw new Error("Refusing to delete an in-use key");
    }
    if (/delete/i.test(joined) && joined.includes(point.key.container)) {
      throw new Error("Refusing to delete an in-use key");
    }
  }
}

function buildInterruptionPlan(point) {
  if (point.mode === "reboot") throw new Error("real reboot is not this case");
  assert.ok(STAGES.includes(point.stage));
  assert.equal(point.key.inUse, true);
  assert.equal(point.key.container, point.serviceName);
  assert.match(point.serviceName, /^tt-op-[a-f0-9]{32}$/);
  const commands = [];
  if (point.mode === "service-stop") {
    commands.push({ step: "interrupt", file: "sc.exe", args: ["stop", point.serviceName] });
    commands.push({
      step: "startup-recovery",
      file: "sc.exe",
      args: ["start", point.serviceName],
    });
  } else if (point.mode === "process-kill") {
    commands.push({
      step: "interrupt",
      file: "taskkill.exe",
      args: ["/PID", String(point.pid), "/F"],
    });
    commands.push({
      step: "startup-recovery",
      file: point.image,
      args: ["--recover", point.runId, "--stage", point.stage, "--sequence", String(point.sequence)],
    });
  } else {
    throw new Error("interruption mode must be service-stop or process-kill");
  }
  assertNoInUseKeyDeletion(point, commands);
  const joined = commands.map((command) => [command.file, ...command.args].join(" ")).join("\n");
  assert.equal(/shutdown|reboot|restart-computer/i.test(joined), false);
  if (point.mode === "process-kill") {
    assert.equal(commands[0].args.includes("/IM"), false);
    assert.equal(commands[0].args[1], String(point.pid));
  }
  const startup = commands.find((command) => command.step === "startup-recovery");
  if (point.mode === "service-stop") {
    assert.deepEqual(startup.args, ["start", point.serviceName]);
  } else {
    assert.equal(startup.file, point.image);
  }
  return commands;
}

function recover({ point, bytes, commands }) {
  const digest = crypto.createHash("sha256").update(bytes).digest("hex");
  if (digest !== point.digest) {
    const error = new Error("Preserve unresolved interruption point");
    error.passed = false;
    error.nativeQualified = false;
    throw error;
  }
  assertNoInUseKeyDeletion(point, commands);
  const startup = commands.filter((command) => command.step === "startup-recovery");
  assert.equal(startup.length, 1);
  const sameOwnedTarget =
    point.mode === "service-stop"
      ? startup[0].args[1] === point.serviceName
      : startup[0].file === point.image;
  assert.equal(sameOwnedTarget, true, "recovery must start the same owned target");
  const proof = {
    scope: SCOPE,
    evidenceLevel: EVIDENCE_LEVEL,
    runId: point.runId,
    stage: point.stage,
    pointKind: point.kind,
    interruptionMode: point.mode,
    recordedSequence: point.sequence,
    startupRecovery: true,
    sameOwnedTarget: true,
    nativeExecutionQualified: false,
    hostCapabilityAbsentIsPass: false,
    powerLossDurabilityQualified: false,
    realRebootQualified: false,
    inUseKeyDeleted: false,
    blanketNetshReset: false,
  };
  verifyProof(proof);
  return { started: true, keyDeleted: false, proof };
}

function writePoint(dir, record) {
  const file = path.join(dir, `interruption-${record.point.stage}.json`);
  fs.writeFileSync(
    file,
    `${JSON.stringify({ point: record.point, payload: record.bytes.toString("base64") })}\n`,
  );
  return file;
}

function readPoint(dir, stage) {
  const parsed = JSON.parse(fs.readFileSync(path.join(dir, `interruption-${stage}.json`), "utf8"));
  return { point: parsed.point, bytes: Buffer.from(parsed.payload, "base64") };
}

const assessHostCapabilities = probe => assessHostProbe(probe, ["windows", "serviceControl", "processControl", "ownedTarget"]);

function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  if (Object.prototype.hasOwnProperty.call(value, "crashDumpContainmentQualified")) {
    assert.equal(value.crashDumpContainmentQualified, false);
  }
  const comparable = Object.keys(value).filter((key) => key !== "crashDumpContainmentQualified");
  assert.deepEqual(comparable.sort(), [...PROOF_KEYS].sort());
  assert.equal(value.scope, SCOPE);
  assert.equal(value.evidenceLevel, EVIDENCE_LEVEL);
  assertRunId(value.runId);
  assert.ok(STAGES.includes(value.stage));
  assert.ok(value.pointKind === "ledger" || value.pointKind === "cng");
  assert.ok(value.interruptionMode === "service-stop" || value.interruptionMode === "process-kill");
  assert.ok(Number.isInteger(value.recordedSequence) && value.recordedSequence > 0);
  assert.equal(value.startupRecovery, true);
  assert.equal(value.sameOwnedTarget, true);
  for (const key of CLOSED) assert.equal(value[key], false, key);
  return true;
}

module.exports = {
  SCOPE,
  SCENARIO,
  EVIDENCE_LEVEL,
  SUITE_ID,
  SUITE_LEVEL,
  REPORT_FIELD,
  REQUIRED_SOURCES,
  PROOF_KEYS,
  STAGES,
  CLOSED,
  createRunManifest,
  recordPoint,
  buildInterruptionPlan,
  assertNoInUseKeyDeletion,
  recover,
  writePoint,
  readPoint,
  assessHostCapabilities,
  verifyProof,
};
