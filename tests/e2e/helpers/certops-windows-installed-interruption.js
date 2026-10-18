"use strict";
const {assessHostProbe} = require("../../../scripts/certops-qualification-report");

/** Script contract for deterministic interruption recovery. The recorded
 * point is a ledger or CNG marker. Recovery is a service start or a re-exec
 * of the owned image after a service stop or process kill. This is
 * host-integration evidence. It is not power-loss durability and it is not
 * a real reboot. An in-use key is never deleted. */

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const SCOPE = "installed-deterministic-interruption-recovery";
const SCENARIO = "windows-installed-deterministic-interruption";
const EVIDENCE_LEVEL = "host-integration";
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-qualification-report.js",
  "tests/e2e/helpers/certops-windows-installed-interruption.js",
  "scripts/certops-windows-installed-interruption.js",
  "scripts/certops-windows-installed-interruption.ps1",
  ".github/workflows/certops-windows-installed-interruption.yml",
]);
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "pointKind",
  "interruptionMode",
  "recordedSequence",
  "startupRecovery",
  "inUseKeyDeleted",
  "powerLossDurabilityQualified",
  "realRebootQualified",
  "nativeExecutionQualified",
  "hostCapabilityAbsentIsPass",
]);
const KEY_DELETE =
  /delkey|certutil|cngkey|remove-item|shutdown|reboot|restart-computer|stop-computer/i;

function assertRunId(runId) {
  assert.match(runId, /^[a-f0-9]{32}$/);
}

function normalizeRoot(root) {
  return String(root).replaceAll("/", "\\").replace(/\\+$/, "");
}

function recordPoint({ kind, runId, sequence, payload, mode, pid, image, root }) {
  assert.ok(kind === "ledger" || kind === "cng", "point must be ledger or cng");
  assert.ok(mode === "service-stop" || mode === "process-kill");
  assertRunId(runId);
  assert.ok(Number.isInteger(sequence) && sequence > 0);
  const bytes = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload));
  assert.ok(bytes.length > 0, "recorded point needs the ledger or CNG bytes");
  const container = `tt-int-${runId}`;
  const point = {
    kind,
    runId,
    sequence,
    digest: crypto.createHash("sha256").update(bytes).digest("hex"),
    mode,
    key: {
      container,
      provider: "Microsoft Software Key Storage Provider",
      inUse: true,
    },
    serviceName: container,
    root: normalizeRoot(root),
  };
  assert.ok(point.root.includes(runId), "interruption root must contain the run id");
  assert.equal(/^C:\\Windows(\\|$)/i.test(point.root), false);
  if (mode === "process-kill") {
    assert.ok(Number.isInteger(pid) && pid > 4 && pid <= 0xffffffff);
    assert.equal(typeof image, "string");
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
    if (KEY_DELETE.test(joined)) {
      throw new Error("Refusing to delete an in-use key");
    }
    if (
      /delete/i.test(joined) &&
      joined.includes(point.key.container)
    ) {
      throw new Error("Refusing to delete an in-use key");
    }
  }
}

function buildInterruptionPlan(point) {
  if (point.mode === "reboot") throw new Error("real reboot is not this case");
  assert.equal(point.key.inUse, true);
  assert.match(point.serviceName, /^tt-int-[a-f0-9]{32}$/);
  assert.equal(point.key.container, point.serviceName);
  assert.ok(point.kind === "ledger" || point.kind === "cng");
  const commands = [];
  if (point.mode === "service-stop") {
    commands.push({
      step: "interrupt",
      file: "sc.exe",
      args: ["stop", point.serviceName],
    });
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
      args: ["--recover", point.runId, "--sequence", String(point.sequence)],
    });
  } else {
    throw new Error("interruption mode must be service-stop or process-kill");
  }
  assertNoInUseKeyDeletion(point, commands);
  const joined = commands
    .map((command) => [command.file, ...command.args].join(" "))
    .join("\n");
  assert.equal(/shutdown|reboot|restart-computer/i.test(joined), false);
  if (point.mode === "process-kill") {
    assert.equal(commands[0].args.includes("/IM"), false);
    assert.equal(commands[0].args[1], String(point.pid));
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
  if (point.mode === "service-stop") {
    assert.deepEqual(startup[0].args, ["start", point.serviceName]);
  } else {
    assert.equal(startup[0].file, point.image);
  }
  const proof = {
    scope: SCOPE,
    evidenceLevel: EVIDENCE_LEVEL,
    pointKind: point.kind,
    interruptionMode: point.mode,
    recordedSequence: point.sequence,
    startupRecovery: true,
    inUseKeyDeleted: false,
    powerLossDurabilityQualified: false,
    realRebootQualified: false,
    nativeExecutionQualified: false,
    hostCapabilityAbsentIsPass: false,
  };
  verifyProof(proof);
  return { started: true, keyDeleted: false, proof };
}

function writePoint(dir, record) {
  const file = path.join(dir, "interruption-point.json");
  fs.writeFileSync(
    file,
    `${JSON.stringify({
      point: record.point,
      payload: record.bytes.toString("base64"),
    })}\n`,
  );
  return file;
}

function readPoint(dir) {
  const parsed = JSON.parse(
    fs.readFileSync(path.join(dir, "interruption-point.json"), "utf8"),
  );
  return { point: parsed.point, bytes: Buffer.from(parsed.payload, "base64") };
}

const assessHostCapabilities = probe => assessHostProbe(probe, ["windows", "serviceControl", "processControl", "ownedTarget"]);

function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...PROOF_KEYS].sort());
  assert.equal(value.scope, SCOPE);
  assert.equal(value.evidenceLevel, EVIDENCE_LEVEL);
  assert.ok(value.pointKind === "ledger" || value.pointKind === "cng");
  assert.ok(
    value.interruptionMode === "service-stop" ||
      value.interruptionMode === "process-kill",
  );
  assert.ok(Number.isInteger(value.recordedSequence) && value.recordedSequence > 0);
  assert.equal(value.startupRecovery, true);
  assert.equal(value.inUseKeyDeleted, false);
  assert.equal(value.powerLossDurabilityQualified, false);
  assert.equal(value.realRebootQualified, false);
  assert.equal(value.nativeExecutionQualified, false);
  assert.equal(value.hostCapabilityAbsentIsPass, false);
  return true;
}

module.exports = {
  SCOPE,
  SCENARIO,
  EVIDENCE_LEVEL,
  REQUIRED_SOURCES,
  PROOF_KEYS,
  recordPoint,
  buildInterruptionPlan,
  assertNoInUseKeyDeletion,
  recover,
  writePoint,
  readPoint,
  assessHostCapabilities,
  verifyProof,
};
