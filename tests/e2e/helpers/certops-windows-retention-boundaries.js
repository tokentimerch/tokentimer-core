/*
 * Qualification notes: retention-boundaries
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Classify zero/negative/below24,min24,default168,through720,above720 policies and before/exact/after
 * deadline. A wait<24h fails elapsed gate; even>=24h script contract never claims actual elapsed run.
 * twentyFourHourElapsedQualified/nativeExecutionQualified remain false; configuration classification
 * is not deletion/native qualification.
 */
"use strict";

/** Script contract for retention boundaries. A full 24 hour elapsed
 * qualification cannot be shortened. A wait below 24 hours records
 * twentyFourHourElapsedQualified false and fails the qualification gate.
 * Deadline and configuration boundaries are classified without claiming
 * that elapsed run. */

const assert = require("node:assert/strict");

const SCOPE = "windows-retention-boundaries";
const SCENARIO = "windows-retention-boundary-contract";
const EVIDENCE_LEVEL = "script";
const SUITE_ID = "windows-retention-boundary-contract";
const SUITE_LEVEL = "integration";
const REPORT_FIELD = "retentionBoundaries";
const WORKFLOW = ".github/workflows/certops-windows-coverage-variants.yml";
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-windows-retention-boundaries.js",
  "scripts/certops-windows-retention-boundaries.js",
  "scripts/certops-windows-retention-boundaries.test.js",
  WORKFLOW,
]);
const MIN_RETENTION_HOURS = 24;
const DEFAULT_RETENTION_HOURS = 168;
const MAX_RETENTION_HOURS = 720;
const DAY_MS = 24 * 60 * 60 * 1000;
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "runId",
  "boundary",
  "configuredHours",
  "acceptedConfiguration",
  "twentyFourHourElapsedQualified",
  "waitedMs",
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
  const host = `p-${runId}.retention.local`;
  const name = `tt-ret-${runId}`;
  return {
    runId,
    root: normalized,
    evidenceLevel: EVIDENCE_LEVEL,
    nativeExecutionQualified: false,
    key: { container: name, inUse: true },
    site: {
      name,
      physicalPath: `${normalized}\\${name}`,
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

function assertManifest(manifest) {
  assert.equal(manifest.evidenceLevel, EVIDENCE_LEVEL);
  assertRunId(manifest.runId);
  assert.equal(manifest.key.inUse, true);
  assert.equal(manifest.site.binding.address, "127.0.0.1");
  assert.equal(
    manifest.site.binding.selector,
    `hostnameport=${manifest.site.binding.host}:${manifest.site.binding.port}`,
  );
}

function boundaryName(hours) {
  if (hours < 0) return "negative";
  if (hours === 0) return "zero";
  if (hours < MIN_RETENTION_HOURS) return "below-minimum";
  if (hours === MIN_RETENTION_HOURS) return "minimum";
  if (hours === DEFAULT_RETENTION_HOURS) return "default";
  if (hours > DEFAULT_RETENTION_HOURS && hours <= MAX_RETENTION_HOURS) return "above-default";
  if (hours > MIN_RETENTION_HOURS && hours < DEFAULT_RETENTION_HOURS) return "below-default";
  return "above-maximum";
}

function configurationAccepted(hours) {
  return (
    Number.isInteger(hours) &&
    hours >= MIN_RETENTION_HOURS &&
    hours <= MAX_RETENTION_HOURS
  );
}

function proofFrom(manifest, fields) {
  const proof = {
    scope: SCOPE,
    evidenceLevel: EVIDENCE_LEVEL,
    runId: manifest.runId,
    boundary: fields.boundary,
    configuredHours: fields.configuredHours,
    acceptedConfiguration: fields.acceptedConfiguration,
    twentyFourHourElapsedQualified: false,
    waitedMs: fields.waitedMs,
    nativeExecutionQualified: false,
    hostCapabilityAbsentIsPass: false,
    powerLossDurabilityQualified: false,
    realRebootQualified: false,
    inUseKeyDeleted: false,
    blanketNetshReset: false,
  };
  verifyProof(proof);
  return proof;
}

function classifyConfiguration(manifest, hours) {
  assertManifest(manifest);
  assert.equal(typeof hours, "number", "retention hours must be a number");
  assert.equal(Number.isInteger(hours), true, "retention hours must be an integer");
  const accepted = configurationAccepted(hours);
  return {
    passed: false,
    proof: proofFrom(manifest, {
      boundary: boundaryName(hours),
      configuredHours: hours,
      acceptedConfiguration: accepted,
      waitedMs: 0,
    }),
  };
}

function classifyDeadline(manifest, { deadlineMs, nowMs }) {
  assertManifest(manifest);
  assert.equal(Number.isInteger(deadlineMs), true);
  assert.equal(Number.isInteger(nowMs), true);
  let boundary = "after-deadline";
  if (nowMs < deadlineMs) boundary = "before-deadline";
  else if (nowMs === deadlineMs) boundary = "exact-deadline";
  return {
    passed: false,
    proof: proofFrom(manifest, {
      boundary,
      configuredHours: DEFAULT_RETENTION_HOURS,
      acceptedConfiguration: true,
      waitedMs: 0,
    }),
  };
}

function evaluateElapsed(manifest, waitedMs) {
  assertManifest(manifest);
  assert.equal(Number.isInteger(waitedMs) && waitedMs >= 0, true);
  const proof = proofFrom(manifest, {
    boundary: "elapsed",
    configuredHours: DEFAULT_RETENTION_HOURS,
    acceptedConfiguration: false,
    waitedMs,
  });
  const error = new Error(
    waitedMs < DAY_MS
      ? "24 hour elapsed qualification cannot be shortened"
      : "script contract does not claim the elapsed run",
  );
  error.passed = false;
  error.proof = proof;
  error.twentyFourHourElapsedQualified = false;
  throw error;
}

function qualificationGate(proof) {
  verifyProof(proof);
  if (proof.waitedMs < DAY_MS || proof.twentyFourHourElapsedQualified !== true) {
    const error = new Error("24 hour elapsed qualification cannot be shortened");
    error.passed = false;
    error.proof = proof;
    throw error;
  }
  return false;
}

function assertOwnedCommands(manifest, commands) {
  assertManifest(manifest);
  for (const command of commands) {
    const joined = [command.file, ...(command.args || [])].join(" ");
    assert.equal(DENIED.test(joined), false, "refusing blanket netsh reset");
    if (/delete/i.test(joined) && joined.includes(manifest.key.container)) {
      throw new Error("Refusing to delete an in-use key");
    }
    if (command.file === "netsh.exe") {
      assert.equal(command.args[3], manifest.site.binding.selector);
    }
  }
}

function assessHostCapabilities(probe) {
  const required = ["windows", "retentionClock", "ownedTarget"];
  if (!probe || typeof probe !== "object" || Array.isArray(probe)) {
    return { available: false, missing: required, nativeQualified: false, passed: false };
  }
  const missing = required.filter((name) => probe[name] !== true);
  return {
    available: missing.length === 0,
    missing,
    nativeQualified: false,
    passed: false,
  };
}

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
  assert.equal(typeof value.boundary, "string");
  assert.equal(Number.isInteger(value.configuredHours), true);
  assert.equal(typeof value.acceptedConfiguration, "boolean");
  assert.equal(value.twentyFourHourElapsedQualified, false);
  assert.equal(Number.isInteger(value.waitedMs) && value.waitedMs >= 0, true);
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
  CLOSED,
  MIN_RETENTION_HOURS,
  DEFAULT_RETENTION_HOURS,
  MAX_RETENTION_HOURS,
  DAY_MS,
  createRunManifest,
  classifyConfiguration,
  classifyDeadline,
  evaluateElapsed,
  qualificationGate,
  assertOwnedCommands,
  assessHostCapabilities,
  verifyProof,
};
