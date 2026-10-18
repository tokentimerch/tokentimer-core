"use strict";

/** Script contract that keeps crash-dump containment explicitly unqualified.
 * Any report that sets crashDumpContainmentQualified true is rejected.
 * This contract does not claim a native pass. */

const assert = require("node:assert/strict");

const SCOPE = "windows-crash-dump-containment";
const SCENARIO = "windows-crash-dump-containment-unqualified";
const EVIDENCE_LEVEL = "script";
const SUITE_ID = "windows-crash-dump-containment-contract";
const SUITE_LEVEL = "integration";
const REPORT_FIELD = "crashDumpContainment";
const WORKFLOW = ".github/workflows/certops-windows-coverage-variants.yml";
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-qualification-report.js",
  "tests/e2e/helpers/certops-windows-crash-dump.js",
  "scripts/certops-windows-crash-dump.js",
  "scripts/certops-windows-crash-dump.test.js",
  "docs/certops/windows/crash-dump.md",
  WORKFLOW,
]);
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "runId",
  "crashDumpContainmentQualified",
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
  const host = `p-${runId}.dump.local`;
  const name = `tt-dump-${runId}`;
  return {
    runId,
    root: normalized,
    evidenceLevel: EVIDENCE_LEVEL,
    nativeExecutionQualified: false,
    crashDumpContainmentQualified: false,
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
  assert.equal(manifest.crashDumpContainmentQualified, false);
  assertRunId(manifest.runId);
  assert.equal(manifest.site.binding.address, "127.0.0.1");
  assert.equal(
    manifest.site.binding.selector,
    `hostnameport=${manifest.site.binding.host}:${manifest.site.binding.port}`,
  );
  assert.ok(manifest.site.binding.host.includes(manifest.runId));
}

function unqualifiedProof(manifest) {
  assertManifest(manifest);
  const proof = {
    scope: SCOPE,
    evidenceLevel: EVIDENCE_LEVEL,
    runId: manifest.runId,
    crashDumpContainmentQualified: false,
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

function rejectReport(report) {
  if (!report || typeof report !== "object" || Array.isArray(report)) {
    throw new Error("crash dump containment is unqualified");
  }
  if (report.crashDumpContainmentQualified === true) {
    const error = new Error("crash dump containment is unqualified");
    error.passed = false;
    error.crashDumpContainmentQualified = false;
    throw error;
  }
  if (
    Object.prototype.hasOwnProperty.call(report, "crashDumpContainmentQualified") &&
    report.crashDumpContainmentQualified !== false
  ) {
    throw new Error("crash dump containment is unqualified");
  }
  return { passed: false, qualified: false, crashDumpContainmentQualified: false };
}

function review(manifest, report) {
  rejectReport(report || {});
  const proof = unqualifiedProof(manifest);
  return { passed: false, qualified: false, proof };
}

function assertOwnedCommands(manifest, commands) {
  assertManifest(manifest);
  for (const command of commands) {
    const joined = [command.file, ...(command.args || [])].join(" ");
    assert.equal(DENIED.test(joined), false, "refusing blanket netsh reset");
    if (command.file === "netsh.exe") {
      assert.equal(command.args[3], manifest.site.binding.selector);
    }
  }
}

function assessHostCapabilities(probe) {
  const required = ["windows", "crashDumpPolicy", "ownedTarget"];
  if (!probe || typeof probe !== "object" || Array.isArray(probe)) {
    return { available: false, missing: required, nativeQualified: false, passed: false };
  }
  const missing = required.filter((name) => probe[name] !== true);
  return {
    available: missing.length === 0,
    missing,
    nativeQualified: false,
    passed: false,
    crashDumpContainmentQualified: false,
  };
}

function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.notEqual(value.crashDumpContainmentQualified, true);
  assert.equal(value.crashDumpContainmentQualified, false);
  assert.deepEqual(Object.keys(value).sort(), [...PROOF_KEYS].sort());
  assert.equal(value.scope, SCOPE);
  assert.equal(value.evidenceLevel, EVIDENCE_LEVEL);
  assertRunId(value.runId);
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
  createRunManifest,
  unqualifiedProof,
  rejectReport,
  review,
  assertOwnedCommands,
  assessHostCapabilities,
  verifyProof,
};
