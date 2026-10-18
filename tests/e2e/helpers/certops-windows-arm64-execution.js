"use strict";

/** Script contract for native ARM64 execution. A pass requires process
 * architecture arm64 and a real ARM64 host probe. Any other architecture, or
 * a missing host, is a failure. This checkout does not carry that probe.
 * nativeArm64ExecutionQualified stays false here. */

const assert = require("node:assert/strict");

const SCOPE = "native-arm64-execution";
const SCENARIO = "windows-native-arm64-execution-refused";
const EVIDENCE_LEVEL = "script";
const SUITE_ID = "windows-native-arm64-execution-contract";
const SUITE_LEVEL = "real-host";
const REPORT_FIELD = "nativeArm64Execution";
const WORKFLOW = ".github/workflows/certops-windows-coverage-variants.yml";
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-qualification-report.js",
  "tests/e2e/helpers/certops-windows-arm64-execution.js",
  "scripts/certops-windows-arm64-execution.js",
  "scripts/certops-windows-arm64-execution.test.js",
  "docs/certops/windows/arm64-execution.md",
  WORKFLOW,
]);
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "runId",
  "architecture",
  "arm64HostPresent",
  "nativeArm64ExecutionQualified",
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
  assert.equal(
    /^C:\\inetpub\\wwwroot(\\|$)/i.test(normalized),
    false,
    "refusing the shared IIS content root",
  );
  return normalized;
}

function createRunManifest({ runId, root }) {
  assertRunId(runId);
  const normalized = assertRunRoot(root, runId);
  const port = 49152 + (Number.parseInt(runId.slice(0, 4), 16) % 8000);
  const host = `p-${runId}.arm64.local`;
  const name = `tt-arm-${runId}`;
  const manifest = {
    runId,
    root: normalized,
    evidenceLevel: EVIDENCE_LEVEL,
    nativeExecutionQualified: false,
    architecture: process.arch,
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
  assertManifest(manifest);
  return manifest;
}

function assertManifest(manifest) {
  assert.equal(manifest.evidenceLevel, EVIDENCE_LEVEL);
  assert.equal(manifest.nativeExecutionQualified, false);
  assertRunId(manifest.runId);
  assert.equal(manifest.site.binding.address, "127.0.0.1");
  assert.equal(
    manifest.site.binding.selector,
    `hostnameport=${manifest.site.binding.host}:${manifest.site.binding.port}`,
  );
  assert.ok(manifest.site.binding.host.includes(manifest.runId));
  assert.equal(manifest.site.binding.selector.includes("0.0.0.0"), false);
}

function realArm64ProbePresent(probe) {
  return Boolean(
    probe &&
      probe.windows === true &&
      probe.architecture === "arm64" &&
      process.arch === "arm64" &&
      probe.arm64Host === true &&
      probe.realArm64Probe === true &&
      probe.probeSource === "arm64-host",
  );
}

function assessHostCapabilities(probe) {
  const required = ["windows", "architecture", "arm64Host"];
  if (!probe || typeof probe !== "object" || Array.isArray(probe)) {
    return {
      available: false,
      missing: required,
      nativeQualified: false,
      passed: false,
      nativeArm64ExecutionQualified: false,
    };
  }
  const missing = [];
  if (probe.windows !== true) missing.push("windows");
  if (probe.architecture !== "arm64" || process.arch !== "arm64") missing.push("architecture");
  if (probe.arm64Host !== true || probe.realArm64Probe !== true) missing.push("arm64Host");
  const real = realArm64ProbePresent(probe);
  return {
    available: real,
    missing: real ? [] : missing.length ? missing : required,
    nativeQualified: false,
    passed: false,
    nativeArm64ExecutionQualified: false,
  };
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

function evaluate(manifest, probe) {
  assertManifest(manifest);
  const gate = assessHostCapabilities(probe);
  const architecture = probe && probe.architecture ? probe.architecture : process.arch;
  if (architecture !== "arm64" || process.arch !== "arm64" || !realArm64ProbePresent(probe)) {
    const proof = {
      scope: SCOPE,
      evidenceLevel: EVIDENCE_LEVEL,
      runId: manifest.runId,
      architecture,
      arm64HostPresent: false,
      nativeArm64ExecutionQualified: false,
      nativeExecutionQualified: false,
      hostCapabilityAbsentIsPass: false,
      powerLossDurabilityQualified: false,
      realRebootQualified: false,
      inUseKeyDeleted: false,
      blanketNetshReset: false,
    };
    verifyProof(proof);
    const reason =
      architecture !== "arm64" || process.arch !== "arm64"
        ? "architecture is not arm64"
        : "ARM64 host absent";
    return {
      passed: false,
      nativeQualified: false,
      nativeArm64ExecutionQualified: false,
      reason,
      missing: gate.missing,
      proof,
    };
  }
  const error = new Error("real ARM64 probe is not accepted by this local contract");
  error.passed = false;
  error.nativeArm64ExecutionQualified = false;
  throw error;
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
  assert.equal(typeof value.architecture, "string");
  assert.equal(value.arm64HostPresent, false);
  assert.equal(value.nativeArm64ExecutionQualified, false);
  if (process.arch !== "arm64" || value.architecture !== "arm64") {
    assert.equal(value.nativeArm64ExecutionQualified, false);
  }
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
  assertManifest,
  assessHostCapabilities,
  realArm64ProbePresent,
  evaluate,
  assertOwnedCommands,
  verifyProof,
};
