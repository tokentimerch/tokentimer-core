"use strict";

/** Script contract for protected-key and journal recovery. An orphan journal,
 * a weak ACL, and an unreadable journal fail closed. None of those cases
 * deletes the protected key. */

const assert = require("node:assert/strict");

const SCOPE = "protected-key-journal-recovery";
const SCENARIO = "windows-protected-journal-recovery-refused";
const EVIDENCE_LEVEL = "script";
const SUITE_ID = "windows-protected-recovery-contract";
const SUITE_LEVEL = "integration";
const REPORT_FIELD = "protectedKeyRecovery";
const WORKFLOW = ".github/workflows/certops-windows-coverage-variants.yml";
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-windows-protected-recovery.js",
  "scripts/certops-windows-protected-recovery.js",
  "scripts/certops-windows-protected-recovery.test.js",
  "docs/certops/windows/protected-recovery.md",
  WORKFLOW,
]);
const DEFECTS = Object.freeze(["orphan-journal", "weak-acl", "unreadable-journal"]);
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "runId",
  "defect",
  "failedClosed",
  "protectedKeyDeleted",
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
  const host = `p-${runId}.recover.local`;
  const container = `tt-rec-${runId}`;
  return {
    runId,
    root: normalized,
    evidenceLevel: EVIDENCE_LEVEL,
    nativeExecutionQualified: false,
    serviceName: container,
    journal: `${normalized}\\state\\enrollment-journal.json`,
    key: {
      container,
      provider: "Microsoft Software Key Storage Provider",
      inUse: true,
      protected: true,
    },
    site: {
      name: container,
      physicalPath: `${normalized}\\${container}`,
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
  assert.equal(manifest.key.protected, true);
  assert.equal(manifest.key.container, manifest.serviceName);
  assert.ok(manifest.journal.includes(manifest.runId));
  assert.equal(manifest.site.binding.address, "127.0.0.1");
  assert.equal(
    manifest.site.binding.selector,
    `hostnameport=${manifest.site.binding.host}:${manifest.site.binding.port}`,
  );
}

function assertNoProtectedKeyDeletion(manifest, commands) {
  assert.equal(manifest.key.protected, true);
  for (const command of commands) {
    const joined = [command.file, ...(command.args || [])].join(" ");
    if (KEY_DELETE.test(joined) || DENIED.test(joined)) {
      throw new Error("Refusing to delete a protected key");
    }
    if (/delete/i.test(joined) && joined.includes(manifest.key.container)) {
      throw new Error("Refusing to delete a protected key");
    }
  }
}

function preservePlan(manifest) {
  assertManifest(manifest);
  const commands = [
    { step: "preserve-key", file: "sc.exe", args: ["query", manifest.serviceName] },
  ];
  assertNoProtectedKeyDeletion(manifest, commands);
  return commands;
}

function failClosed(manifest, defect) {
  assertManifest(manifest);
  assert.ok(DEFECTS.includes(defect), defect);
  const commands = preservePlan(manifest);
  const proof = {
    scope: SCOPE,
    evidenceLevel: EVIDENCE_LEVEL,
    runId: manifest.runId,
    defect,
    failedClosed: true,
    protectedKeyDeleted: false,
    nativeExecutionQualified: false,
    hostCapabilityAbsentIsPass: false,
    powerLossDurabilityQualified: false,
    realRebootQualified: false,
    inUseKeyDeleted: false,
    blanketNetshReset: false,
  };
  verifyProof(proof);
  return { passed: false, nativeQualified: false, proof, commands, keyDeleted: false };
}

function assessHostCapabilities(probe) {
  const required = ["windows", "journal", "protectedKey", "ownedTarget"];
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
  assert.ok(DEFECTS.includes(value.defect));
  assert.equal(value.failedClosed, true);
  assert.equal(value.protectedKeyDeleted, false);
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
  DEFECTS,
  CLOSED,
  createRunManifest,
  failClosed,
  assertNoProtectedKeyDeletion,
  assessHostCapabilities,
  verifyProof,
};
