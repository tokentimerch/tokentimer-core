/*
 * Qualification notes: acl-path-env
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Script refusals cover Everyone-read/unprotected DACL,unquoted spaced binary path and missing
 * LocalSystem environment. Each proof remains
 * nativeExecutionQualified=false/hostCapabilityAbsentIsPass=false; missing host fails. Spaces in owned
 * site path are allowed; exact hostname selector only,never blanket netsh reset. Catalog scope is
 * state ACL,path quoting,system environment without promotion.
 */
"use strict";
const {assessHostProbe} = require("../../../scripts/certops-qualification-report");

/** Script contract for weak ACLs, unquoted paths that contain spaces, and a
 * missing SYSTEM environment. Each defect fails closed. A missing host is
 * not a pass. hostCapabilityAbsentIsPass stays false. */

const assert = require("node:assert/strict");

const SCOPE = "windows-acl-path-environment-failures";
const SCENARIO = "windows-acl-path-env-refusals";
const EVIDENCE_LEVEL = "script";
const SUITE_ID = "windows-acl-path-env-contract";
const SUITE_LEVEL = "integration";
const REPORT_FIELD = "aclPathEnvironment";
const WORKFLOW = ".github/workflows/certops-windows-coverage-variants.yml";
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-qualification-report.js",
  "tests/e2e/helpers/certops-windows-acl-path-env.js",
  "scripts/certops-windows-acl-path-env.js",
  "scripts/certops-windows-acl-path-env.test.js",
  WORKFLOW,
]);
const REFUSALS = Object.freeze([
  "weak-acl",
  "unquoted-path",
  "missing-system-environment",
]);
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "runId",
  "refusal",
  "refused",
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
  const host = `p-${runId}.acl.local`;
  const name = `tt-acl-${runId}`;
  const spacedBinary = `${normalized}\\Program Files\\${name}\\host.exe`;
  const manifest = {
    runId,
    root: normalized,
    evidenceLevel: EVIDENCE_LEVEL,
    nativeExecutionQualified: false,
    binaryPath: spacedBinary,
    quotedBinaryPath: `"${spacedBinary}"`,
    site: {
      name,
      physicalPath: `${normalized}\\site files\\${name}`,
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
  assert.ok(manifest.binaryPath.includes(" "));
  assert.ok(manifest.quotedBinaryPath.startsWith('"') && manifest.quotedBinaryPath.endsWith('"'));
  assert.equal(manifest.site.binding.address, "127.0.0.1");
  assert.equal(
    manifest.site.binding.selector,
    `hostnameport=${manifest.site.binding.host}:${manifest.site.binding.port}`,
  );
  assert.ok(manifest.site.physicalPath.includes(manifest.runId));
  assert.equal(manifest.site.binding.selector.includes("0.0.0.0"), false);
}

function proofFor(manifest, refusal) {
  assert.ok(REFUSALS.includes(refusal), refusal);
  const proof = {
    scope: SCOPE,
    evidenceLevel: EVIDENCE_LEVEL,
    runId: manifest.runId,
    refusal,
    refused: true,
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

function refuseWeakAcl(manifest, acl) {
  assertManifest(manifest);
  const everyone = Boolean(acl && (acl.everyoneRead === true || acl.daclProtected === false));
  if (!everyone) {
    throw new Error("expected a weak ACL");
  }
  return {
    passed: false,
    nativeQualified: false,
    proof: proofFor(manifest, "weak-acl"),
  };
}

function refuseUnquotedPath(manifest, observation) {
  assertManifest(manifest);
  const pathValue = observation && observation.binaryPath;
  const quoted = observation && observation.quoted === true;
  assert.equal(typeof pathValue, "string");
  if (!pathValue.includes(" ") || quoted) {
    throw new Error("expected an unquoted path with spaces");
  }
  assert.equal(pathValue, manifest.binaryPath);
  return {
    passed: false,
    nativeQualified: false,
    proof: proofFor(manifest, "unquoted-path"),
  };
}

function refuseMissingSystemEnvironment(manifest, environment) {
  assertManifest(manifest);
  const identity = environment && environment.identity;
  const systemRoot = environment && environment.systemRoot;
  const present = identity === "LocalSystem" && typeof systemRoot === "string" && systemRoot.length > 0;
  if (present) {
    throw new Error("expected a missing SYSTEM environment");
  }
  return {
    passed: false,
    nativeQualified: false,
    proof: proofFor(manifest, "missing-system-environment"),
  };
}

function assertOwnedCommands(manifest, commands) {
  assertManifest(manifest);
  for (const command of commands) {
    const joined = [command.file, ...(command.args || [])].join(" ");
    assert.equal(DENIED.test(joined), false, "refusing blanket netsh reset");
    if (command.file === "netsh.exe") {
      assert.deepEqual(command.args.slice(0, 3), ["http", "delete", "sslcert"]);
      assert.equal(command.args[3], manifest.site.binding.selector);
      assert.equal(command.args.length, 4);
    }
  }
}

const assessHostCapabilities = probe => assessHostProbe(probe, ["windows", "acl", "quotedPath", "systemEnvironment"]);

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
  assert.ok(REFUSALS.includes(value.refusal));
  assert.equal(value.refused, true);
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
  REFUSALS,
  CLOSED,
  createRunManifest,
  assertManifest,
  refuseWeakAcl,
  refuseUnquotedPath,
  refuseMissingSystemEnvironment,
  assertOwnedCommands,
  assessHostCapabilities,
  verifyProof,
};
