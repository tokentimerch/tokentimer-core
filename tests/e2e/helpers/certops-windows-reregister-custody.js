"use strict";
const {assessHostProbe} = require("../../../scripts/certops-qualification-report");

/** Host-integration contract for installed-service re-registration.
 * Re-registration keeps the same CNG key custody. An in-use key is never
 * deleted. Ambiguous custody fails closed. */

const assert = require("node:assert/strict");

const SCOPE = "installed-service-reregister-custody";
const SCENARIO = "windows-reregister-custody-preserved";
const EVIDENCE_LEVEL = "host-integration";
const SUITE_ID = "windows-reregister-custody-contract";
const SUITE_LEVEL = "integration";
const REPORT_FIELD = "reregisterCustody";
const WORKFLOW = ".github/workflows/certops-windows-coverage-variants.yml";
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-qualification-report.js",
  "tests/e2e/helpers/certops-windows-reregister-custody.js",
  "scripts/certops-windows-reregister-custody.js",
  "scripts/certops-windows-reregister-custody.test.js",
  "docs/certops/windows/reregister-custody.md",
  WORKFLOW,
]);
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "runId",
  "custody",
  "sameContainer",
  "ambiguousCustody",
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
  const host = `p-${runId}.rereg.local`;
  const container = `tt-reg-${runId}`;
  const manifest = {
    runId,
    root: normalized,
    evidenceLevel: EVIDENCE_LEVEL,
    nativeExecutionQualified: false,
    serviceName: container,
    key: {
      container,
      provider: "Microsoft Software Key Storage Provider",
      inUse: true,
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
  assertManifest(manifest);
  return manifest;
}

function assertManifest(manifest) {
  assert.equal(manifest.evidenceLevel, EVIDENCE_LEVEL);
  assert.equal(manifest.nativeExecutionQualified, false);
  assertRunId(manifest.runId);
  assert.equal(manifest.key.inUse, true);
  assert.equal(manifest.key.container, manifest.serviceName);
  assert.match(manifest.key.container, /^tt-reg-[a-f0-9]{32}$/);
  assert.equal(manifest.site.binding.address, "127.0.0.1");
  assert.equal(
    manifest.site.binding.selector,
    `hostnameport=${manifest.site.binding.host}:${manifest.site.binding.port}`,
  );
  assert.ok(manifest.site.binding.host.includes(manifest.runId));
}

function containersOf(request) {
  if (!request || typeof request !== "object") return [];
  if (Array.isArray(request.containers)) return request.containers;
  if (typeof request.container === "string") return [request.container];
  return [];
}

function assertNoInUseKeyDeletion(manifest, commands) {
  assert.equal(manifest.key.inUse, true);
  for (const command of commands) {
    const joined = [command.file, ...(command.args || [])].join(" ");
    if (KEY_DELETE.test(joined) || DENIED.test(joined)) {
      throw new Error("Refusing to delete an in-use key");
    }
    if (/delete/i.test(joined) && joined.includes(manifest.key.container)) {
      throw new Error("Refusing to delete an in-use key");
    }
    if (command.file === "netsh.exe") {
      assert.deepEqual(command.args.slice(0, 3), ["http", "delete", "sslcert"]);
      assert.equal(command.args.length, 4);
      assert.equal(command.args[3], manifest.site.binding.selector);
    }
  }
}

function buildReRegisterPlan(manifest) {
  assertManifest(manifest);
  const commands = [
    { step: "stop-owned", file: "sc.exe", args: ["stop", manifest.serviceName] },
    { step: "reregister", file: "sc.exe", args: ["start", manifest.serviceName] },
  ];
  assertNoInUseKeyDeletion(manifest, commands);
  return commands;
}

function reRegister(manifest, request) {
  assertManifest(manifest);
  const containers = containersOf(request);
  const unique = new Set(containers);
  if (request && request.ambiguous === true) {
    const error = new Error("ambiguous custody");
    error.passed = false;
    error.inUseKeyDeleted = false;
    throw error;
  }
  if (containers.length !== 1 || unique.size !== 1 || containers[0] !== manifest.key.container) {
    const error = new Error("ambiguous custody");
    error.passed = false;
    error.inUseKeyDeleted = false;
    throw error;
  }
  const commands = buildReRegisterPlan(manifest);
  const proof = {
    scope: SCOPE,
    evidenceLevel: EVIDENCE_LEVEL,
    runId: manifest.runId,
    custody: manifest.key.container,
    sameContainer: true,
    ambiguousCustody: false,
    nativeExecutionQualified: false,
    hostCapabilityAbsentIsPass: false,
    powerLossDurabilityQualified: false,
    realRebootQualified: false,
    inUseKeyDeleted: false,
    blanketNetshReset: false,
  };
  verifyProof(proof);
  return { proof, commands, keyDeleted: false, passed: false };
}

const assessHostCapabilities = probe => assessHostProbe(probe, ["windows", "serviceControl", "cngCustody", "ownedTarget"]);

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
  assert.match(value.custody, /^tt-reg-[a-f0-9]{32}$/);
  assert.equal(value.custody, `tt-reg-${value.runId}`);
  assert.equal(value.sameContainer, true);
  assert.equal(value.ambiguousCustody, false);
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
  buildReRegisterPlan,
  assertNoInUseKeyDeletion,
  reRegister,
  assessHostCapabilities,
  verifyProof,
};
