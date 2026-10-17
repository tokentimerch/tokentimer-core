"use strict";

/** Script contract for an authenticated published-package upgrade.
 * Published predecessor archives do not contain service-host executables.
 * This contract fails closed and does not synthesize a successful upgrade.
 * publishedPackageMigrationQualified stays false. */

const assert = require("node:assert/strict");

const SCOPE = "authenticated-published-package-upgrade";
const SCENARIO = "windows-published-package-upgrade-refused";
const EVIDENCE_LEVEL = "script";
const SUITE_ID = "windows-published-package-upgrade-contract";
const SUITE_LEVEL = "real-host";
const REPORT_FIELD = "publishedPackageUpgrade";
const WORKFLOW = ".github/workflows/certops-windows-coverage-variants.yml";
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-windows-published-upgrade.js",
  "scripts/certops-windows-published-upgrade.js",
  "scripts/certops-windows-published-upgrade.test.js",
  "docs/certops/windows/published-upgrade.md",
  WORKFLOW,
]);
const PREDECESSORS = Object.freeze([
  Object.freeze({ version: "0.17.2", archive: "tokentimer-agent-0.17.2.tgz" }),
  Object.freeze({ version: "0.17.3", archive: "tokentimer-agent-0.17.3.tgz" }),
]);
const HOST_MEMBER =
  /(?:^|\/)bin\/tokentimer-agent-host-(?:amd64|arm64)\.exe$/i;
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "runId",
  "predecessorVersion",
  "serviceHostPresent",
  "publishedPackageMigrationQualified",
  "upgradeSynthesized",
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
  assert.equal(typeof root, "string");
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

function ownedPort(runId) {
  return 49152 + (Number.parseInt(runId.slice(0, 4), 16) % 8000);
}

function createRunManifest({ runId, root, predecessorVersion }) {
  assertRunId(runId);
  const normalized = assertRunRoot(root, runId);
  const predecessor = PREDECESSORS.find((row) => row.version === predecessorVersion);
  assert.ok(predecessor, "predecessor must be a published archive version");
  const port = ownedPort(runId);
  const host = `p-${runId}.published.local`;
  const name = `tt-pub-${runId}`;
  const manifest = {
    runId,
    root: normalized,
    evidenceLevel: EVIDENCE_LEVEL,
    nativeExecutionQualified: false,
    predecessorVersion,
    archive: predecessor.archive,
    serviceHostMembers: [],
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
  assert.ok(PREDECESSORS.some((row) => row.version === manifest.predecessorVersion));
  assert.equal(manifest.site.binding.kind, "hostnameport");
  assert.equal(manifest.site.binding.address, "127.0.0.1");
  assert.ok(manifest.site.binding.port >= 49152 && manifest.site.binding.port <= 57151);
  assert.equal(
    manifest.site.binding.selector,
    `hostnameport=${manifest.site.binding.host}:${manifest.site.binding.port}`,
  );
  assert.ok(manifest.site.name.includes(manifest.runId));
  assert.equal(manifest.site.binding.selector.includes("0.0.0.0"), false);
  assert.equal(manifest.site.binding.selector.includes("[::]"), false);
}

function normalizeMember(name) {
  return String(name).replaceAll("\\", "/");
}

function assertNoSynthesizedHost(members) {
  assert.ok(Array.isArray(members), "archive members must be a list");
  for (const name of members) {
    const member = normalizeMember(name);
    assert.equal(member.includes(".."), false, "refusing an unsafe archive member");
    if (HOST_MEMBER.test(member)) {
      throw new Error("refusing to synthesize a service host into a published predecessor");
    }
  }
}

function assertOwnedCommands(manifest, commands) {
  assertManifest(manifest);
  assert.ok(Array.isArray(commands));
  for (const command of commands) {
    const joined = [command.file, ...(command.args || [])].join(" ");
    assert.equal(DENIED.test(joined), false, "refusing blanket netsh reset");
    if (command.file === "netsh.exe") {
      assert.deepEqual(command.args.slice(0, 3), ["http", "delete", "sslcert"]);
      assert.equal(command.args.length, 4);
      assert.equal(command.args[3], manifest.site.binding.selector);
    }
  }
}

function buildCommandPlan(manifest) {
  assertManifest(manifest);
  const plan = {
    manifest,
    steps: [
      {
        step: "inspect-published-archive",
        file: "tar.exe",
        args: ["-tzf", manifest.archive],
      },
      {
        step: "refuse-migration",
        file: "node.exe",
        args: ["--refuse-published-upgrade", manifest.predecessorVersion],
      },
    ],
  };
  assertOwnedCommands(manifest, plan.steps);
  return plan;
}

function inspectPublishedArchive(manifest, members) {
  assertManifest(manifest);
  assertNoSynthesizedHost(members || []);
  const plan = buildCommandPlan(manifest);
  const proof = {
    scope: SCOPE,
    evidenceLevel: EVIDENCE_LEVEL,
    runId: manifest.runId,
    predecessorVersion: manifest.predecessorVersion,
    serviceHostPresent: false,
    publishedPackageMigrationQualified: false,
    upgradeSynthesized: false,
    nativeExecutionQualified: false,
    hostCapabilityAbsentIsPass: false,
    powerLossDurabilityQualified: false,
    realRebootQualified: false,
    inUseKeyDeleted: false,
    blanketNetshReset: false,
  };
  verifyProof(proof);
  return { proof, plan, passed: false, publishedPackageMigrationQualified: false };
}

function assessHostCapabilities(probe) {
  const required = ["windows", "publishedArchive", "serviceHostInArchive"];
  if (!probe || typeof probe !== "object" || Array.isArray(probe)) {
    return {
      available: false,
      missing: required,
      nativeQualified: false,
      passed: false,
      publishedPackageMigrationQualified: false,
    };
  }
  const missing = [];
  if (probe.windows !== true) missing.push("windows");
  if (probe.publishedArchive !== true) missing.push("publishedArchive");
  // A published predecessor never carries the service host. Presence is not success.
  if (probe.serviceHostInArchive === true) missing.push("serviceHostInArchive");
  return {
    available: false,
    missing: missing.length ? missing : ["serviceHostInArchive"],
    nativeQualified: false,
    passed: false,
    publishedPackageMigrationQualified: false,
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
  assert.ok(PREDECESSORS.some((row) => row.version === value.predecessorVersion));
  assert.equal(value.serviceHostPresent, false);
  assert.equal(value.publishedPackageMigrationQualified, false);
  assert.equal(value.upgradeSynthesized, false);
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
  PREDECESSORS,
  CLOSED,
  createRunManifest,
  assertManifest,
  buildCommandPlan,
  assertOwnedCommands,
  inspectPublishedArchive,
  assessHostCapabilities,
  verifyProof,
};
