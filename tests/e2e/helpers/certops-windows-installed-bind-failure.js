/*
 * Qualification notes: installed-bind-failure
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Script contract plans owned BIND_FAILED injection and predecessor restoration on exact primary
 * selector, preserving sibling. Manifest names two run-specific sites/hostnameport selectors with
 * distinct run-derived ports. Cleanup accepts only exact netsh http delete sslcert selector and site
 * delete; refuse blanket reset, wildcard0.0.0.0/[::], selectorless delete or foreign binding sharing
 * the port. Preserve conflicted state. This source is distinct from actual installed
 * verification-failure/failed-rollback qualification and must keep nativeExecutionQualified=false when
 * no host executes; missing host fails.
 */
"use strict";
const {assessHostProbe} = require("../../../scripts/certops-qualification-report");

/** Script contract for installed public bind-failure injection and rollback.
 * Parsers and cleanup guards do not need a Windows host. A missing IIS or
 * netsh host is a failure, not a pass. Nothing here qualifies native execution,
 * VERIFY_FAILED restoration, or the separate failed-rollback lane. */

const assert = require("node:assert/strict");

const SCOPE = "installed-public-bind-failure-injection-and-rollback";
const SCENARIO = "windows-installed-public-bind-failure";
const EVIDENCE_LEVEL = "script";
const BAD_THUMBPRINT = "00".repeat(20);
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-qualification-report.js",
  "tests/e2e/helpers/certops-windows-installed-bind-failure.js",
  "scripts/certops-windows-installed-bind-failure.js",
  "scripts/certops-windows-installed-bind-failure.ps1",
  ".github/workflows/certops-windows-installed-bind-failure.yml",
]);
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "runId",
  "failureCode",
  "rolledBack",
  "siblingUntouched",
  "cleanupOwnedOnly",
  "blanketNetshReset",
  "nativeExecutionQualified",
  "verifyFailureQualified",
  "failedRollbackQualified",
  "hostCapabilityAbsentIsPass",
]);
// Blanket reset and wildcard rebinding are refused even if a caller pastes
// them into an otherwise owned plan. Cleanup may name only manifest selectors.
const DENIED =
  /reset|shutdown|reboot|restart-computer|stop-computer|delkey|0\.0\.0\.0|\[::\]/i;

function assertRunId(runId) {
  assert.match(runId, /^[a-f0-9]{32}$/);
}

function assertThumbprint(value) {
  assert.match(value, /^[A-F0-9]{40}$/);
}

function assertAppId(value) {
  assert.match(
    value,
    /^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$/,
  );
}

function ownedPorts(runId) {
  const span = 8000;
  const floor = 49152;
  const primary = floor + (Number.parseInt(runId.slice(0, 4), 16) % span);
  let sibling = floor + (Number.parseInt(runId.slice(4, 8), 16) % span);
  if (sibling === primary) sibling = primary >= floor + span - 1 ? primary - 1 : primary + 1;
  assert.notEqual(primary, sibling);
  return { primary, sibling };
}

function normalizeRoot(root) {
  return root.replaceAll("/", "\\").replace(/\\+$/, "");
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
}

function createRunManifest({
  runId,
  root,
  predecessorThumbprint,
  siblingThumbprint,
  appIds,
}) {
  assertRunId(runId);
  assertRunRoot(root, runId);
  assertThumbprint(predecessorThumbprint);
  assertThumbprint(siblingThumbprint);
  assert.notEqual(predecessorThumbprint, siblingThumbprint);
  assert.notEqual(predecessorThumbprint, BAD_THUMBPRINT);
  assert.ok(Array.isArray(appIds) && appIds.length === 2);
  for (const appId of appIds) assertAppId(appId);
  assert.notEqual(appIds[0], appIds[1]);
  const ports = ownedPorts(runId);
  const normalized = normalizeRoot(root);
  const roles = [
    ["primary", ports.primary, predecessorThumbprint, appIds[0], "p"],
    ["sibling", ports.sibling, siblingThumbprint, appIds[1], "s"],
  ];
  const manifest = {
    runId,
    root: normalized,
    evidenceLevel: EVIDENCE_LEVEL,
    nativeExecutionQualified: false,
    predecessorThumbprint,
    siblingThumbprint,
    badThumbprint: BAD_THUMBPRINT,
    sites: roles.map(([role, port, thumbprint, appId, prefix]) => {
      const host = `${prefix}-${runId}.bindfail.local`;
      const name = `tt-bindfail-${runId}-${role}`;
      return {
        name,
        role,
        physicalPath: `${normalized}\\${name}`,
        binding: {
          kind: "hostnameport",
          host,
          address: "127.0.0.1",
          port,
          selector: `hostnameport=${host}:${port}`,
          thumbprint,
          appId,
          store: "My",
        },
      };
    }),
  };
  assertManifest(manifest);
  return manifest;
}

function assertManifest(manifest) {
  assert.ok(manifest && typeof manifest === "object" && !Array.isArray(manifest));
  assert.equal(manifest.evidenceLevel, EVIDENCE_LEVEL);
  assert.equal(manifest.nativeExecutionQualified, false);
  assertRunId(manifest.runId);
  assert.equal(manifest.badThumbprint, BAD_THUMBPRINT);
  assert.ok(Array.isArray(manifest.sites) && manifest.sites.length === 2);
  const names = new Set();
  const selectors = new Set();
  const ports = new Set();
  for (const site of manifest.sites) {
    assert.match(
      site.name,
      new RegExp(`^tt-bindfail-${manifest.runId}-(primary|sibling)$`),
    );
    assert.equal(names.has(site.name), false, "owned site names must be unique");
    names.add(site.name);
    assert.equal(site.binding.kind, "hostnameport");
    assert.equal(site.binding.address, "127.0.0.1");
    assert.equal(site.binding.store, "My");
    assert.ok(site.binding.port >= 49152 && site.binding.port <= 57151);
    assert.equal(ports.has(site.binding.port), false, "owned ports must be unique");
    ports.add(site.binding.port);
    assert.equal(
      site.binding.selector,
      `hostnameport=${site.binding.host}:${site.binding.port}`,
    );
    assert.equal(selectors.has(site.binding.selector), false, "owned bindings must be unique");
    selectors.add(site.binding.selector);
    assert.ok(site.binding.host.endsWith(".bindfail.local"));
    assert.ok(site.binding.host.includes(manifest.runId));
    assert.equal(site.physicalPath.startsWith(`${manifest.root}\\`), true);
    assert.equal(site.binding.selector.includes("0.0.0.0"), false);
    assert.equal(site.binding.selector.includes("[::]"), false);
    assertThumbprint(site.binding.thumbprint);
    assertAppId(site.binding.appId);
  }
  const primary = manifest.sites.find((site) => site.role === "primary");
  const sibling = manifest.sites.find((site) => site.role === "sibling");
  assert.ok(primary && sibling);
  assert.equal(primary.binding.thumbprint, manifest.predecessorThumbprint);
  assert.equal(sibling.binding.thumbprint, manifest.siblingThumbprint);
  assert.notEqual(primary.binding.appId, sibling.binding.appId);
}

function netshAdd(selector, thumbprint, appId) {
  return {
    file: "netsh.exe",
    args: [
      "http",
      "add",
      "sslcert",
      selector,
      `certhash=${thumbprint}`,
      `appid=${appId}`,
      "certstorename=My",
    ],
  };
}

function netshDelete(selector) {
  return {
    file: "netsh.exe",
    args: ["http", "delete", "sslcert", selector],
  };
}

function siteByRole(manifest, role) {
  const site = manifest.sites.find((candidate) => candidate.role === role);
  assert.ok(site, role);
  return site;
}

function buildCommandPlan(manifest) {
  assertManifest(manifest);
  const primary = siteByRole(manifest, "primary");
  const sibling = siteByRole(manifest, "sibling");
  const siteStep = (site) => ({
    step: "create-site",
    file: "appcmd.exe",
    args: [
      "add",
      "site",
      `/name:${site.name}`,
      `/bindings:https/127.0.0.1:${site.binding.port}:${site.binding.host}`,
      `/physicalPath:${site.physicalPath}`,
    ],
  });
  const plan = {
    manifest,
    steps: [
      siteStep(primary),
      siteStep(sibling),
      {
        step: "bind-predecessor",
        ...netshAdd(
          primary.binding.selector,
          primary.binding.thumbprint,
          primary.binding.appId,
        ),
      },
      {
        step: "bind-sibling",
        ...netshAdd(
          sibling.binding.selector,
          sibling.binding.thumbprint,
          sibling.binding.appId,
        ),
      },
      { step: "inject-delete", ...netshDelete(primary.binding.selector) },
      {
        step: "inject-add",
        expectedStatus: 1,
        ...netshAdd(
          primary.binding.selector,
          manifest.badThumbprint,
          primary.binding.appId,
        ),
      },
      {
        step: "rollback-add",
        ...netshAdd(
          primary.binding.selector,
          manifest.predecessorThumbprint,
          primary.binding.appId,
        ),
      },
    ],
  };
  assertOwnedPlan(manifest, plan);
  return plan;
}

function selectorsInArgs(args) {
  return args.filter(
    (arg) => arg.startsWith("hostnameport=") || arg.startsWith("ipport="),
  );
}

function siteNamesInArgs(args) {
  const names = [];
  for (const arg of args) {
    const match = /^\/name:(.+)$/.exec(arg);
    if (match) names.push(match[1]);
  }
  return names;
}

function assertOwnedPlan(manifest, plan) {
  assertManifest(manifest);
  assert.equal(plan.manifest, manifest);
  const ownedSelectors = new Set(manifest.sites.map((site) => site.binding.selector));
  const ownedNames = new Set(manifest.sites.map((site) => site.name));
  const primarySelector = siteByRole(manifest, "primary").binding.selector;
  const siblingSelector = siteByRole(manifest, "sibling").binding.selector;
  for (const step of plan.steps) {
    assert.ok(step.file === "netsh.exe" || step.file === "appcmd.exe", step.file);
    const joined = step.args.join(" ");
    assert.equal(DENIED.test(joined), false, joined);
    for (const selector of selectorsInArgs(step.args)) {
      assert.equal(ownedSelectors.has(selector), true, selector);
    }
    for (const name of siteNamesInArgs(step.args)) {
      assert.equal(ownedNames.has(name), true, name);
    }
    if (
      step.step === "inject-delete" ||
      step.step === "inject-add" ||
      step.step === "rollback-add"
    ) {
      assert.deepEqual(selectorsInArgs(step.args), [primarySelector]);
      assert.equal(joined.includes(siblingSelector), false);
    }
    if (step.file === "netsh.exe" && step.args[1] === "delete") {
      assert.deepEqual(step.args.slice(0, 3), ["http", "delete", "sslcert"]);
      assert.equal(step.args.length, 4);
      assert.equal(ownedSelectors.has(step.args[3]), true);
    }
  }
  assert.deepEqual(
    plan.steps.map((step) => step.step),
    [
      "create-site",
      "create-site",
      "bind-predecessor",
      "bind-sibling",
      "inject-delete",
      "inject-add",
      "rollback-add",
    ],
  );
  const injection = plan.steps.find((step) => step.step === "inject-add");
  assert.equal(injection.expectedStatus, 1);
  assert.equal(
    injection.args.includes(`certhash=${BAD_THUMBPRINT}`),
    true,
    "injection must present the unusable hash",
  );
}

function endpointPort(endpoint) {
  if (typeof endpoint !== "string") return null;
  const index = endpoint.lastIndexOf(":");
  if (index <= 0) return null;
  const port = Number(endpoint.slice(index + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return port;
}

function selectorEndpoint(selector) {
  const match = /^(?:hostnameport|ipport)=(.+)$/.exec(selector || "");
  if (!match) throw new Error("unreadable selector");
  return match[1];
}

function parseNetshSslCertListing(text) {
  assert.equal(typeof text, "string");
  const records = [];
  let current = null;
  const flush = () => {
    if (!current) return;
    if (!current.selector || !current.thumbprint) {
      throw new Error("incomplete sslcert record");
    }
    records.push(current);
    current = null;
  };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) {
      flush();
      continue;
    }
    const match =
      /^(IP:port|Hostname:port|Certificate Hash|Application ID|Certificate Store Name)\s*:\s*(.+)$/i.exec(
        line,
      );
    if (!match) continue;
    const key = match[1].toLowerCase();
    const value = match[2].trim();
    if (key === "ip:port" || key === "hostname:port") {
      flush();
      const kind = key === "ip:port" ? "ipport" : "hostnameport";
      current = {
        kind,
        selector: `${kind}=${value}`,
        endpoint: value,
        thumbprint: null,
        appId: null,
        store: null,
      };
      continue;
    }
    if (!current) throw new Error("sslcert field before selector");
    if (key === "certificate hash") {
      const compact = value.replaceAll(" ", "");
      if (!/^[A-Fa-f0-9]{40}$/.test(compact)) {
        throw new Error("unreadable certificate hash");
      }
      current.thumbprint = compact.toUpperCase();
    } else if (key === "application id") {
      current.appId = value;
    } else if (key === "certificate store name") {
      current.store = value;
    }
  }
  flush();
  return records;
}

function parseAppcmdSiteList(text) {
  assert.equal(typeof text, "string");
  const sitePattern =
    /^SITE\s+"([^"]+)"\s+\(id:(\d+),bindings:(.*?),state:([^)]*)\)\s*$/gim;
  const sites = [];
  let match;
  while ((match = sitePattern.exec(text)) !== null) {
    const [, name, id, bindingsField, state] = match;
    const bindings = bindingsField
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0)
      .map((entry) => {
        const bindingMatch = /^([A-Za-z]+)\/([^:]*):(\d+):(.*)$/.exec(entry);
        if (!bindingMatch) throw new Error("unreadable appcmd binding");
        return {
          protocol: bindingMatch[1].toLowerCase(),
          address: bindingMatch[2],
          port: Number(bindingMatch[3]),
          hostHeader: bindingMatch[4],
        };
      });
    sites.push({ name, id, state, bindings });
  }
  return sites;
}

function planCleanup(manifest, observed) {
  assertManifest(manifest);
  assert.ok(
    observed && Array.isArray(observed.bindings) && Array.isArray(observed.sites),
  );
  const owned = new Map(
    manifest.sites.map((site) => [site.binding.selector, site]),
  );
  const ports = new Set(manifest.sites.map((site) => site.binding.port));
  const ownedNames = new Set(manifest.sites.map((site) => site.name));
  for (const binding of observed.bindings) {
    const endpoint = binding.endpoint || selectorEndpoint(binding.selector);
    const port = endpointPort(endpoint);
    if (ports.has(port) && !owned.has(binding.selector)) {
      throw new Error("Preserve unresolved bind-failure fixture");
    }
    if (
      owned.has(binding.selector) &&
      binding.store &&
      String(binding.store).toLowerCase() !== "my"
    ) {
      throw new Error("Preserve unresolved bind-failure fixture");
    }
  }
  const commands = [];
  for (const binding of observed.bindings) {
    if (!owned.has(binding.selector)) continue;
    commands.push({ step: "cleanup-binding", ...netshDelete(binding.selector) });
  }
  for (const site of observed.sites) {
    if (!ownedNames.has(site.name)) continue;
    commands.push({
      step: "cleanup-site",
      file: "appcmd.exe",
      args: ["delete", "site", `/name:${site.name}`],
    });
  }
  assertCleanupSafe(manifest, commands);
  return commands;
}

function assertCleanupSafe(manifest, commands) {
  assertManifest(manifest);
  assert.ok(Array.isArray(commands));
  const ownedSelectors = new Set(
    manifest.sites.map((site) => site.binding.selector),
  );
  const ownedNames = new Set(manifest.sites.map((site) => site.name));
  for (const command of commands) {
    assert.ok(Array.isArray(command.args));
    const joined = command.args.join(" ");
    assert.equal(DENIED.test(joined), false, "refusing blanket netsh reset");
    if (command.file === "netsh.exe") {
      assert.deepEqual(command.args.slice(0, 3), ["http", "delete", "sslcert"]);
      assert.equal(command.args.length, 4);
      assert.equal(ownedSelectors.has(command.args[3]), true);
    } else if (command.file === "appcmd.exe") {
      assert.deepEqual(command.args.slice(0, 2), ["delete", "site"]);
      const name = /^\/name:(.+)$/.exec(command.args[2] || "");
      assert.ok(name && ownedNames.has(name[1]));
      assert.equal(command.args.length, 3);
    } else {
      throw new Error("unexpected cleanup executable");
    }
  }
}

const assessHostCapabilities = probe => assessHostProbe(probe, ["windows", "iis", "netsh", "appcmd"]);

function hashArg(args) {
  const raw = args.find((arg) => arg.startsWith("certhash="));
  const match = /^certhash=([A-F0-9]{40})$/.exec(raw || "");
  assert.ok(match, "certhash must be one owned thumbprint");
  return match[1];
}

function simulateScriptContract(manifest, seed = { bindings: [], sites: [] }) {
  const plan = buildCommandPlan(manifest);
  const bindings = new Map(
    seed.bindings.map((binding) => [binding.selector, { ...binding }]),
  );
  const sites = new Map(seed.sites.map((site) => [site.name, { ...site }]));
  const siblingSelector = siteByRole(manifest, "sibling").binding.selector;
  const siblingBefore = manifest.siblingThumbprint;
  let failureCode = null;
  for (const step of plan.steps) {
    if (step.step === "create-site") {
      sites.set(siteNamesInArgs(step.args)[0], { name: siteNamesInArgs(step.args)[0] });
    } else if (
      step.step === "bind-predecessor" ||
      step.step === "bind-sibling" ||
      step.step === "rollback-add"
    ) {
      const selector = selectorsInArgs(step.args)[0];
      bindings.set(selector, {
        selector,
        endpoint: selectorEndpoint(selector),
        thumbprint: hashArg(step.args),
        store: "My",
        kind: "hostnameport",
      });
    } else if (step.step === "inject-delete") {
      bindings.delete(selectorsInArgs(step.args)[0]);
    } else if (step.step === "inject-add") {
      // The unusable hash is rejected. It must not become the live binding.
      failureCode = "BIND_FAILED";
      assert.equal(bindings.has(selectorsInArgs(step.args)[0]), false);
    }
  }
  const primarySelector = siteByRole(manifest, "primary").binding.selector;
  const rolledBack =
    bindings.get(primarySelector)?.thumbprint === manifest.predecessorThumbprint &&
    bindings.get(siblingSelector)?.thumbprint === siblingBefore;
  if (!rolledBack || failureCode !== "BIND_FAILED") {
    const error = new Error("Preserve unresolved bind-failure fixture");
    error.passed = false;
    error.nativeQualified = false;
    throw error;
  }
  const cleanup = planCleanup(manifest, {
    bindings: [...bindings.values()],
    sites: [...sites.values()],
  });
  for (const command of cleanup) {
    if (command.file === "netsh.exe") bindings.delete(command.args[3]);
    if (command.file === "appcmd.exe") {
      const name = /^\/name:(.+)$/.exec(command.args[2])[1];
      sites.delete(name);
    }
  }
  const proof = {
    scope: SCOPE,
    evidenceLevel: EVIDENCE_LEVEL,
    runId: manifest.runId,
    failureCode: "BIND_FAILED",
    rolledBack: true,
    siblingUntouched: true,
    cleanupOwnedOnly: true,
    blanketNetshReset: false,
    nativeExecutionQualified: false,
    verifyFailureQualified: false,
    failedRollbackQualified: false,
    hostCapabilityAbsentIsPass: false,
  };
  verifyProof(proof);
  return {
    proof,
    cleanup,
    remainingBindings: [...bindings.keys()],
    remainingSites: [...sites.keys()],
  };
}

function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...PROOF_KEYS].sort());
  assert.equal(value.scope, SCOPE);
  assert.equal(value.evidenceLevel, EVIDENCE_LEVEL);
  assertRunId(value.runId);
  assert.equal(value.failureCode, "BIND_FAILED");
  assert.equal(value.rolledBack, true);
  assert.equal(value.siblingUntouched, true);
  assert.equal(value.cleanupOwnedOnly, true);
  assert.equal(value.blanketNetshReset, false);
  assert.equal(value.nativeExecutionQualified, false);
  assert.equal(value.verifyFailureQualified, false);
  assert.equal(value.failedRollbackQualified, false);
  assert.equal(value.hostCapabilityAbsentIsPass, false);
  return true;
}

module.exports = {
  SCOPE,
  SCENARIO,
  EVIDENCE_LEVEL,
  BAD_THUMBPRINT,
  REQUIRED_SOURCES,
  PROOF_KEYS,
  createRunManifest,
  assertManifest,
  buildCommandPlan,
  assertOwnedPlan,
  parseNetshSslCertListing,
  parseAppcmdSiteList,
  planCleanup,
  assertCleanupSafe,
  assessHostCapabilities,
  simulateScriptContract,
  verifyProof,
};
