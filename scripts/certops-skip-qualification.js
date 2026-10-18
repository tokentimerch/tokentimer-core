"use strict";
/**
 * Maps discovered test skip sites to prerequisite ownership and candidate execution environments.
 * Run this CLI to regenerate or check the committed mapping after inventory changes. Entries
 * describe routing and drift only; they never assert that a skipped test actually executed.
 */
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const scanner = require("./generate-skip-inventory.cjs");
const output = path.join(__dirname, "../docs/certops/skip-qualification.generated.json");
// These suites mutate shared scheduler capacity and must never inherit the
// central API runner's concurrently usable fixture ownership.
const exclusiveSchedulerFiles = new Set([
  "tests/e2e/certops-scheduler-capacity-e2e.test.js",
  "tests/e2e/certops-renewal-toggle-e2e.test.js",
  "tests/e2e/certops-retired-scheduler-e2e.test.js",
]);
const schedulerWorkflow = ".github/workflows/certops-scheduler-capacity-qualification.yml";

const windowsPathFile = "packages/agent/scripts/host/windows-installed-paths-filesystem.test.js";
const windowsPathWorkflow = ".github/workflows/certops-windows-e2e.yml";
const windowsContainedFile = "packages/agent/scripts/host/windows-contained-process.test.js";
function environmentFor(site) {
  if (site.file === "packages/agent/src/material-store/material-store.test.js" && site.name.startsWith("real ")) return "distribution-vault-adapter";
  if (site.file === windowsPathFile) return "windows-powershell-filesystem";
  if (site.file === windowsContainedFile) return "windows-native-process-containment";
  const text = `${site.file} ${site.name}`;
  if (site.file === "packages/agent/src/config/config.test.js" && /re-asserts 0700/.test(site.name)) return "linux-filesystem";
  if (site.file === "packages/agent/src/issuers/adcs-enrollment.test.js" && /pins a CA cert/.test(site.name)) return "openssl-fixtures";
  if (site.reason === "unimplemented") return "unsupported-feature";
  if (exclusiveSchedulerFiles.has(site.file)) return "core-exclusive-scheduler-api";
  if (/tests\/e2e\/certops-agent-e2e/.test(text)) return "core-protocol-stack";
  // The runner is the execution inventory. New registered API suites inherit
  // its declared prerequisites instead of falling into an unowned name heuristic.
  if (require("./certops-api-qualification").suites.some(([, file]) => site.file === `tests/e2e/${file}`)) return "core-certificate-api";
  if (/tests\/e2e\/certops-(csr|inventory|governance|trust-api|jobs-api|credentials-api|profiles-api|token-boundaries|agent-logs-api|agent-log-boundaries|agent-lease-api|shared-sources|adcs-gates-api)/.test(text)) return "core-certificate-api";
  if (/tests\/integration\//.test(text)) return "core-postgres-integration";
  if (/host\/windows-host|installer-smoke/.test(text)) return "windows-elevated";
  if (/non-win32|POSIX|symlink|symbolic.link/.test(text)) return "linux-filesystem";
  if (/win32|restricted ACL|windows-service|windows-iis/.test(text)) return "windows-elevated";
  if (/openssl|self-signed|discovery\/windows|discovery\/discovery/i.test(text)) return "openssl-fixtures";
  return "prerequisite-review";
}
const environments = {
  "distribution-vault-adapter": {capabilities:["linux","disposable-vault-kv2","synthetic-credentials"],owner:"Certificate distribution qualification",workflow:".github/workflows/certops-distribution-qualification.yml",status:"candidate-environment-not-qualified"},
  "windows-native-process-containment": {capabilities:["windows","powershell","cim","native-job-object"],owner:"Owned benign process containment regression",workflow:windowsPathWorkflow,status:"candidate-environment-not-qualified"},
  "windows-powershell-filesystem": { capabilities: ["windows", "powershell", "owned-temporary-filesystem"], owner: "Windows installer path supporting controls", workflow: windowsPathWorkflow, status: "candidate-environment-not-qualified" },
  "core-exclusive-scheduler-api": { capabilities: ["postgres", "core-api", "openssl", "disposable-stack", "exclusive-scheduler-stack"], owner: "Exclusive scheduler API qualification", workflow: schedulerWorkflow, status: "candidate-environment-not-qualified" },
  "windows-elevated": { capabilities: ["windows", "elevated"], owner: "Windows qualification", workflow: ".github/workflows/certops-qualification.yml", status: "candidate-environment-not-qualified" },
  "linux-filesystem": { capabilities: ["linux", "posix-permissions", "symlinks"], owner: "Cross-platform agent qualification", workflow: null, status: "qualification-mapping-pending" },
  "openssl-fixtures": { capabilities: ["openssl"], owner: "Certificate fixture qualification", workflow: null, status: "qualification-mapping-pending" },
  "core-protocol-stack": { capabilities: ["postgres", "core-api", "agent-feature-enabled"], owner: "Core protocol qualification", workflow: ".github/workflows/certops-qualification.yml", status: "candidate-environment-not-qualified" },
  "core-certificate-api": { capabilities: ["postgres", "core-api", "openssl", "disposable-stack"], owner: "Core certificate journey qualification", workflow: ".github/workflows/certops-qualification.yml", status: "candidate-environment-not-qualified" },
  "core-postgres-integration": { capabilities: ["postgres", "core-api", "worker", "agent-feature-enabled"], owner: "Core integration qualification", workflow: null, status: "qualification-mapping-pending" },
  "unsupported-feature": { capabilities: [], owner: "Supported capability review", workflow: null, status: "unsupported" },
  "prerequisite-review": { capabilities: [], owner: "Certificate qualification maintainers", workflow: null, status: "prerequisite-review-required" },
};
function generate(sites = scanner.buildInventory()) {
  const occurrences = new Map();
  const workflowText = fs.readFileSync(path.join(__dirname, "../.github/workflows/certops-qualification.yml"), "utf8");
  const schedulerWorkflowText = fs.readFileSync(path.join(__dirname, "..", schedulerWorkflow), "utf8");
  const apiFiles = new Set(require("./certops-api-qualification").suites.map(([, file]) => `tests/e2e/${file}`));
  return { schemaVersion: 1, description: "Static skip ownership and candidate execution environments. Classification is a review aid, never execution evidence. No entry claims qualified execution.", environments, sites: sites.map((site) => {
    const key = `${site.file}\n${site.name}\n${site.kind}`;
    const occurrence = (occurrences.get(key) || 0) + 1; occurrences.set(key, occurrence);
    const exclusive = exclusiveSchedulerFiles.has(site.file);
    const windowsPath = site.file === windowsPathFile || site.file === windowsContainedFile;
    const vaultAdapter = environmentFor(site) === "distribution-vault-adapter";
    const vaultWorkflow = ".github/workflows/certops-distribution-qualification.yml";
    const workflowConfigured = vaultAdapter ? fs.readFileSync(path.join(__dirname,"..",vaultWorkflow),"utf8").includes("node scripts/certops-distribution-vault.js") : windowsPath ? fs.readFileSync(path.join(__dirname,"..",windowsPathWorkflow),"utf8").includes(`node --test ${site.file}`) : exclusive ? schedulerWorkflowText.includes(`node --test ${site.file}`) : workflowText.includes(site.file) || (workflowText.includes("scripts/certops-api-qualification.js") && apiFiles.has(site.file));
    return { id: crypto.createHash("sha256").update(`${key}\n${occurrence}`).digest("hex").slice(0, 20), ...site, environment: environmentFor(site), workflow: workflowConfigured ? (vaultAdapter ? vaultWorkflow : windowsPath ? windowsPathWorkflow : exclusive ? schedulerWorkflow : ".github/workflows/certops-qualification.yml") : null, workflowStatus: workflowConfigured ? "file-selected-not-qualified" : "exact-site-execution-not-configured", executionStatus: "not-qualified", classificationStatus: "candidate-needs-review" };
  }) };
}
function check(committed, current = generate()) {
  return require("node:util").isDeepStrictEqual(expand(committed), current) ? [] : ["Skip qualification mapping drift: review prerequisites and regenerate with --write"];
}
// Only storage repeats these routing/classification facts. Runtime callers still
// receive every explicit site; defaults never establish execution evidence.
const DEFAULT_FIELDS = ["kind", "reason", "workflow", "workflowStatus", "executionStatus", "classificationStatus"];
function compact(value) {
  const result = structuredClone(value);
  result.siteDefaults = {};
  for (const key of DEFAULT_FIELDS) {
    if (!result.sites.every(site => Object.hasOwn(site, key))) continue;
    const counts = new Map();
    for (const site of result.sites) {
      const encoded = JSON.stringify(site[key]);
      if (encoded !== undefined) counts.set(encoded, (counts.get(encoded) || 0) + 1);
    }
    if (!counts.size) continue;
    const selected = JSON.parse([...counts].sort((a, b) => b[1] - a[1])[0][0]);
    result.siteDefaults[key] = selected;
    for (const site of result.sites) if (site[key] === selected) delete site[key];
  }
  return result;
}
function expand(value) {
  const {siteDefaults = {}, ...result} = structuredClone(value);
  require("node:assert/strict").ok(siteDefaults && typeof siteDefaults === "object" && !Array.isArray(siteDefaults) && Object.keys(siteDefaults).every(key => DEFAULT_FIELDS.includes(key)), "Invalid skip site defaults");
  result.sites = result.sites.map(site => ({...siteDefaults, ...site}));
  return result;
}
if (require.main === module) {
  try {
    const current = generate();
    const problems = scanner.validateReasons(current.sites);
    if (process.argv.includes("--write")) { fs.writeFileSync(output, JSON.stringify(compact(current), null, 2) + "\n"); }
    else problems.push(...check(JSON.parse(fs.readFileSync(output, "utf8")), current));
    if (problems.length) { console.error(problems.join("\n")); process.exitCode = 1; }
    else console.log(`Skip qualification mapping: ${current.sites.length} sites, none asserted qualified`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { generate, check, environmentFor, compact, expand };
