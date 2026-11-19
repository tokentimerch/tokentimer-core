/**
 * Qualification notes: Skip inventory maintenance
 * After reviewing skip conditions, run node scripts/certops-skip-qualification.js --write and inspect
 * the diff. This is a heuristic mapping of skipped cases to intended qualification paths; regeneration
 * is neither test execution nor proof that any skipped behavior qualified.
 *
 * Shared execution and evidence policy: .github/maintainers/certops/e2e-qualification.md.
 */
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
const output = path.join(__dirname, "../.github/maintainers/certops/skip-qualification.generated.json");
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
const dedicatedSuites = {
  "tests/e2e/certops-log-maintenance-e2e.test.js": ["log-maintenance-stack", "certops-log-maintenance-qualification.yml", "log-maintenance"],
  "tests/e2e/certops-native-agent-e2e.test.js": ["native-agent-stack", "certops-native-agent-qualification.yml", "native-agent"],
  "tests/e2e/certops-renewal-alert-worker-e2e.test.js": ["renewal-mail-stack", "certops-renewal-alert-qualification.yml", "renewal-alert"],
  "tests/e2e/certops-signing-rotation-native-e2e.test.js": ["signing-rotation-stack", "certops-signing-rotation-qualification.yml", "signing-rotation"],
};
function environmentFor(site) {
  if (site.file === "tests/postgres/material-reconciliation.test.js") return "core-material-reconciliation";
  if (site.reason === "unimplemented") return "unsupported-feature";
  if (site.file === "packages/agent/scripts/installer-revocation-default.test.js") return site.name.startsWith("Windows") ? "windows-elevated" : "linux-filesystem";
  if (["tests/e2e/windows-material-real.test.js", "tests/e2e/windows-material-custody-real.test.js"].includes(site.file)) return "windows-material-iis";
  if (site.file === "packages/agent/src/windows-material/pkcs12.test.js") return "windows-elevated";
  if (site.file === "tests/e2e/material-providers-real.test.js") return site.name.startsWith("real Azure") ? "distribution-azure-live" : "distribution-kv-live";
  if (site.file.startsWith("packages/mcp/")) return /Windows/i.test(site.name) ? "mcp-windows-filesystem" : "mcp-posix-filesystem";
  if (dedicatedSuites[site.file]) return dedicatedSuites[site.file][0];
  if (["packages/agent/scripts/install-agent-sh.test.js", "packages/agent/scripts/pack-release.test.js", "packages/agent/src/material-preflight.test.js"].includes(site.file)) return "linux-filesystem";
  if (site.file === "packages/agent/src/index.test.js") return "windows-elevated";
  if (site.file === "packages/agent/src/issuers/adcs-enrollment-reconcile.test.js") return "openssl-fixtures";
  if (site.file === "packages/agent/src/material-store/material-store.test.js" && site.name.startsWith("real ")) return "distribution-vault-adapter";
  if (site.file === windowsPathFile) return "windows-powershell-filesystem";
  if (["tests/e2e/helpers/certops-acme-ca-watch.test.js", "tests/e2e/helpers/certops-acme-store-native-qualification.test.js"].includes(site.file)) return "windows-store-qualification-helpers";
  if (site.file === windowsContainedFile) return "windows-native-process-containment";
  const text = `${site.file} ${site.name}`;
  if (site.file === "packages/agent/src/config/config.test.js" && /re-asserts 0700/.test(site.name)) return "linux-filesystem";
  if (site.file === "packages/agent/src/issuers/adcs-enrollment.test.js" && /pins a CA cert/.test(site.name)) return "openssl-fixtures";
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
  "core-material-reconciliation": { capabilities: ["linux", "postgres", "core-api", "agent"], owner: "Original deployment reconciliation", workflow: ".github/workflows/ci.yml", status: "candidate-environment-not-qualified" },
  "windows-material-iis": {capabilities:["windows-server","iis","machine-cng","disposable-store"],owner:"Native shared material qualification",workflow:".github/workflows/ci.yml",status:"candidate-environment-not-qualified"},
  "distribution-kv-live": {capabilities:["linux","disposable-vault-kv2","synthetic-credentials"],owner:"Live material provider compatibility",workflow:".github/workflows/ci.yml",status:"candidate-environment-not-qualified"},
  "distribution-azure-live": {capabilities:["azure-keyvault","oidc","protected-environment","disposable-vault"],owner:"Protected Azure material qualification",workflow:".github/workflows/certops-azure-keyvault-qualification.yml",status:"candidate-environment-not-qualified"},
  "mcp-windows-filesystem": {capabilities:["windows","native-user-acls","owned-temporary-filesystem"],owner:"MCP adapter credential qualification",workflow:".github/workflows/ci.yml",status:"candidate-environment-not-qualified"},
  "mcp-posix-filesystem": {capabilities:["linux","posix-permissions","symlinks"],owner:"MCP adapter credential qualification",workflow:".github/workflows/ci.yml",status:"candidate-environment-not-qualified"},
  "distribution-vault-adapter": {capabilities:["linux","disposable-vault-kv2","synthetic-credentials"],owner:"Certificate distribution qualification",workflow:".github/workflows/certops-distribution-qualification.yml",status:"candidate-environment-not-qualified"},
  "windows-native-process-containment": {capabilities:["windows","powershell","cim","native-job-object"],owner:"Owned benign process containment regression",workflow:windowsPathWorkflow,status:"candidate-environment-not-qualified"},
  "windows-powershell-filesystem": { capabilities: ["windows", "powershell", "owned-temporary-filesystem"], owner: "Windows installer path supporting controls", workflow: windowsPathWorkflow, status: "candidate-environment-not-qualified" },
  "windows-store-qualification-helpers": { capabilities: ["windows", "owned-temporary-filesystem", "process-observation"], owner: "Windows store qualification tooling", workflow: ".github/workflows/ci.yml", status: "candidate-environment-not-qualified" },
  "core-exclusive-scheduler-api": { capabilities: ["postgres", "core-api", "openssl", "disposable-stack", "exclusive-scheduler-stack"], owner: "Exclusive scheduler API qualification", workflow: schedulerWorkflow, status: "candidate-environment-not-qualified" },
  "windows-elevated": { capabilities: ["windows", "elevated"], owner: "Windows qualification", workflow: ".github/workflows/certops-qualification.yml", status: "candidate-environment-not-qualified" },
  "linux-filesystem": { capabilities: ["linux", "posix-permissions", "symlinks", "git-checkout"], owner: "Cross-platform agent qualification", workflow: ".github/workflows/ci.yml", status: "candidate-environment-not-qualified" },
  "openssl-fixtures": { capabilities: ["linux", "openssl"], owner: "Certificate fixture qualification", workflow: ".github/workflows/ci.yml", status: "candidate-environment-not-qualified" },
  "core-protocol-stack": { capabilities: ["postgres", "core-api", "agent-feature-enabled"], owner: "Core protocol qualification", workflow: ".github/workflows/certops-qualification.yml", status: "candidate-environment-not-qualified" },
  "core-certificate-api": { capabilities: ["postgres", "core-api", "openssl", "disposable-stack"], owner: "Core certificate journey qualification", workflow: ".github/workflows/certops-qualification.yml", status: "candidate-environment-not-qualified" },
  "core-postgres-integration": { capabilities: ["postgres", "core-api", "worker", "agent-feature-enabled"], owner: "Core integration qualification", workflow: ".github/workflows/ci.yml", status: "candidate-environment-not-qualified" },
  "unsupported-feature": { capabilities: [], owner: "Supported capability review", workflow: null, status: "unsupported" },
  "prerequisite-review": { capabilities: [], owner: "Certificate qualification maintainers", workflow: null, status: "prerequisite-review-required" },
};
for (const [name, file] of Object.values(dedicatedSuites)) {
  environments[name] = { capabilities: ["linux", "core-api", "postgres", "exclusive-disposable-stack"], owner: name, workflow: `.github/workflows/${file}`, status: "candidate-environment-not-qualified" };
}
function routeFor(site, environment) {
  const direct = (workflow, job, command = `node --test ${site.file}`) => ({workflow, job, command});
  if (environment === "windows-store-qualification-helpers") return direct(".github/workflows/ci.yml", "certops_tooling", "node --test tests/e2e/helpers/certops-acme-ca-watch.test.js tests/e2e/helpers/certops-acme-store-native-qualification.test.js");
  if (environment === "core-material-reconciliation") return direct(".github/workflows/ci.yml", "vault_cleanup_regression", "tests/postgres/material-reconciliation.test.js");
  if (environment === "windows-material-iis") return direct(".github/workflows/ci.yml", "windows_material_qualification", site.file);
  if (environment === "distribution-kv-live") return direct(".github/workflows/ci.yml", "material_store_compatibility");
  if (environment === "distribution-azure-live") return direct(".github/workflows/certops-azure-keyvault-qualification.yml", "lab");
  if (environment === "mcp-windows-filesystem") return direct(".github/workflows/ci.yml", "windows_agent_quality", "pnpm --filter @tokentimer/mcp test");
  if (environment === "mcp-posix-filesystem") return direct(".github/workflows/ci.yml", "operator_interface", "pnpm --filter @tokentimer/mcp test");
  if (dedicatedSuites[site.file]) {
    const [, file, job] = dedicatedSuites[site.file];
    return direct(`.github/workflows/${file}`, job);
  }
  if (["linux-filesystem", "openssl-fixtures"].includes(environment)) return direct(".github/workflows/ci.yml", "backend_quality", "pnpm run test:agent");
  if (environment === "core-postgres-integration") return direct(".github/workflows/ci.yml", "build_and_test", "pnpm run test:ci");
  if (environment === "windows-elevated") {
    if (/scripts\/host\/windows-host|scripts\/installer-smoke/.test(site.file)) return direct(".github/workflows/certops-qualification.yml", "windows", "node --test packages/agent/scripts/host/windows-host.test.js");
    return direct(".github/workflows/ci.yml", "windows_agent_quality", 'node --test --test-concurrency=2 "src/**/*.test.js" "scripts/**/*.test.js"');
  }
  if (["windows-powershell-filesystem", "windows-native-process-containment"].includes(environment)) return direct(windowsPathWorkflow, "windows-e2e");
  if (environment === "distribution-vault-adapter") return direct(".github/workflows/certops-distribution-qualification.yml", "postgres", "node scripts/certops-distribution-vault.js");
  if (environment === "core-exclusive-scheduler-api") return direct(schedulerWorkflow, "scheduler-capacity");
  if (environment === "core-protocol-stack") return direct(".github/workflows/certops-qualification.yml", "agent-stack", "tests/e2e/certops-agent-e2e.test.js");
  if (environment === "core-certificate-api" && require("./certops-api-qualification").suites.some(([, file]) => site.file === `tests/e2e/${file}`)) return direct(".github/workflows/certops-qualification.yml", "agent-stack", "node scripts/certops-api-qualification.js");
  return null;
}
function generate(sites = scanner.buildInventory()) {
  const occurrences = new Map();
  const workflows = new Map();
  const yaml = require("node:module").createRequire(require.resolve("mocha/package.json"))("js-yaml");
  return { schemaVersion: 1, description: "Static skip ownership and candidate execution environments. Classification is a review aid, never execution evidence. No entry claims qualified execution.", environments, sites: sites.map((site) => {
    const key = `${site.file}\n${site.name}\n${site.kind}`;
    const occurrence = (occurrences.get(key) || 0) + 1; occurrences.set(key, occurrence);
    const environment = environmentFor(site), route = routeFor(site, environment);
    if (route && !workflows.has(route.workflow)) workflows.set(route.workflow, yaml.load(fs.readFileSync(path.join(__dirname, "..", route.workflow), "utf8")));
    const job = route && workflows.get(route.workflow).jobs?.[route.job];
    const workflowConfigured = Boolean(job && (job.steps || []).some(step => (step.run || "").includes(route.command)));
    return { id: crypto.createHash("sha256").update(`${key}\n${occurrence}`).digest("hex").slice(0, 20), ...site, environment, workflow: workflowConfigured ? route.workflow : null, workflowJob: workflowConfigured ? route.job : null, workflowStatus: workflowConfigured ? "file-selected-not-qualified" : "exact-site-execution-not-configured", executionStatus: "not-qualified", classificationStatus: "candidate-needs-review" };
  }) };
}
function validateRouting(current = generate()) {
  return current.sites.filter(site => site.reason !== "unimplemented" && (!site.workflow || !site.workflowJob)).map(site => `${site.file}:${site.line}: conditional skip has no executable owning CI job`);
}
function check(committed, current = generate()) {
  return require("node:util").isDeepStrictEqual(expand(committed), current) ? [] : ["Skip qualification mapping drift: review prerequisites and regenerate with --write"];
}
// Only storage repeats these routing/classification facts. Runtime callers still
// receive every explicit site; defaults never establish execution evidence.
const DEFAULT_FIELDS = ["kind", "reason", "workflow", "workflowJob", "workflowStatus", "executionStatus", "classificationStatus"];
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
    const problems = [...scanner.validateReasons(current.sites), ...validateRouting(current)];
    if (process.argv.includes("--write")) { fs.writeFileSync(output, JSON.stringify(compact(current), null, 2) + "\n"); }
    else problems.push(...check(JSON.parse(fs.readFileSync(output, "utf8")), current));
    if (problems.length) { console.error(problems.join("\n")); process.exitCode = 1; }
    else console.log(`Skip qualification mapping: ${current.sites.length} sites, none asserted qualified`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { generate, check, environmentFor, compact, expand, validateRouting };
