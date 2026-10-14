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

function environmentFor(site) {
  const text = `${site.file} ${site.name}`;
  if (site.file === "packages/agent/src/config/config.test.js" && /re-asserts 0700/.test(site.name)) return "linux-filesystem";
  if (site.file === "packages/agent/src/issuers/adcs-enrollment.test.js" && /pins a CA cert/.test(site.name)) return "openssl-fixtures";
  if (site.reason === "unimplemented") return "unsupported-feature";
  if (/tests\/e2e\/certops-agent-e2e/.test(text)) return "core-protocol-stack";
  if (/tests\/e2e\/certops-(csr|inventory|governance|trust-api|jobs-api|credentials-api|profiles-api|token-boundaries|agent-logs-api|agent-log-boundaries|agent-lease-api|shared-sources|adcs-gates-api)/.test(text)) return "core-certificate-api";
  if (/tests\/integration\//.test(text)) return "core-postgres-integration";
  if (/host\/windows-host|installer-smoke/.test(text)) return "windows-elevated";
  if (/non-win32|POSIX|symlink|symbolic.link/.test(text)) return "linux-filesystem";
  if (/win32|restricted ACL|windows-service|windows-iis/.test(text)) return "windows-elevated";
  if (/openssl|self-signed|discovery\/windows|discovery\/discovery/i.test(text)) return "openssl-fixtures";
  return "prerequisite-review";
}
const environments = {
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
  const apiFiles = new Set(require("./certops-api-qualification").suites.map(([, file]) => `tests/e2e/${file}`));
  return { schemaVersion: 1, description: "Static skip ownership and candidate execution environments. Classification is a review aid, never execution evidence. No entry claims qualified execution.", environments, sites: sites.map((site) => {
    const key = `${site.file}\n${site.name}\n${site.kind}`;
    const occurrence = (occurrences.get(key) || 0) + 1; occurrences.set(key, occurrence);
    const workflowConfigured = workflowText.includes(site.file) || (workflowText.includes("scripts/certops-api-qualification.js") && apiFiles.has(site.file));
    return { id: crypto.createHash("sha256").update(`${key}\n${occurrence}`).digest("hex").slice(0, 20), ...site, environment: environmentFor(site), workflow: workflowConfigured ? ".github/workflows/certops-qualification.yml" : null, workflowStatus: workflowConfigured ? "file-selected-not-qualified" : "exact-site-execution-not-configured", executionStatus: "not-qualified", classificationStatus: "candidate-needs-review" };
  }) };
}
function check(committed, current = generate()) {
  return JSON.stringify(committed) === JSON.stringify(current) ? [] : ["Skip qualification mapping drift: review prerequisites and regenerate with --write"];
}
if (require.main === module) {
  try {
    const current = generate();
    const problems = scanner.validateReasons(current.sites);
    if (process.argv.includes("--write")) { fs.writeFileSync(output, JSON.stringify(current, null, 2) + "\n"); }
    else problems.push(...check(JSON.parse(fs.readFileSync(output, "utf8")), current));
    if (problems.length) { console.error(problems.join("\n")); process.exitCode = 1; }
    else console.log(`Skip qualification mapping: ${current.sites.length} sites, none asserted qualified`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { generate, check, environmentFor };
