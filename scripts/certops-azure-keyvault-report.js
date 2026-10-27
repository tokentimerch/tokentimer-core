"use strict";
// Closed evidence schema: no URLs, bundles, tokens, assertions, raw HTTP errors,
// free-form messages or resource inventories may be uploaded by this campaign.
const fs = require("node:fs"),
  path = require("node:path");
const { fail } = require("../infra/certops-azure-keyvault/policy");
const SCENARIOS = Object.freeze([
  "owned-isolated-rbac-resources",
  "signed-packaged-publication-and-postgres-pin",
  "exact-version-full-chain-and-key-association",
  "consumer-approved-secret-only",
  "consumer-cannot-write-or-modify",
  "unauthorized-identity-and-foreign-scope-denied",
  "missing-version-no-latest-fallback",
  "real-401-renews-workload-token",
  "disabled-version-fails-closed",
  "transient-reset-and-response-deadline-recovery",
  "committed-lost-response-durable-uncertainty",
  "restart-reconciles-one-exact-version-without-put",
  "linux-pinned-install-interruption-reconciliation",
  "approved-retained-version-rollback",
  "multiple-versions-never-adopt-latest",
  "rbac-revocation-and-restoration",
  "token-file-rotation-and-expired-sink-rejection",
  "real-oidc-assertion-expiry-and-renewal",
]);
const DEFERRED = Object.freeze([
  "azure-imds-managed-identity",
  "natural-azure-access-token-expiration",
  "full-http-operator-and-real-ca-e2e",
  "production-release-artifact",
]);
function requireValue(condition) {
  if (!condition) fail("AZURE_KV_EVIDENCE_SCHEMA_DENIED");
}
function keys(value, allowed, required = allowed) {
  requireValue(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(value).every((key) => allowed.includes(key)) &&
      required.every((key) => Object.hasOwn(value, key)),
  );
}
function counts(rows) {
  return {
    passed: rows.filter((row) => row.status === "passed").length,
    failed: rows.filter((row) => row.status === "failed").length,
    pending: rows.filter((row) => row.status === "pending").length,
    skipped: 0,
  };
}
function emptyReport(sourceSha, packageSha256) {
  const scenarios = SCENARIOS.map((id) => ({ id, status: "pending" }));
  return {
    schemaVersion: 1,
    suite: "real-azure-key-vault-provider-and-signed-service-integration",
    sourceSha,
    packageSha256,
    buildMode: "qualification-only-not-release",
    productionQualified: false,
    fullOperatorE2e: false,
    fixtureCertificateAuthority: true,
    backend: "microsoft-azure-public-key-vault-secrets",
    authModes: ["github-oidc-workload-identity", "token-file"],
    unqualified: [...DEFERRED],
    status: "failed",
    databaseCleanup: "not-created",
    counts: counts(scenarios),
    facts: {
      ambiguousPutAttempts: 0,
      recoveredProviderVersions: 0,
      acceptedProviderPins: 0,
      azure401Responses: 0,
      azure403Responses: 0,
      entraTokenExchanges: 0,
      exactPackageVerified: false,
    },
    scenarios,
  };
}
function verify(
  report,
  { requirePassed = true, sourceSha = process.env.GITHUB_SHA } = {},
) {
  const template = emptyReport("", "");
  keys(report, Object.keys(template));
  for (const field of [
    "schemaVersion",
    "suite",
    "buildMode",
    "productionQualified",
    "fullOperatorE2e",
    "fixtureCertificateAuthority",
    "backend",
    "authModes",
    "unqualified",
  ])
    requireValue(
      JSON.stringify(report[field]) === JSON.stringify(template[field]),
    );
  requireValue(
    /^[a-f0-9]{40}$/.test(report.sourceSha) &&
      (!sourceSha || report.sourceSha === sourceSha) &&
      /^[a-f0-9]{64}$/.test(report.packageSha256),
  );
  requireValue(
    ["passed", "failed"].includes(report.status) &&
      ["completed", "not-created", "failed"].includes(report.databaseCleanup),
  );
  requireValue(
    Array.isArray(report.scenarios) &&
      report.scenarios.length === SCENARIOS.length,
  );
  report.scenarios.forEach((row, i) => {
    keys(row, ["id", "status", "code"], ["id", "status"]);
    requireValue(
      row.id === SCENARIOS[i] &&
        ["passed", "failed", "pending"].includes(row.status),
    );
    if (Object.hasOwn(row, "code"))
      requireValue(
        row.status === "failed" && /^AZURE_KV_[A-Z0-9_]{1,180}$/.test(row.code),
      );
  });
  keys(report.counts, ["passed", "failed", "pending", "skipped"]);
  keys(report.facts, Object.keys(template.facts));
  for (const [key, value] of Object.entries(report.facts))
    requireValue(
      key === "exactPackageVerified"
        ? typeof value === "boolean"
        : Number.isSafeInteger(value) && value >= 0 && value <= 100000,
    );
  requireValue(
    JSON.stringify(report.counts) === JSON.stringify(counts(report.scenarios)),
  );
  if (requirePassed || report.status === "passed")
    requireValue(
      report.status === "passed" &&
        report.databaseCleanup === "completed" &&
        report.counts.passed === SCENARIOS.length &&
        report.counts.failed === 0 &&
        report.counts.pending === 0 &&
        report.facts.ambiguousPutAttempts === 1 &&
        report.facts.recoveredProviderVersions === 1 &&
        report.facts.acceptedProviderPins === 2 &&
        report.facts.azure401Responses >= 1 &&
        report.facts.azure403Responses >= 4 &&
        report.facts.entraTokenExchanges >= 4 &&
        report.facts.exactPackageVerified === true,
    );
  return true;
}
function verifyCleanup(report, sourceSha = process.env.GITHUB_SHA) {
  keys(report, ["schemaVersion", "sourceSha", "cleanup", "purgeRequested"]);
  requireValue(
    report.schemaVersion === 1 &&
      /^[a-f0-9]{40}$/.test(report.sourceSha) &&
      (!sourceSha || sourceSha === report.sourceSha) &&
      ["completed", "failed"].includes(report.cleanup) &&
      report.purgeRequested === false,
  );
}
function read(file) {
  const stat = fs.lstatSync(file);
  requireValue(stat.isFile() && !stat.isSymbolicLink() && stat.size < 131072);
  return JSON.parse(fs.readFileSync(file, "utf8"));
}
function artifactCheck(directory, { sourceSha = process.env.GITHUB_SHA } = {}) {
  const stat = fs.lstatSync(directory);
  requireValue(stat.isDirectory() && !stat.isSymbolicLink());
  const names = fs.readdirSync(directory);
  requireValue(
    names.includes("azure-keyvault-cleanup.json") &&
      names.every((name) =>
        [
          "azure-keyvault-evidence.json",
          "azure-keyvault-cleanup.json",
        ].includes(name),
      ),
  );
  for (const name of names) {
    const report = read(path.join(directory, name));
    if (name === "azure-keyvault-evidence.json")
      verify(report, { requirePassed: false, sourceSha });
    else verifyCleanup(report, sourceSha);
  }
  return true;
}
module.exports = {
  SCENARIOS,
  DEFERRED,
  emptyReport,
  counts,
  verify,
  verifyCleanup,
  artifactCheck,
};
if (require.main === module) {
  try {
    if (process.argv[2] === "--artifact-check") artifactCheck(process.argv[3]);
    else verify(read(process.argv[2]));
    console.log("Azure Key Vault sanitized evidence schema accepted");
  } catch {
    console.error("AZURE_KV_EVIDENCE_REJECTED_NO_SENSITIVE_DIAGNOSTICS");
    process.exitCode = 1;
  }
}
