"use strict";
const path = require("node:path");
const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
const { verifyReport } = require("./certops-qualification-report");
const suites = [
  ["bulk-eligible-api", "certops-bulk-eligible-e2e.test.js", "CERTOPS_BULK_ELIGIBLE_REPORT"],
  ["import-metadata-api", "certops-import-metadata-e2e.test.js", "CERTOPS_IMPORT_METADATA_REPORT"],
  ["adcs-enrollment-policy-api", "certops-enrollment-policy-api-e2e.test.js", "CERTOPS_ADCS_POLICY_API_REPORT"],
  ["integration-certificate-sources-api", "certops-integration-sources-e2e.test.js", "CERTOPS_INTEGRATION_SOURCES_REPORT"],
  ["adcs-installation-recovery-api", "certops-enrollment-recovery-api-e2e.test.js", "CERTOPS_ADCS_INSTALL_RECOVERY_API_REPORT"],
  ["unmanaged-discovery-api", "certops-unmanaged-discovery-e2e.test.js", "CERTOPS_UNMANAGED_DISCOVERY_REPORT"],
  ["certificate-audit-api", "certops-audit-history-e2e.test.js", "CERTOPS_AUDIT_REPORT"],
  ["multi-target-deploy-api", "certops-multi-target-deploy-e2e.test.js", "CERTOPS_MULTI_TARGET_DEPLOY_REPORT"],
  ["derivation-failure-api", "certops-derivation-failure-e2e.test.js", "CERTOPS_DERIVATION_FAILURE_REPORT"],
  ["pause-ingestion-api", "certops-pause-ingestion-e2e.test.js", "CERTOPS_PAUSE_INGESTION_REPORT"],
  ["first-issuance-admission-api", "certops-first-issuance-admission-e2e.test.js", "CERTOPS_FIRST_ISSUANCE_ADMISSION_REPORT"],
  ["queued-profile-snapshot-api", "certops-queued-profile-snapshot-e2e.test.js", "CERTOPS_QUEUED_SNAPSHOT_REPORT"],
  ["ca-capacity-api", "certops-ca-capacity-e2e.test.js", "CERTOPS_CA_CAPACITY_REPORT"],
  ["profile-issuer-switch-api", "certops-profile-issuer-switch-e2e.test.js", "CERTOPS_ISSUER_SWITCH_REPORT"],
  ["trust-multiple-api", "certops-trust-multiple-e2e.test.js", "CERTOPS_TRUST_MULTIPLE_REPORT"],
  ["agent-log-disabled-api", "certops-log-disabled-e2e.test.js", "CERTOPS_LOG_DISABLED_REPORT"],
  ["agent-log-pagination-api", "certops-log-pagination-e2e.test.js", "CERTOPS_LOG_PAGINATION_REPORT"],
  ["csr-bound-observation-api", "certops-csr-bound-observation-e2e.test.js", "CERTOPS_CSR_BOUND_OBSERVATION_REPORT"],
  ["csr-frozen-api", "certops-csr-frozen-e2e.test.js", "CERTOPS_CSR_FROZEN_REPORT"],
  ["result-fences-api", "certops-result-fences-e2e.test.js", "CERTOPS_RESULT_FENCES_REPORT"],
  ["certificate-transfer-api", "certops-certificate-transfer-e2e.test.js", "CERTOPS_TRANSFER_REPORT"],
  ["observe-only-api", "certops-observe-only-e2e.test.js", "CERTOPS_OBSERVE_ONLY_REPORT"],
  ["agent-alert-api", "certops-agent-alert-e2e.test.js", "CERTOPS_AGENT_ALERT_REPORT"],
  ["diagnostic-agent-api", "certops-diagnostic-agent-e2e.test.js", "CERTOPS_DIAGNOSTIC_REPORT"],

  ["csr-observation-api", "certops-csr-observation-e2e.test.js", "CERTOPS_CSR_OBSERVATION_REPORT"],
  ["renewal-admission-api", "certops-renewal-admission-e2e.test.js", "CERTOPS_RENEWAL_ADMISSION_REPORT"],
  ["agent-log-order-api", "certops-agent-log-order-e2e.test.js", "CERTOPS_LOG_ORDER_REPORT"],
  ["profile-permissions-api", "certops-profile-permissions-e2e.test.js", "CERTOPS_PROFILE_PERMISSIONS_REPORT"],
  ["public-import-api", "certops-public-import-e2e.test.js", "CERTOPS_PUBLIC_IMPORT_REPORT"],
  ["bootstrap-api-fences", "certops-bootstrap-fences-e2e.test.js", "CERTOPS_BOOTSTRAP_FENCES_REPORT"],
  ["membership-api-fences", "certops-membership-fences-e2e.test.js", "CERTOPS_MEMBERSHIP_REPORT"],
  ["job-decisions-api", "certops-job-decisions-e2e.test.js", "CERTOPS_JOB_DECISIONS_REPORT"],
  ["csr-api-lifecycle", "certops-csr-lifecycle-e2e.test.js", "CERTOPS_CSR_REPORT"],
  ["csr-api-algorithms", "certops-csr-algorithms-e2e.test.js", "CERTOPS_CSR_ALGORITHMS_REPORT"],
  ["csr-api-chain", "certops-csr-chain-e2e.test.js", "CERTOPS_CSR_CHAIN_REPORT"],
  ["inventory-api-lifecycle", "certops-inventory-lifecycle-e2e.test.js", "CERTOPS_INVENTORY_REPORT"],
  ["governance-api-lifecycle", "certops-governance-e2e.test.js", "CERTOPS_GOVERNANCE_REPORT"],
  ["trust-api-lifecycle", "certops-trust-api-e2e.test.js", "CERTOPS_TRUST_API_REPORT"],
  ["jobs-api-boundaries", "certops-jobs-api-e2e.test.js", "CERTOPS_JOBS_API_REPORT"],
  ["credentials-api-lifecycle", "certops-credentials-api-e2e.test.js", "CERTOPS_CREDENTIALS_API_REPORT"],
  ["profiles-api-policy", "certops-profiles-api-e2e.test.js", "CERTOPS_PROFILES_API_REPORT"],
  ["token-api-boundaries", "certops-token-boundaries-e2e.test.js", "CERTOPS_TOKEN_BOUNDARIES_REPORT"],
  ["agent-log-api", "certops-agent-logs-api-e2e.test.js", "CERTOPS_AGENT_LOG_API_REPORT"],
  ["adcs-api-release-gates", "certops-adcs-gates-api-e2e.test.js", "CERTOPS_ADCS_GATES_API_REPORT"],
  ["agent-log-boundaries", "certops-agent-log-boundaries-e2e.test.js", "CERTOPS_AGENT_LOG_BOUNDARIES_REPORT"],
  ["agent-lease-api", "certops-agent-lease-api-e2e.test.js", "CERTOPS_AGENT_LEASE_API_REPORT"],
  ["shared-source-lifecycle", "certops-shared-sources-e2e.test.js", "CERTOPS_SHARED_SOURCES_REPORT"],
  ["retired-observation-lifecycle", "certops-retired-observation-e2e.test.js", "CERTOPS_RETIRED_OBSERVATION_REPORT"],
];
function verifySource(report, file, root = path.resolve(__dirname, "..")) {
  const expectedPath = "tests/e2e/" + file;
  const digest = require("node:crypto").createHash("sha256").update(fs.readFileSync(path.join(root, expectedPath))).digest("hex");
  return report?.fixtureSource?.file === expectedPath && report.fixtureSource.sha256 === digest;
}
function run() {
  if (!process.env.CERTOPS_CSR_API_URL || process.env.CERTOPS_CSR_DISPOSABLE_STACK !== "1") throw new Error("Explicit disposable API URL and stack authorization are required");
  if (!/^[a-f0-9]{40}$/i.test(process.env.GITHUB_SHA || "")) throw new Error("Candidate baseline GITHUB_SHA is required for verifiable reports");
  const root = path.resolve(__dirname, "..");
  const outputDirectory = path.resolve(process.env.CERTOPS_API_REPORTS_DIR || path.join(root, "qualification-results", "api"));
  fs.mkdirSync(outputDirectory, { recursive: true });
  const failures = [];
  for (const [name, file, reportVariable] of suites) {
    const reportPath = path.join(outputDirectory, `${name}.json`);
    // Remove an older result so a crashed current process cannot accidentally
    // qualify using a report from a previous candidate or invocation.
    fs.rmSync(reportPath, { force: true });
    const child = spawnSync(process.execPath, ["--test", path.join(root, "tests", "e2e", file)], { cwd: root, stdio: "inherit", timeout: 150000, env: { ...process.env, CERTOPS_E2E_REQUIRED: "1", CERTOPS_QUALIFICATION_STRICT: "1", [reportVariable]: reportPath } });
    if (child.error || child.status !== 0) { failures.push(`${name}: test process failed`); continue; }
    try {
      const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
      if (report.suite !== name) throw new Error("Unexpected suite report");
      if (!verifySource(report, file, root)) throw new Error("Current suite source evidence missing or mismatched");
      const errors = verifyReport(report);
      if (errors.length) failures.push(`${name}: mandatory qualification evidence incomplete`);
      else console.log(`${name}: mandatory execution verified`);
    } catch (_error) { failures.push(`${name}: valid current report missing`); }
  }
  if (failures.length) throw new Error(failures.join("\n"));
}
if (require.main === module) {
  try { run(); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { suites, run, verifySource };
