/*
 * Qualification notes: native-retention-policy-expiry
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * For explicit168h/720h policies independently own2 cutovers,short-lived CNG leaves,IIS and immutable
 * ledger. Actual expiry+300s grace wins before policy deadline: preserve before due, real
 * wall/monotonic wait<10min/policy, interrupt after native cert deletion before key deletion, then
 * default-clock retry. Require both old certs/keys absent and unchanged history/replacement
 * custody/TLS. Each interrupt child starts suspended in retained JobObject, actual runner
 * SID/gate,exit86,zero members/closed handles+wrapper before cleanup; exact CngKey.Exists observes
 * absence. Four policy/interruption cases required per Server.
 * installedServiceTimerQualified/fullRetentionWindowQualified=false: direct collector and explicit168h
 * are not omitted-loader/default6h cadence or168/720hour passage. Actual timer jitter4.8-7.2h after
 * completion would need same process/boot evidence.
 */
"use strict";
/** Native host adapter: run the existing genuine short-leaf cutover fixture
 * under the default and maximum retention policies. Each run owns its own
 * native keys, certificates, site, endpoint and ledger, including cleanup.
 * This calls the production collector directly, not the installed timer.
 */
const assert = require("node:assert/strict");
const contract = require("./retention-policy-expiry-proof");

const REQUIRED_SOURCES = Object.freeze([
  ...require("./retention-interrupted-process").REQUIRED_SOURCES,
  "packages/agent/scripts/host/retention-policy-expiry-fixture.js",
  "packages/agent/scripts/host/retention-policy-expiry-proof.js",
  "packages/agent/scripts/host/retention-elapsed-fixture.js",
  "packages/agent/scripts/host/retention-interrupted-child.js",
  "packages/agent/src/config/index.js",
  "packages/agent/src/index.js",
  "packages/agent/src/windows-retention/index.js",
  "packages/agent/src/windows-cert-store/index.js",
  "packages/agent/src/windows-key-survivors/index.js",
  "packages/agent/src/windows-iis/index.js",
  "packages/agent/src/windows-discovery/index.js",
  "scripts/certops_retention_policy_expiry.py",
]);

async function qualifyPolicyExpiry(context) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_HOST_TESTS, "1");
  const { qualifyElapsedRetention } = require("./retention-elapsed-fixture");
  for (const retentionHours of contract.POLICIES) {
    await context.gate.scenario(
      `windows-retention-policy-${retentionHours}-expiry-wins`,
      async () => {
        await qualifyElapsedRetention({ ...context, retentionHours });
        contract.verifyProof(
          context.gate.report.nativeRetentionPolicyExpiry[
            String(retentionHours)
          ],
        );
      },
      {
        evidenceLevel: "real-host",
        oracle: `Actual two CNG/IIS cutovers with ${retentionHours}h collector policy; real native predecessor expiry plus300s wins, measured grace wait and interrupted deletion recovery; protected replacement trustedTLS unchanged. No service timer or full policy-window claim.`,
      },
    );
  }
  return context.gate.report.nativeRetentionPolicyExpiry;
}

module.exports = { ...contract, REQUIRED_SOURCES, qualifyPolicyExpiry };
