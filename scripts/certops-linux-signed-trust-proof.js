"use strict";
/** Closed public signed Ubuntu trust proof. Manual workflow_dispatch only. Not native qualification. */
const assert = require("node:assert/strict");
const SUITE = "linux-public-signed-trust-lifecycle";
const FIELD = "nativeSignedTrustLifecycle";
const SCENARIOS = [
  "linux-signed-trust-root-install",
  "linux-signed-trust-intermediate-install",
  "linux-signed-trust-selective-revoke",
  "linux-signed-trust-root-revoke",
  "linux-signed-trust-cleanup",
];
const FLAGS = [
  "actualAdminAdmission",
  "managerRefusedBeforeMutation",
  "freshDeclaredTrustCapability",
  "fourSignedCurrentClaims",
  "fourConsumedNonces",
  "claimBoundTrustEvidence",
  "actualNativeReceiptTransitions",
  "defaultOsRootLeafTrust",
  "defaultOsIntermediateLeafTrust",
  "intermediateRemovalRefusesDependentLeaf",
  "rootReceiptAndSourcePreserved",
  "rootRemovalRefusesBothLeaves",
  "originalAgentRetainedDrain",
  "ownedSourcesAndDerivedReferencesAbsent",
  "publicAndPrivateCleanupCompleted",
];
const REQUIRED_SOURCES = [
  ...new Set([
    "scripts/certops-linux-signed-trust.js",
    "scripts/certops-linux-signed-trust-proof.js",
    ".github/workflows/certops-linux-signed-trust.yml",
    ...require("../tests/e2e/helpers/certops-acme-native-adoption")
      .REQUIRED_SOURCES,
    "tests/e2e/helpers/certops-api-fixture.js",
    "tests/e2e/helpers/certops-acme-agent-attachment.js",
    "tests/e2e/helpers/certops-acme-agent-pidfd.py",
    "apps/api/services/certops/trustAnchors.js",
    "apps/api/services/certops/agentJobEligibility.js",
    "apps/api/services/certops/jobApprovals.js",
    "apps/api/services/rbac.js",
    "apps/api/services/workspace.js",
    "apps/api/services/certops/agentRegistry.js",
    "apps/api/services/certops/agentCredentials.js",
    "apps/api/services/certops/evidence.js",
    "apps/api/services/certops/parser.js",
    "apps/api/routes/certops-agent.js",
    "apps/api/services/certops/registrationCredentialCrypto.js",
    "packages/agent/src/config/index.js",
    "packages/agent/src/protocol/index.js",
    "packages/agent/src/protocol/schemaValidation.js",
    "packages/agent/src/evidence/index.js",
    "packages/agent/src/replay/index.js",
    "packages/agent/src/clock/index.js",
    "packages/agent/src/platform/index.js",
    "packages/agent/src/outbox/index.js",
    "packages/agent/vendor/log-scrub/secret-material.js",
    "packages/contracts/certops/validate-trust-result.cjs",
    "packages/contracts/certops/trust-result-contract.schema.json",
    "packages/contracts/certops/trust-job-payload.schema.json",
    "packages/contracts/certops/agent-protocol.schema.json",
    "scripts/certops_linux_signed_trust_proof.py",
    "packages/agent/src/trust-store/index.js",
    "packages/agent/src/trust-store/receipt.js",
    "packages/agent/src/platform/durability.js",
    "packages/agent/src/capabilities/index.js",
    "packages/agent/src/capabilities/qualified-capabilities.generated.js",
    "packages/agent/src/capabilities/gated-capabilities.js",
    "packages/agent/scripts/host-gate.js",
    "deploy/compose/docker-compose.test.yml",
  ]),
];
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "workspaceId",
      "agentId",
      "anchorIds",
      "jobIds",
      "claimIds",
      "fingerprints",
      "backgroundReconciliationQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SUITE);
  const uuid = (x) =>
    typeof x === "string" &&
    /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(x);
  assert.ok(uuid(p.workspaceId) && uuid(p.agentId));
  for (const [key, count] of [
    ["anchorIds", 2],
    ["jobIds", 4],
    ["claimIds", 4],
    ["fingerprints", 2],
  ]) {
    assert.ok(
      Array.isArray(p[key]) &&
        p[key].length === count &&
        p[key].every(
          key === "fingerprints"
            ? (x) => typeof x === "string" && /^[a-f0-9]{64}$/.test(x)
            : uuid,
        ) &&
        new Set(p[key]).size === count,
    );
  }
  for (const key of FLAGS) assert.equal(p[key], true, key);
  assert.equal(p.backgroundReconciliationQualified, false);
  return p;
}
module.exports = {
  SUITE,
  FIELD,
  SCENARIOS,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
};
