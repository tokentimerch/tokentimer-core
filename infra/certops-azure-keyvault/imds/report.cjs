"use strict";

const assert = require("node:assert/strict");
const { sha256 } = require("./probe.cjs");

const PROFILE = "azure-imds-managed-identity";

function verifyAbsence(actual, expected) {
  assert.ok(Array.isArray(actual) && Array.isArray(expected) && expected.length > 0);
  assert.ok(new Set(expected).size === expected.length);
  assert.deepEqual(actual.map(item => item.id).sort(), [...expected].sort());
  for (const item of actual) assert.deepEqual(item, { id: item.id, state: "absent" });
}

function verifyObservation(observation, plan, role, expectedWriteStatus) {
  assert.deepEqual(Object.keys(observation).sort(), ["runId", "attempt", "sourceSha", "packageArtifact",
    "identity", "azureReadStatus", "azureConsumerWriteStatus", "pinnedVersion"].sort());
  const own = plan.hosts[role];
  const opposite = plan.hosts[role === "issuer" ? "consumer" : "issuer"];
  assert.equal(observation.runId, plan.runId);
  assert.equal(observation.attempt, plan.attempt);
  assert.equal(observation.sourceSha, plan.sourceSha);
  assert.deepEqual(observation.packageArtifact, plan.packageArtifact);
  assert.deepEqual(observation.identity, {
    role,
    hostIdSha256: sha256(own.vmId),
    identitySha256: sha256(own.principalId),
    oppositeIdentitySha256: sha256(opposite.principalId),
    imdsRequests: 2,
    ownTokenStatus: 200,
    oppositeIdentityTokenStatus: 400,
  });
  assert.equal(observation.azureReadStatus, 200);
  assert.equal(observation.pinnedVersion, plan.pinnedVersion);
  assert.equal(observation.azureConsumerWriteStatus, expectedWriteStatus);
}

// The trusted workflow supplies the verified package identity, two matching ARM
// command outputs and a separately verified teardown receipt for its own lease.
function assemble({ plan, observations, owned, teardown, run }) {
  const { PROFILES, verify } = require("../../../scripts/certops-final-package-evidence.cjs");
  return assembleReport({ plan, observations, owned, teardown, run }, { PROFILES, verify });
}

function assembleReport({ plan, observations, owned, teardown, run }, { PROFILES, verify }) {
  assert.equal(teardown.runId, plan.runId);
  assert.equal(teardown.attempt, plan.attempt);
  assert.equal(plan.attempt, "1");
  assert.equal(teardown.sourceSha, plan.sourceSha);
  assert.deepEqual(teardown.packageArtifact, plan.packageArtifact);
  assert.equal(String(run.id), plan.runId);
  assert.equal(run.run_attempt, 1);
  assert.equal(run.head_sha, plan.sourceSha);
  assert.equal(run.event, "workflow_dispatch");
  assert.equal(run.head_branch, "main");
  const groupId = "/subscriptions/" + plan.subscriptionId + "/resourceGroups/" + plan.group;
  assert.equal(owned.groupId, groupId);
  assert.equal(teardown.groupId, owned.groupId);
  const vmIds = ["issuer", "consumer"].map(role =>
    groupId + "/providers/Microsoft.Compute/virtualMachines/tt-imds-" + role);
  assert.ok(vmIds.every(vmId => owned.resourceIds.includes(vmId)));
  assert.ok(owned.resourceIds.includes(groupId + "/providers/Microsoft.KeyVault/vaults/" + plan.vault));
  assert.equal(teardown.vault, plan.vault);
  assert.equal(teardown.vaultState, "soft-deleted");
  assert.equal(teardown.purged, false);
  assert.equal(teardown.commands.length, 2);
  const commandIds = vmIds.map(vmId => vmId + "/runCommands/imds-proof").sort();
  assert.deepEqual([...owned.commandIds].sort(), commandIds);
  assert.deepEqual(teardown.commands.map(command => command.id).sort(), commandIds);
  assert.ok(teardown.commands.every(command => command.state === "Succeeded" && command.exitCode === 0));
  verifyAbsence(teardown.absence, [owned.groupId, ...owned.resourceIds, ...owned.roleAssignmentIds, ...owned.commandIds]);

  assert.equal(observations.length, 2);
  verifyObservation(observations[0], plan, "issuer", null);
  verifyObservation(observations[1], plan, "consumer", 403);

  const scenarios = PROFILES[PROFILE].scenarios.map(id => ({ id, status: "passed" }));
  const report = {
    schemaVersion: 1,
    profile: PROFILE,
    sourceSha: plan.sourceSha,
    runId: plan.runId,
    packageArtifact: plan.packageArtifact,
    status: "passed",
    productionQualified: false,
    fullOperatorE2e: false,
    counts: { passed: scenarios.length, failed: 0, pending: 0, skipped: 0 },
    scenarios,
    cleanup: { database: "completed", provider: "completed", agent: "completed",
      credentials: "completed", resources: "completed" },
    facts: {
      authMode: PROFILE,
      imdsHost: "169.254.169.254",
      metadataHeader: true,
      identities: observations.map(observation => observation.identity),
      azureReadStatus: observations[1].azureReadStatus,
      azureConsumerWriteStatus: observations[1].azureConsumerWriteStatus,
      pinnedVersion: plan.pinnedVersion,
    },
    nativeService: null,
  };
  verify(PROFILE, report, {
    sourceSha: plan.sourceSha, runId: plan.runId, packageIdentity: plan.packageArtifact,
    files: {}, requireNative: false, run,
  });
  return report;
}

module.exports = { assemble, assembleReport, verifyObservation };
