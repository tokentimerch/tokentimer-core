"use strict";
// Profiles without a real producer remain unsatisfied. No generic PASS fallback.
const assert = require("node:assert/strict");
const { verifyIdentity } = require("./certops-azure-keyvault-package.cjs");
const OPERATOR = Object.freeze(["public-http-configuration", "real-ca-protocol-issuance", "independent-approval",
  "signed-agent-job-execution", "distinct-renewable-role-identities", "cross-role-denials", "exact-provider-version-pin",
  "served-tls-certificate-chain", "interruption-resume-without-republish", "owned-teardown"]);
const PROFILES = Object.freeze({
  "azure-operator-http-real-ca": { file: "azure-operator-final-package.json", scenarios: OPERATOR },
  "openbao-operator-http-real-ca": { file: "openbao-operator-final-package.json", scenarios: OPERATOR },
  "azure-imds-managed-identity": { file: "azure-imds-final-package.json", scenarios: ["real-imds-token-endpoint",
    "distinct-hosts-and-identities", "opposite-identity-token-denied", "scoped-secret-read", "consumer-secret-write-denied", "exact-version-no-latest", "owned-teardown"] },
  "azure-natural-access-token-expiration": { file: "azure-natural-expiration-final-package.json", scenarios: [
    "token-naturally-expires", "token-renewed-after-expiry", "exact-version-read-after-renewal", "owned-teardown"] },
});
function keys(value, expected) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort());
}
const hash = value => assert.match(value, /^[a-f0-9]{64}$/);
const positive = value => assert.ok(Number.isSafeInteger(value) && value > 0 && value <= 10000000000);
function verifyNative(value, files) {
  keys(value, ["kind", "installedFileHashes", "agentId", "enrolledAgentId", "before", "after"]);
  assert.equal(value.kind, "installed-linux-systemd");
  assert.deepEqual(value.installedFileHashes, files);
  assert.match(value.agentId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i);
  assert.equal(value.enrolledAgentId, value.agentId);
  for (const observation of [value.before, value.after]) {
    keys(observation, ["unit", "activeState", "subState", "mainPid", "procPid", "procStartTicks", "serviceUid", "procUid",
      "commandPackageEntry", "processEntrySha256"]);
    assert.match(observation.unit, /^tokentimer-agent(?:-[a-z0-9]{8,32})?\.service$/);
    assert.equal(observation.activeState, "active"); assert.equal(observation.subState, "running");
    positive(observation.mainPid); assert.equal(observation.procPid, observation.mainPid);
    assert.match(observation.procStartTicks, /^[1-9][0-9]{0,19}$/);
    positive(observation.serviceUid); assert.equal(observation.procUid, observation.serviceUid);
    assert.equal(observation.commandPackageEntry, "bin/tokentimer-agent.js");
    assert.equal(observation.processEntrySha256, files[observation.commandPackageEntry]);
  }
  assert.equal(value.before.unit, value.after.unit); assert.equal(value.before.serviceUid, value.after.serviceUid);
  assert.ok(value.before.mainPid !== value.after.mainPid || value.before.procStartTicks !== value.after.procStartTicks);
}
function operatorFacts(facts, profile) {
  keys(facts, ["http", "ca", "tls", "jobs", "identities"]);
  keys(facts.http, ["mutations", "directDatabaseInjection", "signatureChecksBypassed"]);
  positive(facts.http.mutations); assert.equal(facts.http.directDatabaseInjection, false); assert.equal(facts.http.signatureChecksBypassed, false);
  keys(facts.ca, ["kind", "fixture", "requests", "leafSha256", "chainSha256"]);
  assert.ok(["acme", "adcs", "vault-pki", "openbao-pki"].includes(facts.ca.kind));
  assert.equal(facts.ca.fixture, false); positive(facts.ca.requests); hash(facts.ca.leafSha256); hash(facts.ca.chainSha256);
  keys(facts.tls, ["leafSha256", "chainSha256", "verifiedChain"]);
  assert.equal(facts.tls.leafSha256, facts.ca.leafSha256); assert.equal(facts.tls.chainSha256, facts.ca.chainSha256);
  assert.equal(facts.tls.verifiedChain, true);
  keys(facts.jobs, ["requestedBySha256", "approvedBySha256", "signerKeyIdSha256", "signed", "verified", "approved",
    "signatureFailureDenied", "providerPutAttempts", "providerVersion", "exactVersionReads", "latestFallbacks", "restartRepublishAttempts"]);
  for (const field of ["requestedBySha256", "approvedBySha256", "signerKeyIdSha256"]) hash(facts.jobs[field]);
  assert.notEqual(facts.jobs.requestedBySha256, facts.jobs.approvedBySha256);
  positive(facts.jobs.signed); assert.ok(facts.jobs.signed >= 2); assert.equal(facts.jobs.verified, facts.jobs.signed);
  positive(facts.jobs.approved); assert.ok(facts.jobs.approved >= 2); assert.equal(facts.jobs.signatureFailureDenied, true);
  assert.equal(facts.jobs.providerPutAttempts, 1); positive(facts.jobs.exactVersionReads);
  assert.match(facts.jobs.providerVersion, profile.startsWith("azure-") ? /^[a-f0-9]{32}$/ : /^[1-9][0-9]{0,9}$/);
  assert.equal(facts.jobs.latestFallbacks, 0); assert.equal(facts.jobs.restartRepublishAttempts, 0);
  assert.ok(Array.isArray(facts.identities) && facts.identities.length === 2);
  facts.identities.forEach((identity, i) => {
    keys(identity, ["role", "subjectSha256", "tokenRenewals", "crossRoleDenials", "crossRoleDeniedOperation", "consumerWriteStatus"]);
    assert.equal(identity.role, ["issuer", "consumer"][i]); hash(identity.subjectSha256);
    positive(identity.tokenRenewals); positive(identity.crossRoleDenials);
    assert.equal(identity.crossRoleDeniedOperation, "opposite-identity-acquisition");
    assert.equal(identity.consumerWriteStatus, i === 1 ? 403 : null);
  });
  assert.notEqual(facts.identities[0].subjectSha256, facts.identities[1].subjectSha256);
}
function verify(profile, report, { sourceSha, runId, packageIdentity, files, requireNative, run }) {
  const specification = PROFILES[profile]; assert.ok(specification);
  keys(report, ["schemaVersion", "profile", "sourceSha", "runId", "packageArtifact", "status", "productionQualified",
    "fullOperatorE2e", "counts", "scenarios", "cleanup", "facts", "nativeService"]);
  assert.equal(report.schemaVersion, 1); assert.equal(report.profile, profile); assert.equal(report.sourceSha, sourceSha);
  assert.equal(report.runId, runId); assert.equal(report.status, "passed"); assert.equal(report.productionQualified, false);
  assert.deepEqual(verifyIdentity(report.packageArtifact), packageIdentity);
  const operator = profile.endsWith("operator-http-real-ca"); assert.equal(report.fullOperatorE2e, operator);
  assert.deepEqual(report.scenarios, specification.scenarios.map(id => ({ id, status: "passed" })));
  assert.deepEqual(report.counts, { passed: specification.scenarios.length, failed: 0, pending: 0, skipped: 0 });
  keys(report.cleanup, ["database", "provider", "agent", "credentials", "resources"]);
  for (const result of Object.values(report.cleanup)) assert.equal(result, "completed");
  if (operator) operatorFacts(report.facts, profile);
  else if (profile === "azure-imds-managed-identity") {
    keys(report.facts, ["authMode", "imdsHost", "metadataHeader", "identities", "azureReadStatus", "azureConsumerWriteStatus", "pinnedVersion"]);
    assert.equal(report.facts.authMode, "azure-imds-managed-identity"); assert.equal(report.facts.imdsHost, "169.254.169.254");
    assert.equal(report.facts.metadataHeader, true);
    assert.ok(Array.isArray(report.facts.identities) && report.facts.identities.length === 2);
    report.facts.identities.forEach((identity, i) => {
      keys(identity, ["role", "hostIdSha256", "identitySha256", "oppositeIdentitySha256", "imdsRequests", "ownTokenStatus", "oppositeIdentityTokenStatus"]);
      assert.equal(identity.role, ["issuer", "consumer"][i]); hash(identity.hostIdSha256); hash(identity.identitySha256);
      assert.equal(identity.oppositeIdentitySha256, report.facts.identities[1 - i].identitySha256);
      positive(identity.imdsRequests); assert.ok(identity.imdsRequests >= 2);
      assert.equal(identity.ownTokenStatus, 200); assert.ok([400, 403, 404].includes(identity.oppositeIdentityTokenStatus));
    });
    assert.notEqual(report.facts.identities[0].hostIdSha256, report.facts.identities[1].hostIdSha256);
    assert.notEqual(report.facts.identities[0].identitySha256, report.facts.identities[1].identitySha256);
    assert.equal(report.facts.azureReadStatus, 200); assert.equal(report.facts.azureConsumerWriteStatus, 403);
    assert.match(report.facts.pinnedVersion, /^[a-f0-9]{32}$/);
  } else {
    keys(report.facts, ["issuedAt", "expiresAt", "observedExpiredAt", "renewedAt", "renewedExpiresAt", "forced401", "clockOverridden",
      "azureStatusBefore", "azureStatusExpired", "azureStatusAfter", "pinnedVersion"]);
    for (const field of ["issuedAt", "expiresAt", "observedExpiredAt", "renewedAt", "renewedExpiresAt"]) positive(report.facts[field]);
    assert.ok(report.facts.expiresAt > report.facts.issuedAt && report.facts.observedExpiredAt >= report.facts.expiresAt &&
      report.facts.renewedAt >= report.facts.observedExpiredAt && report.facts.renewedExpiresAt > report.facts.renewedAt);
    assert.ok(report.facts.observedExpiredAt >= Date.parse(run.run_started_at) / 1000 - 30 && report.facts.renewedAt <= Date.parse(run.updated_at) / 1000 + 30);
    assert.equal(report.facts.forced401, false); assert.equal(report.facts.clockOverridden, false); assert.equal(report.facts.azureStatusAfter, 200);
    assert.equal(report.facts.azureStatusBefore, 200); assert.equal(report.facts.azureStatusExpired, 401);
    assert.match(report.facts.pinnedVersion, /^[a-f0-9]{32}$/);
  }
  if (report.nativeService !== null) { assert.ok(operator); verifyNative(report.nativeService, files); }
  if (requireNative) { assert.ok(operator && report.nativeService); }
  return true;
}
module.exports = { PROFILES, verify, verifyNative };
