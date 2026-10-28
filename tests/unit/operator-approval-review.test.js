"use strict";
const { it } = require("node:test");
const assert = require("node:assert/strict");
const { publicFields, safeText } = require("../../apps/api/services/operator/approvalReview");
const schema = require("../../packages/contracts/certops/renewal-profile.schema.json");

it("human review includes declared destinations and revision but excludes internal extras", () => {
  const profile = { ca: { endpoint: "https://ca.example.test", accountRef: "local-account", hmac: "never disclose" },
    deploymentTargets: [{ type: "windows-iis", reference: "web", store: "My", binding: { site: "Default Web Site", port: 443, sniHost: "app.example.test" }, internalSecret: "never disclose" }],
    publicationDestination: { type: "vault-kv-v2", secretRef: "never disclose", deploymentProfileRef: "production-web", profileRevision: "a".repeat(64) }, internalSecret: "never disclose" };
  const result = publicFields(profile, schema);
  assert.equal(result.ca.accountRef, "local-account");
  assert.equal(result.deploymentTargets[0].binding.port, 443);
  assert.equal(result.publicationDestination.profileRevision, "a".repeat(64));
  assert.ok(!JSON.stringify(result).includes("never disclose"));
});
it("human labels cannot disclose credential-shaped strings or URL credentials", () => {
  const token = `ttopc_${"a".repeat(16)}_${"b".repeat(64)}`;
  assert.ok(!safeText(`client ${token}`).includes(token));
  assert.ok(!safeText("https://person:password@ca.example.test/directory").includes("password"));
  assert.equal(safeText("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"), "[redacted]");
});
it("assistant approval intent binds executor routing as well as payload", () => {
  const { computeCanonicalIntentHash } = require("../../apps/api/services/certops/jobApprovals");
  const job = { requestedByConnectionId: "connection", operation: "renew", subjectId: "certificate", payload: { target: { reference: "web" } }, assignedAgentId: "agent-a", requiredCommandProfile: "renew" };
  for (const field of ["assignedAgentId", "requiredTargetSelector", "requiredDnsProvider", "requiredCommandProfile"]) {
    assert.notEqual(computeCanonicalIntentHash(job), computeCanonicalIntentHash({ ...job, [field]: "changed" }), field);
  }
});
