"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { evaluateCapabilities } = require("../../apps/api/services/onboarding/capabilities");
const { summarizeAgents, loadDistributionReality } = require("../../apps/api/services/onboarding/certopsReality");
const { validateSessionWrite } = require("../../apps/api/services/onboarding/sessionSchema");
const GROUP = "22222222-2222-4222-8222-222222222222";

test("onboarding provider qualification agrees with the shipped manifest and does not elevate a viewer", () => {
  const manifest = require("../../packages/agent/src/capabilities/qualified-capabilities.json").qualified;
  const manager = { workspaceRole: "workspace_manager", certopsEnabled: true };
  for (const [suffix, agentCapability] of [["material_store_vault_kv2", "material-store-vault-kv2-v1"],
    ["material_store_openbao_kv2", "material-store-openbao-kv2-v1"], ["material_store_azure_key_vault", "material-store-azure-key-vault-v1"],
    ["windows_material_iis", "windows-material-iis-v1"]]) {
    const id = `certops.${suffix}`;
    const cap = evaluateCapabilities(manager).find(c => c.id === id);
    assert.equal(cap.qualified, manifest.includes(agentCapability));
    assert.equal(cap.state, cap.qualified ? "ready" : "candidate");
    assert.equal(evaluateCapabilities({ ...manager, workspaceRole: "viewer", isSystemAdmin: true }).find(c => c.id === id).authorized, false);
  }
});
test("onboarding agent freshness uses the actual claim-evidence predicate", () => {
  const now = Date.now();
  const agent = { id: "issuer", status: "active", agentKind: "normal", declaredCapabilities: ["evidence-claim-binding-v1"] };
  assert.equal(summarizeAgents([{ ...agent, capabilitiesUpdatedAt: new Date(now).toISOString() }], { now }).items[0].claimEvidenceFresh, true);
  assert.equal(summarizeAgents([{ ...agent, capabilitiesUpdatedAt: "2020-01-01" }], { now }).items[0].claimEvidenceFresh, false);
  assert.equal(summarizeAgents([agent], { now }).items[0].claimEvidenceFresh, false);
});
test("onboarding publication metadata is workspace-scoped, lifecycle-checked and excludes local secrets", async () => {
  const seen = [];
  const answers = [
    { rows: [{ groups: 1, bindings: 0 }] },
    { rows: [{ id: GROUP, active: true, material_store_ref: "customer", material_store_provider: "openbao-kv2",
      issuer_agent_id: "issuer", issuance_profile_ref: "shared", profile_revision: 2,
      material_version_id: "version", published_at: new Date(), valid_to: new Date(Date.now() + 86400000),
      tokenFile: "/must-not-leak", privateKey: "must-not-leak", address: "must-not-leak" }] },
    { rows: [] }, { rows: [{ n: 0 }] },
  ];
  const result = await loadDistributionReality({ query: async (sql, params) => { seen.push({ sql, params }); return answers.shift(); } }, "workspace", { groupId: GROUP });
  const item = result.items[0];
  assert.equal(item.provider, "openbao-kv2"); assert.equal(item.publication.materialVersionId, "version");
  assert.equal(item.completed, false, "publication is not consumer convergence");
  assert.equal(JSON.stringify(result).includes("must-not-leak"), false);
  assert.deepEqual(seen[1].params, ["workspace", GROUP]);
  assert.match(seen[1].sql, /ORDER BY \(g.id=\$2::uuid\) DESC/);
  for (const guard of ["v.workspace_id=g.workspace_id", "v.state='published'", "identity.lifecycle_status='active'", "period.ended_at IS NULL", "v.management_period_id=period.id"])
    assert.ok(seen[1].sql.includes(guard), guard);
});
test("inactive management periods cannot publish onboarding completion evidence", async () => {
  const answers = [{ rows: [{ groups: 1, bindings: 1 }] }, { rows: [{ id: GROUP, active: false,
    latest_generation: 1, latest_rollout_state: "verified", verification_only: false, material_version_id: "old", published_at: new Date(), valid_to: new Date() }] },
    { rows: [{ group_id: GROUP, binding_state: "active", converged: true, live_verified: true, desired_generation: 1 }] }, { rows: [{ n: 0 }] }];
  const result = await loadDistributionReality({ query: async () => answers.shift() }, "workspace");
  assert.equal(result.items[0].publication, null); assert.equal(result.completed, false); assert.equal(result.verified, false);
});
test("the existing session validator accepts only the public setup and frozen request, with no schema migration", () => {
  const materialSetup = { provider: "vault-kv2", materialStoreRef: "customer", issuerAgentId: "issuer", issuanceProfileRef: "shared", profileRevision: 1, groupId: "group" };
  const input = { expectedRevision: 1, progress: { certops: { objective: "vault", materialSetup,
    materialPublicationRequest: { ...materialSetup, names: ["web.example.test"], zone: "example.test", dnsProvider: "cloudflare" } } } };
  assert.doesNotThrow(() => validateSessionWrite(input));
  assert.throws(() => validateSessionWrite({ ...input, progress: { certops: { materialSetup: { token: "hvs.must-not-persist" } } } }), /credential/);
});
