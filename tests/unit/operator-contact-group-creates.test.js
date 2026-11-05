"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const imports = require("../../apps/api/services/operator/inventoryImports");
const policy = require("../../apps/api/services/operator/inventoryPolicy");
const audit = require("../../apps/api/services/audit");
imports.authorize = async (_client, operator, scope) => {
  if (!operator.scopes.includes(scope)) throw Object.assign(new Error("denied"), { code: "OPERATOR_CONNECTION_SCOPE_DENIED" });
  return { workspaceOwnerId: 1 };
};
policy.assertInventoryImportAllowed = async () => {};
audit.writeAudit = async () => {};
const { previewGroup, createGroup } = require("../../apps/api/services/operator/contactGroupCreates");
const operator = { workspaceId: "workspace", connectionId: "connection", userId: 1, scopes: ["mcp:groups:create"] };
const planId = "b6b7a2c6-c57d-4c31-b699-9dd90e1e8e29", requestId = "f24604a6-a89a-456c-a69d-a07dfb2455c8", contactId = "a0c34a67-37f3-461e-9ee5-c76c699be086";
const group = { name: "Ops", emailContactIds: [contactId], whatsappContactIds: [contactId], webhookNames: ["Alerts"], weeklyDigest: { email: true, whatsapp: true, webhooks: false } };
function database() {
  const state = { plan: null, request: null, groups: [], hooks: [{ name: "Alerts", url: "https://example.test/private" }], version: "1", writes: 0 };
  return { state, query: async (sql, params) => {
    if (sql.startsWith("SELECT COUNT")) return { rows: [{ count: 0 }] };
    if (sql.startsWith("SELECT contact_groups")) return { rows: [{ contact_groups: state.groups, webhook_urls: state.hooks }] };
    if (sql.startsWith("SELECT plan FROM")) return { rows: [{ plan: "oss" }] };
    if (sql.startsWith("SELECT id,first_name")) return { rows: [{ id: contactId, first_name: "Ada", last_name: "Example", phone_e164: "+41791234567", details: { email: "ada@example.test" }, version: state.version }] };
    if (sql.startsWith("INSERT INTO operator_inventory_plans")) {
      state.plan = { plan_hash: params[2], decisions: JSON.parse(params[3]), imported_at: null, expired: false };
      return { rows: [{ id: planId, expires_at: new Date("2030-01-01T00:00:00Z") }] };
    }
    if (sql.startsWith("SELECT plan_id,plan_hash,result")) return { rows: state.request ? [state.request] : [] };
    if (sql.startsWith("SELECT *,expires_at")) return { rows: state.plan ? [state.plan] : [] };
    if (sql.startsWith("UPDATE workspace_settings")) { state.groups = JSON.parse(params[1]); state.writes++; }
    if (sql.startsWith("INSERT INTO operator_inventory_requests")) state.request = { plan_id: params[3], plan_hash: params[4], result: JSON.parse(params[5]) };
    if (sql.startsWith("UPDATE operator_inventory_plans")) state.plan.imported_at = new Date();
    return { rows: [] };
  } };
}
test("reviewed group creation preserves recipients and digest settings and retries safely", async () => {
  const client = database();
  await assert.rejects(previewGroup({ client, operator: { ...operator, scopes: [] }, group }), { code: "OPERATOR_CONNECTION_SCOPE_DENIED" });
  const plan = await previewGroup({ client, operator, group });
  assert.equal(plan.effect.contacts[0].name.value, "Ada Example");
  assert.ok(!JSON.stringify(plan).includes("https://example.test/private"));
  const payload = { client, operator, planId, planHash: plan.planHash, requestId };
  assert.equal((await createGroup(payload)).state, "succeeded");
  assert.equal((await createGroup(payload)).replayed, true);
  assert.equal(client.state.writes, 1);
  assert.deepEqual(client.state.groups[0].email_contact_ids, [contactId]);
  assert.deepEqual(client.state.groups[0].whatsapp_contact_ids, [contactId]);
  assert.deepEqual(client.state.groups[0].webhook_names, ["Alerts"]);
  assert.equal(client.state.groups[0].weekly_digest_email, true);
  assert.equal(client.state.groups[0].weekly_digest_whatsapp, true);
});
test("group creation rejects contacts changed after preview", async () => {
  const client = database(), plan = await previewGroup({ client, operator, group });
  client.state.version = "2";
  await assert.rejects(createGroup({ client, operator, planId, planHash: plan.planHash, requestId }), { code: "OPERATOR_INTENT_STALE" });
  assert.equal(client.state.writes, 0);
});
