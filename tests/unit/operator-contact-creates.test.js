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
const { previewContact, createContact } = require("../../apps/api/services/operator/contactCreates");
const operator = { workspaceId: "workspace", connectionId: "connection", userId: 1, scopes: ["mcp:contacts:create"] };
const planId = "b6b7a2c6-c57d-4c31-b699-9dd90e1e8e29", requestId = "f24604a6-a89a-456c-a69d-a07dfb2455c8", contactId = "a0c34a67-37f3-461e-9ee5-c76c699be086";
function database() {
  const state = { plan: null, request: null, duplicate: false, inserts: 0 };
  return { state, query: async (sql, params) => {
    if (sql.startsWith("SELECT COUNT")) return { rows: [{ count: 0 }] };
    if (sql.startsWith("SELECT 1 FROM workspace_contacts")) return { rowCount: state.duplicate ? 1 : 0, rows: [] };
    if (sql.startsWith("INSERT INTO operator_inventory_plans")) {
      state.plan = { plan_hash: params[2], decisions: JSON.parse(params[3]), imported_at: null, expired: false };
      return { rows: [{ id: planId, expires_at: new Date("2030-01-01T00:00:00Z") }] };
    }
    if (sql.startsWith("SELECT plan_id,plan_hash,result")) return { rows: state.request ? [state.request] : [] };
    if (sql.startsWith("SELECT *,expires_at")) return { rows: state.plan ? [state.plan] : [] };
    if (sql.startsWith("INSERT INTO workspace_contacts")) { state.inserts++; return { rows: [{ id: contactId }] }; }
    if (sql.startsWith("INSERT INTO operator_inventory_requests")) state.request = { plan_id: params[3], plan_hash: params[4], result: JSON.parse(params[5]) };
    if (sql.startsWith("UPDATE operator_inventory_plans")) state.plan.imported_at = new Date();
    return { rows: [] };
  } };
}
const contact = { firstName: "Ada", lastName: "Example", email: "ADA@example.test", phoneE164: "+41791234567" };

test("contact creation requires a distinct scope and replays safely", async () => {
  const client = database();
  await assert.rejects(previewContact({ client, operator: { ...operator, scopes: [] }, contact }), { code: "OPERATOR_CONNECTION_SCOPE_DENIED" });
  const plan = await previewContact({ client, operator, contact });
  assert.equal(plan.effect.email.value, "ada@example.test");
  const payload = { client, operator, planId, planHash: plan.planHash, requestId };
  assert.equal((await createContact(payload)).contactId, contactId);
  assert.equal((await createContact(payload)).replayed, true);
  assert.equal(client.state.inserts, 1);
});

test("contact creation refuses changed phone availability and tampered previews", async () => {
  const client = database(), plan = await previewContact({ client, operator, contact });
  client.state.duplicate = true;
  await assert.rejects(createContact({ client, operator, planId, planHash: plan.planHash, requestId }), { code: "OPERATOR_INTENT_STALE" });
  client.state.duplicate = false;
  client.state.plan.decisions[0].contact.firstName = "Mallory";
  await assert.rejects(createContact({ client, operator, planId, planHash: plan.planHash, requestId }), { code: "OPERATOR_PLAN_MISMATCH" });
  assert.equal(client.state.inserts, 0);
});
