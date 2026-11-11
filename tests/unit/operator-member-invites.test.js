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
const { previewInvite, createInvite, deliverInvite } = require("../../apps/api/services/operator/memberInvites");
const operator = { workspaceId: "workspace", connectionId: "connection", userId: 2, scopes: ["mcp:members:invite"] };
const planId = "b6b7a2c6-c57d-4c31-b699-9dd90e1e8e29", requestId = "f24604a6-a89a-456c-a69d-a07dfb2455c8";
function database() {
  const state = { plan: null, request: null, targetId: null, member: false, invited: false, sends: 0, writes: 0, personal: false };
  return { state, query: async (sql, params) => {
    if (sql.startsWith("SELECT COUNT(*)::int AS count FROM operator_inventory_plans")) return { rows: [{ count: 0 }] };
    if (sql.startsWith("SELECT id,name,created_by,plan")) return { rows: [{ id: "workspace", name: "Example", created_by: 1, plan: "oss", is_personal_default: state.personal }] };
    if (sql.startsWith("SELECT created_by FROM workspaces")) return { rows: [{ created_by: 1 }] };
    if (sql.startsWith("SELECT id FROM users WHERE id IN")) return { rows: [{ id: 1 }, { id: 2 }, ...(state.targetId ? [{ id: state.targetId }] : [])] };
    if (sql.startsWith("SELECT email FROM users")) return { rows: [{ email: "actor@example.test" }] };
    if (sql.startsWith("SELECT id FROM users")) return { rows: state.targetId ? [{ id: state.targetId }] : [] };
    if (sql.startsWith("SELECT 1 FROM workspace_memberships")) return { rows: state.member ? [{}] : [], rowCount: state.member ? 1 : 0 };
    if (sql.startsWith("SELECT 1 FROM workspace_invitations")) return { rows: state.invited ? [{}] : [], rowCount: state.invited ? 1 : 0 };
    if (sql.startsWith("INSERT INTO operator_inventory_plans")) {
      state.plan = { plan_hash: params[2], decisions: JSON.parse(params[3]), imported_at: null, expired: false };
      return { rows: [{ id: planId, expires_at: new Date("2030-01-01T00:00:00Z") }] };
    }
    if (sql.startsWith("SELECT plan_id,plan_hash,result")) return { rows: state.request ? [state.request] : [] };
    if (sql.startsWith("SELECT *,expires_at")) return { rows: state.plan ? [state.plan] : [] };
    if (sql.startsWith("INSERT INTO workspace_invitations")) { state.invited = true; state.writes++; return { rows: [{ id: params[0] }], rowCount: 1 }; }
    if (sql.startsWith("INSERT INTO workspace_memberships")) { state.member = true; state.writes++; return { rows: [{}], rowCount: 1 }; }
    if (sql.startsWith("INSERT INTO operator_inventory_requests")) state.request = { plan_id: params[3], plan_hash: params[4], result: JSON.parse(params[5]) };
    if (sql.startsWith("UPDATE operator_inventory_plans")) state.plan.imported_at = new Date();
    if (sql.startsWith("UPDATE operator_inventory_requests") && sql.includes("RETURNING plan_id")) {
      if (state.request.result.emailStatus !== "pending") return { rows: [], rowCount: 0 };
      state.request.result.emailStatus = "unknown";
      return { rows: [{ plan_id: planId }], rowCount: 1 };
    }
    if (sql.startsWith("SELECT result FROM operator_inventory_requests")) return { rows: state.request ? [{ result: state.request.result }] : [] };
    if (sql.startsWith("SELECT decisions FROM operator_inventory_plans")) return { rows: [state.plan] };
    if (sql.startsWith("SELECT token FROM workspace_invitations")) return { rows: state.invited ? [{ token: "synthetic-invite-token" }] : [] };
    if (sql.startsWith("UPDATE operator_inventory_requests SET result")) state.request.result.emailStatus = params[3];
    return { rows: [], rowCount: 0 };
  } };
}
test("email-only invitation is reviewed, viewer-only, and safely replayed", async () => {
  const client = database();
  await assert.rejects(previewInvite({ client, operator: { ...operator, scopes: [] }, invite: { email: "new@example.test" } }), { code: "OPERATOR_CONNECTION_SCOPE_DENIED" });
  const plan = await previewInvite({ client, operator, invite: { email: "NEW@example.test" } });
  assert.equal(plan.effect.role, "viewer"); assert.equal(plan.effect.mode, "invite_new_user");
  const payload = { client, operator, planId, planHash: plan.planHash, requestId };
  const result = await createInvite(payload);
  assert.equal(result.emailStatus, "pending"); assert.ok(!JSON.stringify(result).includes("token"));
  assert.equal((await createInvite(payload)).replayed, true); assert.equal(client.state.writes, 1);
  const send = async (message) => { client.state.sends++; assert.equal(message.to, "new@example.test"); return { success: true }; };
  const template = async () => ({ html: "test", text: "test", useEmbeddedLogo: false });
  assert.equal(await deliverInvite({ operator, requestId, db: client, send, template }), "sent");
  assert.equal(await deliverInvite({ operator, requestId, db: client, send, template }), "sent");
  assert.equal(client.state.sends, 1);
});
test("invitation refuses changed identity, personal workspaces and disabled manual invitations", async () => {
  const client = database(), plan = await previewInvite({ client, operator, invite: { email: "new@example.test" } });
  client.state.targetId = 9;
  await assert.rejects(createInvite({ client, operator, planId, planHash: plan.planHash, requestId }), { code: "OPERATOR_INTENT_STALE" });
  client.state.targetId = null; client.state.personal = true;
  await assert.rejects(previewInvite({ client, operator, invite: { email: "new@example.test" } }), { code: "PERSONAL_DEFAULT" });
  const old = process.env.DISABLE_MANUAL_INVITES;
  try {
    process.env.DISABLE_MANUAL_INVITES = "true";
    await assert.rejects(previewInvite({ client, operator, invite: { email: "new@example.test" } }), { code: "MANUAL_INVITES_DISABLED" });
  } finally { if (old === undefined) delete process.env.DISABLE_MANUAL_INVITES; else process.env.DISABLE_MANUAL_INVITES = old; }
});
test("an uncertain mail attempt is not repeated automatically", async () => {
  const client = database(), plan = await previewInvite({ client, operator, invite: { email: "new@example.test" } });
  await createInvite({ client, operator, planId, planHash: plan.planHash, requestId });
  let sends = 0;
  const send = async () => { sends++; throw new Error("provider failure"); };
  const template = async () => ({ html: "test", text: "test", useEmbeddedLogo: false });
  assert.equal(await deliverInvite({ operator, requestId, db: client, send, template }), "unknown");
  assert.equal(await deliverInvite({ operator, requestId, db: client, send, template }), "unknown");
  assert.equal(sends, 1);
});
