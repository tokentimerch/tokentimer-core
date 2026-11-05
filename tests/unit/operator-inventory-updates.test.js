"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const imports = require("../../apps/api/services/operator/inventoryImports");
const policy = require("../../apps/api/services/operator/inventoryPolicy");
const Token = require("../../apps/api/db/models/Token");
const audit = require("../../apps/api/services/audit");
imports.authorize = async (_client, operator, scope) => {
  if (scope !== "mcp:inventory:update" || !operator.scopes.includes(scope)) throw Object.assign(new Error("denied"), { code: "OPERATOR_CONNECTION_SCOPE_DENIED" });
  return { workspaceOwnerId: 1 };
};
policy.assertInventoryImportAllowed = async () => {};
Token.update = async (_id, changes) => { calls.push(changes); };
audit.writeAudit = async () => {};
const { previewUpdate, updateInventory, effectFor } = require("../../apps/api/services/operator/inventoryUpdates");
const calls = [];
const operator = { workspaceId: "workspace", connectionId: "connection", userId: 1, scopes: ["mcp:inventory:update"] };
const planId = "b6b7a2c6-c57d-4c31-b699-9dd90e1e8e29", requestId = "f24604a6-a89a-456c-a69d-a07dfb2455c8";

function database() {
  const state = { version: "v1", plan: null, request: null };
  return { state, query: async (sql, params) => {
    if (sql.includes("COUNT(*)")) return { rows: [{ count: 0 }] };
    if (sql.startsWith("SELECT id,name,type")) return { rows: [{ id: 7, name: "API key", type: "api_key", category: "key_secret", expiration: "2099-12-31", location: null, used_by: "old", section: [], domains: [], description: null, source_provider: null, auto_sync_managed: false, version: state.version }] };
    if (sql.startsWith("INSERT INTO operator_inventory_plans")) {
      const d = JSON.parse(params[3])[0];
      // PostgreSQL jsonb may reorder object keys.
      state.plan = { id: planId, plan_hash: params[2], decisions: [{ destination: d.destination, identity: d.identity, version: d.version, changes: d.changes, before: d.before, tokenId: d.tokenId, kind: d.kind }], imported_at: null, expired: false };
      return { rows: [{ id: planId, expires_at: new Date("2030-01-01T00:00:00Z") }] };
    }
    if (sql.startsWith("SELECT plan_id,plan_hash,result")) return { rows: state.request ? [state.request] : [] };
    if (sql.startsWith("SELECT *,expires_at")) return { rows: state.plan ? [state.plan] : [] };
    if (sql.startsWith("INSERT INTO operator_inventory_requests")) { state.request = { plan_id: params[3], plan_hash: params[4], result: JSON.parse(params[5]) }; return { rows: [] }; }
    if (sql.startsWith("UPDATE operator_inventory_plans")) state.plan.imported_at = new Date();
    return { rows: [] };
  } };
}

test("an explicitly granted reviewed update is idempotent despite jsonb key ordering", async () => {
  calls.length = 0;
  const client = database();
  const plan = await previewUpdate({ client, operator, tokenId: 7, changes: { usedBy: "new" } });
  const result = await updateInventory({ client, operator, planId, planHash: plan.planHash, requestId });
  assert.equal(result.state, "succeeded");
  assert.deepEqual(calls, [{ used_by: "new" }]);
  assert.equal((await updateInventory({ client, operator, planId, planHash: plan.planHash, requestId })).replayed, true);
  assert.equal(calls.length, 1);
});

test("a changed record or missing scope refuses an update", async () => {
  const client = database();
  await assert.rejects(previewUpdate({ client, operator: { ...operator, scopes: [] }, tokenId: 7, changes: { usedBy: "new" } }), { code: "OPERATOR_CONNECTION_SCOPE_DENIED" });
  const plan = await previewUpdate({ client, operator, tokenId: 7, changes: { usedBy: "new" } });
  client.state.version = "v2";
  await assert.rejects(updateInventory({ client, operator, planId, planHash: plan.planHash, requestId }), { code: "OPERATOR_INTENT_STALE" });
});

test("update previews mask existing filesystem locations and refuse obscured destinations", async () => {
  const effect = effectFor({ tokenId: 7, before: { location: "/private/service/key.pem" }, changes: { location: "gitlab:project" } });
  assert.equal(effect.fields[0].before.value, "(filesystem location)");
  const client = database();
  await assert.rejects(previewUpdate({ client, operator, tokenId: 7, changes: { location: "/private/new.pem" } }), { code: "OPERATOR_VALIDATION_ERROR" });
});
