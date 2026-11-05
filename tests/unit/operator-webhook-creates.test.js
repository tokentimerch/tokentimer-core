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
const { previewWebhook, createWebhook } = require("../../apps/api/services/operator/webhookCreates");
const operator = { workspaceId: "workspace", connectionId: "connection", userId: 1, scopes: ["mcp:webhooks:create"] };
const planId = "b6b7a2c6-c57d-4c31-b699-9dd90e1e8e29", requestId = "f24604a6-a89a-456c-a69d-a07dfb2455c8";
const webhook = { name: "Alerts", url: "https://example.test/opaque-private-value", kind: "generic" };
function database() {
  const state = { plan: null, request: null, hooks: [], writes: 0 };
  return { state, query: async (sql, params) => {
    if (sql.startsWith("SELECT COUNT")) return { rows: [{ count: 0 }] };
    if (sql.startsWith("SELECT webhook_urls")) return { rows: [{ webhook_urls: state.hooks }] };
    if (sql.startsWith("INSERT INTO operator_inventory_plans")) {
      state.plan = { plan_hash: params[2], decisions: JSON.parse(params[3]), imported_at: null, expired: false };
      return { rows: [{ id: planId, expires_at: new Date("2030-01-01T00:00:00Z") }] };
    }
    if (sql.startsWith("SELECT plan_id,plan_hash,result")) return { rows: state.request ? [state.request] : [] };
    if (sql.startsWith("SELECT *,expires_at") || sql.startsWith("SELECT decisions FROM operator_inventory_plans")) return { rows: state.plan ? [state.plan] : [] };
    if (sql.startsWith("UPDATE workspace_settings")) { state.hooks = JSON.parse(params[1]); state.writes++; }
    if (sql.startsWith("INSERT INTO operator_inventory_requests")) state.request = { plan_id: params[3], plan_hash: params[4], result: JSON.parse(params[5]) };
    if (sql.startsWith("UPDATE operator_inventory_plans")) state.plan.imported_at = new Date();
    return { rows: [] };
  } };
}

test("preview omits the secret-bearing destination and only the reviewed URL can be saved", async () => {
  const client = database();
  await assert.rejects(previewWebhook({ client, operator: { ...operator, scopes: [] }, webhook }), { code: "OPERATOR_CONNECTION_SCOPE_DENIED" });
  const plan = await previewWebhook({ client, operator, webhook });
  assert.ok(!JSON.stringify(plan).includes("opaque-private-value"));
  assert.ok(!JSON.stringify(client.state.plan).includes("opaque-private-value"));
  assert.equal(plan.effect.host.value, "example.test");
  const payload = { client, operator, planId, planHash: plan.planHash, requestId, url: webhook.url };
  await assert.rejects(createWebhook({ ...payload, url: "https://example.test/different" }), { code: "OPERATOR_PLAN_MISMATCH" });
  assert.equal((await createWebhook(payload)).state, "succeeded");
  assert.equal((await createWebhook(payload)).replayed, true);
  await assert.rejects(createWebhook({ ...payload, url: "https://example.test/different" }), { code: "OPERATOR_IDEMPOTENCY_CONFLICT" });
  assert.equal(client.state.writes, 1);
  assert.equal(client.state.hooks[0].url, webhook.url);
  assert.equal(client.state.hooks[0].verified, false);
});

test("webhook creation refuses changed settings after the preview", async () => {
  const client = database(), plan = await previewWebhook({ client, operator, webhook });
  client.state.hooks = [{ name: "Other", url: "https://other.test" }];
  await assert.rejects(createWebhook({ client, operator, planId, planHash: plan.planHash, requestId, url: webhook.url }), { code: "OPERATOR_INTENT_STALE" });
  assert.equal(client.state.writes, 0);
});

test("a PagerDuty routing key never appears in the preview or persisted plan", async () => {
  const client = database();
  const pagerduty = { name: "PagerDuty", url: "https://events.pagerduty.com/v2/enqueue", kind: "pagerduty", routingKey: "synthetic-routing-key" };
  const plan = await previewWebhook({ client, operator, webhook: pagerduty });
  assert.equal(plan.effect.routingKeyRequired, true);
  assert.ok(!JSON.stringify([plan, client.state.plan]).includes(pagerduty.routingKey));
  const result = await createWebhook({ client, operator, planId, planHash: plan.planHash, requestId, url: pagerduty.url, routingKey: pagerduty.routingKey });
  assert.equal(result.state, "succeeded");
  assert.equal(client.state.hooks[0].routingKey, pagerduty.routingKey);
});
