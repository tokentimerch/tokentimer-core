"use strict";

const crypto = require("node:crypto");
const { writeAudit } = require("../audit");
const { authorize } = require("./inventoryImports");
const { assertInventoryImportAllowed } = require("./inventoryPolicy");
const { normalizeWebhook } = require("./webhookValidation");
const { untrustedText } = require("./projections");
const { invalid } = require("./tokenInventory");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
const fail = (code, message) => Object.assign(new Error(message), { code });
const digest = (value) => crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
async function authorizeWebhook(client, operator) {
  const actorLocks = await authorize(client, operator, "mcp:webhooks:create");
  await assertInventoryImportAllowed({ client, workspaceId: operator.workspaceId, userId: operator.userId, additionalTokens: 0, actorLocks });
}
async function currentHooks(client, workspaceId, lock = false) {
  if (lock) await client.query("INSERT INTO workspace_settings(workspace_id) VALUES($1) ON CONFLICT(workspace_id) DO NOTHING", [workspaceId]);
  const row = (await client.query("SELECT webhook_urls FROM workspace_settings WHERE workspace_id=$1" + (lock ? " FOR UPDATE" : ""), [workspaceId])).rows[0];
  return Array.isArray(row?.webhook_urls) ? row.webhook_urls : [];
}
function ensureNameAvailable(hooks, name) {
  if (hooks.some((item) => String(item?.name || "").trim().toLowerCase() === name.toLowerCase())) throw fail("OPERATOR_INTENT_STALE", "A webhook with this name already exists");
}
function intent(webhook, hooks) {
  return { kind: "create_webhook", name: webhook.name, webhookKind: webhook.kind, host: new URL(webhook.url).host,
    urlHash: digest(webhook.url), routingKeyHash: digest(webhook.routingKey), hooksHash: digest(hooks) };
}
function planDigest(operator, decision) {
  return digest(["create_webhook", operator.workspaceId, operator.connectionId, decision.name, decision.webhookKind, decision.host, decision.urlHash, decision.routingKeyHash, decision.hooksHash]);
}
async function previewWebhook({ client, operator, webhook }) {
  await authorizeWebhook(client, operator);
  const normalized = normalizeWebhook(webhook);
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [JSON.stringify(["operator-inventory-previews", operator.connectionId])]);
  await client.query("DELETE FROM operator_inventory_plans WHERE connection_id=$1 AND expires_at<=NOW() AND imported_at IS NULL", [operator.connectionId]);
  const pending = await client.query("SELECT COUNT(*)::int AS count FROM operator_inventory_plans WHERE connection_id=$1 AND imported_at IS NULL AND expires_at>NOW()", [operator.connectionId]);
  if (pending.rows[0].count >= 10) throw fail("OPERATOR_PENDING_LIMIT", "Too many previews are open");
  const hooks = await currentHooks(client, operator.workspaceId);
  ensureNameAvailable(hooks, normalized.name);
  const decision = intent(normalized, hooks), planHash = planDigest(operator, decision);
  const row = (await client.query("INSERT INTO operator_inventory_plans(workspace_id,connection_id,plan_hash,decisions) VALUES($1,$2,$3,$4::jsonb) RETURNING id,expires_at", [operator.workspaceId, operator.connectionId, planHash, JSON.stringify([decision])])).rows[0];
  return { planId: row.id, planHash, expiresAt: row.expires_at.toISOString(), effect: {
    name: untrustedText(normalized.name), host: untrustedText(decision.host), kind: normalized.kind,
    destinationPathHidden: true, routingKeyRequired: normalized.kind === "pagerduty", deliveryMayStart: true, verified: false,
  } };
}
async function createWebhook({ client, operator, planId, planHash, requestId, url, routingKey }) {
  await authorizeWebhook(client, operator);
  if (!UUID.test(String(planId || "")) || !UUID.test(String(requestId || "")) || !HASH.test(String(planHash || "")) || typeof url !== "string") throw invalid();
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [JSON.stringify(["operator-inventory-request", operator.connectionId, requestId])]);
  const previous = (await client.query("SELECT plan_id,plan_hash,result FROM operator_inventory_requests WHERE connection_id=$1 AND request_id=$2", [operator.connectionId, requestId])).rows[0];
  if (previous) {
    if (previous.plan_id !== planId || previous.plan_hash !== planHash || previous.result.operation !== "create_webhook") throw fail("OPERATOR_IDEMPOTENCY_CONFLICT", "Request id was used for another action");
    const original = (await client.query("SELECT decisions FROM operator_inventory_plans WHERE id=$1 AND workspace_id=$2 AND connection_id=$3", [planId, operator.workspaceId, operator.connectionId])).rows[0];
    if (!original || digest(url.trim()) !== original.decisions?.[0]?.urlHash || digest(typeof routingKey === "string" ? routingKey.trim() : "") !== original.decisions?.[0]?.routingKeyHash) throw fail("OPERATOR_IDEMPOTENCY_CONFLICT", "Request id was used for another action");
    return { ...previous.result, replayed: true };
  }
  const plan = (await client.query("SELECT *,expires_at<=NOW() AS expired FROM operator_inventory_plans WHERE id=$1 AND workspace_id=$2 AND connection_id=$3 FOR UPDATE", [planId, operator.workspaceId, operator.connectionId])).rows[0];
  if (!plan) throw fail("NOT_FOUND", "Preview not found");
  if (plan.plan_hash !== planHash || !Array.isArray(plan.decisions) || plan.decisions.length !== 1 || plan.decisions[0]?.kind !== "create_webhook") throw fail("OPERATOR_PLAN_MISMATCH", "Preview does not match");
  if (plan.imported_at) throw fail("OPERATOR_PLAN_USED", "Preview was already submitted");
  if (plan.expired) throw fail("OPERATOR_PLAN_EXPIRED", "Preview expired");
  const decision = plan.decisions[0], webhook = normalizeWebhook({ name: decision.name, kind: decision.webhookKind, url, routingKey });
  if (planDigest(operator, decision) !== planHash || digest(webhook.url) !== decision.urlHash || digest(webhook.routingKey) !== decision.routingKeyHash || new URL(webhook.url).host !== decision.host) throw fail("OPERATOR_PLAN_MISMATCH", "Preview does not match");
  const hooks = await currentHooks(client, operator.workspaceId, true);
  if (digest(hooks) !== decision.hooksHash) throw fail("OPERATOR_INTENT_STALE", "Webhook settings changed; preview again");
  ensureNameAvailable(hooks, webhook.name);
  hooks.push({ name: webhook.name, url: webhook.url, kind: webhook.kind, severity: "", template: "", routingKey: webhook.routingKey, verified: false });
  await client.query("UPDATE workspace_settings SET webhook_urls=$2::jsonb WHERE workspace_id=$1", [operator.workspaceId, JSON.stringify(hooks)]);
  await writeAudit({ client, actorUserId: operator.userId, subjectUserId: operator.userId, action: "WORKSPACE_ALERT_SETTINGS_UPDATED", targetType: "workspace", targetId: null, workspaceId: operator.workspaceId,
    metadata: { via: "operator_connection", connection_id: operator.connectionId, changed_fields: ["webhook_urls"] } });
  const result = { operation: "create_webhook", requestId, planId, state: "succeeded", replayed: false };
  await client.query("INSERT INTO operator_inventory_requests(workspace_id,connection_id,request_id,plan_id,plan_hash,result) VALUES($1,$2,$3,$4,$5,$6::jsonb)", [operator.workspaceId, operator.connectionId, requestId, planId, planHash, JSON.stringify(result)]);
  await client.query("UPDATE operator_inventory_plans SET imported_at=NOW() WHERE id=$1", [planId]);
  return result;
}

module.exports = { previewWebhook, createWebhook };
