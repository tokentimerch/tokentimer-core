"use strict";

const crypto = require("node:crypto");
const Token = require("../../db/models/Token");
const connections = require("./connections");
const { hasAtLeastRole } = require("../rbac");
const { writeAudit } = require("../audit");
const inventory = require("./tokenInventory");
const { assertInventoryImportAllowed } = require("./inventoryPolicy");
const { untrustedText } = require("./projections");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
const fail = (code, message) => Object.assign(new Error(message), { code });
const hash = (value) => crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
async function authorize(client, operator, scope = "mcp:inventory:import") {
  // Billing/account deletion lock users before workspaces and connections.
  // Prelock the actor and workspace owner in that order even when authority
  // comes from implicit ownership rather than a membership row.
  const owner = (await client.query("SELECT created_by FROM workspaces WHERE id=$1", [operator.workspaceId])).rows[0]?.created_by;
  if (owner == null) throw fail("NOT_FOUND", "Workspace unavailable");
  await client.query("SELECT id FROM users WHERE id IN ($1,$2) ORDER BY id FOR KEY SHARE", [owner, operator.userId]);
  const locked = await connections.lockConnectionAuthority({ client, connectionId: operator.connectionId });
  if (!locked.valid || locked.connection.workspaceId !== operator.workspaceId || String(locked.connection.userId) !== String(operator.userId)) throw fail("OPERATOR_CONNECTION_UNAUTHORIZED", "Operator connection authentication required");
  if (!locked.authority.scopes.includes(scope) || !hasAtLeastRole(locked.authority.effectiveRole, "workspace_manager")) throw fail("OPERATOR_CONNECTION_SCOPE_DENIED", "Operator connection scope denied");
  if (String(process.env.MCP_OPERATOR_WRITES_ENABLED || "").trim().toLowerCase() !== "true") throw fail("OPERATOR_WRITES_DISABLED", "Assistant inventory changes are disabled");
  return { workspaceOwnerId: owner };
}
async function decisionsFor(client, workspaceId, records) {
  const decisions = [];
  for (const record of records) {
    const result = await client.query("SELECT id FROM tokens WHERE workspace_id = $1 AND name = $2 AND location IS NOT DISTINCT FROM $3 ORDER BY id LIMIT 1", [workspaceId, record.name, record.location]);
    decisions.push({ record, existingId: result.rows[0] ? Number(result.rows[0].id) : null });
  }
  return decisions;
}
function effectFor(decisions) {
  return {
    operation: "import_inventory", creates: decisions.filter((item) => item.existingId === null).length,
    keeps: decisions.filter((item) => item.existingId !== null).length, updatesExisting: false,
    items: decisions.map(({ record, existingId }, index) => ({
      index, action: existingId === null ? "create" : "keep_existing", existingId,
      name: untrustedText(record.name), type: record.type, category: record.category, expiresAt: record.expiresAt,
      location: untrustedText(record.location), usedBy: untrustedText(record.usedBy), sections: record.sections.map(untrustedText), domains: record.domains.map(untrustedText), description: untrustedText(record.description),
    })),
  };
}
async function previewImport({ client, operator, records }) {
  const actorLocks = await authorize(client, operator);
  const normalized = inventory.normalizeRecords(records);
  await assertInventoryImportAllowed({ client, workspaceId: operator.workspaceId, userId: operator.userId, additionalTokens: 0, actorLocks });
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [JSON.stringify(["operator-inventory-previews", operator.connectionId])]);
  await client.query("DELETE FROM operator_inventory_plans WHERE connection_id=$1 AND expires_at<=NOW() AND imported_at IS NULL", [operator.connectionId]);
  const pending = await client.query("SELECT COUNT(*)::int AS count FROM operator_inventory_plans WHERE connection_id=$1 AND imported_at IS NULL AND expires_at>NOW()", [operator.connectionId]);
  if (pending.rows[0].count >= 10) throw fail("OPERATOR_PENDING_LIMIT", "Too many inventory previews are open");
  const decisions = await decisionsFor(client, operator.workspaceId, normalized), planHash = hash({ workspaceId: operator.workspaceId, connectionId: operator.connectionId, decisions });
  const result = await client.query("INSERT INTO operator_inventory_plans(workspace_id,connection_id,plan_hash,decisions)VALUES($1,$2,$3,$4::jsonb)RETURNING id,expires_at", [operator.workspaceId, operator.connectionId, planHash, JSON.stringify(decisions)]);
  return { planId: result.rows[0].id, planHash, expiresAt: result.rows[0].expires_at.toISOString(), effect: effectFor(decisions) };
}
async function importInventory({ client, operator, planId, planHash, requestId }) {
  const actorLocks = await authorize(client, operator);
  if (typeof planId !== "string" || typeof requestId !== "string" || typeof planHash !== "string" || !UUID.test(planId) || !UUID.test(requestId) || !HASH.test(planHash)) throw inventory.invalid();
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [JSON.stringify(["operator-inventory-request", operator.connectionId, requestId])]);
  const previous = await client.query("SELECT plan_id,plan_hash,result FROM operator_inventory_requests WHERE connection_id=$1 AND request_id=$2", [operator.connectionId, requestId]);
  if (previous.rows[0]) {
    if (previous.rows[0].plan_id !== planId || previous.rows[0].plan_hash !== planHash || previous.rows[0].result.operation) throw fail("OPERATOR_IDEMPOTENCY_CONFLICT", "Request id was used for another inventory action");
    return { ...previous.rows[0].result, replayed: true };
  }
  const found = await client.query("SELECT *,expires_at<=NOW() AS expired FROM operator_inventory_plans WHERE id=$1 AND workspace_id=$2 AND connection_id=$3 FOR UPDATE", [planId, operator.workspaceId, operator.connectionId]);
  const plan = found.rows[0];
  if (!plan) throw fail("NOT_FOUND", "Inventory preview not found");
  if (plan.plan_hash !== planHash || !Array.isArray(plan.decisions) || plan.decisions.some((item) => !item || item.kind || !item.record)) throw fail("OPERATOR_PLAN_MISMATCH", "Inventory preview does not match");
  if (plan.imported_at) throw fail("OPERATOR_PLAN_USED", "Inventory preview was already imported");
  if (plan.expired) throw fail("OPERATOR_PLAN_EXPIRED", "Inventory preview expired");
  const records = inventory.normalizeRecords(plan.decisions.map((item) => item.record));
  // Use the same identity locks as normal manual imports, in stable order.
  for (const identity of records.map((record) => JSON.stringify([operator.workspaceId, "name", record.name, record.location])).sort()) await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [identity]);
  const current = await decisionsFor(client, operator.workspaceId, records);
  if (hash({ workspaceId: operator.workspaceId, connectionId: operator.connectionId, decisions: current }) !== planHash) throw fail("OPERATOR_INTENT_STALE", "Inventory changed since the preview; preview again");
  const creates = current.filter((item) => item.existingId === null).length;
  await assertInventoryImportAllowed({ client, workspaceId: operator.workspaceId, userId: operator.userId, additionalTokens: creates, actorLocks });
  const createdIds = [], keptIds = [];
  for (const { record, existingId } of current) {
    if (existingId !== null) { keptIds.push(existingId); continue; }
    const token = await Token.create({ userId: operator.userId, workspaceId: operator.workspaceId, created_by: operator.userId,
      name: record.name, type: record.type, category: record.category, expiration: record.expiresAt || "2099-12-31",
      location: record.location, used_by: record.usedBy, section: record.sections.length ? record.sections : null,
      domains: record.domains.length ? record.domains : null, description: record.description, imported_at: new Date() }, { client });
    createdIds.push(Number(token.id));
    await writeAudit({ client, actorUserId: operator.userId, subjectUserId: operator.userId, action: "TOKEN_CREATED", targetType: "token", targetId: token.id, workspaceId: operator.workspaceId,
      metadata: { via: "operator_connection", connection_id: operator.connectionId, request_id: requestId, type: record.type, category: record.category } });
  }
  const result = { requestId, planId, state: "succeeded", createdIds, keptIds, replayed: false };
  await client.query("INSERT INTO operator_inventory_requests(workspace_id,connection_id,request_id,plan_id,plan_hash,result)VALUES($1,$2,$3,$4,$5,$6::jsonb)", [operator.workspaceId, operator.connectionId, requestId, planId, planHash, JSON.stringify(result)]);
  await client.query("UPDATE operator_inventory_plans SET imported_at=NOW() WHERE id=$1", [planId]);
  return result;
}
module.exports = { previewImport, importInventory, effectFor, authorize };
