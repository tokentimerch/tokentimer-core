"use strict";

const crypto = require("node:crypto");
const Token = require("../../db/models/Token");
const { TOKEN_TYPES_BY_CATEGORY } = require("../../utils/tokenClassification");
const { writeAudit } = require("../audit");
const inventory = require("./tokenInventory");
const { authorize } = require("./inventoryImports");
const { assertInventoryImportAllowed, AUTO_SYNC_PROJECTION } = require("./inventoryPolicy");
const { normalizeUpdate } = require("./inventoryUpdateValidation");
const { untrustedText } = require("./projections");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
const fail = (code, message) => Object.assign(new Error(message), { code });
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  return value;
}
const hash = (value) => crypto.createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");

async function currentRecord(client, workspaceId, tokenId, lock = false) {
  if (!Number.isSafeInteger(tokenId) || tokenId < 1 || tokenId > 2147483647) throw inventory.invalid();
  const query = `SELECT id,name,type,category,expiration::text AS expiration,location,used_by,section,domains,description,source_provider,source_kind,${AUTO_SYNC_PROJECTION},updated_at::text AS version FROM tokens WHERE workspace_id=$1 AND id=$2${lock ? " FOR UPDATE" : ""}`;
  const row = (await client.query(query, [workspaceId, tokenId])).rows[0];
  if (!row) throw fail("NOT_FOUND", "Inventory record not found");
  // Provider and certificate records have additional reconciliation rules.
  if (row.source_provider || row.source_kind || row.auto_sync_managed || row.category === "cert" || TOKEN_TYPES_BY_CATEGORY.cert.includes(row.type)) throw fail("OPERATOR_UPDATE_UNSUPPORTED", "This record cannot be updated by an assistant");
  const record = { name: row.name, type: row.type, category: row.category,
    expiresAt: row.expiration === "2099-12-31" ? null : row.expiration,
    location: row.location, usedBy: row.used_by, sections: row.section || [], domains: row.domains || [], description: row.description };
  inventory.assertSafe(record);
  return { record, version: row.version };
}

function effectFor(decision) {
  const text = (value) => typeof value === "string" ? untrustedText(value) : Array.isArray(value) ? value.map(untrustedText) : value;
  const project = (field, value) => field === "location" ? inventory.publicLocation(value) : text(value);
  return { tokenId: decision.tokenId, fields: Object.keys(decision.changes).map((field) => ({ field, before: project(field, decision.before[field]), after: project(field, decision.changes[field]) })) };
}

async function ensureIdentityAvailable(client, workspaceId, tokenId, name, location) {
  const duplicate = await client.query("SELECT id FROM tokens WHERE workspace_id=$1 AND id<>$2 AND name=$3 AND location IS NOT DISTINCT FROM $4 LIMIT 1", [workspaceId, tokenId, name, location]);
  if (duplicate.rows.length) throw fail("OPERATOR_INTENT_STALE", "Another inventory record has this name and location");
}

async function previewUpdate({ client, operator, tokenId, changes }) {
  const actorLocks = await authorize(client, operator, "mcp:inventory:update");
  await assertInventoryImportAllowed({ client, workspaceId: operator.workspaceId, userId: operator.userId, additionalTokens: 0, actorLocks });
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [JSON.stringify(["operator-inventory-previews", operator.connectionId])]);
  await client.query("DELETE FROM operator_inventory_plans WHERE connection_id=$1 AND expires_at<=NOW() AND imported_at IS NULL", [operator.connectionId]);
  const pending = await client.query("SELECT COUNT(*)::int AS count FROM operator_inventory_plans WHERE connection_id=$1 AND imported_at IS NULL AND expires_at>NOW()", [operator.connectionId]);
  if (pending.rows[0].count >= 10) throw fail("OPERATOR_PENDING_LIMIT", "Too many inventory previews are open");
  const current = await currentRecord(client, operator.workspaceId, tokenId);
  const normalized = normalizeUpdate(current.record, changes);
  if (normalized.location && inventory.publicLocation(normalized.location)?.value !== normalized.location) throw inventory.invalid();
  const before = Object.fromEntries(Object.keys(normalized).map((key) => [key, current.record[key]]));
  const identity = { name: current.record.name, location: current.record.location };
  const destination = { name: normalized.name ?? identity.name, location: Object.hasOwn(normalized, "location") ? normalized.location : identity.location };
  await ensureIdentityAvailable(client, operator.workspaceId, tokenId, destination.name, destination.location);
  const decision = { kind: "update", tokenId, before, changes: normalized, version: current.version, identity, destination };
  const planHash = hash({ workspaceId: operator.workspaceId, connectionId: operator.connectionId, decision });
  const row = (await client.query("INSERT INTO operator_inventory_plans(workspace_id,connection_id,plan_hash,decisions) VALUES($1,$2,$3,$4::jsonb) RETURNING id,expires_at", [operator.workspaceId, operator.connectionId, planHash, JSON.stringify([decision])])).rows[0];
  return { planId: row.id, planHash, expiresAt: row.expires_at.toISOString(), effect: effectFor(decision) };
}

async function updateInventory({ client, operator, planId, planHash, requestId }) {
  const actorLocks = await authorize(client, operator, "mcp:inventory:update");
  if (!UUID.test(String(planId || "")) || !UUID.test(String(requestId || "")) || !HASH.test(String(planHash || ""))) throw inventory.invalid();
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [JSON.stringify(["operator-inventory-request", operator.connectionId, requestId])]);
  const previous = (await client.query("SELECT plan_id,plan_hash,result FROM operator_inventory_requests WHERE connection_id=$1 AND request_id=$2", [operator.connectionId, requestId])).rows[0];
  if (previous) {
    if (previous.plan_id !== planId || previous.plan_hash !== planHash || previous.result.operation !== "update_inventory") throw fail("OPERATOR_IDEMPOTENCY_CONFLICT", "Request id was used for another inventory action");
    return { ...previous.result, replayed: true };
  }
  const plan = (await client.query("SELECT *,expires_at<=NOW() AS expired FROM operator_inventory_plans WHERE id=$1 AND workspace_id=$2 AND connection_id=$3 FOR UPDATE", [planId, operator.workspaceId, operator.connectionId])).rows[0];
  if (!plan) throw fail("NOT_FOUND", "Inventory preview not found");
  if (plan.plan_hash !== planHash || !Array.isArray(plan.decisions) || plan.decisions.length !== 1 || plan.decisions[0]?.kind !== "update") throw fail("OPERATOR_PLAN_MISMATCH", "Inventory preview does not match");
  if (plan.imported_at) throw fail("OPERATOR_PLAN_USED", "Inventory preview was already used");
  if (plan.expired) throw fail("OPERATOR_PLAN_EXPIRED", "Inventory preview expired");
  const decision = plan.decisions[0];
  if (hash({ workspaceId: operator.workspaceId, connectionId: operator.connectionId, decision }) !== planHash) throw fail("OPERATOR_PLAN_MISMATCH", "Inventory preview does not match");
  await assertInventoryImportAllowed({ client, workspaceId: operator.workspaceId, userId: operator.userId, additionalTokens: 0, actorLocks });
  for (const identity of [decision.identity, decision.destination].map((item) => JSON.stringify([operator.workspaceId, "name", item.name, item.location])).sort()) {
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [identity]);
  }
  const current = await currentRecord(client, operator.workspaceId, decision.tokenId, true);
  const changes = normalizeUpdate(current.record, decision.changes);
  const before = Object.fromEntries(Object.keys(changes).map((key) => [key, current.record[key]]));
  if (current.version !== decision.version || hash(before) !== hash(decision.before) || current.record.name !== decision.identity.name || current.record.location !== decision.identity.location) throw fail("OPERATOR_INTENT_STALE", "Inventory changed since the preview; preview again");
  await ensureIdentityAvailable(client, operator.workspaceId, decision.tokenId, decision.destination.name, decision.destination.location);
  const mapping = { name: "name", expiresAt: "expiration", location: "location", usedBy: "used_by", sections: "section", domains: "domains", description: "description" };
  const updates = Object.fromEntries(Object.entries(changes).map(([key, value]) => [mapping[key], key === "expiresAt" && value === null ? "2099-12-31" : value]));
  await Token.update(decision.tokenId, updates, { client, manualExpirationSnapshot: current.record.expiresAt });
  await writeAudit({ client, actorUserId: operator.userId, subjectUserId: operator.userId, action: "TOKEN_UPDATED", targetType: "token", targetId: decision.tokenId, workspaceId: operator.workspaceId,
    metadata: { via: "operator_connection", connection_id: operator.connectionId, request_id: requestId, fields: Object.keys(changes) } });
  const result = { operation: "update_inventory", requestId, planId, tokenId: decision.tokenId, state: "succeeded", replayed: false };
  await client.query("INSERT INTO operator_inventory_requests(workspace_id,connection_id,request_id,plan_id,plan_hash,result) VALUES($1,$2,$3,$4,$5,$6::jsonb)", [operator.workspaceId, operator.connectionId, requestId, planId, planHash, JSON.stringify(result)]);
  await client.query("UPDATE operator_inventory_plans SET imported_at=NOW() WHERE id=$1", [planId]);
  return result;
}

module.exports = { previewUpdate, updateInventory, effectFor };
