"use strict";

const crypto = require("node:crypto");
const { writeAudit } = require("../audit");
const { maskPhone } = require("../../utils/sanitize");
const { authorize } = require("./inventoryImports");
const { assertInventoryImportAllowed } = require("./inventoryPolicy");
const { normalizeContact } = require("./contactValidation");
const { untrustedText } = require("./projections");
const { invalid } = require("./tokenInventory");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
const fail = (code, message) => Object.assign(new Error(message), { code });
const digest = ({ workspaceId, connectionId, contact }) => crypto.createHash("sha256").update(JSON.stringify([
  "create_contact", workspaceId, connectionId, contact.firstName, contact.lastName, contact.email, contact.phoneE164,
])).digest("hex");
async function authorizeContact(client, operator) {
  const actorLocks = await authorize(client, operator, "mcp:contacts:create");
  await assertInventoryImportAllowed({ client, workspaceId: operator.workspaceId, userId: operator.userId, additionalTokens: 0, actorLocks });
}
async function ensurePhoneAvailable(client, workspaceId, phone) {
  if (!phone) return;
  const found = await client.query("SELECT 1 FROM workspace_contacts WHERE workspace_id=$1 AND phone_e164=$2", [workspaceId, phone]);
  if (found.rowCount) throw fail("OPERATOR_INTENT_STALE", "A workspace contact already uses that phone number");
}
async function previewContact({ client, operator, contact }) {
  await authorizeContact(client, operator);
  const normalized = normalizeContact(contact);
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [JSON.stringify(["operator-inventory-previews", operator.connectionId])]);
  await client.query("DELETE FROM operator_inventory_plans WHERE connection_id=$1 AND expires_at<=NOW() AND imported_at IS NULL", [operator.connectionId]);
  const pending = await client.query("SELECT COUNT(*)::int AS count FROM operator_inventory_plans WHERE connection_id=$1 AND imported_at IS NULL AND expires_at>NOW()", [operator.connectionId]);
  if (pending.rows[0].count >= 10) throw fail("OPERATOR_PENDING_LIMIT", "Too many previews are open");
  await ensurePhoneAvailable(client, operator.workspaceId, normalized.phoneE164);
  const planHash = digest({ ...operator, contact: normalized });
  const plan = (await client.query("INSERT INTO operator_inventory_plans(workspace_id,connection_id,plan_hash,decisions) VALUES($1,$2,$3,$4::jsonb) RETURNING id,expires_at", [operator.workspaceId, operator.connectionId, planHash, JSON.stringify([{ kind: "create_contact", contact: normalized }])])).rows[0];
  return { planId: plan.id, planHash, expiresAt: plan.expires_at.toISOString(),
    effect: { firstName: untrustedText(normalized.firstName), lastName: untrustedText(normalized.lastName), email: untrustedText(normalized.email), phoneE164: untrustedText(normalized.phoneE164) } };
}
async function createContact({ client, operator, planId, planHash, requestId }) {
  await authorizeContact(client, operator);
  if (!UUID.test(String(planId || "")) || !UUID.test(String(requestId || "")) || !HASH.test(String(planHash || ""))) throw invalid();
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [JSON.stringify(["operator-inventory-request", operator.connectionId, requestId])]);
  const previous = (await client.query("SELECT plan_id,plan_hash,result FROM operator_inventory_requests WHERE connection_id=$1 AND request_id=$2", [operator.connectionId, requestId])).rows[0];
  if (previous) {
    if (previous.plan_id !== planId || previous.plan_hash !== planHash || previous.result.operation !== "create_contact") throw fail("OPERATOR_IDEMPOTENCY_CONFLICT", "Request id was used for another action");
    return { ...previous.result, replayed: true };
  }
  const plan = (await client.query("SELECT *,expires_at<=NOW() AS expired FROM operator_inventory_plans WHERE id=$1 AND workspace_id=$2 AND connection_id=$3 FOR UPDATE", [planId, operator.workspaceId, operator.connectionId])).rows[0];
  if (!plan) throw fail("NOT_FOUND", "Preview not found");
  if (plan.plan_hash !== planHash || !Array.isArray(plan.decisions) || plan.decisions.length !== 1 || plan.decisions[0]?.kind !== "create_contact") throw fail("OPERATOR_PLAN_MISMATCH", "Preview does not match");
  if (plan.imported_at) throw fail("OPERATOR_PLAN_USED", "Preview was already submitted");
  if (plan.expired) throw fail("OPERATOR_PLAN_EXPIRED", "Preview expired");
  const contact = normalizeContact(plan.decisions[0].contact);
  if (digest({ ...operator, contact }) !== planHash) throw fail("OPERATOR_PLAN_MISMATCH", "Preview does not match");
  await ensurePhoneAvailable(client, operator.workspaceId, contact.phoneE164);
  let created;
  try {
    created = (await client.query("INSERT INTO workspace_contacts(workspace_id,first_name,last_name,phone_e164,details,created_by) VALUES($1,$2,$3,$4,$5::jsonb,$6) RETURNING id",
      [operator.workspaceId, contact.firstName, contact.lastName, contact.phoneE164, JSON.stringify(contact.email ? { email: contact.email } : {}), operator.userId])).rows[0];
  } catch (error) {
    if (error.code === "23505") throw fail("OPERATOR_INTENT_STALE", "A workspace contact already uses that phone number");
    throw error;
  }
  await writeAudit({ client, actorUserId: operator.userId, subjectUserId: operator.userId, action: "WORKSPACE_CONTACT_CREATED", targetType: "workspace", targetId: null, workspaceId: operator.workspaceId,
    metadata: { contact_id: created.id, phone_masked: contact.phoneE164 ? maskPhone(contact.phoneE164) : null, via: "operator_connection", connection_id: operator.connectionId } });
  const result = { operation: "create_contact", requestId, planId, contactId: created.id, state: "succeeded", replayed: false };
  await client.query("INSERT INTO operator_inventory_requests(workspace_id,connection_id,request_id,plan_id,plan_hash,result) VALUES($1,$2,$3,$4,$5,$6::jsonb)", [operator.workspaceId, operator.connectionId, requestId, planId, planHash, JSON.stringify(result)]);
  await client.query("UPDATE operator_inventory_plans SET imported_at=NOW() WHERE id=$1", [planId]);
  return result;
}

module.exports = { previewContact, createContact };
