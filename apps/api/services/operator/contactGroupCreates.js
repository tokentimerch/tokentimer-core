"use strict";

const crypto = require("node:crypto");
const { writeAudit } = require("../audit");
const { CONTACT_GROUP_LIMITS, CONTACT_GROUP_MEMBER_LIMITS } = require("../planLimits");
const { isValidEmail } = require("../../utils/emailAddress");
const { authorize } = require("./inventoryImports");
const { assertInventoryImportAllowed } = require("./inventoryPolicy");
const { normalizeContactGroup } = require("./contactGroupValidation");
const { untrustedText } = require("./projections");
const { invalid, assertSafe } = require("./tokenInventory");
const { completeness, decodeCursor } = require("./readProjections");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
const fail = (code, message) => Object.assign(new Error(message), { code });
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  return value;
}
const digest = (value) => crypto.createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
async function authorizeGroup(client, operator) {
  const actorLocks = await authorize(client, operator, "mcp:groups:create");
  await assertInventoryImportAllowed({ client, workspaceId: operator.workspaceId, userId: operator.userId, additionalTokens: 0, actorLocks });
}
// Exposes only the names and available channels needed to select recipients;
// addresses, phone numbers and webhook destinations remain private.
async function listGroupSources({ client, operator, query = {} }) {
  if (Object.keys(query).some((key) => !["limit", "cursor"].includes(key))) throw invalid();
  const limit = query.limit === undefined ? 25 : Number(query.limit);
  if ((query.limit !== undefined && (typeof query.limit !== "string" || !/^[1-9]\d?$/.test(query.limit))) || limit > 50) throw invalid();
  const offset = query.cursor === undefined ? 0 : decodeCursor(query.cursor);
  const source = `(SELECT 'contact'::text AS kind, id::text AS id, concat_ws(' ',first_name,last_name) AS name,
    (COALESCE(details->>'email','') <> '') AS has_email, (COALESCE(phone_e164,'') <> '') AS has_whatsapp
    FROM workspace_contacts WHERE workspace_id=$1
    UNION ALL SELECT 'webhook', NULL::text, btrim(hook->>'name'), false, false
    FROM workspace_settings CROSS JOIN LATERAL jsonb_array_elements(
      CASE WHEN jsonb_typeof(webhook_urls)='array' THEN webhook_urls ELSE '[]'::jsonb END) hook
    WHERE workspace_id=$1 AND btrim(COALESCE(hook->>'name',''))<>'') group_sources`;
  const total = (await client.query(`SELECT COUNT(*)::int AS total FROM ${source}`, [operator.workspaceId])).rows[0].total;
  const rows = (await client.query(`SELECT * FROM ${source} ORDER BY kind,name,id NULLS LAST LIMIT $2 OFFSET $3`, [operator.workspaceId, limit, offset])).rows;
  const items = rows.map((row) => ({ kind: row.kind, id: row.id, name: untrustedText(row.name), hasEmail: row.has_email, hasWhatsapp: row.has_whatsapp }));
  assertSafe(items);
  return { items, completeness: completeness({ offset, returned: items.length, total }) };
}
async function settings(client, workspaceId, lock = false) {
  if (lock) await client.query("INSERT INTO workspace_settings(workspace_id) VALUES($1) ON CONFLICT(workspace_id) DO NOTHING", [workspaceId]);
  const row = (await client.query("SELECT contact_groups,webhook_urls FROM workspace_settings WHERE workspace_id=$1" + (lock ? " FOR UPDATE" : ""), [workspaceId])).rows[0];
  return { groups: Array.isArray(row?.contact_groups) ? row.contact_groups : [], hooks: Array.isArray(row?.webhook_urls) ? row.webhook_urls : [] };
}
async function resolveGroup(client, workspaceId, group, state) {
  if (state.groups.some((item) => String(item?.name || "").trim().toLowerCase() === group.name.toLowerCase())) throw fail("OPERATOR_INTENT_STALE", "A contact group with this name already exists");
  const { rows: plans } = await client.query("SELECT plan FROM workspaces WHERE id=$1", [workspaceId]);
  const plan = String(plans[0]?.plan || "oss").toLowerCase();
  const groupLimit = CONTACT_GROUP_LIMITS[plan] ?? CONTACT_GROUP_LIMITS.oss ?? Infinity;
  const memberLimit = CONTACT_GROUP_MEMBER_LIMITS[plan] ?? CONTACT_GROUP_MEMBER_LIMITS.oss ?? Infinity;
  const ids = [...new Set([...group.emailContactIds, ...group.whatsappContactIds])].sort();
  if (state.groups.length >= groupLimit || ids.length > memberLimit) throw fail("PLAN_CONTACT_GROUP_LIMIT", "The workspace plan does not allow this contact group");
  const found = ids.length ? (await client.query("SELECT id,first_name,last_name,phone_e164,details,updated_at::text AS version FROM workspace_contacts WHERE workspace_id=$1 AND id=ANY($2::uuid[]) ORDER BY id FOR SHARE", [workspaceId, ids])).rows : [];
  if (found.length !== ids.length) throw fail("OPERATOR_INTENT_STALE", "A selected contact is no longer available");
  const lookup = new Map(found.map((row) => [String(row.id), row]));
  for (const id of group.emailContactIds) if (!isValidEmail(String(lookup.get(id)?.details?.email || ""))) throw fail("OPERATOR_INTENT_STALE", "A selected email contact has no valid email");
  for (const id of group.whatsappContactIds) if (!lookup.get(id)?.phone_e164) throw fail("OPERATOR_INTENT_STALE", "A selected WhatsApp contact has no phone number");
  if (group.webhookNames.some((name) => !state.hooks.some((hook) => hook?.name === name))) throw fail("OPERATOR_INTENT_STALE", "A selected webhook is no longer available");
  const contacts = found.map((row) => ({ id: String(row.id), name: untrustedText([row.first_name, row.last_name].filter(Boolean).join(" ")) }));
  assertSafe(contacts);
  const contactsHash = digest(found.map((row) => [String(row.id), row.first_name, row.last_name, row.phone_e164, row.details?.email || null, row.version]));
  return { contacts, contactsHash, settingsHash: digest(state), plan };
}
function planDigest(operator, decision) { return digest(["create_contact_group", operator.workspaceId, operator.connectionId, decision]); }
async function previewGroup({ client, operator, group }) {
  await authorizeGroup(client, operator);
  const normalized = normalizeContactGroup(group);
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [JSON.stringify(["operator-inventory-previews", operator.connectionId])]);
  await client.query("DELETE FROM operator_inventory_plans WHERE connection_id=$1 AND expires_at<=NOW() AND imported_at IS NULL", [operator.connectionId]);
  const pending = await client.query("SELECT COUNT(*)::int AS count FROM operator_inventory_plans WHERE connection_id=$1 AND imported_at IS NULL AND expires_at>NOW()", [operator.connectionId]);
  if (pending.rows[0].count >= 10) throw fail("OPERATOR_PENDING_LIMIT", "Too many previews are open");
  const state = await settings(client, operator.workspaceId), resolved = await resolveGroup(client, operator.workspaceId, normalized, state);
  const decision = { kind: "create_contact_group", group: normalized, groupId: crypto.randomUUID(), ...resolved };
  const planHash = planDigest(operator, decision);
  const plan = (await client.query("INSERT INTO operator_inventory_plans(workspace_id,connection_id,plan_hash,decisions) VALUES($1,$2,$3,$4::jsonb) RETURNING id,expires_at", [operator.workspaceId, operator.connectionId, planHash, JSON.stringify([decision])])).rows[0];
  return { planId: plan.id, planHash, expiresAt: plan.expires_at.toISOString(), effect: {
    name: untrustedText(normalized.name), contacts: resolved.contacts, emailContactIds: normalized.emailContactIds,
    whatsappContactIds: normalized.whatsappContactIds, webhookNames: normalized.webhookNames.map(untrustedText), weeklyDigest: normalized.weeklyDigest,
  } };
}
async function createGroup({ client, operator, planId, planHash, requestId }) {
  await authorizeGroup(client, operator);
  if (!UUID.test(String(planId || "")) || !UUID.test(String(requestId || "")) || !HASH.test(String(planHash || ""))) throw invalid();
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [JSON.stringify(["operator-inventory-request", operator.connectionId, requestId])]);
  const previous = (await client.query("SELECT plan_id,plan_hash,result FROM operator_inventory_requests WHERE connection_id=$1 AND request_id=$2", [operator.connectionId, requestId])).rows[0];
  if (previous) {
    if (previous.plan_id !== planId || previous.plan_hash !== planHash || previous.result.operation !== "create_contact_group") throw fail("OPERATOR_IDEMPOTENCY_CONFLICT", "Request id was used for another action");
    return { ...previous.result, replayed: true };
  }
  const plan = (await client.query("SELECT *,expires_at<=NOW() AS expired FROM operator_inventory_plans WHERE id=$1 AND workspace_id=$2 AND connection_id=$3 FOR UPDATE", [planId, operator.workspaceId, operator.connectionId])).rows[0];
  if (!plan) throw fail("NOT_FOUND", "Preview not found");
  if (plan.plan_hash !== planHash || !Array.isArray(plan.decisions) || plan.decisions.length !== 1 || plan.decisions[0]?.kind !== "create_contact_group") throw fail("OPERATOR_PLAN_MISMATCH", "Preview does not match");
  if (plan.imported_at) throw fail("OPERATOR_PLAN_USED", "Preview was already submitted");
  if (plan.expired) throw fail("OPERATOR_PLAN_EXPIRED", "Preview expired");
  const decision = plan.decisions[0], group = normalizeContactGroup(decision.group);
  if (!UUID.test(String(decision.groupId || "")) || planDigest(operator, decision) !== planHash) throw fail("OPERATOR_PLAN_MISMATCH", "Preview does not match");
  const state = await settings(client, operator.workspaceId, true), current = await resolveGroup(client, operator.workspaceId, group, state);
  if (current.settingsHash !== decision.settingsHash || current.contactsHash !== decision.contactsHash || current.plan !== decision.plan) throw fail("OPERATOR_INTENT_STALE", "Group configuration changed; preview again");
  state.groups.push({ id: decision.groupId, name: group.name,
    ...(group.emailContactIds.length ? { email_contact_ids: group.emailContactIds } : {}),
    ...(group.whatsappContactIds.length ? { whatsapp_contact_ids: group.whatsappContactIds } : {}),
    ...(group.webhookNames.length ? { webhook_names: group.webhookNames } : {}),
    weekly_digest_email: group.weeklyDigest.email, weekly_digest_whatsapp: group.weeklyDigest.whatsapp, weekly_digest_webhooks: group.weeklyDigest.webhooks });
  await client.query("UPDATE workspace_settings SET contact_groups=$2::jsonb WHERE workspace_id=$1", [operator.workspaceId, JSON.stringify(state.groups)]);
  await writeAudit({ client, actorUserId: operator.userId, subjectUserId: operator.userId, action: "WORKSPACE_ALERT_SETTINGS_UPDATED", targetType: "workspace", targetId: null, workspaceId: operator.workspaceId,
    metadata: { via: "operator_connection", connection_id: operator.connectionId, changed_fields: ["contact_groups"], contact_group_id: decision.groupId } });
  const result = { operation: "create_contact_group", requestId, planId, groupId: decision.groupId, state: "succeeded", replayed: false };
  await client.query("INSERT INTO operator_inventory_requests(workspace_id,connection_id,request_id,plan_id,plan_hash,result) VALUES($1,$2,$3,$4,$5,$6::jsonb)", [operator.workspaceId, operator.connectionId, requestId, planId, planHash, JSON.stringify(result)]);
  await client.query("UPDATE operator_inventory_plans SET imported_at=NOW() WHERE id=$1", [planId]);
  return result;
}
module.exports = { listGroupSources, previewGroup, createGroup };
