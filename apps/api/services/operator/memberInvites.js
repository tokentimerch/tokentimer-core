"use strict";

const crypto = require("node:crypto");
const { MEMBER_LIMITS } = require("../planLimits");
const { writeAudit } = require("../audit");
const { pool } = require("../../db/database");
const emailService = require("../emailService");
const { escapeHtml, sanitizeSingleLine } = require("../../utils/sanitize");
const { authorize } = require("./inventoryImports");
const { assertInventoryImportAllowed } = require("./inventoryPolicy");
const { normalizeInvite } = require("./memberInviteValidation");
const { registrationUrl } = require("./memberInvitePolicy");
const { untrustedText } = require("./projections");
const { invalid } = require("./tokenInventory");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
const fail = (code, message) => Object.assign(new Error(message), { code });
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  return value;
}
const digest = (value) => crypto.createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
async function authorizeInvite(client, operator) {
  const actorLocks = await authorize(client, operator, "mcp:members:invite");
  await assertInventoryImportAllowed({ client, workspaceId: operator.workspaceId, userId: operator.userId, additionalTokens: 0, actorLocks });
  if (String(process.env.DISABLE_MANUAL_INVITES || "").toLowerCase() === "true") throw fail("MANUAL_INVITES_DISABLED", "Manual invitations are disabled");
}
async function inspectInvite(client, operator, email) {
  const ws = (await client.query("SELECT id,name,created_by,plan,is_personal_default FROM workspaces WHERE id=$1 FOR SHARE", [operator.workspaceId])).rows[0];
  if (!ws) throw fail("NOT_FOUND", "Workspace unavailable");
  if (ws.is_personal_default === true) throw fail("PERSONAL_DEFAULT", "Personal workspaces cannot invite members");
  if (ws.is_personal_default == null) {
    const members = (await client.query("SELECT COUNT(*)::int AS count, COUNT(*) FILTER (WHERE user_id=$2 AND role='admin')::int AS owner_admin FROM workspace_memberships WHERE workspace_id=$1", [operator.workspaceId, ws.created_by])).rows[0];
    if (members.count === 1 && members.owner_admin === 1) throw fail("PERSONAL_DEFAULT", "Personal workspaces cannot invite members");
  }
  const actor = (await client.query("SELECT email FROM users WHERE id=$1", [operator.userId])).rows[0];
  if (!actor || String(actor.email || "").trim().toLowerCase() === email) throw fail("OPERATOR_INTENT_STALE", "This email cannot be invited");
  const targets = (await client.query("SELECT id FROM users WHERE LOWER(email)=$1 ORDER BY id LIMIT 2", [email])).rows;
  if (targets.length > 1) throw fail("OPERATOR_INTENT_STALE", "This email cannot be invited");
  const targetId = targets[0]?.id || null;
  if (targetId && String(targetId) === String(ws.created_by)) throw fail("OPERATOR_INTENT_STALE", "This email cannot be invited");
  if (targetId && (await client.query("SELECT 1 FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2", [operator.workspaceId, targetId])).rowCount) throw fail("OPERATOR_INTENT_STALE", "This user already belongs to the workspace");
  if ((await client.query("SELECT 1 FROM workspace_invitations WHERE workspace_id=$1 AND LOWER(email)=$2 AND accepted_at IS NULL", [operator.workspaceId, email])).rowCount) throw fail("OPERATOR_INTENT_STALE", "This email already has a pending invitation");
  const plan = String(ws.plan || "oss").toLowerCase();
  const limit = MEMBER_LIMITS[plan] ?? MEMBER_LIMITS.oss ?? MEMBER_LIMITS.free ?? Infinity;
  if (Number.isFinite(limit)) {
    const counts = (await client.query(`SELECT
      (SELECT COUNT(DISTINCT wm.user_id)::int FROM workspaces w JOIN workspace_memberships wm ON wm.workspace_id=w.id WHERE w.created_by=$1) AS members,
      (SELECT COUNT(DISTINCT LOWER(wi.email))::int FROM workspaces w JOIN workspace_invitations wi ON wi.workspace_id=w.id WHERE w.created_by=$1 AND wi.accepted_at IS NULL) AS pending,
      EXISTS(SELECT 1 FROM workspaces w JOIN workspace_memberships wm ON wm.workspace_id=w.id JOIN users u ON u.id=wm.user_id WHERE w.created_by=$1 AND LOWER(u.email)=$2) AS already_member,
      EXISTS(SELECT 1 FROM workspaces w JOIN workspace_invitations wi ON wi.workspace_id=w.id WHERE w.created_by=$1 AND LOWER(wi.email)=$2 AND wi.accepted_at IS NULL) AS already_pending`, [ws.created_by, email])).rows[0];
    if (counts.members + counts.pending + (counts.already_member || counts.already_pending ? 0 : 1) > limit) throw fail("PLAN_MEMBER_LIMIT", "The workspace plan does not allow another member");
  }
  return { workspaceName: ws.name, workspaceOwnerId: ws.created_by, plan, targetId, mode: targetId ? "add_existing_user" : "invite_new_user" };
}
function planDigest(operator, decision) { return digest(["invite_member", operator.workspaceId, operator.connectionId, decision]); }
async function previewInvite({ client, operator, invite }) {
  await authorizeInvite(client, operator);
  const normalized = normalizeInvite(invite);
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [JSON.stringify(["operator-inventory-previews", operator.connectionId])]);
  await client.query("DELETE FROM operator_inventory_plans WHERE connection_id=$1 AND expires_at<=NOW() AND imported_at IS NULL", [operator.connectionId]);
  const pending = await client.query("SELECT COUNT(*)::int AS count FROM operator_inventory_plans WHERE connection_id=$1 AND imported_at IS NULL AND expires_at>NOW()", [operator.connectionId]);
  if (pending.rows[0].count >= 10) throw fail("OPERATOR_PENDING_LIMIT", "Too many previews are open");
  const state = await inspectInvite(client, operator, normalized.email);
  const decision = { kind: "invite_member", invite: normalized, invitationId: crypto.randomUUID(), ...state };
  const planHash = planDigest(operator, decision);
  const row = (await client.query("INSERT INTO operator_inventory_plans(workspace_id,connection_id,plan_hash,decisions) VALUES($1,$2,$3,$4::jsonb) RETURNING id,expires_at", [operator.workspaceId, operator.connectionId, planHash, JSON.stringify([decision])])).rows[0];
  return { planId: row.id, planHash, expiresAt: row.expires_at.toISOString(), effect: {
    email: untrustedText(normalized.email), workspaceName: untrustedText(state.workspaceName), role: "viewer", mode: state.mode, attemptsEmail: true,
  } };
}
async function createInvite({ client, operator, planId, planHash, requestId }) {
  if (!UUID.test(String(planId || "")) || !UUID.test(String(requestId || "")) || !HASH.test(String(planHash || ""))) throw invalid();
  // Lock the actor, owner and previewed target in user-id order before taking
  // the workspace lock, matching account deletion and billing lock order.
  const hint = (await client.query("SELECT decisions FROM operator_inventory_plans WHERE id=$1 AND workspace_id=$2 AND connection_id=$3", [planId, operator.workspaceId, operator.connectionId])).rows[0];
  const owner = (await client.query("SELECT created_by FROM workspaces WHERE id=$1", [operator.workspaceId])).rows[0]?.created_by;
  if (owner == null) throw fail("NOT_FOUND", "Workspace unavailable");
  const hintedTarget = Number.isSafeInteger(Number(hint?.decisions?.[0]?.targetId)) && Number(hint.decisions[0].targetId) > 0 ? Number(hint.decisions[0].targetId) : owner;
  const lockedUsers = await client.query("SELECT id FROM users WHERE id IN ($1,$2,$3) ORDER BY id FOR KEY SHARE", [owner, operator.userId, hintedTarget]);
  await authorizeInvite(client, operator);
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [JSON.stringify(["operator-inventory-request", operator.connectionId, requestId])]);
  const previous = (await client.query("SELECT plan_id,plan_hash,result FROM operator_inventory_requests WHERE connection_id=$1 AND request_id=$2", [operator.connectionId, requestId])).rows[0];
  if (previous) {
    if (previous.plan_id !== planId || previous.plan_hash !== planHash || previous.result.operation !== "invite_member") throw fail("OPERATOR_IDEMPOTENCY_CONFLICT", "Request id was used for another action");
    return { ...previous.result, replayed: true };
  }
  const plan = (await client.query("SELECT *,expires_at<=NOW() AS expired FROM operator_inventory_plans WHERE id=$1 AND workspace_id=$2 AND connection_id=$3 FOR UPDATE", [planId, operator.workspaceId, operator.connectionId])).rows[0];
  if (!plan) throw fail("NOT_FOUND", "Preview not found");
  if (plan.plan_hash !== planHash || !Array.isArray(plan.decisions) || plan.decisions.length !== 1 || plan.decisions[0]?.kind !== "invite_member") throw fail("OPERATOR_PLAN_MISMATCH", "Preview does not match");
  if (plan.imported_at) throw fail("OPERATOR_PLAN_USED", "Preview was already submitted");
  if (plan.expired) throw fail("OPERATOR_PLAN_EXPIRED", "Preview expired");
  const decision = plan.decisions[0], { email } = normalizeInvite(decision.invite);
  if (!UUID.test(String(decision.invitationId || "")) || planDigest(operator, decision) !== planHash) throw fail("OPERATOR_PLAN_MISMATCH", "Preview does not match");
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [JSON.stringify(["operator-member-admission", String(decision.workspaceOwnerId)])]);
  const current = await inspectInvite(client, operator, email);
  if (digest(current) !== digest({ workspaceName: decision.workspaceName, workspaceOwnerId: decision.workspaceOwnerId, plan: decision.plan, targetId: decision.targetId, mode: decision.mode })) throw fail("OPERATOR_INTENT_STALE", "Invitation details changed; preview again");
  if (current.targetId && !lockedUsers.rows.some((row) => String(row.id) === String(current.targetId))) throw fail("OPERATOR_INTENT_STALE", "Invitation details changed; preview again");
  if (current.targetId) {
    const inserted = await client.query("INSERT INTO workspace_memberships(user_id,workspace_id,role,invited_by) VALUES($1,$2,'viewer',$3) ON CONFLICT DO NOTHING RETURNING user_id", [current.targetId, operator.workspaceId, operator.userId]);
    if (!inserted.rowCount) throw fail("OPERATOR_INTENT_STALE", "This user already belongs to the workspace");
  } else {
    const token = crypto.randomBytes(32).toString("hex");
    const inserted = await client.query("INSERT INTO workspace_invitations(id,workspace_id,email,role,invited_by,token) VALUES($1,$2,$3,'viewer',$4,$5) ON CONFLICT(workspace_id,email) DO NOTHING RETURNING id", [decision.invitationId, operator.workspaceId, email, operator.userId, token]);
    if (!inserted.rowCount) throw fail("OPERATOR_INTENT_STALE", "This email already has an invitation");
  }
  await writeAudit({ client, actorUserId: operator.userId, subjectUserId: current.targetId || operator.userId, action: "MEMBER_INVITED_OR_UPDATED", targetType: "workspace", targetId: null, workspaceId: operator.workspaceId,
    metadata: { role: "viewer", email, workspace_name: current.workspaceName, recipient_type: current.targetId ? "existing_user" : "new_user", via: "operator_connection", connection_id: operator.connectionId } });
  const result = { operation: "invite_member", requestId, planId, mode: current.mode, role: "viewer", state: "succeeded", emailStatus: "pending", replayed: false };
  await client.query("INSERT INTO operator_inventory_requests(workspace_id,connection_id,request_id,plan_id,plan_hash,result) VALUES($1,$2,$3,$4,$5,$6::jsonb)", [operator.workspaceId, operator.connectionId, requestId, planId, planHash, JSON.stringify(result)]);
  await client.query("UPDATE operator_inventory_plans SET imported_at=NOW() WHERE id=$1", [planId]);
  return result;
}

// Claim the notification before calling the mail provider. A process failure
// after the claim leaves an honest "unknown" state and never sends twice.
async function deliverInvite({ operator, requestId, db = pool, send = emailService.sendEmail, template = emailService.generateEmailTemplate }) {
  const claimed = await db.query(`UPDATE operator_inventory_requests
    SET result=jsonb_set(result,'{emailStatus}','"unknown"'::jsonb)
    WHERE connection_id=$1 AND workspace_id=$2 AND request_id=$3
      AND result->>'operation'='invite_member' AND result->>'emailStatus'='pending'
    RETURNING plan_id`, [operator.connectionId, operator.workspaceId, requestId]);
  if (!claimed.rowCount) {
    const prior = (await db.query("SELECT result FROM operator_inventory_requests WHERE connection_id=$1 AND workspace_id=$2 AND request_id=$3", [operator.connectionId, operator.workspaceId, requestId])).rows[0];
    return prior?.result?.emailStatus || "unknown";
  }
  try {
    const plan = (await db.query("SELECT decisions FROM operator_inventory_plans WHERE id=$1 AND workspace_id=$2 AND connection_id=$3", [claimed.rows[0].plan_id, operator.workspaceId, operator.connectionId])).rows[0];
    const decision = plan?.decisions?.[0];
    if (!decision || decision.kind !== "invite_member") return "unknown";
    const { email } = normalizeInvite(decision.invite);
    const base = String(process.env.FRONTEND_URL || process.env.APP_URL || "http://localhost:5173").replace(/\/+$/, "");
    let actionUrl = base + "/dashboard";
    if (decision.mode === "invite_new_user") {
      const invitation = (await db.query("SELECT token FROM workspace_invitations WHERE workspace_id=$1 AND LOWER(email)=$2 AND id=$3 AND role='viewer' AND invited_by=$4 AND accepted_at IS NULL", [operator.workspaceId, email, decision.invitationId, operator.userId])).rows[0];
      if (!invitation?.token) return "unknown";
      actionUrl = registrationUrl(base, email, invitation.token);
    } else {
      const membership = await db.query("SELECT 1 FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2 AND role='viewer' AND invited_by=$3", [operator.workspaceId, decision.targetId, operator.userId]);
      if (!membership.rowCount) return "unknown";
    }
    const workspace = sanitizeSingleLine(decision.workspaceName, 120);
    const title = decision.mode === "invite_new_user" ? "Workspace invitation" : "Workspace access";
    const rendered = await template({ title, greeting: "Hello,",
      content: `<p>You have been granted viewer access to <strong>${escapeHtml(workspace)}</strong>.</p>`,
      buttonText: decision.mode === "invite_new_user" ? "Create your account" : "Open TokenTimer",
      buttonUrl: actionUrl, plainTextContent: `You have been granted viewer access to ${workspace}.\n\n${actionUrl}` });
    const delivery = await send({ to: email, subject: `TokenTimer workspace: ${workspace}`, html: rendered.html, text: rendered.text, useEmbeddedLogo: rendered.useEmbeddedLogo });
    const status = delivery?.success === true ? "sent" : "failed";
    await db.query("UPDATE operator_inventory_requests SET result=jsonb_set(result,'{emailStatus}',to_jsonb($4::text)) WHERE connection_id=$1 AND workspace_id=$2 AND request_id=$3", [operator.connectionId, operator.workspaceId, requestId, status]);
    return status;
  } catch (_error) {
    // Do not log addresses, links, provider output or invitation tokens.
    return "unknown";
  }
}
module.exports = { inspectInvite, previewInvite, createInvite, deliverInvite };
