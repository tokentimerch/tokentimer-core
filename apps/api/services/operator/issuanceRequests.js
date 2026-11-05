"use strict";

const crypto = require("node:crypto");
const { authorize } = require("./inventoryImports");
const { assertInventoryImportAllowed } = require("./inventoryPolicy");
const { normalizeIssuance } = require("./issuanceValidation");
const { canonicalize, PLAN_TTL_MS, APPROVAL_TTL_MS } = require("./planEffects");
const { untrustedText } = require("./projections");
const { createCertificateIssuanceJob } = require("../certops/issuance");
const { lockWorkspaceForCertOpsSideEffect } = require("../certops/workspaceKillSwitch");
const { writeAudit } = require("../audit");
const { requestView, assistantPendingLimit } = require("./renewRequests");
const { endLapsedWindows } = require("./requestMaintenance");
const { resolveRenewalPerCaCap } = require("../certops/renewalCapacity");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
const fail = (code, message) => Object.assign(new Error(message), { code });
const hash = (value) => crypto.createHash("sha256").update(JSON.stringify(canonicalize(value))).digest("hex");

async function authorizeIssuance(client, operator) {
  const actorLocks = await authorize(client, operator, "mcp:issue:request");
  const hostedWorkspace = await assertInventoryImportAllowed({ client, workspaceId: operator.workspaceId, userId: operator.userId, additionalTokens: 0, actorLocks });
  const workspace = (await client.query(
    "SELECT operator_issuance_enabled,certops_paused,certops_require_approval_always FROM workspaces WHERE id=$1 FOR SHARE",
    [operator.workspaceId],
  )).rows[0];
  if (!workspace?.operator_issuance_enabled) throw fail("OPERATOR_WRITES_DISABLED", "Assistant issuance is not enabled in this workspace");
  return { ...workspace, plan: hostedWorkspace?.plan };
}

async function effectFor(client, operator, normalized, workspace) {
  const agent = (await client.query(
    "SELECT id,name,status,agent_kind FROM certops_agents WHERE workspace_id=$1 AND id=$2 FOR SHARE",
    [operator.workspaceId, normalized.agentId],
  )).rows[0];
  if (!agent || agent.status === "retired" || agent.agent_kind === "diagnostic") throw fail("NOT_FOUND", "Issuance agent is unavailable");
  const payload = normalized.payload;
  return {
    operation: "issue", lifecycleEffect: "creates_and_installs_certificate", issuerEffect: "contacts_issuer",
    commonName: untrustedText(payload.target.reference), sans: payload.sans.map(untrustedText),
    agent: { id: agent.id, name: untrustedText(agent.name) },
    issuerHost: untrustedText(new URL(payload.caEndpoint).host),
    dnsZone: untrustedText(payload.dnsZone), dnsProvider: untrustedText(payload.dnsProvider),
    commandProfile: untrustedText(payload.commandRef),
    destination: "The supplied certificate file path on the selected agent",
    destinationDigest: hash(payload.certPath),
    approvalAuthority: workspace.certops_require_approval_always ? "other_manager_or_admin" : "none",
    standingRenewal: "A successful issuance can create an active renewal profile; future renewal follows workspace policy.",
    warnings: workspace.certops_paused ? ["CertOps is paused; submission is unavailable until it resumes."] : [],
  };
}

function planHash(operator, intentHash, effect) {
  const { warnings: _warnings, ...boundEffect } = effect;
  return hash({ operation: "issue", workspaceId: operator.workspaceId, connectionId: operator.connectionId, intentHash, effect: boundEffect });
}

async function previewIssuance({ client, operator, issuance, now = new Date() }) {
  const workspace = await authorizeIssuance(client, operator);
  const normalized = normalizeIssuance(issuance);
  const effect = await effectFor(client, operator, normalized, workspace);
  const intentHash = hash(normalized), digest = planHash(operator, intentHash, effect);
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`operator-issuance-preview:${operator.connectionId}`]);
  const count = await client.query("SELECT COUNT(*)::int AS n FROM operator_action_plans p WHERE p.connection_id=$1 AND p.operation='issue' AND p.expires_at>NOW() AND NOT EXISTS(SELECT 1 FROM operator_action_requests r WHERE r.plan_id=p.id)", [operator.connectionId]);
  if (count.rows[0].n >= 10) throw fail("OPERATOR_PENDING_LIMIT", "Too many previews are open");
  const expiresAt = new Date(now.getTime() + PLAN_TTL_MS);
  const result = await client.query(
    `INSERT INTO operator_action_plans(workspace_id,connection_id,operation,identity_id,subject_id,bound_intent_hash,plan_hash,effect,created_at,expires_at)
     VALUES($1,$2,'issue',NULL,NULL,$3,$4,$5::jsonb,$6,$7) RETURNING id`,
    [operator.workspaceId, operator.connectionId, intentHash, digest, JSON.stringify(effect), now, expiresAt],
  );
  return { planId: result.rows[0].id, planHash: digest, expiresAt: expiresAt.toISOString(), effect };
}

async function requestIssuance({ client, operator, issuance, planId, planHash: suppliedHash, requestId, now = new Date() }) {
  const workspace = await authorizeIssuance(client, operator);
  if (!UUID.test(String(planId || "")) || !UUID.test(String(requestId || "")) || !HASH.test(String(suppliedHash || ""))) throw fail("OPERATOR_PLAN_MISMATCH", "The preview does not match");
  const normalized = normalizeIssuance(issuance);
  const intentHash = hash(normalized);
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`operator-request:${operator.connectionId}:${requestId}`]);
  const previous = (await client.query("SELECT * FROM operator_action_requests WHERE connection_id=$1 AND request_id=$2", [operator.connectionId, requestId])).rows[0];
  if (previous) {
    if (previous.operation !== "issue" || previous.plan_id !== planId || previous.plan_hash !== suppliedHash) throw fail("OPERATOR_IDEMPOTENCY_CONFLICT", "Request id was already used");
    const boundPlan = (await client.query(
      "SELECT bound_intent_hash FROM operator_action_plans WHERE id=$1 AND workspace_id=$2 AND connection_id=$3",
      [previous.plan_id, operator.workspaceId, operator.connectionId],
    )).rows[0];
    if (boundPlan?.bound_intent_hash !== intentHash) throw fail("OPERATOR_IDEMPOTENCY_CONFLICT", "Request id was already used with different issuance details");
    const job = (await client.query("SELECT id,status,error_code,approved_at FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [operator.workspaceId, previous.job_id])).rows[0];
    return requestView(previous, job, { replayed: true });
  }
  const plan = (await client.query("SELECT * FROM operator_action_plans WHERE id=$1 AND workspace_id=$2 AND connection_id=$3 FOR UPDATE", [planId, operator.workspaceId, operator.connectionId])).rows[0];
  if (!plan || plan.operation !== "issue" || plan.plan_hash !== suppliedHash) throw fail("OPERATOR_PLAN_MISMATCH", "The preview does not match");
  if (new Date(plan.expires_at) <= now) throw fail("OPERATOR_PLAN_EXPIRED", "The preview has expired");
  if ((await client.query("SELECT 1 FROM operator_action_requests WHERE plan_id=$1", [planId])).rowCount) throw fail("OPERATOR_PLAN_USED", "The preview was already submitted");
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`operator-pending:${operator.workspaceId}`]);
  await endLapsedWindows(client, operator.workspaceId);
  if (workspace.certops_require_approval_always) {
    const count = (await client.query(`SELECT COUNT(*)::int AS total,COUNT(*) FILTER (WHERE requested_by_connection_id=$2)::int AS mine FROM certificate_jobs
      WHERE workspace_id=$1 AND status='pending_approval' AND requested_by_connection_id IS NOT NULL`, [operator.workspaceId, operator.connectionId])).rows[0];
    if (count.mine >= 10 || count.total >= assistantPendingLimit(resolveRenewalPerCaCap())) throw fail("OPERATOR_PENDING_LIMIT", "Too many assistant requests await approval");
  }
  await lockWorkspaceForCertOpsSideEffect({ client, workspaceId: operator.workspaceId });
  const effect = await effectFor(client, operator, normalized, workspace);
  if (intentHash !== plan.bound_intent_hash || planHash(operator, intentHash, effect) !== suppliedHash) throw fail("OPERATOR_INTENT_STALE", "Issuance details changed; preview again");
  const recordId = crypto.randomUUID();
  const outcome = await createCertificateIssuanceJob({ client, workspaceId: operator.workspaceId, workspacePlan: workspace.plan, assignedAgentId: normalized.agentId,
    payload: normalized.payload, source: "api", requestedByUserId: operator.userId, requestedByConnectionId: operator.connectionId,
    requiresApproval: false, idempotencyKey: `mcp-issue:${recordId}`, returnOutcome: true });
  const job = outcome.job || outcome;
  await writeAudit({ client, actorUserId: operator.userId, subjectUserId: operator.userId, action: "CERTOPS_JOB_CREATED_MANUAL",
    targetType: "certificate_job", targetId: job.id, workspaceId: operator.workspaceId,
    metadata: { jobId: job.id, operation: "issue", subjectType: job.subjectType, subjectId: job.subjectId, source: "api", via: "operator_connection" } });
  const expires = new Date(now.getTime() + APPROVAL_TTL_MS);
  const inserted = await client.query(`INSERT INTO operator_action_requests
    (id,workspace_id,connection_id,user_id,request_id,plan_id,plan_hash,operation,identity_id,subject_id,job_id,approval_expires_at,created_at,updated_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,'issue',NULL,$8,$9,$10,$11,$11) RETURNING *`,
    [recordId, operator.workspaceId, operator.connectionId, operator.userId, requestId, planId, suppliedHash, job.subjectId, job.id, expires, now]);
  return requestView(inserted.rows[0], job);
}

module.exports = { previewIssuance, requestIssuance, effectFor };
