"use strict";

// Human-session review only. This projection is deliberately not an MCP tool:
// routing and local reference details belong to the independent reviewer.
const crypto = require("node:crypto");
const profileSchema = require("../../../../packages/contracts/certops/renewal-profile.schema.json");
const payloadSchema = require("../../../../packages/contracts/certops/job-payload.schema.json");
const { redactGenericSecrets, containsPrivateKeyMaterial } = require("../../utils/secretMaterial");
const { hashRenewalIntent } = require("./planEffects");

const STALE = "CERTOPS_APPROVAL_REQUEST_STALE";
const REVIEW_REQUIRED = "CERTOPS_APPROVAL_REVIEW_REQUIRED";
function stale() {
  const error = new Error("The assistant request changed or ended. Request a fresh preview.");
  error.code = STALE;
  return error;
}
function safeText(value) {
  const text = String(value);
  if (containsPrivateKeyMaterial(text)) return "[redacted]";
  return redactGenericSecrets(text)
    .replace(/\btt(?:opc|opg|agent|boot|x)_[a-f0-9]{16}_[a-f0-9]{64}\b/gi, "[redacted]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/gi, "Bearer [redacted]")
    .replace(/(https?:\/\/)[^/\s@]+@/gi, "$1[redacted]@");
}

// Walk only declared public contract fields; future internal payload fields
// cannot appear in the review. References are local JSON-schema references.
function publicFields(value, schema, root = schema) {
  if (schema.$ref) return publicFields(value, schema.$ref.slice(2).split("/").reduce((s, key) => s[key], root), root);
  if (value == null) return null;
  if (schema.properties) return Object.fromEntries(Object.entries(schema.properties)
    .filter(([key]) => Object.hasOwn(value, key))
    .map(([key, child]) => [key, publicFields(value[key], child, root)]));
  if (schema.items && Array.isArray(value)) return value.map(item => publicFields(item, schema.items, root));
  if (["string", "number", "boolean"].includes(typeof value)) return typeof value === "string" ? safeText(value) : value;
  return null;
}

async function buildAssistantApprovalReview({ db, job, intentHash, lockSources = false }) {
  if (!job.requestedByConnectionId) return null;
  const found = await db.query(
    `SELECT r.id, r.plan_id, r.plan_hash, r.approval_expires_at, r.state_override,
            p.expires_at AS preview_expires_at, p.bound_intent_hash, p.bound_profile_id,
            p.bound_fingerprint_sha256, c.id AS connection_id, c.name AS connection_name,
            c.expires_at AS connection_expires_at, c.status AS connection_status, c.scopes, c.role_ceiling,
            u.display_name AS requester_name, u.id AS requester_id
       FROM operator_action_requests r
       JOIN operator_action_plans p ON p.id = r.plan_id AND p.workspace_id = r.workspace_id
       JOIN operator_connections c ON c.id = r.connection_id AND c.workspace_id = r.workspace_id
       JOIN users u ON u.id = c.user_id
      WHERE r.job_id = $1 AND r.workspace_id = $2 AND c.id = $3`,
    [job.id, job.workspaceId, job.requestedByConnectionId],
  );
  const row = found.rows[0];
  if (!row || String(row.requester_id) !== String(job.requestedByUserId)) throw stale();
  const { preflightManualRenewalJob } = require("../certops/jobs");
  const source = await db.query(`SELECT fingerprint_sha256, profile_id FROM managed_certificates
    WHERE workspace_id = $1 AND id = $2${lockSources ? " FOR SHARE" : ""}`, [job.workspaceId, job.subjectId]);
  if (lockSources && source.rows[0]?.profile_id) await db.query(
    "SELECT id FROM certificate_profiles WHERE workspace_id = $1 AND id = $2 FOR SHARE", [job.workspaceId, source.rows[0].profile_id]);
  let live;
  try { live = await preflightManualRenewalJob({ client: db, workspaceId: job.workspaceId, certificateId: job.subjectId, payload: {} }); }
  catch { throw stale(); }
  // createCertificateJob adds the explicit execution mode after preflight.
  // Assistant renewals are always real; mode is separately constrained here.
  const snapshot = { ...job.payload };
  delete snapshot.mode;
  const matches = job.mode === "real" && source.rows[0]?.fingerprint_sha256?.toLowerCase() === row.bound_fingerprint_sha256 &&
    source.rows[0]?.profile_id === row.bound_profile_id &&
    hashRenewalIntent(live) === row.bound_intent_hash &&
    hashRenewalIntent(snapshot) === row.bound_intent_hash;
  // Preview expiry limits submission only. Accepted requests retain their own
  // independent approval deadline and must remain reviewable afterwards.
  const connections = require("./connections");
  const currentRole = await connections.resolveCurrentWorkspaceRole(db, { userId: row.requester_id, workspaceId: job.workspaceId });
  const authority = connections.computeAuthority({ connection: { scopes: row.scopes, roleCeiling: row.role_ceiling }, currentRole });
  const active = authority.scopes.includes("mcp:renew:request") && row.connection_status === "active" && !row.state_override &&
    new Date(row.connection_expires_at) > new Date() && new Date(row.approval_expires_at) > new Date();
  const binding = { intentHash, requestRecordId: row.id, planId: row.plan_id,
    planHash: row.plan_hash, connectionId: row.connection_id,
    approvalExpiresAt: row.approval_expires_at, connectionExpiresAt: row.connection_expires_at };
  return {
    origin: "assistant", reviewHash: crypto.createHash("sha256").update(JSON.stringify(binding)).digest("hex"),
    current: active && matches && job.status === "pending_approval",
    requester: { id: String(row.requester_id), name: safeText(row.requester_name || "Unnamed user") },
    connection: { id: row.connection_id, label: safeText(row.connection_name), expiresAt: row.connection_expires_at },
    requestRecordId: row.id, approvalExpiresAt: row.approval_expires_at, previewExpiresAt: row.preview_expires_at,
    effect: {
      operation: job.operation, certificateId: job.subjectId, fingerprintSha256: row.bound_fingerprint_sha256,
      certificateExpiry: job.payload.notAfter,
      renewalProfile: publicFields(job.payload.renewalProfile, profileSchema),
      publication: job.payload.publication ? publicFields(job.payload.publication, payloadSchema.properties.publication, payloadSchema) : null,
      standingRenewal: "Renews an existing managed certificate. Creates no new automatic-renewal authority; existing renewal management and current workspace policies continue.",
      verification: "Issuance or publication alone does not prove installation or live TLS. Check executor evidence and configured verification separately.",
    },
  };
}

module.exports = { buildAssistantApprovalReview, publicFields, safeText, REVIEW_REQUIRED, STALE };
