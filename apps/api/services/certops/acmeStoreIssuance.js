"use strict";

// Transaction-owned admission used by the job route and renewal scheduler.
// Native execution and result reconciliation require separate qualification.
const crypto = require("node:crypto");
const { createCertificateJob } = require("./jobs");
const { hasFreshCapability } = require("./agentJobEligibility");
const { freezeAcmeStoreRequest } = require("./acmeStoreContract");
const { createAcmeStoreEnrollmentTx } = require("./acmeStorePersistence");
const { buildRenewalJobPayload, validateRenewalManualOverrides } = require("./renewalProfile");
const { assertNoPrivateKeyMaterial } = require("../../utils/secretMaterial");

function invalid(message) { const error = new Error(message); error.code = "CERTOPS_ACME_STORE_INVALID"; throw error; }
function transaction(options) {
  if (!options.client || options.transactionOwned !== true || (typeof options.client.connect === "function" && typeof options.client.idleCount === "number")) invalid("ACME store creation requires an existing transaction");
  if (options.mode && options.mode !== "real") invalid("ACME store supports real execution only");
  if (typeof options.idempotencyKey !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(options.idempotencyKey)) invalid("ACME store requires an idempotency key");
}
const keyName = (algorithm, size) => algorithm === "rsa" ? `rsa-${size}` : algorithm === "ecdsa" ? `ec-p${size}` : "";
function frozenRequest({ workspaceId, certificateId, agentId, agentPublicId, jobId, payload, issuanceMode, predecessorFingerprintSha256 }) {
  return freezeAcmeStoreRequest({ workspaceId, certificateId, agentId, agentPublicId, jobId, target: payload.target,
    dnsNames: payload.sans, caEndpoint: payload.caEndpoint, commandRef: payload.commandRef,
    dnsProvider: payload.dnsProvider, dnsZone: payload.dnsZone, keyAlgorithm: keyName(payload.keyAlgorithm, payload.keySize),
    acmeKind: payload.acmeKind || "certbot", preferredChain: payload.preferredChain || null,
    eabAccountRef: payload.eabRef || payload.accountRef || null, issuanceMode, predecessorFingerprintSha256 });
}
async function owner(client, workspaceId, agentId, env, { fresh = true } = {}) {
  const row = (await client.query(`SELECT agent_id,status,platform,declared_capabilities,capabilities_updated_at
    FROM certops_agents WHERE workspace_id=$1 AND id=$2::uuid FOR SHARE`, [workspaceId, agentId])).rows[0];
  if (!row || (fresh && (row.status !== "active" || row.platform !== "win32" ||
    ["windows-store-only-acme-v1", "evidence-claim-binding-v1"].some(capability => !hasFreshCapability({
      declaredCapabilities: row.declared_capabilities, capabilitiesUpdatedAt: row.capabilities_updated_at, capability, env }))))) {
    invalid("selected agent requires fresh ACME store and claim-bound evidence capabilities");
  }
  return row.agent_id;
}
function callbackFor(requestBase) {
  return async ({ client, job }) => createAcmeStoreEnrollmentTx({ client, enrollmentId: crypto.randomUUID(),
    request: { ...requestBase, jobId: job.id } });
}

async function createAcmeStoreIssueTx(options = {}) {
  transaction(options);
  const { client, workspaceId, assignedAgentId, idempotencyKey } = options;
  const body = options.payload;
  if (options.subjectId != null || options.subjectType != null || !assignedAgentId || !body || typeof body !== "object" || Array.isArray(body)) invalid("first issue requires an explicit agent and no existing subject");
  assertNoPrivateKeyMaterial(body);
  const allowed = ["target", "sans", "caEndpoint", "commandRef", "dnsProvider", "dnsZone", "keyAlgorithm", "keySize", "acmeKind", "preferredChain", "eabRef", "accountRef"];
  if (Object.keys(body).some(key => !allowed.includes(key))) invalid("unsupported first-issue field");
  const target = body.target && { ...body.target, reference: typeof body.target.reference === "string" ? body.target.reference.trim().toLowerCase() : body.target.reference };
  const sans = Array.isArray(body.sans) ? body.sans.map(name => typeof name === "string" ? name.trim().toLowerCase() : name) : [target?.reference];
  const payload = { ...body, target, sans, keyAlgorithm: body.keyAlgorithm === undefined ? "rsa" : body.keyAlgorithm,
    keySize: body.keySize === undefined ? 2048 : body.keySize, keyMode: "os-store-managed" };
  const digest = crypto.createHash("sha256").update(`certops-issuance-identity:${workspaceId}:${idempotencyKey}`).digest().readBigInt64BE(0).toString();
  await client.query("SELECT pg_advisory_xact_lock($1)", [digest]);
  const existing = (await client.query("SELECT id FROM managed_certificates WHERE workspace_id=$1 AND source='agent_issuance' AND source_ref=$2 LIMIT 1", [workspaceId, idempotencyKey])).rows[0];
  const agentPublicId = await owner(client, workspaceId, assignedAgentId, options.env, { fresh: !existing });
  const certificateId = existing?.id || crypto.randomUUID();
  frozenRequest({ workspaceId, certificateId, agentId: assignedAgentId, agentPublicId, jobId: crypto.randomUUID(), payload,
    issuanceMode: "issue", predecessorFingerprintSha256: null });
  if (!existing) {
    await client.query(`INSERT INTO managed_certificates(id,workspace_id,status,source,source_ref,name,common_name,subject_alt_names,key_mode,key_reference,public_metadata,deployed_agent_id)
      VALUES($1,$2,'provisioning','agent_issuance',$3,$4,$4,$5,'os-store-managed',$6,$7::jsonb,$8)`,
    [certificateId, workspaceId, idempotencyKey, target.reference, sans, `winstore://My/${target.reference}`,
      JSON.stringify({ issuance: { target, requestedAt: new Date().toISOString() } }), assignedAgentId]);
  }
  return createCertificateJob({ ...options, client, operation: "issue", subjectType: "managed_certificate", subjectId: certificateId,
    assignedAgentId, payload, transactionOwned: true, returnOutcome: true,
    createAcmeStoreBinding: callbackFor({ workspaceId, certificateId, agentId: assignedAgentId, agentPublicId,
      target, dnsNames: sans, caEndpoint: payload.caEndpoint, commandRef: payload.commandRef, dnsProvider: payload.dnsProvider,
      dnsZone: payload.dnsZone, keyAlgorithm: keyName(payload.keyAlgorithm, payload.keySize), acmeKind: payload.acmeKind || "certbot",
      preferredChain: payload.preferredChain || null, eabAccountRef: payload.eabRef || payload.accountRef || null, issuanceMode: "issue", predecessorFingerprintSha256: null }) });
}

async function createAcmeStoreRenewalTx(options = {}) {
  transaction(options);
  const { client, workspaceId, subjectId: certificateId, assignedAgentId, idempotencyKey } = options;
  if (!certificateId || !assignedAgentId) invalid("renewal requires the certificate and original agent");
  validateRenewalManualOverrides(options.payload || {});
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))", [`certops-acme-store:${workspaceId}:${certificateId}`]);
  const row = (await client.query(`SELECT mc.*,cp.name AS profile_name,cp.key_mode AS profile_key_mode,cp.issuer_id AS profile_issuer_id,
      cp.public_metadata AS profile_public_metadata,ci.lifecycle_status AS identity_lifecycle_status
    FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id
    LEFT JOIN certops_certificate_identities ci ON ci.workspace_id=mc.workspace_id AND ci.fingerprint_sha256=certops_normalize_fingerprint(mc.fingerprint_sha256)
    WHERE mc.workspace_id=$1 AND mc.id=$2::uuid FOR UPDATE OF mc`, [workspaceId, certificateId])).rows[0];
  if (!row || row.status !== "active" || row.profile_issuer_id || row.key_mode !== "os-store-managed" ||
      String(row.deployed_agent_id) !== String(assignedAgentId) || ["revoked", "decommissioned"].includes(row.identity_lifecycle_status)) invalid("renewal requires an active certificate owned by the selected agent and an ACME profile");
  const predecessorFingerprintSha256 = String(row.fingerprint_sha256 || "").replace(/:/g, "").toLowerCase();
  const existing = (await client.query("SELECT id,operation,subject_type,subject_id,assigned_agent_id,payload FROM certificate_jobs WHERE workspace_id=$1 AND idempotency_key=$2", [workspaceId, idempotencyKey])).rows[0];
  if (existing && (existing.operation !== "renew" || existing.subject_type !== "managed_certificate" ||
      existing.subject_id !== String(certificateId) || String(existing.assigned_agent_id) !== String(assignedAgentId))) {
    const error = new Error("Idempotency key was used for a different job"); error.code = "CERTOPS_JOB_IDEMPOTENCY_CONFLICT"; throw error;
  }
  const payload = existing ? { ...existing.payload, reason: options.payload?.reason || "manual-renewal" }
    : buildRenewalJobPayload({ certificate: row, reason: options.payload?.reason || "manual-renewal" });
  if (payload.target?.type !== "windows-cert-store") invalid("unsupported ACME store profile");
  if (!existing) {
    const open = (await client.query(`SELECT id FROM certops_acme_store_enrollments WHERE workspace_id=$1 AND certificate_id=$2::uuid AND state<>'installed' LIMIT 1`, [workspaceId, certificateId])).rows[0];
    if (open) invalid("an ACME store enrollment is already open or uncertain");
  }
  const agentPublicId = await owner(client, workspaceId, assignedAgentId, options.env, { fresh: !existing });
  frozenRequest({ workspaceId, certificateId, agentId: assignedAgentId, agentPublicId, jobId: crypto.randomUUID(), payload, issuanceMode: "renew", predecessorFingerprintSha256 });
  return createCertificateJob({ ...options, client, operation: "renew", subjectType: "managed_certificate", subjectId: certificateId, assignedAgentId,
    payload, transactionOwned: true, returnOutcome: true, createAcmeStoreBinding: callbackFor({ workspaceId, certificateId,
      agentId: assignedAgentId, agentPublicId, target: payload.target, dnsNames: payload.sans, caEndpoint: payload.caEndpoint,
      commandRef: payload.commandRef, dnsProvider: payload.dnsProvider, dnsZone: payload.dnsZone,
      keyAlgorithm: keyName(payload.keyAlgorithm, payload.keySize), acmeKind: payload.acmeKind || "certbot",
      preferredChain: payload.preferredChain || null, eabAccountRef: payload.eabRef || payload.accountRef || null, issuanceMode: "renew", predecessorFingerprintSha256 }) });
}

module.exports = { createAcmeStoreIssueTx, createAcmeStoreRenewalTx };
