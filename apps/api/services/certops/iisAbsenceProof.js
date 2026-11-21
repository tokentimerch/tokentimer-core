"use strict";

const { isIP } = require("node:net");
const { pool } = require("../../db/database");
const { assertCurrentAgentCredential } = require("./agentCredentialFence");
const { enforceAgentSequence } = require("./agentDispatch");
const { hasFreshCapability } = require("./agentJobEligibility");
const { WINDOWS_IIS_SITE_PATTERN } = require("./renewalProfile");

const MAX_AGE_MS = 120000;
const FAIL = message => Object.assign(new Error(message), { code: "CERTOPS_AGENT_OBSERVATION_INVALID" });
function isConcreteAddress(value) {
  if (typeof value !== "string" || value.includes("%")) return false;
  const family = isIP(value);
  if (family === 4) return value !== "0.0.0.0";
  if (family !== 6) return false;
  const canonical = new URL(`http://[${value}]/`).hostname.slice(1,-1);
  return canonical !== "::" && !canonical.startsWith("::ffff:");
}

function normalizeIisAbsenceProof(item, now = Date.now()) {
  if (!item || typeof item !== "object" || Array.isArray(item)) throw FAIL("IIS proof is invalid");
  const keys = ["evidenceId", "targetHost", "site", "port", "address", "fingerprintSha256", "thumbprint", "observedAt"];
  if (Object.keys(item).length !== keys.length || keys.some(key => !Object.hasOwn(item, key))) throw FAIL("IIS proof fields are invalid");
  if (typeof item.evidenceId !== "string" || !/^[A-Za-z0-9_.:-]{1,128}$/.test(item.evidenceId) ||
      typeof item.targetHost !== "string" || !/^[A-Za-z0-9_.-]{1,255}$/.test(item.targetHost) ||
      typeof item.site !== "string" || !WINDOWS_IIS_SITE_PATTERN.test(item.site) || item.site.length > 128 ||
      !Number.isInteger(item.port) || item.port < 1 || item.port > 65535 ||
      !isConcreteAddress(item.address) ||
      typeof item.fingerprintSha256 !== "string" || !/^[a-f0-9]{64}$/.test(item.fingerprintSha256) ||
      typeof item.thumbprint !== "string" || !/^[a-f0-9]{40}$/.test(item.thumbprint)) throw FAIL("IIS proof target is invalid");
  const at = typeof item.observedAt === "string" ? Date.parse(item.observedAt) : NaN;
  if (!Number.isFinite(at) || at > now || at < now - MAX_AGE_MS) throw FAIL("IIS proof time is invalid or expired");
  return { ...item, observedAt: new Date(at).toISOString() };
}

async function persistIisAbsenceProofBatch({ dbPool = pool, agent, envelope, proofs, deps = {} }) {
  if (!agent?.id || !agent.workspaceId || !agent.agentId || !Number.isSafeInteger(envelope?.sequence) || envelope.sequence < 1 ||
      !Array.isArray(proofs) || proofs.length < 1 || proofs.length > 16) throw FAIL("IIS proof batch is invalid");
  const normalized = proofs.map(item => normalizeIisAbsenceProof(item));
  if (new Set(normalized.map(item => item.evidenceId)).size !== normalized.length) throw FAIL("Duplicate IIS proof identifiers");
  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    await (deps.assertCurrentAgentCredential || assertCurrentAgentCredential)({ client, agent });
    await (deps.enforceAgentSequence || enforceAgentSequence)({ client, agentRowId:agent.id, envelope });
    const row = (await client.query(`SELECT status,platform,declared_capabilities,capabilities_updated_at FROM certops_agents WHERE workspace_id=$1 AND id=$2 FOR UPDATE`, [agent.workspaceId, agent.id])).rows[0];
    if (!row || row.status !== "active" || row.platform !== "win32" || !hasFreshCapability({ declaredCapabilities:row.declared_capabilities, capabilitiesUpdatedAt:row.capabilities_updated_at, capability:"iis-explicit-ip-v1" })) throw FAIL("Agent is not qualified for IIS proof");
    // Bound storage per credential without discarding still-fresh identifiers:
    // deleting those early would allow a retry to masquerade as a new scan.
    await client.query(`DELETE FROM certops_iis_absence_proofs WHERE ctid IN (SELECT ctid FROM certops_iis_absence_proofs
      WHERE workspace_id=$1 AND agent_id=$2 AND received_at < clock_timestamp()-interval '5 minutes' LIMIT 100)`, [agent.workspaceId,agent.id]);
    const count = (await client.query(`SELECT count(*)::int AS count FROM certops_iis_absence_proofs WHERE workspace_id=$1 AND agent_id=$2`, [agent.workspaceId,agent.id])).rows[0]?.count;
    if (!Number.isInteger(count) || count + normalized.length > 512) throw FAIL("IIS proof storage limit reached");
    let inserted = 0;
    for (const item of normalized) {
      const result = await client.query(`INSERT INTO certops_iis_absence_proofs
        (workspace_id,agent_id,evidence_id,target_host,site,port,address,fingerprint_sha256,thumbprint,observed_at,agent_sequence)
        VALUES ($1,$2,$3,$4,$5,$6,$7::inet,$8,$9,$10::timestamptz,$11)
        ON CONFLICT (workspace_id,agent_id,evidence_id) DO NOTHING`,
      [agent.workspaceId,agent.id,item.evidenceId,item.targetHost,item.site,item.port,item.address,item.fingerprintSha256,item.thumbprint,item.observedAt,envelope.sequence]);
      inserted += result.rowCount;
    }
    await client.query("COMMIT");
    return { ok:true, proofCount:inserted, duplicateCount:normalized.length-inserted };
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch (_) { /* preserve failure */ }
    throw error;
  } finally { client.release(); }
}

async function purgeExpiredIisAbsenceProofs({ client, batchSize = 1000 }) {
  if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > 10000) throw new Error("Invalid IIS proof purge batch size");
  const result = await client.query(`DELETE FROM certops_iis_absence_proofs WHERE ctid IN
    (SELECT ctid FROM certops_iis_absence_proofs WHERE received_at < clock_timestamp()-interval '5 minutes'
     ORDER BY received_at LIMIT $1 FOR UPDATE SKIP LOCKED)`, [batchSize]);
  return { deleted:result.rowCount };
}

module.exports = { MAX_AGE_MS, normalizeIisAbsenceProof, persistIisAbsenceProofBatch, purgeExpiredIisAbsenceProofs };
