"use strict";

// A prepared candidate is never an ordinary credential until its holder
// proves possession by authenticating the confirmation request. This service
// does not protect a secret from another process with the same OS authority.
const crypto = require("node:crypto");
const { pool } = require("../../db/database");
const { lockCurrentAgentCredential } = require("./agentCredentialFence");
const { parseRawAgentCredential } = require("./agentCredentials");
const { writeAudit } = require("../audit");
const OPERATION_ID = /^[a-f0-9]{32}$/;
const PREFIX = /^ttagent_[a-f0-9]{16}$/;
const HASH = /^[a-f0-9]{64}$/;

function failure(code = "CERTOPS_AGENT_ROTATION_UNAUTHORIZED") {
  const e = new Error("Agent credential rotation unavailable"); e.code = code; return e;
}
function isCredentialRotationEnabled(env = process.env) {
  // This is an operator attestation, not an automatic discovery of old API
  // instances. Enable only after every API instance enforces credential and
  // job-claim fences and is running this protocol version.
  return env.CERTOPS_AGENT_ROTATION_ALL_API_FENCED === "true";
}
async function transaction(dbPool, fn) {
  const client = await dbPool.connect();
  try { await client.query("BEGIN"); const out = await fn(client); await client.query("COMMIT"); return out; }
  catch (err) {
    try { await client.query("ROLLBACK"); } catch (_) {}
    // Never expose the conflicting prefix, digest or database error details.
    if (err?.code === "23505") throw failure("CERTOPS_AGENT_ROTATION_CONFLICT");
    throw err;
  }
  finally { client.release(); }
}
function checkOperation(operationId) {
  if (typeof operationId !== "string" || !OPERATION_ID.test(operationId)) throw failure("CERTOPS_AGENT_ROTATION_INVALID");
}
function isCredentialRotationAckEnabled(env = process.env) {
  return isCredentialRotationEnabled(env) && env.CERTOPS_AGENT_ROTATION_ACK_ENABLED === "true";
}
// Called under the agent row lock. This is a database coordination fence,
// not evidence that an external effect has stopped.
async function requireNoAgentJobs(client, agentId) {
  const result = await client.query(`SELECT 1 FROM certificate_jobs
    WHERE (claimed_by_agent_id = $1 AND status IN ('claimed', 'running'))
       OR (workspace_id = (SELECT workspace_id FROM certops_agents WHERE id = $1)
           AND (status = 'orphaned_unknown_effect' OR needs_operator_reconciliation))
    LIMIT 1`, [agentId]);
  if (result.rows.length) throw failure("CERTOPS_AGENT_ROTATION_CONFLICT");
}
function sameHash(a, b) {
  return typeof a === "string" && typeof b === "string" && HASH.test(a) && HASH.test(b) &&
    crypto.timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
async function prepareCredentialRotation({ dbPool = pool, agent, operationId, candidatePrefix, candidateHash, env = process.env }) {
  if (!isCredentialRotationEnabled(env)) throw failure("CERTOPS_AGENT_ROTATION_DISABLED");
  checkOperation(operationId);
  if (typeof candidatePrefix !== "string" || !PREFIX.test(candidatePrefix) || typeof candidateHash !== "string" || !HASH.test(candidateHash)) throw failure("CERTOPS_AGENT_ROTATION_INVALID");
  return await transaction(dbPool, async client => {
    await lockCurrentAgentCredential(client, agent);
    const current = (await client.query("SELECT credential_prefix, credential_hash FROM certops_agents WHERE id = $1", [agent.id])).rows[0];
    const previous = (await client.query("SELECT *, expires_at > NOW() AS unexpired FROM certops_agent_credential_rotations WHERE agent_id = $1 FOR UPDATE", [agent.id])).rows[0];
    if (previous && previous.operation_id === operationId) {
      if (previous.candidate_prefix !== candidatePrefix || !sameHash(previous.candidate_hash, candidateHash)) throw failure("CERTOPS_AGENT_ROTATION_CONFLICT");
      if (previous.state === "pending" && !previous.unexpired) throw failure("CERTOPS_AGENT_ROTATION_CONFLICT");
      return { state: previous.state === "acknowledged" ? "committed" : previous.state };
    }
    // A committed receipt must survive a lost response. A future protocol
    // needs an explicit durable acknowledgement before replacing it.
    if (previous && (previous.state === "committed" || previous.state === "pending" && previous.unexpired)) throw failure("CERTOPS_AGENT_ROTATION_CONFLICT");
    await requireNoAgentJobs(client, agent.id);
    if (current.credential_prefix === candidatePrefix || sameHash(current.credential_hash, candidateHash)) throw failure("CERTOPS_AGENT_ROTATION_INVALID");
    await client.query(`INSERT INTO certops_agent_credential_rotations
      (agent_id, operation_id, prior_hash, candidate_prefix, candidate_hash, state, expires_at)
      VALUES ($1, $2, $3, $4, $5, 'pending', NOW() + interval '15 minutes')
      ON CONFLICT (agent_id) DO UPDATE SET operation_id = EXCLUDED.operation_id, prior_hash = EXCLUDED.prior_hash,
        candidate_prefix = EXCLUDED.candidate_prefix, candidate_hash = EXCLUDED.candidate_hash,
        state = EXCLUDED.state, expires_at = EXCLUDED.expires_at, updated_at = NOW()`,
    [agent.id, operationId, current.credential_hash, candidatePrefix, candidateHash]);
    return { state: "pending" };
  });
}
async function authenticateRotationCandidate({ dbPool = pool, operationId, rawCandidate, env = process.env }) {
  if (!isCredentialRotationEnabled(env)) throw failure("CERTOPS_AGENT_ROTATION_DISABLED");
  if (typeof operationId !== "string" || !OPERATION_ID.test(operationId)) throw failure();
  const parsed = parseRawAgentCredential(rawCandidate);
  if (!parsed) throw failure();
  const candidateHash = crypto.createHash("sha256").update(parsed.rawCredential).digest("hex");
  const row = (await dbPool.query(`SELECT r.operation_id, r.state, r.expires_at > NOW() AS unexpired,
    r.candidate_prefix, r.candidate_hash, r.prior_hash, a.id, a.workspace_id, a.agent_id,
    a.status, a.credential_hash, a.credential_prefix FROM certops_agent_credential_rotations r
    JOIN certops_agents a ON a.id = r.agent_id WHERE r.operation_id = $1`, [operationId])).rows[0];
  if (!row || !["active", "offline"].includes(row.status) || row.candidate_prefix !== parsed.credentialPrefix ||
      !sameHash(row.candidate_hash, candidateHash) ||
      !(row.state === "pending" && row.unexpired && sameHash(row.prior_hash, row.credential_hash) ||
        ["committed", "acknowledged"].includes(row.state) && row.credential_prefix === parsed.credentialPrefix && sameHash(row.credential_hash, candidateHash))) throw failure();
  return { id: row.id, workspaceId: row.workspace_id, agentId: row.agent_id, status: row.status };
}
async function confirmCredentialRotation({ dbPool = pool, operationId, rawCandidate, env = process.env, audit = writeAudit }) {
  if (!isCredentialRotationEnabled(env)) throw failure("CERTOPS_AGENT_ROTATION_DISABLED");
  checkOperation(operationId);
  const parsed = parseRawAgentCredential(rawCandidate);
  if (!parsed) throw failure();
  const candidateHash = crypto.createHash("sha256").update(parsed.rawCredential).digest("hex");
  return await transaction(dbPool, async client => {
    // Lookup is untrusted until both records are re-read under agent->rotation
    // lock order. Operation IDs are random and requests have pre-auth limits.
    const lookup = (await client.query("SELECT agent_id FROM certops_agent_credential_rotations WHERE operation_id = $1", [operationId])).rows[0];
    if (!lookup) throw failure();
    const current = (await client.query("SELECT id, workspace_id, agent_id, status, credential_prefix, credential_hash FROM certops_agents WHERE id = $1 FOR UPDATE", [lookup.agent_id])).rows[0];
    const pending = (await client.query("SELECT *, expires_at > NOW() AS unexpired FROM certops_agent_credential_rotations WHERE agent_id = $1 FOR UPDATE", [lookup.agent_id])).rows[0];
    if (!current || !["active", "offline"].includes(current.status) || !pending || pending.operation_id !== operationId || pending.candidate_prefix !== parsed.credentialPrefix || !sameHash(pending.candidate_hash, candidateHash)) throw failure();
    if (["committed", "acknowledged"].includes(pending.state)) {
      if (current.credential_prefix !== parsed.credentialPrefix || !sameHash(current.credential_hash, candidateHash)) throw failure();
      return { state: "committed" };
    }
    if (pending.state !== "pending" || !pending.unexpired || !sameHash(current.credential_hash, pending.prior_hash)) throw failure();
    await requireNoAgentJobs(client, current.id);
    await client.query("UPDATE certops_agents SET credential_prefix = $2, credential_hash = $3, updated_at = NOW() WHERE id = $1", [current.id, parsed.credentialPrefix, candidateHash]);
    await client.query("DELETE FROM certops_agent_registration_replays WHERE workspace_id = $1 AND agent_id = $2", [current.workspace_id, current.agent_id]);
    await client.query("UPDATE certops_agent_credential_rotations SET state = 'committed', updated_at = NOW() WHERE agent_id = $1", [current.id]);
    await audit({ client, action: "CERTOPS_AGENT_CREDENTIAL_ROTATED", workspaceId: current.workspace_id, targetType: "certops_agent", metadata: { agentId: current.agent_id } });
    return { state: "committed" };
  });
}
// The server cannot prove client disk durability. The caller must persist
// the new credential before ACK and serialize rotations across all local
// agents. This endpoint remains separately disabled until that client exists.
async function acknowledgeCredentialRotation({ dbPool = pool, agent, operationId, env = process.env, audit = writeAudit }) {
  if (!isCredentialRotationAckEnabled(env)) throw failure("CERTOPS_AGENT_ROTATION_DISABLED");
  checkOperation(operationId);
  return await transaction(dbPool, async client => {
    await lockCurrentAgentCredential(client, agent);
    const current = (await client.query("SELECT credential_prefix, credential_hash FROM certops_agents WHERE id = $1", [agent.id])).rows[0];
    const receipt = (await client.query("SELECT * FROM certops_agent_credential_rotations WHERE agent_id = $1 FOR UPDATE", [agent.id])).rows[0];
    if (!receipt || receipt.operation_id !== operationId || !["committed", "acknowledged"].includes(receipt.state) ||
        receipt.candidate_prefix !== current.credential_prefix || !sameHash(receipt.candidate_hash, current.credential_hash)) throw failure();
    if (receipt.state === "committed") {
      // Unknown workspace effects or active agent jobs can appear after
      // promotion. Do not reopen claims on the first ACK while they remain.
      // This read is not a workspace-wide quiescence proof.
      await requireNoAgentJobs(client, agent.id);
      await client.query("UPDATE certops_agent_credential_rotations SET state = 'acknowledged', updated_at = NOW() WHERE agent_id = $1", [agent.id]);
      await audit({ client, action: "CERTOPS_AGENT_CREDENTIAL_ROTATION_ACKNOWLEDGED", workspaceId: agent.workspaceId, targetType: "certops_agent", metadata: { agentId: agent.agentId } });
    }
    return { state: "acknowledged" };
  });
}
module.exports = { prepareCredentialRotation, authenticateRotationCandidate, confirmCredentialRotation, acknowledgeCredentialRotation, isCredentialRotationEnabled, isCredentialRotationAckEnabled };
