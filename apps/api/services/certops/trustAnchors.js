"use strict";

/**
 * Trust-anchor ownership-aware orchestration service. See
 * docs/adr/0012-certops-windows-execution-surface-and-trust-anchors.md.
 *
 * This is the ONLY module that may create a distribute-trust or revoke-trust
 * certificate_jobs row: every other write path must call createTrustJob
 * below rather than jobs.createCertificateJob directly, because a trust
 * job's job row and its certops_trust_anchor_installations ownership-
 * reference row must always advance together, in one transaction.
 *
 * TERMINOLOGY: the certops_trust_anchors.status column is CHECK (status IN
 * ('active', 'revoked')) and is deliberately not renamed. "revoke-trust"
 * means only the wire-level per-installation dispatch operation. The
 * anchor-level lifecycle action is called "retire" throughout this file's
 * public surface (function names, error messages, audit actions, routes)
 * even though it still writes status = 'revoked'.
 */

const { X509Certificate, createHash } = require("node:crypto");
const { pool } = require("../../db/database");
const { writeAudit } = require("../audit");
const { parsePublicCertificateMaterial } = require("./parser");
const {
  lockWorkspaceForCertOpsSideEffect,
} = require("./workspaceKillSwitch");
const {
  createCertificateJob,
  normalizePublicObject,
  normalizeWorkspaceId,
  normalizeRequiredId,
  isTrustAnchorOperation,
  serviceError: jobServiceError,
} = require("./jobs");
const {
  validateTrustResult,
} = require("../../../../packages/contracts/certops/validate-trust-result.cjs");
const { getAgentById } = require("./agentRegistry");

// --- Error codes ---
const CERTOPS_TRUST_ANCHOR_INVALID = "CERTOPS_TRUST_ANCHOR_INVALID";
const CERTOPS_TRUST_ANCHOR_NOT_FOUND = "CERTOPS_TRUST_ANCHOR_NOT_FOUND";
const CERTOPS_TRUST_ANCHOR_PEM_INVALID = "CERTOPS_TRUST_ANCHOR_PEM_INVALID";
const CERTOPS_TRUST_ANCHOR_NOT_ACTIVE = "CERTOPS_TRUST_ANCHOR_NOT_ACTIVE";
const CERTOPS_TRUST_JOB_IDEMPOTENCY_KEY_REQUIRED =
  "CERTOPS_TRUST_JOB_IDEMPOTENCY_KEY_REQUIRED";
const CERTOPS_TRUST_JOB_OPERATION_INVALID =
  "CERTOPS_TRUST_JOB_OPERATION_INVALID";
const CERTOPS_TRUST_INSTALLATION_NOT_FOUND =
  "CERTOPS_TRUST_INSTALLATION_NOT_FOUND";
const CERTOPS_TRUST_RESULT_INVALID = "CERTOPS_TRUST_RESULT_INVALID";
const CERTOPS_TRUST_RESULT_MISMATCH = "CERTOPS_TRUST_RESULT_MISMATCH";
const CERTOPS_TRUST_RESULT_STALE_GENERATION =
  "CERTOPS_TRUST_RESULT_STALE_GENERATION";
// dispatching distribute-trust/revoke-trust against an agentId that isn't a
// well-formed UUID, or one that is well-formed but not registered in this
// workspace, used to skip application-level validation entirely and fall
// through to lockOrCreateInstallation's INSERT: a malformed id raised a raw
// "invalid input syntax for type uuid" and an unregistered-but-well-formed
// id raised a raw FK violation on fk_certops_trust_anchor_installations_agent.
// Neither mapped to a CERTOPS_* code, so both surfaced as a bare 500.
// assertTargetAgentRegistered (below) distinguishes the two the same way
// this file already distinguishes CERTOPS_TRUST_ANCHOR_INVALID (malformed)
// from CERTOPS_TRUST_ANCHOR_NOT_FOUND (well-formed but absent) for anchors.
const CERTOPS_TARGET_AGENT_INVALID = "CERTOPS_TARGET_AGENT_INVALID";
const CERTOPS_TARGET_AGENT_NOT_FOUND = "CERTOPS_TARGET_AGENT_NOT_FOUND";
const ANCHOR_TYPES = Object.freeze(["root", "intermediate"]);
const ANCHOR_TYPE_SET = new Set(ANCHOR_TYPES);
const ANCHOR_STATUSES = Object.freeze(["active", "revoked"]);
const ANCHOR_SOURCES = Object.freeze(["api", "system"]);

const STORE_PATTERN = /^[A-Za-z0-9 _.-]{1,64}$/;
const OWNER_MAX_LENGTH = 128;
const NAME_MAX_LENGTH = 255;
// certops_agents.id is UUID PRIMARY KEY (gen_random_uuid()); this mirrors
// the shape jobs.js's SUBJECT_ID_UUID_PATTERN already uses for the same
// "is this even shaped like a UUID before we ask Postgres" purpose.
const AGENT_ID_UUID_PATTERN =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

// Delay before a freshly pending row's first reconciliation pass. A pending
// transition an agent never reports back on must surface as alertable, not
// retry forever; certops-worker.js acts on next_reconcile_at once due.
const DEFAULT_RECONCILE_DELAY_MS = 15 * 60 * 1000;

function trustAnchorError(message, code) {
  return jobServiceError(message, code);
}

function dateToIso(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

async function withTransaction(dbPool, fn) {
  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_rollbackError) {
      // The original error is more useful to the caller.
    }
    throw error;
  } finally {
    client.release();
  }
}

// --- Normalization helpers ---

function normalizeName(value) {
  const name = typeof value === "string" ? value.trim() : "";
  if (!name || name.length > NAME_MAX_LENGTH) {
    throw trustAnchorError(
      "Trust anchor name is required and must be 1-255 characters",
      CERTOPS_TRUST_ANCHOR_INVALID,
    );
  }
  return name;
}

function normalizeAnchorType(value) {
  if (!ANCHOR_TYPE_SET.has(value)) {
    throw trustAnchorError(
      `anchorType must be one of: ${ANCHOR_TYPES.join(", ")}`,
      CERTOPS_TRUST_ANCHOR_INVALID,
    );
  }
  return value;
}

function normalizeAnchorSource(value) {
  if (value === undefined || value === null) return "api";
  if (!ANCHOR_SOURCES.includes(value)) {
    throw trustAnchorError(
      `source must be one of: ${ANCHOR_SOURCES.join(", ")}`,
      CERTOPS_TRUST_ANCHOR_INVALID,
    );
  }
  return value;
}

function normalizeStore(value) {
  if (typeof value !== "string" || !STORE_PATTERN.test(value)) {
    throw trustAnchorError(
      "store must be 1-64 characters matching [A-Za-z0-9 _.-]",
      CERTOPS_TRUST_ANCHOR_INVALID,
    );
  }
  return value;
}

/**
 * The store bookkeeping/wire label for a trust job, derived purely from
 * anchor_type - never accepted from a caller. Mirrors the agent's own
 * resolveWireStore (packages/agent/src/trust-store/index.js): both sides
 * compute the identical "Root"/"CA" label from the same signed anchorType,
 * so a correct result can never be rejected as a store mismatch, and a
 * caller can never name an arbitrary store (ADR-0012 decision 4 - a
 * payload-supplied store name would be a second, disagreeable source of
 * truth). Deliberately platform-neutral: which real OS mechanism an anchor
 * type maps to is the executor's concern, not the control plane's.
 */
const TRUST_ANCHOR_STORE_LABEL_BY_TYPE = Object.freeze({
  root: "Root",
  intermediate: "CA",
});

function resolveTrustAnchorStoreLabel(anchorType) {
  const label = TRUST_ANCHOR_STORE_LABEL_BY_TYPE[anchorType];
  if (!label) {
    throw trustAnchorError(
      `Cannot resolve a store label for anchorType ${JSON.stringify(anchorType)}`,
      CERTOPS_TRUST_ANCHOR_INVALID,
    );
  }
  return label;
}

function normalizeOwner(value) {
  const owner = typeof value === "string" ? value.trim() : "";
  if (!owner || owner.length > OWNER_MAX_LENGTH) {
    throw trustAnchorError(
      "owner is required and must be 1-128 characters",
      CERTOPS_TRUST_ANCHOR_INVALID,
    );
  }
  return owner;
}

function normalizeAgentId(value) {
  const agentId = typeof value === "string" ? value.trim() : "";
  if (!agentId) {
    throw trustAnchorError(
      "agentId is required for a trust-anchor job: distribute-trust/" +
        "revoke-trust always target one specific agent's trust store",
      CERTOPS_TRUST_ANCHOR_INVALID,
    );
  }
  return agentId;
}

/**
 * Distinguishes "the agentId isn't even shaped like a UUID" (400,
 * CERTOPS_TARGET_AGENT_INVALID) from "well-formed but no such agent in this
 * workspace" (404, CERTOPS_TARGET_AGENT_NOT_FOUND), mirroring how this file
 * already splits CERTOPS_TRUST_ANCHOR_INVALID from
 * CERTOPS_TRUST_ANCHOR_NOT_FOUND for anchor lookups above. Must run before
 * lockOrCreateInstallation's INSERT: certops_trust_anchor_installations'
 * agent_id column has no CHECK of its own, and its FK
 * (fk_certops_trust_anchor_installations_agent) only fires at INSERT time,
 * by which point the raw Postgres error (invalid UUID syntax, or an FK
 * violation) has no CERTOPS_* code for handleCertOpsError to recognize.
 */
async function assertTargetAgentRegistered({ client, workspaceId, agentId }) {
  if (!AGENT_ID_UUID_PATTERN.test(agentId)) {
    throw trustAnchorError(
      "agentId must be a well-formed UUID identifying a registered agent",
      CERTOPS_TARGET_AGENT_INVALID,
    );
  }
  const agent = await getAgentById({ client, workspaceId, agentId });
  if (!agent) {
    throw trustAnchorError(
      "Target agent not found in this workspace",
      CERTOPS_TARGET_AGENT_NOT_FOUND,
    );
  }
  return agent;
}

function normalizeIdempotencyKey(value) {
  const key = typeof value === "string" ? value.trim() : "";
  if (!key) {
    // Required, not merely accepted: a trust mutation is not naturally
    // retry-safe on its own.
    throw trustAnchorError(
      "idempotencyKey is required to create a distribute-trust or " +
        "revoke-trust job",
      CERTOPS_TRUST_JOB_IDEMPOTENCY_KEY_REQUIRED,
    );
  }
  return key;
}

// trust-job-payload.schema.json's "metadata" is an array of {name, value}
// entries, not a free-form object. A caller's publicMetadata is taken here
// as a plain object and converted to that array shape; entries failing the
// schema's name pattern or value union are dropped rather than thrown.
const METADATA_NAME_PATTERN =
  /^(?!.*(?:private[-_]?key|encrypted[-_]?private[-_]?key|key[-_]?material|pfx[-_]?blob|jks[-_]?blob|tls[-_]?key|ca[-_]?private[-_]?key|keystore[-_]?password|private[-_]?key[-_]?password|key[-_]?password|key[-_]?pem|password|secret|credential))[A-Za-z0-9_.:-]{1,64}$/i;

function buildTrustJobPublicMetadataEntries(publicMetadata) {
  if (!publicMetadata || typeof publicMetadata !== "object") return [];
  const entries = [];
  for (const [name, rawValue] of Object.entries(publicMetadata)) {
    if (entries.length >= 32) break;
    if (!METADATA_NAME_PATTERN.test(name)) continue;
    const valueType = typeof rawValue;
    if (
      rawValue !== null &&
      valueType !== "string" &&
      valueType !== "number" &&
      valueType !== "boolean"
    ) {
      continue;
    }
    if (valueType === "string" && rawValue.length > 512) continue;
    entries.push({ name, value: rawValue });
  }
  return entries;
}

// --- PEM parsing / validation ---

/**
 * Parses and validates a caller-supplied CA certificate PEM: exactly one
 * certificate block, Basic Constraints CA=true. The fingerprint is always
 * computed server-side over the parsed DER, never trusted from client
 * input. anchorType is an explicit caller decision, never inferred from the
 * certificate itself.
 * @returns {{ pem: string, fingerprintSha256: string, subjectCommonName: string|null }}
 */
function parseAndValidateAnchorPem(pemInput) {
  if (typeof pemInput !== "string" || pemInput.trim().length === 0) {
    throw trustAnchorError(
      "pem is required and must be a non-empty string",
      CERTOPS_TRUST_ANCHOR_PEM_INVALID,
    );
  }

  let parsed;
  try {
    parsed = parsePublicCertificateMaterial(pemInput);
  } catch (error) {
    throw trustAnchorError(
      error?.message || "Trust anchor PEM could not be parsed",
      CERTOPS_TRUST_ANCHOR_PEM_INVALID,
    );
  }

  if (!Array.isArray(parsed) || parsed.length !== 1) {
    throw trustAnchorError(
      "Trust anchor PEM must contain exactly one certificate; bundles and " +
        "multi-certificate PEM input are rejected",
      CERTOPS_TRUST_ANCHOR_PEM_INVALID,
    );
  }

  const [entry] = parsed;
  let x509;
  try {
    x509 = new X509Certificate(entry.certificatePem);
  } catch (_error) {
    throw trustAnchorError(
      "Trust anchor PEM could not be parsed",
      CERTOPS_TRUST_ANCHOR_PEM_INVALID,
    );
  }

  if (x509.ca !== true) {
    throw trustAnchorError(
      "Trust anchor PEM must be a CA certificate (Basic Constraints " +
        "CA=true); leaf certificates are rejected",
      CERTOPS_TRUST_ANCHOR_PEM_INVALID,
    );
  }

  const fingerprintSha256 =
    entry.fingerprintSha256 ||
    createHash("sha256").update(x509.raw).digest("hex");

  return {
    pem: entry.certificatePem,
    fingerprintSha256: fingerprintSha256.toLowerCase(),
    subjectCommonName: entry.commonName || null,
  };
}

// --- Anchor row shaping ---

function anchorFromRow(row) {
  if (!row) return null;
  return {
    id: String(row.id),
    workspaceId: String(row.workspace_id),
    name: row.name,
    anchorType: row.anchor_type,
    fingerprintSha256: row.fingerprint_sha256,
    subjectCommonName: row.subject_common_name || null,
    status: row.status,
    source: row.source,
    publicMetadata: row.public_metadata || {},
    createdBy: row.created_by || null,
    createdAt: dateToIso(row.created_at),
    updatedAt: dateToIso(row.updated_at),
    revokedAt: dateToIso(row.revoked_at),
  };
}

const ANCHOR_SELECT_FIELDS = `
  id, workspace_id, name, anchor_type, fingerprint_sha256,
  subject_common_name, status, source, public_metadata, created_by,
  created_at, updated_at, revoked_at
`;

// --- Anchor CRUD ---

/**
 * Creates (or re-approves, if the same fingerprint already exists) a trust
 * anchor row. Re-approving updates the existing row rather than creating a
 * duplicate, and reactivates a previously retired anchor.
 */
async function createTrustAnchor(options = {}) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const name = normalizeName(options.name);
  const anchorType = normalizeAnchorType(options.anchorType);
  const source = normalizeAnchorSource(options.source);
  const publicMetadata = normalizePublicObject(
    options.publicMetadata,
    "publicMetadata",
  );
  const createdByUserId = options.createdByUserId ?? null;

  const { pem, fingerprintSha256, subjectCommonName } =
    parseAndValidateAnchorPem(options.pem);

  const result = await db.query(
    `INSERT INTO certops_trust_anchors (
       workspace_id, name, pem, anchor_type, fingerprint_sha256,
       subject_common_name, source, public_metadata, created_by
     )
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)
     ON CONFLICT (workspace_id, fingerprint_sha256) DO UPDATE SET
       name = EXCLUDED.name,
       -- Re-approving reactivates: re-submitting a retired anchor's PEM
       -- means it should accept new distributions again.
       status = 'active',
       revoked_at = NULL,
       source = EXCLUDED.source,
       public_metadata = EXCLUDED.public_metadata,
       subject_common_name = EXCLUDED.subject_common_name,
       updated_at = NOW()
     RETURNING ${ANCHOR_SELECT_FIELDS}`,
    [
      workspaceId,
      name,
      pem,
      anchorType,
      fingerprintSha256,
      subjectCommonName,
      source,
      JSON.stringify(publicMetadata),
      createdByUserId,
    ],
  );

  const anchor = anchorFromRow(result.rows[0]);

  await writeAudit({
    client: db,
    actorUserId: createdByUserId,
    subjectUserId: createdByUserId,
    action: "CERTOPS_TRUST_ANCHOR_APPROVED",
    targetType: "certops_trust_anchor",
    targetId: anchor.id,
    workspaceId,
    metadata: {
      trustAnchorId: anchor.id,
      fingerprintSha256: anchor.fingerprintSha256,
      anchorType: anchor.anchorType,
      name: anchor.name,
    },
  });

  return anchor;
}

async function listTrustAnchors(options = {}) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const status =
    options.status && ANCHOR_STATUSES.includes(options.status)
      ? options.status
      : null;

  const result = await db.query(
    `SELECT ${ANCHOR_SELECT_FIELDS}
       FROM certops_trust_anchors
      WHERE workspace_id = $1
        AND ($2::text IS NULL OR status = $2::text)
      ORDER BY created_at DESC`,
    [workspaceId, status],
  );
  return result.rows.map(anchorFromRow);
}

async function getTrustAnchorById(db, workspaceId, anchorId) {
  const result = await db.query(
    `SELECT ${ANCHOR_SELECT_FIELDS}
       FROM certops_trust_anchors
      WHERE workspace_id = $1 AND id = $2`,
    [workspaceId, anchorId],
  );
  return anchorFromRow(result.rows[0]);
}

/**
 * Anchor-level "retire": sets status to 'revoked' (the DB column name is
 * unchanged) but every user/audit-facing surface calls this "retire", never
 * "revoke", so it isn't confused with the wire-level revoke-trust job
 * operation (a separate, per-installation action). Retiring never fans out
 * removal jobs against existing installations; those need their own
 * revoke-trust job via createTrustJob. Idempotent: no-op success on an
 * already-retired anchor.
 */
async function retireTrustAnchor(options = {}) {
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const anchorId = normalizeRequiredId(
    options.anchorId,
    CERTOPS_TRUST_ANCHOR_INVALID,
  );
  const retiredByUserId = options.retiredByUserId ?? null;
  const reason =
    typeof options.reason === "string" && options.reason.trim()
      ? options.reason.trim().slice(0, 500)
      : null;

  return withTransaction(options.dbPool || pool, async (client) => {
    await lockWorkspaceForCertOpsSideEffect({ client, workspaceId });

    const existing = await client.query(
      `SELECT ${ANCHOR_SELECT_FIELDS}
         FROM certops_trust_anchors
        WHERE workspace_id = $1 AND id = $2
        FOR UPDATE`,
      [workspaceId, anchorId],
    );
    if (!existing.rows[0]) {
      throw trustAnchorError(
        "Trust anchor not found",
        CERTOPS_TRUST_ANCHOR_NOT_FOUND,
      );
    }
    if (existing.rows[0].status === "revoked") {
      return { anchor: anchorFromRow(existing.rows[0]), retiredNow: false };
    }

    const updated = await client.query(
      `UPDATE certops_trust_anchors
          SET status = 'revoked',
              revoked_at = NOW(),
              updated_at = NOW()
        WHERE workspace_id = $1 AND id = $2
        RETURNING ${ANCHOR_SELECT_FIELDS}`,
      [workspaceId, anchorId],
    );
    const anchor = anchorFromRow(updated.rows[0]);

    await writeAudit({
      client,
      actorUserId: retiredByUserId,
      subjectUserId: retiredByUserId,
      action: "CERTOPS_TRUST_ANCHOR_RETIRED",
      targetType: "certops_trust_anchor",
      targetId: anchor.id,
      workspaceId,
      metadata: {
        trustAnchorId: anchor.id,
        fingerprintSha256: anchor.fingerprintSha256,
        anchorType: anchor.anchorType,
        ...(reason ? { reason } : {}),
      },
    });

    return { anchor, retiredNow: true };
  });
}

// --- Installation row helpers ---

const INSTALLATION_SELECT_FIELDS = `
  id, workspace_id, trust_anchor_id, host, store, fingerprint_sha256,
  owner, transition_state, provenance, agent_id, last_job_id,
  transition_generation, last_attempt_at, last_error, next_reconcile_at,
  public_metadata, created_at, updated_at
`;

function installationFromRow(row) {
  if (!row) return null;
  return {
    id: String(row.id),
    workspaceId: String(row.workspace_id),
    trustAnchorId: String(row.trust_anchor_id),
    host: row.host,
    store: row.store,
    fingerprintSha256: row.fingerprint_sha256,
    owner: row.owner,
    transitionState: row.transition_state,
    provenance: row.provenance,
    agentId: String(row.agent_id),
    lastJobId: row.last_job_id ? String(row.last_job_id) : null,
    transitionGeneration: row.transition_generation,
    lastAttemptAt: dateToIso(row.last_attempt_at),
    lastError: row.last_error || null,
    nextReconcileAt: dateToIso(row.next_reconcile_at),
    publicMetadata: row.public_metadata || {},
    createdAt: dateToIso(row.created_at),
    updatedAt: dateToIso(row.updated_at),
  };
}

/**
 * Locks (or creates, if absent) the ownership-reference row for
 * (workspace, agent, store, fingerprint, owner) inside the caller's
 * transaction. SELECT ... FOR UPDATE serializes concurrent requests on this
 * row, the same idiom agentDispatch.js's claimJobs/renewJobLease/
 * ingestResult already use.
 */
async function lockOrCreateInstallation({
  client,
  workspaceId,
  trustAnchorId,
  agentId,
  store,
  fingerprintSha256,
  owner,
  host,
}) {
  const locked = await client.query(
    `SELECT ${INSTALLATION_SELECT_FIELDS}
       FROM certops_trust_anchor_installations
      WHERE workspace_id = $1
        AND agent_id = $2
        AND store = $3
        AND fingerprint_sha256 = $4
        AND owner = $5
      FOR UPDATE`,
    [workspaceId, agentId, store, fingerprintSha256, owner],
  );
  if (locked.rows[0]) return { row: locked.rows[0], created: false };

  // A fresh row starts pending_install/preexisting at generation 1;
  // createTrustJob below immediately advances it to the correct state for
  // the requested operation in the same transaction. provenance starts
  // 'preexisting' (not 'tokentimer_installed') because at insert time we
  // haven't run the job yet - ingestResult's nextProvenance below is the
  // only place that promotes it to 'tokentimer_installed', and only on a
  // genuine outcome:"installed" mutation. Starting optimistic here would
  // let an outcome:"preexisting" result (agent found the cert already
  // there, no mutation performed) keep a provenance TokenTimer never earned.
  const inserted = await client.query(
    `INSERT INTO certops_trust_anchor_installations (
       workspace_id, trust_anchor_id, host, store, fingerprint_sha256,
       owner, agent_id, provenance
     )
     VALUES ($1, $2, $3, $4, $5, $6, $7, 'preexisting')
     ON CONFLICT (workspace_id, agent_id, store, fingerprint_sha256, owner)
       DO NOTHING
     RETURNING ${INSTALLATION_SELECT_FIELDS}`,
    [workspaceId, trustAnchorId, host, store, fingerprintSha256, owner, agentId],
  );
  if (inserted.rows[0]) return { row: inserted.rows[0], created: true };

  // Lost the insert race to a concurrent transaction; lock its row instead.
  const retried = await client.query(
    `SELECT ${INSTALLATION_SELECT_FIELDS}
       FROM certops_trust_anchor_installations
      WHERE workspace_id = $1
        AND agent_id = $2
        AND store = $3
        AND fingerprint_sha256 = $4
        AND owner = $5
      FOR UPDATE`,
    [workspaceId, agentId, store, fingerprintSha256, owner],
  );
  return { row: retried.rows[0], created: false };
}

/**
 * Counts other owners' confirmed-live reference rows for the same
 * (workspace, agent, store, fingerprint). ADR-0012 decision 6: the store is
 * only physically touched when the last reference is released.
 *
 * Deliberately excludes `pending_install`: that state means the other
 * owner's material isn't confirmed present yet, and its row can still be
 * deleted outright by unwindTerminalTrustJob if that job fails. Crediting it
 * here would let this owner's revoke short-circuit to `removed` with no OS
 * mutation, and if the sibling row is later deleted, the certificate is
 * orphaned on the host with nothing left tracking it. Only `installed` and
 * `pending_remove` are states where the material is confirmed physically
 * present right now, so only those count. The narrow cost: if this owner's
 * revoke is requested while a sibling install is still in flight, the revoke
 * proceeds instead of short-circuiting; the agent's own idempotent install
 * check corrects that once the sibling's job completes, so it self-heals
 * instead of leaking permanently.
 */
async function countOtherLiveReferences({
  client,
  workspaceId,
  agentId,
  store,
  fingerprintSha256,
  owner,
}) {
  const result = await client.query(
    `SELECT COUNT(*)::int AS count
       FROM certops_trust_anchor_installations
      WHERE workspace_id = $1
        AND agent_id = $2
        AND store = $3
        AND fingerprint_sha256 = $4
        AND owner != $5
        AND transition_state IN ('installed', 'pending_remove')`,
    [workspaceId, agentId, store, fingerprintSha256, owner],
  );
  return result.rows[0]?.count ?? 0;
}

// --- Terminal-state unwinding ---
// pending_install rows are deleted on a terminal-negative status (never a
// real reference); pending_remove rows revert to installed (the anchor was
// never actually removed). A superseded-by-newer-generation row needs no
// special handling here: the stale-generation check in
// ingestTrustJobResult rejects that job's eventual result outright.

const TRUST_JOB_TERMINAL_NEGATIVE_STATUSES = new Set([
  "rejected",
  "cancelled",
  "failed",
  "blocked",
]);

/**
 * Applies the terminal-state transition table above to the installation row
 * `last_job_id` points at, for a trust job that just reached a terminal-
 * negative status. Called from the generic job-terminal-state hook (see
 * wireTrustAnchorTerminalHook), so denied/cancelled/failed jobs all unwind
 * the same way regardless of code path.
 *
 * Only unwinds the current generation: a job whose transition_generation
 * has already been superseded is stale and must not touch the row.
 */
async function unwindTerminalTrustJob({ client, job }) {
  if (!isTrustAnchorOperation(job.operation)) return null;
  if (!TRUST_JOB_TERMINAL_NEGATIVE_STATUSES.has(job.status)) return null;

  const locked = await client.query(
    `SELECT ${INSTALLATION_SELECT_FIELDS}
       FROM certops_trust_anchor_installations
      WHERE workspace_id = $1 AND last_job_id = $2
      FOR UPDATE`,
    [job.workspace_id || job.workspaceId, job.id],
  );
  const row = locked.rows[0];
  if (!row) return null;

  if (row.transition_state === "pending_install") {
    // Never a real reference; delete outright.
    const deleted = await client.query(
      `DELETE FROM certops_trust_anchor_installations
        WHERE id = $1
        RETURNING id`,
      [row.id],
    );
    return deleted.rows[0] ? { action: "deleted", installationId: row.id } : null;
  }
  if (row.transition_state === "pending_remove") {
    // The anchor was never actually removed; the reference is still real.
    const reverted = await client.query(
      `UPDATE certops_trust_anchor_installations
          SET transition_state = 'installed',
              last_error = $2,
              updated_at = NOW()
        WHERE id = $1
        RETURNING id`,
      [row.id, `terminal_${job.status}`.slice(0, 128)],
    );
    return reverted.rows[0]
      ? { action: "reverted_to_installed", installationId: row.id }
      : null;
  }
  // Already installed/removed: nothing pending to unwind.
  return null;
}

/**
 * Wired into the existing job-terminal-state code path: call this alongside
 * whatever already marks a certificate_jobs row rejected/cancelled/failed/
 * blocked. This file has no separate polling loop for trust jobs; the
 * caller (jobApprovals, agentDispatch.ingestResult, or a cancellation
 * route) invokes this once the job row is locked and its terminal status
 * is about to be persisted.
 */
async function onTrustJobTerminalTransition({ client, job }) {
  return unwindTerminalTrustJob({ client, job });
}

// --- Idempotent trust-job creation ---

/**
 * The only path that creates a distribute-trust or revoke-trust
 * certificate_jobs row. Advances the installation row's transition_state
 * and transition_generation in the same transaction as the job insert.
 * idempotencyKey is required: a replay with the same key returns the same
 * job/transitionGeneration read back from the persisted (immutable) job
 * payload, so a replay never needs to re-lock the installation row.
 */
async function createTrustJob(options = {}) {
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  if (!isTrustAnchorOperation(options.operation)) {
    throw trustAnchorError(
      `operation must be one of: distribute-trust, revoke-trust`,
      CERTOPS_TRUST_JOB_OPERATION_INVALID,
    );
  }
  const operation = options.operation;
  const trustAnchorId = normalizeRequiredId(
    options.trustAnchorId,
    CERTOPS_TRUST_ANCHOR_INVALID,
  );
  const agentId = normalizeAgentId(options.agentId);
  const owner = normalizeOwner(options.owner);
  const idempotencyKey = normalizeIdempotencyKey(options.idempotencyKey);
  const publicMetadata = normalizePublicObject(
    options.publicMetadata,
    "publicMetadata",
  );

  return options.client
    ? runCreateTrustJob(options.client, {
        workspaceId,
        operation,
        trustAnchorId,
        agentId,
        owner,
        idempotencyKey,
        publicMetadata,
        requiresApproval: options.requiresApproval === true,
        requestedByUserId: options.requestedByUserId ?? null,
        requestedByApiTokenId: options.requestedByApiTokenId ?? null,
        source: options.source || "api",
        env: options.env || process.env,
      })
    : withTransaction(options.dbPool || pool, (client) =>
        runCreateTrustJob(client, {
          workspaceId,
          operation,
          trustAnchorId,
          agentId,
          owner,
          idempotencyKey,
          publicMetadata,
          requiresApproval: options.requiresApproval === true,
          requestedByUserId: options.requestedByUserId ?? null,
          requestedByApiTokenId: options.requestedByApiTokenId ?? null,
          source: options.source || "api",
          env: options.env || process.env,
        }),
      );
}

async function runCreateTrustJob(client, params) {
  const {
    workspaceId,
    operation,
    trustAnchorId,
    agentId,
    owner,
    idempotencyKey,
    publicMetadata,
    requiresApproval,
    requestedByUserId,
    requestedByApiTokenId,
    source,
    env,
  } = params;

  await lockWorkspaceForCertOpsSideEffect({ client, workspaceId, env });

  // The anchor is locked first so its status and routing columns can't
  // change under us while the installation row and job are written.
  const anchorLock = await client.query(
    `SELECT id, workspace_id, name, anchor_type, fingerprint_sha256, status
       FROM certops_trust_anchors
      WHERE workspace_id = $1 AND id = $2
      FOR UPDATE`,
    [workspaceId, trustAnchorId],
  );
  const anchor = anchorLock.rows[0];
  if (!anchor) {
    throw trustAnchorError(
      "Trust anchor not found",
      CERTOPS_TRUST_ANCHOR_NOT_FOUND,
    );
  }
  if (operation === "distribute-trust" && anchor.status !== "active") {
    // A retired anchor acquires no new pending_install rows.
    throw trustAnchorError(
      "Trust anchor is retired and cannot be distributed; retire is not " +
        "reversible without a fresh approval",
      CERTOPS_TRUST_ANCHOR_NOT_ACTIVE,
    );
  }

  // Derived from the anchor's own anchor_type, the same signed value the
  // agent routes on - never accepted from a caller. See
  // resolveTrustAnchorStoreLabel's header: this is the only place a trust
  // job's store is decided, so the value persisted here and the value an
  // agent echoes back can never disagree.
  const store = normalizeStore(resolveTrustAnchorStoreLabel(anchor.anchor_type));

  // Without this check, a nonexistent/unregistered agentId skipped straight
  // to lockOrCreateInstallation's INSERT and surfaced as a raw Postgres
  // error (invalid UUID syntax or an FK violation on
  // fk_certops_trust_anchor_installations_agent) that handleCertOpsError
  // could not recognize, so both cases fell through to a bare 500.
  await assertTargetAgentRegistered({ client, workspaceId, agentId });

  const { row: installationRow, created: installationCreated } =
    await lockOrCreateInstallation({
      client,
      workspaceId,
      trustAnchorId,
      agentId,
      store,
      fingerprintSha256: anchor.fingerprint_sha256,
      owner,
      host: agentId,
    });

  if (operation === "revoke-trust" && installationCreated) {
    // Nothing was ever tracked for this tuple; roll back the just-inserted
    // placeholder row rather than leaving a phantom pending_remove behind.
    await client.query(
      `DELETE FROM certops_trust_anchor_installations WHERE id = $1`,
      [installationRow.id],
    );
    throw trustAnchorError(
      "No tracked installation exists for this agent/store/owner; nothing " +
        "to remove",
      CERTOPS_TRUST_INSTALLATION_NOT_FOUND,
    );
  }

  if (operation === "revoke-trust") {
    const otherLiveReferences = await countOtherLiveReferences({
      client,
      workspaceId,
      agentId,
      store,
      fingerprintSha256: anchor.fingerprint_sha256,
      owner,
    });
    if (otherLiveReferences > 0) {
      // ADR-0012 decision 6: the store is only physically touched when the
      // last reference is released. Another owner still references this
      // tuple, so go straight to removed with no job/dispatch - a real
      // revoke-trust job would delete that owner's still-live certificate.
      const releasedRow = await client.query(
        `UPDATE certops_trust_anchor_installations
            SET transition_state = 'removed',
                transition_generation = transition_generation + 1,
                last_attempt_at = NOW(),
                last_error = NULL,
                next_reconcile_at = NULL,
                updated_at = NOW()
          WHERE id = $1
          RETURNING ${INSTALLATION_SELECT_FIELDS}`,
        [installationRow.id],
      );
      const releasedInstallation = installationFromRow(releasedRow.rows[0]);

      await writeAudit({
        client,
        actorUserId: requestedByUserId,
        subjectUserId: requestedByUserId,
        action: "CERTOPS_TRUST_REFERENCE_RELEASED",
        targetType: "certops_trust_anchor_installation",
        targetId: releasedInstallation.id,
        workspaceId,
        metadata: {
          trustAnchorId: anchor.id,
          anchorName: anchor.name,
          fingerprintSha256: anchor.fingerprint_sha256,
          agentId,
          store,
          host: releasedInstallation.host,
          owner,
          transitionGeneration: releasedInstallation.transitionGeneration,
          otherLiveReferences,
        },
      });

      return {
        job: null,
        created: false,
        skippedOsMutation: true,
        transitionGeneration: releasedInstallation.transitionGeneration,
        installation: releasedInstallation,
      };
    }
  }

  const nextTransitionState =
    operation === "distribute-trust" ? "pending_install" : "pending_remove";
  const nextReconcileAt = new Date(Date.now() + DEFAULT_RECONCILE_DELAY_MS);

  // provenance is deliberately left untouched here: neither removing nor
  // re-distributing an anchor changes who originally installed the material.
  const advanced = await client.query(
    `UPDATE certops_trust_anchor_installations
        SET transition_state = $2,
            transition_generation = transition_generation + 1,
            last_attempt_at = NOW(),
            last_error = NULL,
            next_reconcile_at = $3,
            updated_at = NOW()
      WHERE id = $1
      RETURNING ${INSTALLATION_SELECT_FIELDS}`,
    [installationRow.id, nextTransitionState, nextReconcileAt],
  );
  const installation = installationFromRow(advanced.rows[0]);

  // Volatile values stay out of the stored payload: createCertificateJob
  // fingerprints it into creation_request_hash, so anything that varies per
  // call would make an idempotent replay hash differently. Both are
  // resolved at dispatch time instead (see agentDispatch.js).
  const payload = {
    trustAnchorId: anchor.id,
    anchorType: anchor.anchor_type,
    fingerprintSha256: anchor.fingerprint_sha256,
  };
  const metadataEntries = buildTrustJobPublicMetadataEntries(publicMetadata);
  if (metadataEntries.length > 0) payload.metadata = metadataEntries;

  const outcome = await createCertificateJob({
    client,
    workspaceId,
    operation,
    subjectType: "trust_anchor",
    subjectId: anchor.id,
    payload,
    idempotencyKey,

    assignedAgentId: agentId,
    executorKind: "agent",
    requiresApproval,
    requestedByUserId,
    requestedByApiTokenId,
    source,
    env,
    returnOutcome: true,
  });
  const job = outcome.job;
  const created = outcome.created === true;

  if (created) {
    await client.query(
      `UPDATE certops_trust_anchor_installations
          SET last_job_id = $2, updated_at = NOW()
        WHERE id = $1`,
      [installation.id, job.id],
    );
    installation.lastJobId = String(job.id);

    await writeAudit({
      client,
      actorUserId: requestedByUserId,
      subjectUserId: requestedByUserId,
      action:
        operation === "distribute-trust"
          ? "CERTOPS_TRUST_DISTRIBUTE_JOB_CREATED"
          : "CERTOPS_TRUST_REVOKE_JOB_CREATED",
      targetType: "certificate_job",
      targetId: job.id,
      workspaceId,
      metadata: {
        jobId: String(job.id),
        trustAnchorId: anchor.id,
        anchorName: anchor.name,
        fingerprintSha256: anchor.fingerprint_sha256,
        agentId,
        store,
        host: installation.host,
        owner,
        transitionGeneration: installation.transitionGeneration,
      },
    });
  } else {
    // Idempotent replay: undo the speculative generation bump above so a
    // replayed request is indistinguishable from running exactly once.
    // createCertificateJob's replay path already detected the duplicate
    // before this SQL could be observed by another transaction.
    await client.query(
      `UPDATE certops_trust_anchor_installations
          SET transition_state = $2,
              transition_generation = $3,
              next_reconcile_at = $4,
              updated_at = NOW()
        WHERE id = $1`,
      [
        installation.id,
        installationRow.transition_state,
        installationRow.transition_generation,
        installationRow.next_reconcile_at,
      ],
    );
    // The row was restored to the original generation, and this
    // transaction still holds its lock, so it's authoritative.
    installation.transitionGeneration = installationRow.transition_generation;
    installation.transitionState = installationRow.transition_state;
    installation.lastJobId = installationRow.last_job_id
      ? String(installationRow.last_job_id)
      : String(job.id);
  }

  return {
    job,
    created,
    transitionGeneration: installation.transitionGeneration,
    installation,
  };
}

/**
 * jobCreator swapped in by routes/certops.js for the generic manual-job
 * route's trust-anchor branch, mirroring manualRenewalJobCreator's (jobs.js)
 * calling convention: a factory closed over trustAnchorId/agentId/store/
 * owner, returning a function createManualCertificateJob
 * (workspaceKillSwitch.js) can call the same way it calls
 * createCertificateJob for every other operation. This keeps createTrustJob
 * the only path into a trust job even from the shared manual-job route.
 */
function manualTrustJobCreator({ trustAnchorId, agentId, owner } = {}) {
  return async function manualTrustJobCreator(options) {
    const outcome = await createTrustJob({
      client: options.client,
      workspaceId: options.workspaceId,
      operation: options.operation,
      trustAnchorId,
      agentId,
      owner,
      idempotencyKey: options.idempotencyKey,
      publicMetadata: options.payload,
      requiresApproval: options.requiresApproval === true,
      requestedByUserId: options.requestedByUserId ?? null,
      requestedByApiTokenId: options.requestedByApiTokenId ?? null,
      source: options.source || "api",
      env: options.env || process.env,
    });
    // createManualCertificateJob (workspaceKillSwitch.js) reads
    // outcome.job/outcome.created off whatever jobCreator returns; this
    // wrapper is transparent to that caller. skippedOsMutation/installation
    // pass through too, since a revoke-trust call that released one owner's
    // reference while another's is still live returns job: null here.
    return {
      job: outcome.job,
      created: outcome.created,
      skippedOsMutation: outcome.skippedOsMutation === true,
      installation: outcome.installation,
    };
  };
}

// --- Dispatch-time revalidation ---

/**
 * Must be called immediately before a distribute-trust/revoke-trust job is
 * signed for dispatch (see agentDispatch.claimJobs), inside the same
 * transaction that holds the job row lock. Re-checks the anchor's current
 * status and re-verifies the job's signed pem/anchorType/fingerprintSha256
 * still match the anchor row, as defense-in-depth even though those columns
 * are immutable after creation.
 *
 * - distribute-trust: anchor must still be 'active'; if retired after
 *   approval but before dispatch, the pending install is unwound (deleted)
 *   instead of dispatched.
 * - revoke-trust: always permitted regardless of anchor status.
 *
 * Returns { allow: true, anchor, pem, transitionGeneration } (pem only for
 * distribute-trust, read fresh here rather than trusting a stale job-payload
 * copy) or { allow: false, reason }.
 */
async function revalidateTrustJobForDispatch({ client, job }) {
  if (!isTrustAnchorOperation(job.operation)) {
    return { allow: true };
  }
  const workspaceId = job.workspace_id || job.workspaceId;
  const payload =
    job.payload && typeof job.payload === "object" ? job.payload : {};
  const trustAnchorId = payload.trustAnchorId || job.subject_id;

  const anchorResult = await client.query(
    `SELECT id, pem, anchor_type, fingerprint_sha256, status
       FROM certops_trust_anchors
      WHERE workspace_id = $1 AND id = $2
      FOR UPDATE`,
    [workspaceId, trustAnchorId],
  );
  const anchor = anchorResult.rows[0];
  if (!anchor) {
    // Anchor rows are additive-only, so this should be unreachable. Fail
    // closed rather than dispatch against nothing.
    return { allow: false, reason: "trust_anchor_not_found" };
  }

  if (
    anchor.anchor_type !== payload.anchorType ||
    anchor.fingerprint_sha256 !== payload.fingerprintSha256
  ) {
    // Both columns are immutable after insert, so reaching this branch
    // indicates a programmer error elsewhere - fail closed all the same.
    return { allow: false, reason: "trust_anchor_payload_mismatch" };
  }

  if (job.operation === "distribute-trust" && anchor.status !== "active") {
    await unwindTerminalTrustJob({
      client,
      job: { ...job, status: "rejected", workspace_id: workspaceId },
    });
    return { allow: false, reason: "trust_anchor_retired" };
  }

  const installation = await client.query(
    `SELECT transition_generation, store
       FROM certops_trust_anchor_installations
      WHERE workspace_id = $1 AND last_job_id = $2
      FOR UPDATE`,
    [workspaceId, job.id],
  );
  const installationRow = installation.rows[0];
  if (!installationRow) {
    // Every trust job is created with its installation row in one
    // transaction, so a job with no row is a broken invariant, not a race.
    return { allow: false, reason: "trust_installation_not_found" };
  }

  return {
    allow: true,
    anchor: anchorFromRow(anchor),
    pem: job.operation === "distribute-trust" ? anchor.pem : undefined,
    // The agent must echo this back so a superseded transition's late
    // result is rejected as stale. Resolved here rather than read off the
    // job payload, since that payload is fingerprinted for idempotency and
    // can't carry a value that changes per transition.
    transitionGeneration: installationRow.transition_generation,
  };
}

// --- Result ingestion ---

/**
 * Validates an agent-reported trust-job result against
 * trust-result-contract.schema.json and against the persisted job/
 * installation row: agentId, store, fingerprintSha256, and
 * transitionGeneration must all match what was signed. Rejects a
 * stale-generation result outright.
 *
 * Called from the same result-ingestion transaction agentDispatch.ingestResult
 * opens for every job family, once it has identified the job as trust-anchor.
 *
 * On a validated match: advances the installation row per the outcome
 * enum - preexisting/installed both settle at 'installed' (provenance is
 * left as-is, since a result can't retroactively rewrite who originally
 * installed the material); already_absent/removed both settle at 'removed'.
 */
async function ingestTrustJobResult({ client, job, result }) {
  if (!isTrustAnchorOperation(job.operation)) {
    throw trustAnchorError(
      "ingestTrustJobResult was called for a non-trust-anchor job",
      CERTOPS_TRUST_RESULT_INVALID,
    );
  }

  const shapeCheck = validateTrustResult(result);
  if (!shapeCheck.valid) {
    const error = trustAnchorError(
      "Trust job result does not match trust-result-contract.schema.json",
      CERTOPS_TRUST_RESULT_INVALID,
    );
    error.validationErrors = shapeCheck.errors;
    throw error;
  }

  // This function only ever runs from agentDispatch.ingestResult's
  // jobStatus === "succeeded" branch, and the agent itself never reports
  // status "succeeded" alongside a non-null trustResult.failureCategory
  // (packages/agent/src/index.js's executeTrustJob always maps a non-null
  // failureCategory to status "failed"). A result claiming both is
  // self-contradictory - shape-valid per the schema (failureCategory has no
  // cross-field tie to the envelope status, which lives one level up) but
  // never something a well-behaved agent would send - so it is rejected
  // rather than silently trusted.
  if (typeof result.failureCategory === "string" && result.failureCategory.length > 0) {
    throw trustAnchorError(
      "Result reports a non-null failureCategory but was ingested as a " +
        "succeeded job; a successful trust job result must never carry a " +
        "failure category",
      CERTOPS_TRUST_RESULT_INVALID,
    );
  }

  const workspaceId = job.workspace_id || job.workspaceId;

  const installationLock = await client.query(
    `SELECT ${INSTALLATION_SELECT_FIELDS}
       FROM certops_trust_anchor_installations
      WHERE workspace_id = $1 AND last_job_id = $2
      FOR UPDATE`,
    [workspaceId, job.id],
  );
  const installationRow = installationLock.rows[0];
  if (!installationRow) {
    throw trustAnchorError(
      "No installation row references this trust job",
      CERTOPS_TRUST_INSTALLATION_NOT_FOUND,
    );
  }

  // A result whose store/fingerprint/transitionGeneration differs from the
  // signed job it claims to answer is rejected, not merely logged.
  //
  // Compares job.assigned_agent_id vs installationRow.agent_id (both UUIDs
  // in the same certops_agents.id space). Not result.agentId - that's the
  // agent's wire-format string identity, a different id space, already
  // re-proven separately by agentDispatch.ingestResult before this runs.
  if (String(job.assigned_agent_id) !== String(installationRow.agent_id)) {
    throw trustAnchorError(
      "Job's assigned agent does not match the installation this job was signed for",
      CERTOPS_TRUST_RESULT_MISMATCH,
    );
  }
  if (result.store !== installationRow.store) {
    throw trustAnchorError(
      "Result store does not match the installation this job was signed for",
      CERTOPS_TRUST_RESULT_MISMATCH,
    );
  }
  if (result.trustAnchorId !== String(installationRow.trust_anchor_id)) {
    throw trustAnchorError(
      "Result trustAnchorId does not match the signed job",
      CERTOPS_TRUST_RESULT_MISMATCH,
    );
  }
  // Whichever fingerprint the agent observed (before or after mutation; at
  // least one is non-null for every outcome) must match this row's tracked
  // fingerprint.
  const observedFingerprint =
    result.observedFingerprintAfter || result.observedFingerprintBefore;
  if (
    observedFingerprint &&
    observedFingerprint !== installationRow.fingerprint_sha256
  ) {
    throw trustAnchorError(
      "Result fingerprint does not match the installation this job was signed for",
      CERTOPS_TRUST_RESULT_MISMATCH,
    );
  }

  // A stale-generation result (transitionGeneration no longer matches the
  // row's current generation) is rejected outright as evidence of a
  // superseded transition.
  if (result.transitionGeneration !== installationRow.transition_generation) {
    throw trustAnchorError(
      "Result transitionGeneration is stale; a newer transition has " +
        "already superseded this generation",
      CERTOPS_TRUST_RESULT_STALE_GENERATION,
    );
  }

  const nextState =
    result.outcome === "preexisting" || result.outcome === "installed"
      ? "installed"
      : "removed";
  // A result claiming the material is now installed but performed no
  // mutation ('preexisting') must not overwrite an existing
  // 'tokentimer_installed' provenance - provenance only ever tightens
  // toward "we know we put this here", never loosens.
  const nextProvenance =
    result.outcome === "installed"
      ? "tokentimer_installed"
      : installationRow.provenance;
  // failureCategory is always null here: the guard above already rejected
  // any succeeded-status result carrying one. A real success always clears
  // whatever last_error a prior failed attempt left behind.

  const updated = await client.query(
    `UPDATE certops_trust_anchor_installations
        SET transition_state = $2,
            provenance = $3,
            last_error = NULL,
            next_reconcile_at = NULL,
            updated_at = NOW()
      WHERE id = $1
      RETURNING ${INSTALLATION_SELECT_FIELDS}`,
    [installationRow.id, nextState, nextProvenance],
  );

  return installationFromRow(updated.rows[0]);
}

// --- Reconciliation sweep support ---

/**
 * Finds pending_* installation rows past their next_reconcile_at, locking
 * each with SELECT ... FOR UPDATE SKIP LOCKED so multiple worker replicas
 * never both act on the same row.
 */
async function findOverdueTrustInstallations({ client, limit = 50 }) {
  const result = await client.query(
    `SELECT tai.id, tai.workspace_id, tai.trust_anchor_id, tai.host,
            tai.store, tai.fingerprint_sha256, tai.owner,
            tai.transition_state, tai.provenance, tai.agent_id,
            tai.last_job_id, tai.transition_generation, tai.last_attempt_at,
            tai.last_error, tai.next_reconcile_at, tai.public_metadata,
            tai.created_at, tai.updated_at,
            cj.status AS last_job_status,
            cj.operation AS last_job_operation
       FROM certops_trust_anchor_installations tai
       LEFT JOIN certificate_jobs cj
         ON cj.workspace_id = tai.workspace_id AND cj.id = tai.last_job_id
      WHERE tai.transition_state IN ('pending_install', 'pending_remove')
        AND tai.next_reconcile_at IS NOT NULL
        AND tai.next_reconcile_at <= NOW()
      ORDER BY tai.next_reconcile_at
      LIMIT $1
      FOR UPDATE OF tai SKIP LOCKED`,
    [limit],
  );
  return result.rows.map((row) => ({
    installation: installationFromRow(row),
    lastJobStatus: row.last_job_status || null,
    lastJobOperation: row.last_job_operation || null,
  }));
}

/**
 * Marks an overdue row as reported/alerted rather than silently retried:
 * clearing next_reconcile_at removes it from automatic revalidation.
 */
async function markTrustInstallationStale({ client, installationId, reason }) {
  const sanitized = typeof reason === "string" ? reason.slice(0, 128) : "reconciliation_stale";
  const updated = await client.query(
    `UPDATE certops_trust_anchor_installations
        SET next_reconcile_at = NULL,
            last_error = $2,
            updated_at = NOW()
      WHERE id = $1
      RETURNING ${INSTALLATION_SELECT_FIELDS}`,
    [installationId, sanitized],
  );
  return installationFromRow(updated.rows[0]);
}

/**
 * Reschedules an overdue row for a later reconciliation pass, used when the
 * sweep decides a row deserves another look rather than being marked
 * stale/alertable yet.
 */
async function rescheduleTrustInstallation({
  client,
  installationId,
  delayMs = DEFAULT_RECONCILE_DELAY_MS,
}) {
  const nextReconcileAt = new Date(Date.now() + delayMs);
  const updated = await client.query(
    `UPDATE certops_trust_anchor_installations
        SET next_reconcile_at = $2,
            updated_at = NOW()
      WHERE id = $1
      RETURNING ${INSTALLATION_SELECT_FIELDS}`,
    [installationId, nextReconcileAt],
  );
  return installationFromRow(updated.rows[0]);
}

// How long a pending row may keep being rescheduled before the sweep gives
// up and reports it stale. Measured from last_attempt_at, not an attempt
// counter (this row shape has no per-row attempt count).
const DEFAULT_MAX_RECONCILE_AGE_MS = 6 * DEFAULT_RECONCILE_DELAY_MS;

/**
 * The reconciliation sweep, called by certops-worker.js on the same
 * tick-based schedule as this codebase's other certops sweeps. Owns one
 * transaction for the whole batch; findOverdueTrustInstallations's
 * SELECT ... FOR UPDATE SKIP LOCKED holds each candidate locked for the
 * rest of this function.
 *
 * This sweep never signs or assigns a job itself; agentDispatch.claimJobs
 * is what redispatches.
 *
 * Per-row disposition:
 *  - job already terminal-negative: unwind now (onTrustJobTerminalTransition
 *    should have done this already, so finding one here is itself alertable).
 *  - job in flight, within maxAgeMs: reschedule.
 *  - job in flight, past maxAgeMs: mark stale.
 *  - no job row at all (unreachable): treated as past its age budget.
 */
async function sweepOverdueTrustInstallations({
  dbPool = pool,
  limit = 50,
  maxAgeMs = DEFAULT_MAX_RECONCILE_AGE_MS,
  reconcileDelayMs = DEFAULT_RECONCILE_DELAY_MS,
  now = () => Date.now(),
} = {}) {
  const summary = {
    scanned: 0,
    unwound: 0,
    rescheduled: 0,
    markedStale: 0,
  };

  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    const overdue = await findOverdueTrustInstallations({ client, limit });
    summary.scanned = overdue.length;

    for (const { installation, lastJobStatus, lastJobOperation } of overdue) {
      if (
        lastJobStatus &&
        TRUST_JOB_TERMINAL_NEGATIVE_STATUSES.has(lastJobStatus)
      ) {
        // Should already have been unwound by onTrustJobTerminalTransition;
        // finding one here means that hook was missed upstream. Unwind now.
        await unwindTerminalTrustJob({
          client,
          job: {
            id: installation.lastJobId,
            operation: lastJobOperation,
            status: lastJobStatus,
            workspace_id: installation.workspaceId,
          },
        });
        summary.unwound += 1;
        continue;
      }

      const lastAttemptAtMs = installation.lastAttemptAt
        ? new Date(installation.lastAttemptAt).getTime()
        : NaN;
      const ageMs = Number.isFinite(lastAttemptAtMs)
        ? now() - lastAttemptAtMs
        : Infinity;

      if (ageMs > maxAgeMs) {
        await markTrustInstallationStale({
          client,
          installationId: installation.id,
          reason: lastJobStatus
            ? `reconciliation_stale_job_${lastJobStatus}`
            : "reconciliation_stale_no_job",
        });
        summary.markedStale += 1;
        continue;
      }

      await rescheduleTrustInstallation({
        client,
        installationId: installation.id,
        delayMs: reconcileDelayMs,
      });
      summary.rescheduled += 1;
    }

    await client.query("COMMIT");
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_rollbackError) {
      // Preserve the original sweep error.
    }
    throw error;
  } finally {
    client.release();
  }

  return summary;
}

module.exports = {
  CERTOPS_TRUST_ANCHOR_INVALID,
  CERTOPS_TRUST_ANCHOR_NOT_FOUND,
  CERTOPS_TRUST_ANCHOR_PEM_INVALID,
  CERTOPS_TRUST_ANCHOR_NOT_ACTIVE,
  CERTOPS_TRUST_JOB_IDEMPOTENCY_KEY_REQUIRED,
  CERTOPS_TRUST_JOB_OPERATION_INVALID,
  CERTOPS_TRUST_INSTALLATION_NOT_FOUND,
  CERTOPS_TRUST_RESULT_INVALID,
  CERTOPS_TRUST_RESULT_MISMATCH,
  CERTOPS_TRUST_RESULT_STALE_GENERATION,
  CERTOPS_TARGET_AGENT_INVALID,
  CERTOPS_TARGET_AGENT_NOT_FOUND,
  ANCHOR_TYPES,
  DEFAULT_RECONCILE_DELAY_MS,
  parseAndValidateAnchorPem,
  createTrustAnchor,
  listTrustAnchors,
  getTrustAnchorById,
  retireTrustAnchor,
  anchorFromRow,
  installationFromRow,
  normalizeStore,
  normalizeOwner,
  normalizeAgentId,
  assertTargetAgentRegistered,
  normalizeIdempotencyKey,
  createTrustJob,
  manualTrustJobCreator,
  onTrustJobTerminalTransition,
  unwindTerminalTrustJob,
  TRUST_JOB_TERMINAL_NEGATIVE_STATUSES,
  revalidateTrustJobForDispatch,
  ingestTrustJobResult,
  findOverdueTrustInstallations,
  markTrustInstallationStale,
  rescheduleTrustInstallation,
  sweepOverdueTrustInstallations,
  DEFAULT_MAX_RECONCILE_AGE_MS,
};