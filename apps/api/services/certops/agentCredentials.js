"use strict";

const crypto = require("crypto");

const { pool } = require("../../db/database");
const { containsPrivateKeyMaterial } = require("../../utils/secretMaterial");
const { assertSafePublicValue } = require("./jobs");

const CERTOPS_AGENT_BOOTSTRAP_TOKEN_INVALID =
  "CERTOPS_AGENT_BOOTSTRAP_TOKEN_INVALID";
const CERTOPS_AGENT_BOOTSTRAP_TOKEN_MALFORMED =
  "CERTOPS_AGENT_BOOTSTRAP_TOKEN_MALFORMED";
const CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRED =
  "CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRED";
const CERTOPS_AGENT_BOOTSTRAP_TOKEN_USED =
  "CERTOPS_AGENT_BOOTSTRAP_TOKEN_USED";
const CERTOPS_AGENT_BOOTSTRAP_TOKEN_REVOKED =
  "CERTOPS_AGENT_BOOTSTRAP_TOKEN_REVOKED";
const CERTOPS_AGENT_BOOTSTRAP_TOKEN_NAME_INVALID =
  "CERTOPS_AGENT_BOOTSTRAP_TOKEN_NAME_INVALID";
const CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRY_INVALID =
  "CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRY_INVALID";
const CERTOPS_AGENT_CREDENTIAL_INVALID = "CERTOPS_AGENT_CREDENTIAL_INVALID";
const CERTOPS_AGENT_CREDENTIAL_MALFORMED =
  "CERTOPS_AGENT_CREDENTIAL_MALFORMED";
const CERTOPS_AGENT_WORKSPACE_REQUIRED = "CERTOPS_AGENT_WORKSPACE_REQUIRED";
const PRIVATE_KEY_MATERIAL_REJECTED = "PRIVATE_KEY_MATERIAL_REJECTED";

const BOOTSTRAP_TOKEN_PREFIX = "ttboot_";
const AGENT_CREDENTIAL_PREFIX = "ttagent_";
const ID_HEX_LENGTH = 16;
const SECRET_HEX_LENGTH = 64;
const ID_BYTES = ID_HEX_LENGTH / 2;
const SECRET_BYTES = SECRET_HEX_LENGTH / 2;
// "ttboot_" + 16 + "_" + 64
const RAW_BOOTSTRAP_TOKEN_LENGTH =
  BOOTSTRAP_TOKEN_PREFIX.length + ID_HEX_LENGTH + 1 + SECRET_HEX_LENGTH;
// "ttagent_" + 16 + "_" + 64
const RAW_AGENT_CREDENTIAL_LENGTH =
  AGENT_CREDENTIAL_PREFIX.length + ID_HEX_LENGTH + 1 + SECRET_HEX_LENGTH;
const RAW_BOOTSTRAP_TOKEN_PATTERN = /^ttboot_([a-f0-9]{16})_([a-f0-9]{64})$/;
const RAW_AGENT_CREDENTIAL_PATTERN = /^ttagent_([a-f0-9]{16})_([a-f0-9]{64})$/;
const RAW_CREDENTIAL_EMBEDDED_PATTERN = new RegExp(
  `(?:${BOOTSTRAP_TOKEN_PREFIX}|${AGENT_CREDENTIAL_PREFIX})[a-f0-9]{${ID_HEX_LENGTH}}_[a-f0-9]{${SECRET_HEX_LENGTH}}`,
  "i",
);
const TOKEN_HASH_ASSIGNMENT_PATTERN =
  /\b(?:token|credential)[_-]?hash\s*[:=]\s*[a-f0-9]{64}\b/i;
const BARE_BEARER_CREDENTIAL_PATTERN =
  /\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}\b/i;
const MAX_TOKEN_CREATE_ATTEMPTS = 3;
const MAX_BOOTSTRAP_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

const BOOTSTRAP_SAFE_SELECT_FIELDS = `
  id,
  workspace_id,
  name,
  token_prefix,
  status,
  expires_at,
  used_at,
  used_by_agent_id,
  revoked_at,
  revoked_by,
  created_by,
  created_at,
  updated_at
`;

function serviceError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function dateToIso(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

function containsRawAgentCredentialMaterial(value) {
  return RAW_CREDENTIAL_EMBEDDED_PATTERN.test(String(value || ""));
}

function containsGenericCredentialMaterial(value) {
  const text = String(value || "");
  if (
    TOKEN_HASH_ASSIGNMENT_PATTERN.test(text) ||
    BARE_BEARER_CREDENTIAL_PATTERN.test(text)
  ) {
    return true;
  }

  try {
    assertSafePublicValue(text);
    return false;
  } catch (_error) {
    return true;
  }
}

function normalizeName(value) {
  if (typeof value !== "string") {
    throw serviceError(
      "Agent bootstrap token name is required",
      CERTOPS_AGENT_BOOTSTRAP_TOKEN_NAME_INVALID,
    );
  }
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 128) {
    throw serviceError(
      "Agent bootstrap token name is invalid",
      CERTOPS_AGENT_BOOTSTRAP_TOKEN_NAME_INVALID,
    );
  }
  if (containsPrivateKeyMaterial(trimmed)) {
    throw serviceError(
      "Private key material is not accepted in CertOps agent bootstrap token metadata",
      PRIVATE_KEY_MATERIAL_REJECTED,
    );
  }
  if (
    containsRawAgentCredentialMaterial(trimmed) ||
    containsGenericCredentialMaterial(trimmed)
  ) {
    throw serviceError(
      "Agent bootstrap token name is invalid",
      CERTOPS_AGENT_BOOTSTRAP_TOKEN_NAME_INVALID,
    );
  }
  return trimmed;
}

function normalizeWorkspaceId(value) {
  const workspaceId = typeof value === "string" ? value.trim() : "";
  if (!workspaceId) {
    throw serviceError(
      "Workspace is required for agent bootstrap tokens",
      CERTOPS_AGENT_WORKSPACE_REQUIRED,
    );
  }
  return workspaceId;
}

function normalizeRequiredExpiresAt(value, now = new Date()) {
  if (value === undefined || value === null || value === "") {
    throw serviceError(
      "Agent bootstrap token expiry is required",
      CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRY_INVALID,
    );
  }
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw serviceError(
      "Agent bootstrap token expiry is invalid",
      CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRY_INVALID,
    );
  }
  if (date.getTime() <= now.getTime()) {
    throw serviceError(
      "Agent bootstrap token expiry must be in the future",
      CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRY_INVALID,
    );
  }
  if (date.getTime() > now.getTime() + MAX_BOOTSTRAP_TOKEN_TTL_MS) {
    throw serviceError(
      "Agent bootstrap token expiry must be at most 30 days out",
      CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRY_INVALID,
    );
  }
  return date;
}

function generateRawSecret(prefix) {
  const idPart = crypto.randomBytes(ID_BYTES).toString("hex");
  const secretPart = crypto.randomBytes(SECRET_BYTES).toString("hex");
  return `${prefix}${idPart}_${secretPart}`;
}

function generateRawBootstrapToken() {
  return generateRawSecret(BOOTSTRAP_TOKEN_PREFIX);
}

function generateRawAgentCredential() {
  return generateRawSecret(AGENT_CREDENTIAL_PREFIX);
}

function parseRawBootstrapToken(rawToken) {
  if (
    typeof rawToken !== "string" ||
    rawToken.length !== RAW_BOOTSTRAP_TOKEN_LENGTH
  ) {
    return null;
  }
  const match = RAW_BOOTSTRAP_TOKEN_PATTERN.exec(rawToken);
  if (!match) return null;
  return {
    rawToken,
    tokenId: match[1],
    tokenPrefix: `${BOOTSTRAP_TOKEN_PREFIX}${match[1]}`,
  };
}

function parseRawAgentCredential(rawCredential) {
  if (
    typeof rawCredential !== "string" ||
    rawCredential.length !== RAW_AGENT_CREDENTIAL_LENGTH
  ) {
    return null;
  }
  const match = RAW_AGENT_CREDENTIAL_PATTERN.exec(rawCredential);
  if (!match) return null;
  return {
    rawCredential,
    credentialId: match[1],
    credentialPrefix: `${AGENT_CREDENTIAL_PREFIX}${match[1]}`,
  };
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function safeCompareSha256Hex(candidateHash, storedHash) {
  const candidateIsSha256 = /^[a-f0-9]{64}$/.test(candidateHash);
  const storedIsSha256 = /^[a-f0-9]{64}$/.test(String(storedHash || ""));
  const candidate = candidateIsSha256
    ? Buffer.from(candidateHash, "hex")
    : Buffer.alloc(32);
  const stored = storedIsSha256
    ? Buffer.from(storedHash, "hex")
    : Buffer.alloc(32);
  const matches = crypto.timingSafeEqual(candidate, stored);
  return candidateIsSha256 && storedIsSha256 && matches;
}

function bootstrapTokenStatusFromRow(row) {
  if (row?.status !== "active") return row?.status || null;
  const expiresAt = row.expires_at ? new Date(row.expires_at) : null;
  if (
    expiresAt &&
    !Number.isNaN(expiresAt.getTime()) &&
    expiresAt <= new Date()
  ) {
    return "expired";
  }
  return "active";
}

function bootstrapTokenMetadataFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    name: row.name,
    tokenPrefix: row.token_prefix,
    status: bootstrapTokenStatusFromRow(row),
    expiresAt: dateToIso(row.expires_at),
    usedAt: dateToIso(row.used_at),
    usedByAgentId: row.used_by_agent_id || null,
    revokedAt: dateToIso(row.revoked_at),
    revokedBy: row.revoked_by,
    createdBy: row.created_by,
    createdAt: dateToIso(row.created_at),
    updatedAt: dateToIso(row.updated_at),
  };
}

function agentMetadataFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    agentId: row.agent_id,
    name: row.name ?? null,
    status: row.status,
    protocolVersion: row.protocol_version,
    agentVersion: row.agent_version,
    pinnedSigningKeyId: row.pinned_signing_key_id || null,
    lastSeenAt: dateToIso(row.last_seen_at),
    retiredAt: dateToIso(row.retired_at),
  };
}

function invalidBootstrapValidation(code = CERTOPS_AGENT_BOOTSTRAP_TOKEN_INVALID) {
  return { valid: false, code };
}

function invalidCredentialValidation(code = CERTOPS_AGENT_CREDENTIAL_INVALID) {
  return { valid: false, code };
}

async function createBootstrapToken(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const name = normalizeName(options.name);
  const expiresAt = normalizeRequiredExpiresAt(options.expiresAt);

  for (let attempt = 1; attempt <= MAX_TOKEN_CREATE_ATTEMPTS; attempt += 1) {
    const plaintextToken = generateRawBootstrapToken();
    const tokenPrefix = parseRawBootstrapToken(plaintextToken).tokenPrefix;
    const tokenHash = sha256Hex(plaintextToken);

    try {
      const result = await db.query(
        `INSERT INTO certops_agent_bootstrap_tokens (
           workspace_id,
           name,
           token_prefix,
           token_hash,
           status,
           expires_at,
           created_by
         )
         VALUES ($1, $2, $3, $4, 'active', $5, $6)
         RETURNING ${BOOTSTRAP_SAFE_SELECT_FIELDS}`,
        [
          workspaceId,
          name,
          tokenPrefix,
          tokenHash,
          expiresAt,
          options.createdBy || null,
        ],
      );

      return {
        token: bootstrapTokenMetadataFromRow(result.rows[0]),
        plaintextToken,
      };
    } catch (error) {
      if (
        error?.code === "23505" &&
        attempt < MAX_TOKEN_CREATE_ATTEMPTS &&
        /certops_agent_bootstrap_tokens_(?:prefix|hash)/.test(
          String(error.constraint || ""),
        )
      ) {
        continue;
      }
      throw error;
    }
  }

  throw serviceError(
    "Unable to create agent bootstrap token",
    CERTOPS_AGENT_BOOTSTRAP_TOKEN_INVALID,
  );
}

async function listBootstrapTokens(options) {
  const result = await (options.client || pool).query(
    `SELECT ${BOOTSTRAP_SAFE_SELECT_FIELDS}
       FROM certops_agent_bootstrap_tokens
      WHERE workspace_id = $1
      ORDER BY created_at DESC, id ASC`,
    [normalizeWorkspaceId(options.workspaceId)],
  );
  return result.rows.map(bootstrapTokenMetadataFromRow);
}

async function getBootstrapTokenById(options) {
  const result = await (options.client || pool).query(
    `SELECT ${BOOTSTRAP_SAFE_SELECT_FIELDS}
       FROM certops_agent_bootstrap_tokens
      WHERE workspace_id = $1
        AND id = $2
      LIMIT 1`,
    [normalizeWorkspaceId(options.workspaceId), options.tokenId],
  );
  return bootstrapTokenMetadataFromRow(result.rows[0] || null);
}

async function revokeBootstrapToken(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const result = await db.query(
    `UPDATE certops_agent_bootstrap_tokens
        SET status = 'revoked',
            revoked_at = NOW(),
            revoked_by = $3,
            updated_at = NOW()
      WHERE workspace_id = $1
        AND id = $2
        AND status = 'active'
      RETURNING ${BOOTSTRAP_SAFE_SELECT_FIELDS}`,
    [workspaceId, options.tokenId, options.revokedBy || null],
  );

  if (result.rows[0]) {
    return bootstrapTokenMetadataFromRow(result.rows[0]);
  }
  return getBootstrapTokenById({
    client: db,
    workspaceId,
    tokenId: options.tokenId,
  });
}

async function validateBootstrapToken(options) {
  const parsed = parseRawBootstrapToken(options.rawToken);
  if (!parsed) {
    return invalidBootstrapValidation(CERTOPS_AGENT_BOOTSTRAP_TOKEN_MALFORMED);
  }

  const candidateHash = sha256Hex(parsed.rawToken);
  const result = await (options.client || pool).query(
    `SELECT id,
            workspace_id,
            name,
            token_prefix,
            token_hash,
            status,
            expires_at,
            used_at,
            used_by_agent_id,
            revoked_at,
            revoked_by,
            created_by,
            created_at,
            updated_at
       FROM certops_agent_bootstrap_tokens
      WHERE token_prefix = $1
      LIMIT 1`,
    [parsed.tokenPrefix],
  );

  const row = result.rows[0];
  if (!row) return invalidBootstrapValidation();
  if (!safeCompareSha256Hex(candidateHash, row.token_hash)) {
    return invalidBootstrapValidation();
  }
  if (row.status === "used") {
    // Registration retries after a lost response must authenticate with the
    // already-consumed bootstrap token so the control plane can replay the
    // stored credential (H1). Callers pass allowUsed: true only on register.
    if (options.allowUsed === true) {
      return {
        valid: true,
        bootstrapToken: bootstrapTokenMetadataFromRow(row),
      };
    }
    return invalidBootstrapValidation(CERTOPS_AGENT_BOOTSTRAP_TOKEN_USED);
  }
  if (row.status === "revoked") {
    return invalidBootstrapValidation(CERTOPS_AGENT_BOOTSTRAP_TOKEN_REVOKED);
  }
  if (row.status === "expired") {
    return invalidBootstrapValidation(CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRED);
  }
  if (row.status !== "active") {
    return invalidBootstrapValidation();
  }
  const expiresAt = row.expires_at ? new Date(row.expires_at) : null;
  if (!expiresAt || Number.isNaN(expiresAt.getTime())) {
    return invalidBootstrapValidation();
  }
  if (expiresAt.getTime() <= Date.now()) {
    return invalidBootstrapValidation(CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRED);
  }

  return { valid: true, bootstrapToken: bootstrapTokenMetadataFromRow(row) };
}

// Single-use consumption. Runs inside the registration transaction; the
// WHERE guard makes the active-to-used transition atomic. A null return
// means another registration won the race (or the token expired between
// validation and consumption) and the caller must treat it as auth failure.
async function consumeBootstrapToken(options) {
  const result = await (options.client || pool).query(
    `UPDATE certops_agent_bootstrap_tokens
        SET status = 'used',
            used_at = NOW(),
            used_by_agent_id = $2,
            updated_at = NOW()
      WHERE id = $1
        AND status = 'active'
        AND expires_at > NOW()
      RETURNING ${BOOTSTRAP_SAFE_SELECT_FIELDS}`,
    [options.tokenId, options.agentRowId],
  );
  return bootstrapTokenMetadataFromRow(result.rows[0] || null);
}

// No DB write: the registration service inserts the row (prefix + hash) in
// its own transaction. The plaintext credential is returned exactly once.
function generateAgentCredential() {
  const plaintextCredential = generateRawAgentCredential();
  const parsed = parseRawAgentCredential(plaintextCredential);
  return {
    plaintextCredential,
    credentialPrefix: parsed.credentialPrefix,
    credentialHash: sha256Hex(plaintextCredential),
  };
}

async function validateAgentCredential(options) {
  const parsed = parseRawAgentCredential(options.rawCredential);
  if (!parsed) {
    return invalidCredentialValidation(CERTOPS_AGENT_CREDENTIAL_MALFORMED);
  }

  const candidateHash = sha256Hex(parsed.rawCredential);
  const result = await (options.client || pool).query(
    `SELECT id,
            workspace_id,
            agent_id,
            name,
            credential_hash,
            status,
            protocol_version,
            agent_version,
            pinned_signing_key_id,
            last_seen_at,
            retired_at
       FROM certops_agents
      WHERE credential_prefix = $1
      LIMIT 1`,
    [parsed.credentialPrefix],
  );

  const row = result.rows[0];
  if (!row) return invalidCredentialValidation();
  if (!safeCompareSha256Hex(candidateHash, row.credential_hash)) {
    return invalidCredentialValidation();
  }

  // Frozen-retired rule: a retired agent still authenticates so the route
  // layer can answer 410 on heartbeat instead of a generic 401. The caller
  // must check agent.status === 'retired'.
  return { valid: true, agent: agentMetadataFromRow(row) };
}

module.exports = {
  AGENT_CREDENTIAL_PREFIX,
  BOOTSTRAP_TOKEN_PREFIX,
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRED,
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRY_INVALID,
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_INVALID,
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_MALFORMED,
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_NAME_INVALID,
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_REVOKED,
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_USED,
  CERTOPS_AGENT_CREDENTIAL_INVALID,
  CERTOPS_AGENT_CREDENTIAL_MALFORMED,
  CERTOPS_AGENT_WORKSPACE_REQUIRED,
  PRIVATE_KEY_MATERIAL_REJECTED,
  consumeBootstrapToken,
  createBootstrapToken,
  generateAgentCredential,
  getBootstrapTokenById,
  listBootstrapTokens,
  revokeBootstrapToken,
  validateAgentCredential,
  validateBootstrapToken,
  _test: {
    MAX_BOOTSTRAP_TOKEN_TTL_MS,
    RAW_AGENT_CREDENTIAL_LENGTH,
    RAW_AGENT_CREDENTIAL_PATTERN,
    RAW_BOOTSTRAP_TOKEN_LENGTH,
    RAW_BOOTSTRAP_TOKEN_PATTERN,
    agentMetadataFromRow,
    bootstrapTokenMetadataFromRow,
    bootstrapTokenStatusFromRow,
    containsGenericCredentialMaterial,
    containsRawAgentCredentialMaterial,
    normalizeName,
    normalizeRequiredExpiresAt,
    parseRawAgentCredential,
    parseRawBootstrapToken,
    safeCompareSha256Hex,
    sha256Hex,
  },
};
