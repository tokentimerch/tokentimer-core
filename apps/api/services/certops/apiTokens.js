"use strict";

const crypto = require("crypto");

const { pool } = require("../../db/database");
const { containsPrivateKeyMaterial } = require("../../utils/secretMaterial");

const CERTOPS_API_TOKEN_INVALID = "CERTOPS_API_TOKEN_INVALID";
const CERTOPS_API_TOKEN_MALFORMED = "CERTOPS_API_TOKEN_MALFORMED";
const CERTOPS_API_TOKEN_NAME_INVALID = "CERTOPS_API_TOKEN_NAME_INVALID";
const CERTOPS_API_TOKEN_SCOPE_DENIED = "CERTOPS_API_TOKEN_SCOPE_DENIED";
const CERTOPS_API_TOKEN_SCOPE_INVALID = "CERTOPS_API_TOKEN_SCOPE_INVALID";
const CERTOPS_API_TOKEN_WORKSPACE_REQUIRED =
  "CERTOPS_API_TOKEN_WORKSPACE_REQUIRED";
const PRIVATE_KEY_MATERIAL_REJECTED = "PRIVATE_KEY_MATERIAL_REJECTED";

const TOKEN_PREFIX = "ttx_";
const TOKEN_ID_BYTES = 8;
const TOKEN_RANDOM_BYTES = 32;
const MAX_TOKEN_CREATE_ATTEMPTS = 3;
const RAW_TOKEN_PATTERN = /^ttx_([A-Za-z0-9]+)_([A-Za-z0-9]+)$/;

const ALLOWED_SCOPES = Object.freeze([
  "certops:read",
  "certops:events:write",
  "certops:jobs:read",
  "certops:evidence:write",
]);
const ALLOWED_SCOPE_SET = new Set(ALLOWED_SCOPES);

const SAFE_SELECT_FIELDS = `
  id,
  workspace_id,
  name,
  token_prefix,
  scopes,
  status,
  expires_at,
  last_used_at,
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

function normalizeName(value) {
  if (typeof value !== "string") {
    throw serviceError("API token name is required", CERTOPS_API_TOKEN_NAME_INVALID);
  }
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 128) {
    throw serviceError("API token name is invalid", CERTOPS_API_TOKEN_NAME_INVALID);
  }
  if (containsPrivateKeyMaterial(trimmed)) {
    throw serviceError(
      "Private key material is not accepted in CertOps API token metadata",
      PRIVATE_KEY_MATERIAL_REJECTED,
    );
  }
  return trimmed;
}

function normalizeScopes(scopes) {
  if (!Array.isArray(scopes) || scopes.length === 0 || scopes.length > 8) {
    throw serviceError(
      "CertOps API token scopes are invalid",
      CERTOPS_API_TOKEN_SCOPE_INVALID,
    );
  }

  const normalized = [];
  for (const scope of scopes) {
    if (typeof scope !== "string") {
      throw serviceError(
        "CertOps API token scopes are invalid",
        CERTOPS_API_TOKEN_SCOPE_INVALID,
      );
    }
    const trimmed = scope.trim();
    if (!ALLOWED_SCOPE_SET.has(trimmed)) {
      throw serviceError(
        "CertOps API token scope is not allowed",
        CERTOPS_API_TOKEN_SCOPE_INVALID,
      );
    }
    if (!normalized.includes(trimmed)) normalized.push(trimmed);
  }

  return normalized;
}

function normalizeRequiredScopes(requiredScopes) {
  if (requiredScopes === undefined || requiredScopes === null) return [];
  const scopes = Array.isArray(requiredScopes) ? requiredScopes : [requiredScopes];
  if (scopes.length === 0) return [];

  const normalized = [];
  for (const scope of scopes) {
    if (typeof scope !== "string") {
      throw serviceError(
        "CertOps API token scopes are invalid",
        CERTOPS_API_TOKEN_SCOPE_INVALID,
      );
    }
    const trimmed = scope.trim();
    if (!ALLOWED_SCOPE_SET.has(trimmed)) {
      throw serviceError(
        "CertOps API token scope is not allowed",
        CERTOPS_API_TOKEN_SCOPE_INVALID,
      );
    }
    if (!normalized.includes(trimmed)) normalized.push(trimmed);
  }
  return normalized;
}

function normalizeExpiresAt(value) {
  if (value === undefined || value === null || value === "") return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw serviceError("API token expiry is invalid", CERTOPS_API_TOKEN_INVALID);
  }
  return date;
}

function normalizeWorkspaceId(value) {
  const workspaceId = typeof value === "string" ? value.trim() : "";
  if (!workspaceId) {
    throw serviceError(
      "Workspace is required for API token validation",
      CERTOPS_API_TOKEN_WORKSPACE_REQUIRED,
    );
  }
  return workspaceId;
}

function generateRawToken() {
  const tokenId = crypto.randomBytes(TOKEN_ID_BYTES).toString("hex");
  const randomPart = crypto.randomBytes(TOKEN_RANDOM_BYTES).toString("hex");
  return `${TOKEN_PREFIX}${tokenId}_${randomPart}`;
}

function parseRawToken(rawToken) {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  const match = RAW_TOKEN_PATTERN.exec(token);
  if (!match) return null;

  return {
    rawToken: token,
    tokenId: match[1],
    tokenPrefix: `${TOKEN_PREFIX}${match[1]}`,
  };
}

function tokenPrefixFor(rawToken) {
  return parseRawToken(rawToken)?.tokenPrefix || null;
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function safeCompareSha256Hex(candidateHash, storedHash) {
  const candidate = /^[a-f0-9]{64}$/.test(candidateHash)
    ? Buffer.from(candidateHash, "hex")
    : Buffer.alloc(32);
  const stored = /^[a-f0-9]{64}$/.test(String(storedHash || ""))
    ? Buffer.from(storedHash, "hex")
    : Buffer.alloc(32);
  return crypto.timingSafeEqual(candidate, stored) && storedHash === candidateHash;
}

function scopesFromRow(row) {
  if (Array.isArray(row?.scopes)) return row.scopes;
  if (typeof row?.scopes === "string") {
    try {
      const parsed = JSON.parse(row.scopes);
      if (Array.isArray(parsed)) return parsed;
    } catch (_error) {
      return [];
    }
  }
  return [];
}

function hasRequiredScopes(grantedScopes, requiredScopes) {
  const granted = new Set(grantedScopes);
  return requiredScopes.every(
    (scope) =>
      granted.has(scope) ||
      (scope.endsWith(":read") && granted.has("certops:read")),
  );
}

function isPastExpiry(expiresAt) {
  if (!expiresAt) return false;
  const expires = expiresAt instanceof Date ? expiresAt : new Date(expiresAt);
  return !Number.isNaN(expires.getTime()) && expires.getTime() <= Date.now();
}

function displayStatusFromRow(row) {
  if (row.status === "active" && isPastExpiry(row.expires_at)) {
    return "expired";
  }
  return row.status;
}

function tokenMetadataFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    name: row.name,
    tokenPrefix: row.token_prefix,
    scopes: scopesFromRow(row),
    status: displayStatusFromRow(row),
    expiresAt: dateToIso(row.expires_at),
    lastUsedAt: dateToIso(row.last_used_at),
    revokedAt: dateToIso(row.revoked_at),
    revokedBy: row.revoked_by,
    createdBy: row.created_by,
    createdAt: dateToIso(row.created_at),
    updatedAt: dateToIso(row.updated_at),
  };
}

function invalidValidation(code = CERTOPS_API_TOKEN_INVALID) {
  return { valid: false, code };
}

async function createApiToken(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const name = normalizeName(options.name);
  const scopes = normalizeScopes(options.scopes);
  const expiresAt = normalizeExpiresAt(options.expiresAt);

  for (let attempt = 1; attempt <= MAX_TOKEN_CREATE_ATTEMPTS; attempt += 1) {
    const plaintextToken = generateRawToken();
    const tokenPrefix = tokenPrefixFor(plaintextToken);
    const tokenHash = sha256Hex(plaintextToken);

    try {
      const result = await db.query(
        `INSERT INTO api_tokens (
           workspace_id,
           name,
           token_prefix,
           token_hash,
           scopes,
           status,
           expires_at,
           created_by
         )
         VALUES ($1, $2, $3, $4, $5::text[], 'active', $6, $7)
         RETURNING ${SAFE_SELECT_FIELDS}`,
        [
          workspaceId,
          name,
          tokenPrefix,
          tokenHash,
          scopes,
          expiresAt,
          options.createdBy || null,
        ],
      );

      return {
        token: tokenMetadataFromRow(result.rows[0]),
        plaintextToken,
      };
    } catch (error) {
      if (
        error?.code === "23505" &&
        attempt < MAX_TOKEN_CREATE_ATTEMPTS &&
        /api_tokens_token_(?:prefix|hash)/.test(String(error.constraint || ""))
      ) {
        continue;
      }
      throw error;
    }
  }

  throw serviceError("Unable to create API token", CERTOPS_API_TOKEN_INVALID);
}

async function listApiTokens(options) {
  const result = await (options.client || pool).query(
    `SELECT ${SAFE_SELECT_FIELDS}
       FROM api_tokens
      WHERE workspace_id = $1
      ORDER BY created_at DESC, id ASC`,
    [normalizeWorkspaceId(options.workspaceId)],
  );
  return result.rows.map(tokenMetadataFromRow);
}

async function getApiTokenById(options) {
  const result = await (options.client || pool).query(
    `SELECT ${SAFE_SELECT_FIELDS}
       FROM api_tokens
      WHERE workspace_id = $1
        AND id = $2
      LIMIT 1`,
    [normalizeWorkspaceId(options.workspaceId), options.tokenId],
  );
  return tokenMetadataFromRow(result.rows[0] || null);
}

async function revokeApiToken(options) {
  const result = await (options.client || pool).query(
    `UPDATE api_tokens
        SET status = 'revoked',
            revoked_at = COALESCE(revoked_at, NOW()),
            revoked_by = COALESCE(revoked_by, $3),
            updated_at = NOW()
      WHERE workspace_id = $1
        AND id = $2
      RETURNING ${SAFE_SELECT_FIELDS}`,
    [
      normalizeWorkspaceId(options.workspaceId),
      options.tokenId,
      options.revokedBy || null,
    ],
  );
  return tokenMetadataFromRow(result.rows[0] || null);
}

async function markApiTokenUsed(options) {
  const result = await (options.client || pool).query(
    `UPDATE api_tokens
        SET last_used_at = NOW(),
            updated_at = NOW()
      WHERE id = $1
      RETURNING ${SAFE_SELECT_FIELDS}`,
    [options.tokenId],
  );
  return tokenMetadataFromRow(result.rows[0] || null);
}

async function validateApiToken(options) {
  let workspaceId = null;
  let requiredScopes;
  try {
    if (options.workspaceId !== undefined && options.workspaceId !== null) {
      workspaceId = normalizeWorkspaceId(options.workspaceId);
    } else if (options.allowTokenWorkspace !== true) {
      workspaceId = normalizeWorkspaceId(options.workspaceId);
    }
    requiredScopes = normalizeRequiredScopes(options.requiredScopes);
  } catch (error) {
    if (error.code === CERTOPS_API_TOKEN_WORKSPACE_REQUIRED) {
      return invalidValidation(error.code);
    }
    throw error;
  }

  const parsedToken = parseRawToken(options.rawToken);
  if (!parsedToken) {
    return invalidValidation(CERTOPS_API_TOKEN_MALFORMED);
  }

  const rawToken = parsedToken.rawToken;
  const candidateHash = sha256Hex(rawToken);
  const result = await (options.client || pool).query(
    `SELECT id,
            workspace_id,
            name,
            token_prefix,
            token_hash,
            scopes,
            status,
            expires_at,
            last_used_at,
            revoked_at,
            revoked_by,
            created_by,
            created_at,
            updated_at
       FROM api_tokens
      WHERE token_prefix = $1
      LIMIT 1`,
    [parsedToken.tokenPrefix],
  );

  const row = result.rows[0];
  if (!row) return invalidValidation();
  if (!safeCompareSha256Hex(candidateHash, row.token_hash)) {
    return invalidValidation();
  }
  if (workspaceId && String(row.workspace_id) !== workspaceId) {
    return invalidValidation();
  }
  if (row.status !== "active") {
    return invalidValidation();
  }

  const expiresAt = row.expires_at ? new Date(row.expires_at) : null;
  if (expiresAt && expiresAt.getTime() <= Date.now()) {
    return invalidValidation();
  }

  if (!hasRequiredScopes(scopesFromRow(row), requiredScopes)) {
    return invalidValidation(CERTOPS_API_TOKEN_SCOPE_DENIED);
  }

  const token = await markApiTokenUsed({
    client: options.client,
    tokenId: row.id,
  });
  return { valid: true, token: token || tokenMetadataFromRow(row) };
}

module.exports = {
  ALLOWED_SCOPES,
  CERTOPS_API_TOKEN_INVALID,
  CERTOPS_API_TOKEN_MALFORMED,
  CERTOPS_API_TOKEN_NAME_INVALID,
  CERTOPS_API_TOKEN_SCOPE_DENIED,
  CERTOPS_API_TOKEN_SCOPE_INVALID,
  CERTOPS_API_TOKEN_WORKSPACE_REQUIRED,
  PRIVATE_KEY_MATERIAL_REJECTED,
  TOKEN_PREFIX,
  createApiToken,
  getApiTokenById,
  listApiTokens,
  markApiTokenUsed,
  revokeApiToken,
  validateApiToken,
  _test: {
    hasRequiredScopes,
    safeCompareSha256Hex,
    scopesFromRow,
    sha256Hex,
    parseRawToken,
    tokenMetadataFromRow,
    tokenPrefixFor,
  },
};
