"use strict";

const {
  ALLOWED_SCOPES,
  CERTOPS_API_TOKEN_SCOPE_DENIED,
  CERTOPS_API_TOKEN_SCOPE_INVALID,
  validateApiToken,
} = require("../services/certops/apiTokens");

const CERTOPS_API_TOKEN_UNAUTHORIZED = "CERTOPS_API_TOKEN_UNAUTHORIZED";
const CERTOPS_API_TOKEN_WORKSPACE_REQUIRED =
  "CERTOPS_API_TOKEN_WORKSPACE_REQUIRED";

const UNAUTHORIZED_RESPONSE = Object.freeze({
  error: "CertOps API token authentication required",
  code: CERTOPS_API_TOKEN_UNAUTHORIZED,
});

const SCOPE_DENIED_RESPONSE = Object.freeze({
  error: "CertOps API token scope denied",
  code: CERTOPS_API_TOKEN_SCOPE_DENIED,
});

function authError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function responseForUnauthorized(code = CERTOPS_API_TOKEN_UNAUTHORIZED) {
  return code === CERTOPS_API_TOKEN_WORKSPACE_REQUIRED
    ? {
        error: "Workspace context is required for CertOps API token authentication",
        code,
      }
    : UNAUTHORIZED_RESPONSE;
}

function bearerTokenFromRequest(req) {
  const header =
    typeof req.get === "function"
      ? req.get("Authorization")
      : req.headers?.authorization;
  if (typeof header !== "string" || !header.trim()) {
    return { ok: false };
  }

  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  if (!match || !match[1].trim()) {
    return { ok: false };
  }

  return { ok: true, rawToken: match[1].trim() };
}

function normalizeRequiredScopes(scopes) {
  const values = scopes === undefined || scopes === null ? [] : scopes;
  const list = Array.isArray(values) ? values : [values];
  const normalized = [];
  const allowed = new Set(ALLOWED_SCOPES);

  for (const scope of list) {
    if (typeof scope !== "string") {
      throw authError(
        "CertOps API token scope is invalid",
        CERTOPS_API_TOKEN_SCOPE_INVALID,
      );
    }

    const trimmed = scope.trim();
    if (!allowed.has(trimmed)) {
      throw authError(
        "CertOps API token scope is not allowed",
        CERTOPS_API_TOKEN_SCOPE_INVALID,
      );
    }

    if (!normalized.includes(trimmed)) normalized.push(trimmed);
  }

  return normalized;
}

function firstNonEmptyString(values) {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return null;
}

function workspaceIdFromRequest(req, options = {}) {
  if (typeof options.resolveWorkspaceId === "function") {
    const resolved = options.resolveWorkspaceId(req);
    if (typeof resolved === "string" && resolved.trim()) return resolved.trim();
  }

  const paramNames = [
    options.workspaceIdParam,
    "workspaceId",
    "id",
  ].filter(Boolean);
  const paramValues = paramNames.map((name) => req.params?.[name]);
  const workspaceId = firstNonEmptyString(paramValues);
  if (workspaceId) return workspaceId;

  if (options.allowBodyWorkspaceId === true) {
    return firstNonEmptyString([req.body?.workspaceId]);
  }

  return null;
}

function safeApiTokenIdentity(token) {
  if (!token) return null;

  return {
    id: token.id,
    workspaceId: token.workspaceId,
    tokenPrefix: token.tokenPrefix,
    scopes: Array.isArray(token.scopes) ? [...token.scopes] : [],
    name: token.name,
    createdBy: token.createdBy ?? null,
    lastUsedAt: token.lastUsedAt || null,
  };
}

function createCertOpsApiTokenAuth(options = {}) {
  const requiredScopes = normalizeRequiredScopes(
    options.scopes ?? options.requiredScopes,
  );
  // Per plan A2: "Required-scopes argument must be non-empty (empty scopes is
  // a config error, not a wildcard)." An empty array here would otherwise
  // make hasRequiredScopes()'s Array#every() vacuously true, letting a
  // misconfigured route accept ANY valid token regardless of scope. Fail at
  // middleware construction time (route wiring), not per-request, so a
  // missing `scopes`/`requiredScopes` option is caught immediately rather
  // than silently granting universal access.
  if (requiredScopes.length === 0) {
    throw authError(
      "createCertOpsApiTokenAuth requires a non-empty scopes/requiredScopes option",
      CERTOPS_API_TOKEN_SCOPE_INVALID,
    );
  }
  const validateToken = options.validateApiToken || validateApiToken;

  return async function certOpsApiTokenAuth(req, res, next) {
    const bearer = bearerTokenFromRequest(req);
    if (!bearer.ok) {
      return res.status(401).json(UNAUTHORIZED_RESPONSE);
    }

    const workspaceId = workspaceIdFromRequest(req, options);
    if (!workspaceId && options.allowTokenWorkspace !== true) {
      return res
        .status(401)
        .json(responseForUnauthorized(CERTOPS_API_TOKEN_WORKSPACE_REQUIRED));
    }

    let validation;
    try {
      validation = await validateToken({
        client: options.client,
        rawToken: bearer.rawToken,
        workspaceId,
        requiredScopes,
        allowTokenWorkspace: options.allowTokenWorkspace === true,
      });
    } catch (error) {
      if (error?.code === CERTOPS_API_TOKEN_SCOPE_INVALID) {
        return res.status(403).json(SCOPE_DENIED_RESPONSE);
      }
      return next(error);
    }

    if (!validation?.valid) {
      if (validation?.code === CERTOPS_API_TOKEN_SCOPE_DENIED) {
        return res.status(403).json(SCOPE_DENIED_RESPONSE);
      }
      return res.status(401).json(UNAUTHORIZED_RESPONSE);
    }

    req.apiToken = safeApiTokenIdentity(validation.token);
    return next();
  };
}

module.exports = {
  CERTOPS_API_TOKEN_UNAUTHORIZED,
  CERTOPS_API_TOKEN_WORKSPACE_REQUIRED,
  bearerTokenFromRequest,
  createCertOpsApiTokenAuth,
  requireCertOpsApiToken: createCertOpsApiTokenAuth,
  safeApiTokenIdentity,
  workspaceIdFromRequest,
  _test: {
    normalizeRequiredScopes,
    responseForUnauthorized,
  },
};
