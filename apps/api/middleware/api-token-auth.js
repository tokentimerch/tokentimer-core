"use strict";

const {
  ALLOWED_SCOPES,
  CERTOPS_API_TOKEN_SCOPE_DENIED,
  CERTOPS_API_TOKEN_SCOPE_INVALID,
  validateApiToken,
} = require("../services/certops/apiTokens");

const CERTOPS_API_TOKEN_UNAUTHORIZED = "CERTOPS_API_TOKEN_UNAUTHORIZED";
const CERTOPS_API_TOKEN_SCOPE_REQUIRED = "CERTOPS_API_TOKEN_SCOPE_REQUIRED";
const CERTOPS_API_TOKEN_WORKSPACE_REQUIRED =
  "CERTOPS_API_TOKEN_WORKSPACE_REQUIRED";
const CERTOPS_API_TOKEN_WORKSPACE_MISMATCH =
  "CERTOPS_API_TOKEN_WORKSPACE_MISMATCH";
const CERTOPS_API_TOKEN_SESSION_IDENTITY_FORBIDDEN =
  "CERTOPS_API_TOKEN_SESSION_IDENTITY_FORBIDDEN";

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
  if (code === CERTOPS_API_TOKEN_WORKSPACE_REQUIRED) {
    return {
        error: "Workspace context is required for CertOps API token authentication",
        code,
    };
  }
  if (code === CERTOPS_API_TOKEN_WORKSPACE_MISMATCH) {
    return {
      error: "CertOps API token workspace context did not match",
      code,
    };
  }
  if (code === CERTOPS_API_TOKEN_SESSION_IDENTITY_FORBIDDEN) {
    return {
      error: "Session identity is not allowed for CertOps API token authentication",
      code,
    };
  }
  return UNAUTHORIZED_RESPONSE;
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

  if (list.length === 0) {
    throw authError(
      "At least one CertOps API token scope is required",
      CERTOPS_API_TOKEN_SCOPE_REQUIRED,
    );
  }

  for (const scope of list) {
    if (typeof scope !== "string") {
      throw authError(
        "CertOps API token scope is invalid",
        CERTOPS_API_TOKEN_SCOPE_INVALID,
      );
    }

    const trimmed = scope.trim();
    if (!trimmed) {
      throw authError(
        "At least one CertOps API token scope is required",
        CERTOPS_API_TOKEN_SCOPE_REQUIRED,
      );
    }
    if (!allowed.has(trimmed)) {
      throw authError(
        "CertOps API token scope is not allowed",
        CERTOPS_API_TOKEN_SCOPE_INVALID,
      );
    }

    if (!normalized.includes(trimmed)) normalized.push(trimmed);
  }

  if (normalized.length === 0) {
    throw authError(
      "At least one CertOps API token scope is required",
      CERTOPS_API_TOKEN_SCOPE_REQUIRED,
    );
  }
  return normalized;
}

function firstNonEmptyString(values) {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return null;
}

function workspaceIdFromRouteParams(req, options = {}) {
  const paramName = options.workspaceIdParam || "workspaceId";
  return firstNonEmptyString([req.params?.[paramName]]);
}

function workspaceResolutionFromRequest(req, options = {}) {
  const routeWorkspaceId = workspaceIdFromRouteParams(req, options);
  const bodyWorkspaceId = firstNonEmptyString([req.body?.workspaceId]);
  const resolvedWorkspaceId =
    typeof options.resolveWorkspaceId === "function"
      ? firstNonEmptyString([options.resolveWorkspaceId(req)])
      : null;

  if (routeWorkspaceId) {
    if (bodyWorkspaceId && bodyWorkspaceId !== routeWorkspaceId) {
      return { workspaceId: null, code: CERTOPS_API_TOKEN_WORKSPACE_MISMATCH };
    }
    if (resolvedWorkspaceId && resolvedWorkspaceId !== routeWorkspaceId) {
      return { workspaceId: null, code: CERTOPS_API_TOKEN_WORKSPACE_MISMATCH };
    }
    return { workspaceId: routeWorkspaceId, code: null };
  }

  if (
    resolvedWorkspaceId &&
    options.allowBodyWorkspaceId === true &&
    bodyWorkspaceId &&
    bodyWorkspaceId !== resolvedWorkspaceId
  ) {
    return { workspaceId: null, code: CERTOPS_API_TOKEN_WORKSPACE_MISMATCH };
  }
  if (resolvedWorkspaceId) {
    return { workspaceId: resolvedWorkspaceId, code: null };
  }

  if (options.allowBodyWorkspaceId === true) {
    return { workspaceId: bodyWorkspaceId, code: null };
  }

  return { workspaceId: null, code: CERTOPS_API_TOKEN_WORKSPACE_REQUIRED };
}

function workspaceIdFromRequest(req, options = {}) {
  return workspaceResolutionFromRequest(req, options).workspaceId;
}

function hasSessionIdentity(req) {
  const sessionUserId = req.session?.userId;
  const passportUser = req.session?.passport?.user;
  const hasSessionUserId =
    sessionUserId !== undefined && sessionUserId !== null && sessionUserId !== "";
  const hasPassportUser =
    passportUser !== undefined && passportUser !== null && passportUser !== "";
  return Boolean(
    req.user ||
      hasSessionUserId ||
      hasPassportUser ||
      req.isAdmin === true ||
      req.authenticated === true ||
      (typeof req.isAuthenticated === "function" && req.isAuthenticated() === true),
  );
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
  const validateToken = options.validateApiToken || validateApiToken;

  return async function certOpsApiTokenAuth(req, res, next) {
    if (hasSessionIdentity(req)) {
      return res
        .status(401)
        .json(responseForUnauthorized(CERTOPS_API_TOKEN_SESSION_IDENTITY_FORBIDDEN));
    }

    const bearer = bearerTokenFromRequest(req);
    if (!bearer.ok) {
      return res.status(401).json(UNAUTHORIZED_RESPONSE);
    }

    const workspaceResolution = workspaceResolutionFromRequest(req, options);
    const workspaceId = workspaceResolution.workspaceId;
    if (
      !workspaceId &&
      (workspaceResolution.code === CERTOPS_API_TOKEN_WORKSPACE_MISMATCH ||
        options.allowTokenWorkspace !== true)
    ) {
      return res
        .status(401)
        .json(
          responseForUnauthorized(
            workspaceResolution.code || CERTOPS_API_TOKEN_WORKSPACE_REQUIRED,
          ),
        );
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
        if (options.deferScopeEnforcement === true && validation.token) {
          // The token is fully authenticated; only the route scope failed.
          // Bind the identity and let the route decide, so private-key
          // material can still be rejected (422 + synchronous audit) with
          // the scope denial enforced immediately afterwards.
          req.apiToken = safeApiTokenIdentity(validation.token);
          req.apiTokenScopeDenied = true;
          return next();
        }
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
  CERTOPS_API_TOKEN_SCOPE_REQUIRED,
  CERTOPS_API_TOKEN_WORKSPACE_REQUIRED,
  CERTOPS_API_TOKEN_WORKSPACE_MISMATCH,
  CERTOPS_API_TOKEN_SESSION_IDENTITY_FORBIDDEN,
  bearerTokenFromRequest,
  createCertOpsApiTokenAuth,
  requireCertOpsApiToken: createCertOpsApiTokenAuth,
  safeApiTokenIdentity,
  workspaceIdFromRequest,
  _test: {
    normalizeRequiredScopes,
    hasSessionIdentity,
    responseForUnauthorized,
    workspaceResolutionFromRequest,
  },
};
