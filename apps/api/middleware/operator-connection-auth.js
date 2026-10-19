"use strict";

// Operator connection authentication and the route allowlist (ADR-0015).
//
// Two pieces:
//   guardOperatorCredentials  mounted early on /api. Any request that presents
//                             an operator credential is rejected unless it
//                             targets a route on the allowlist. Everything
//                             else in the API therefore stays closed to it.
//   requireOperatorConnection per-route guard. Authenticates the credential,
//                             resolves live authority, enforces the scope and
//                             sets req.operator. It never sets req.user,
//                             req.isWorkerCall or a session.

const { CONNECTION_CREDENTIAL, authenticateCredential, recordUse } = require("../services/operator/connections");
const { GRANT_CREDENTIAL } = require("../services/operator/enrollments");
const { hasAtLeastRole } = require("../services/rbac");

const OPERATOR_UNAUTHORIZED = "OPERATOR_CONNECTION_UNAUTHORIZED";
const OPERATOR_SCOPE_DENIED = "OPERATOR_CONNECTION_SCOPE_DENIED";
const OPERATOR_ROUTE_FORBIDDEN = "OPERATOR_CONNECTION_ROUTE_FORBIDDEN";
const OPERATOR_SESSION_FORBIDDEN = "OPERATOR_CONNECTION_SESSION_FORBIDDEN";

// Operator routes live in their own namespace. The workspace is never taken
// from the path: it comes from the connection.
const OPERATOR_PATH_PREFIX = "/api/v1/operator/";

const UNAUTHORIZED_BODY = Object.freeze({
  error: "Operator connection authentication required",
  code: OPERATOR_UNAUTHORIZED,
});

function bearerFromRequest(req) {
  const header =
    typeof req.get === "function" ? req.get("Authorization") : req.headers?.authorization;
  if (typeof header !== "string") return { present: false, raw: null };
  const match = /^Bearer[ \t]+(\S+)[ \t]*$/i.exec(header.trim());
  return { present: true, raw: match ? match[1] : null };
}

// Any credential-shaped bearer value with the operator prefix counts as an
// operator credential for routing purposes, even if malformed, so a mangled
// one still cannot reach a route that is not meant for it.
function looksLikeOperatorCredential(raw) {
  return typeof raw === "string" && raw.startsWith(CONNECTION_CREDENTIAL.prefix);
}

// The enrollment grant is a different credential family with its own prefix.
// It is accepted at one route, the redemption endpoint, and nowhere else.
const ENROLLMENT_REDEEM_PATH = "/api/v1/operator/enroll/redeem";

function looksLikeEnrollmentGrant(raw) {
  return typeof raw === "string" && raw.startsWith(GRANT_CREDENTIAL.prefix);
}

function isRedeemRequest(req) {
  return (
    String(req.method || "").toUpperCase() === "POST" &&
    requestPath(req) === ENROLLMENT_REDEEM_PATH
  );
}

function hasCookieHeader(req) {
  const header = req.headers?.cookie;
  return typeof header === "string" && header.trim() !== "";
}

// A browser attaches cookies on its own; an operator client does not. Any
// cookie or session identity next to a bearer credential is ambiguous, so the
// request is refused rather than letting the stronger identity win.
function hasSessionIdentity(req) {
  const hasUserId =
    req.session?.userId !== undefined && req.session?.userId !== null && req.session?.userId !== "";
  const hasPassport = Boolean(req.session?.passport?.user);
  return Boolean(
    req.user ||
      hasUserId ||
      hasPassport ||
      hasCookieHeader(req) ||
      req.isWorkerCall === true ||
      (typeof req.isAuthenticated === "function" && req.isAuthenticated() === true),
  );
}

function requestPath(req) {
  // originalUrl keeps the full path whether the middleware is mounted on /api
  // or on the router, and includes no query string once split.
  return String(req.originalUrl || req.url || req.path || "").split("?")[0];
}

// The remainder after the prefix must be plain path segments. Dot segments,
// percent-encoding and empty segments are refused outright, so a path cannot
// look like it is inside the namespace while resolving somewhere else.
const OPERATOR_REMAINDER_PATTERN = /^[a-z0-9][a-z0-9_-]*(?:\/[a-z0-9][a-z0-9_-]*)*$/i;

function isOperatorRoute(req) {
  const path = requestPath(req);
  if (!path.startsWith(OPERATOR_PATH_PREFIX)) return false;
  return OPERATOR_REMAINDER_PATTERN.test(path.slice(OPERATOR_PATH_PREFIX.length));
}

// Mounted before any other authentication. Fail closed.
function guardOperatorCredentials(req, res, next) {
  const bearer = bearerFromRequest(req);
  if (bearer.present && looksLikeEnrollmentGrant(bearer.raw)) {
    // A grant is spent at exactly one route and nowhere else.
    if (isRedeemRequest(req)) return next();
    return res.status(403).json({
      error: "Operator enrollment codes are not accepted on this route",
      code: OPERATOR_ROUTE_FORBIDDEN,
    });
  }
  if (!bearer.present || !looksLikeOperatorCredential(bearer.raw)) return next();
  if (!isOperatorRoute(req)) {
    return res.status(403).json({
      error: "Operator connection credentials are not accepted on this route",
      code: OPERATOR_ROUTE_FORBIDDEN,
    });
  }
  return next();
}

function requireOperatorConnection(options = {}) {
  const requiredScope = options.scope;
  const authenticate = options.authenticateCredential || authenticateCredential;
  const touch = options.recordUse || recordUse;
  if (typeof requiredScope !== "string" || !requiredScope.startsWith("mcp:")) {
    throw new Error("requireOperatorConnection needs a scope");
  }
  const requiredRole = options.minRole || null;

  return async function operatorConnectionGuard(req, res, next) {
    // A session or worker identity alongside a bearer credential is ambiguous.
    // Refuse rather than let the stronger identity win.
    if (hasSessionIdentity(req)) {
      return res.status(401).json({
        error: "Session identity is not allowed with an operator connection",
        code: OPERATOR_SESSION_FORBIDDEN,
      });
    }
    const bearer = bearerFromRequest(req);
    if (!bearer.present || !bearer.raw || !looksLikeOperatorCredential(bearer.raw)) {
      return res.status(401).json(UNAUTHORIZED_BODY);
    }

    let result;
    try {
      result = await authenticate({ client: options.client, rawCredential: bearer.raw });
    } catch (error) {
      return next(error);
    }
    if (!result?.valid) return res.status(401).json(UNAUTHORIZED_BODY);

    const { connection, authority } = result;
    if (!authority.scopes.includes(requiredScope)) {
      return res.status(403).json({
        error: "Operator connection scope denied",
        code: OPERATOR_SCOPE_DENIED,
      });
    }
    if (requiredRole && !hasAtLeastRole(authority.effectiveRole, requiredRole)) {
      return res.status(403).json({
        error: "Operator connection scope denied",
        code: OPERATOR_SCOPE_DENIED,
      });
    }

    req.operator = Object.freeze({
      connectionId: connection.id,
      userId: connection.userId,
      workspaceId: connection.workspaceId,
      scopes: Object.freeze([...authority.scopes]),
      role: authority.effectiveRole,
      roleCeiling: authority.ceiling,
      currentRole: authority.currentRole,
      expiresAt: connection.expiresAt,
    });
    await touch({ client: options.client, connectionId: connection.id });
    return next();
  };
}

module.exports = {
  OPERATOR_PATH_PREFIX,
  OPERATOR_ROUTE_FORBIDDEN,
  OPERATOR_SCOPE_DENIED,
  OPERATOR_SESSION_FORBIDDEN,
  OPERATOR_UNAUTHORIZED,
  bearerFromRequest,
  guardOperatorCredentials,
  hasSessionIdentity,
  isOperatorRoute,
  isRedeemRequest,
  looksLikeEnrollmentGrant,
  looksLikeOperatorCredential,
  requireOperatorConnection,
};
