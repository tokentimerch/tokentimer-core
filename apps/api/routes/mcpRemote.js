"use strict";

const express = require("express");
const rateLimit = require("express-rate-limit");
const { isIP } = require("node:net");
const { requireAuth } = require("../middleware/auth");
const { getApiLimiter } = require("../middleware/rateLimit");
const {
  bearerFromRequest,
  hasSessionIdentity,
} = require("../middleware/operator-connection-auth");
const {
  remoteConfig,
  MCP_PATH,
  OAUTH_PATH,
  OAUTH_SCOPE,
} = require("../services/operator/remoteConfig");
const { forwardingHeaders } = require("../services/operator/remoteForwarding");
const oauth = require("../services/operator/oauth");
const { UUID, oauthError } = require("../services/operator/oauthProtocol");
const { resolveSessionCookieOptions } = require("../session-cookie-options");
const { logger } = require("../utils/logger");
const publicLimiter = (max) =>
  rateLimit({
    windowMs: 60000,
    limit: process.env.NODE_ENV === "test" ? 10000 : max,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, res) =>
      res.status(429).json({ error: "temporarily_unavailable" }),
  });
const registrationLimiter = publicLimiter(20);
const authorizationLimiter = publicLimiter(60);
const tokenLimiter = publicLimiter(300);

function cookieName(id) {
  return "mcp-consent-" + id;
}
function cookieOptions(config) {
  return {
    httpOnly: true,
    secure: config.secureCookie,
    sameSite: resolveSessionCookieOptions(process.env).sameSite,
    path: new URL(config.oauthBase).pathname,
    maxAge: oauth.REQUEST_SECONDS * 1000,
  };
}
function noStore(_req, res, next) {
  res.set({
    "Cache-Control": "no-store",
    Pragma: "no-cache",
    "Referrer-Policy": "no-referrer",
  });
  next();
}
function sessionOnly(req, res, next) {
  if (
    !req.user?.id ||
    req.isWorkerCall ||
    typeof req.sessionID !== "string" ||
    typeof req.isAuthenticated !== "function" ||
    !req.isAuthenticated() ||
    bearerFromRequest(req).present
  )
    return res.status(401).json({ error: "login_required" });
  next();
}
function machineOnly(req, res, next) {
  if (hasSessionIdentity(req) || bearerFromRequest(req).present)
    return res.status(400).json({ error: "invalid_request" });
  if (!req.body || typeof req.body !== "object" || Array.isArray(req.body))
    return res.status(400).json({ error: "invalid_request" });
  next();
}
function errorReply(res, error) {
  // Unexpected transport errors may carry request or client metadata.
  // Keep diagnostics useful without writing arbitrary exception contents.
  if (!error.oauthCode) logger.error("Remote MCP request failed", { code: "UNEXPECTED_REMOTE_ERROR" });
  return res
    .status(error.oauthCode ? error.status : 500)
    .json({ error: error.oauthCode || "server_error" });
}
function consentInput(req) {
  const id = req.params.requestId;
  return {
    requestId: id,
    browserNonce: UUID.test(String(id || ""))
      ? req.cookies?.[cookieName(id)]
      : null,
    userId: req.user.id,
    sessionId: req.sessionID,
  };
}

function isRemoteMcpPath(req) {
  const path = String(req.originalUrl || req.url).split("?")[0];
  if (remoteParserKind(path)) return true;
  if (
    [
      "/.well-known/oauth-protected-resource",
      "/.well-known/oauth-authorization-server",
      "/.well-known/oauth-protected-resource" + MCP_PATH,
    ].includes(path)
  )
    return true;
  if (!path.startsWith("/.well-known/oauth-")) return false;
  const config = remoteConfig();
  return Boolean(
    config &&
    [config.metadataPath, config.authorizationMetadataPath].includes(path),
  );
}

// Express matches literal routes case-insensitively and allows a trailing slash.
// Match those same aliases before CORS and body parsing.
function remoteParserKind(path) {
  const lower = path.toLowerCase();
  if (lower === MCP_PATH || lower === MCP_PATH + "/") return "mcp";
  if (lower.startsWith(OAUTH_PATH + "/")) return "oauth";
  return null;
}

// Isolated from general API CORS: trusting an MCP browser origin must never
// give that origin access to the account/session API.
function remoteCors(req, res, next) {
  let config;
  try {
    if (!isRemoteMcpPath(req)) return next();
    config = remoteConfig();
  } catch (error) {
    return errorReply(res, error);
  }
  if (!config) return res.status(404).json({ error: "not_found" });
  if (String(req.get("host") || "").toLowerCase() !== config.host)
    return res.status(403).json({ error: "invalid_host" });
  const origin = req.get("origin"),
    consent = req.path.toLowerCase().startsWith(OAUTH_PATH + "/requests/");
  const allowed = consent
    ? new Set([new URL(config.appUrl).origin, new URL(config.resource).origin])
    : config.origins;
  if (origin && !allowed.has(origin))
    return res.status(403).json({ error: "invalid_origin" });
  if (origin) {
    res.vary("Origin");
    res.set("Access-Control-Allow-Origin", origin);
    if (consent) res.set("Access-Control-Allow-Credentials", "true");
    res.set(
      "Access-Control-Allow-Headers",
      "Authorization, Content-Type, X-CSRF-Token, MCP-Protocol-Version, MCP-Session-Id, Last-Event-ID",
    );
    res.set(
      "Access-Control-Expose-Headers",
      "WWW-Authenticate, MCP-Protocol-Version, MCP-Session-Id, Retry-After",
    );
    res.set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  }
  req.mcpRemoteConfig = config;
  if (req.method === "OPTIONS") return res.sendStatus(204);
  return next();
}

// Mount before the general JSON parser; public endpoints have small body caps.
function createRemoteBodyParser({ limit = process.env.NODE_ENV === "test" ? 10000 : 1000 } = {}) {
  const limiter = rateLimit({
    windowMs: 60000,
    limit,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, res) => res.status(429).json({ error: "temporarily_unavailable" }),
  });
  const mcpParser = express.json({ limit: "256kb", strict: true });
  const oauthJson = express.json({ limit: "16kb", strict: true });
  const oauthForm = express.urlencoded({ extended: false, limit: "16kb", parameterLimit: 20 });
  return (req, res, next) => {
    const path = String(req.originalUrl || req.url).split("?")[0];
    const kind = remoteParserKind(path);
    const parser = kind === "mcp" ? mcpParser : kind === "oauth"
      ? (req.is("application/x-www-form-urlencoded") ? oauthForm : oauthJson)
      : null;
    if (!parser) return next();
    return limiter(req, res, (error) => error ? next(error) : parser(req, res, next));
  };
}
const remoteBodyParser = createRemoteBodyParser();

function createMcpRemoteRouter({ admitWorkspace } = {}) {
  const router = express.Router();
  let handler;
  router.use(remoteCors);
  router.use((req, res, next) => {
    if (!req.mcpRemoteConfig) return next();
    const config = req.mcpRemoteConfig;
    if (
      [config.metadataPath, "/.well-known/oauth-protected-resource"].includes(
        req.path,
      ) &&
      req.method === "GET"
    ) {
      return res.json({
        resource: config.resource,
        authorization_servers: [config.issuer],
        scopes_supported: [OAUTH_SCOPE],
        bearer_methods_supported: ["header"],
      });
    }
    if (
      [
        config.authorizationMetadataPath,
        "/.well-known/oauth-authorization-server",
      ].includes(req.path) &&
      req.method === "GET"
    ) {
      return res.json({
        issuer: config.issuer,
        authorization_endpoint: config.oauthBase + "/authorize",
        token_endpoint: config.oauthBase + "/token",
        registration_endpoint: config.oauthBase + "/register",
        revocation_endpoint: config.oauthBase + "/revoke",
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        token_endpoint_auth_methods_supported: ["none"],
        revocation_endpoint_auth_methods_supported: ["none"],
        code_challenge_methods_supported: ["S256"],
        scopes_supported: [OAUTH_SCOPE],
        client_id_metadata_document_supported: false,
        authorization_response_iss_parameter_supported: true,
      });
    }
    return next();
  });

  router.post(
    OAUTH_PATH + "/register",
    noStore,
    registrationLimiter,
    machineOnly,
    async (req, res) => {
      try {
        const client = await oauth.registerClient(req.body);
        const { clientId, ...metadata } = client;
        return res.status(201).json({
          client_id: clientId,
          client_id_issued_at: Math.floor(Date.now() / 1000),
          ...metadata,
        });
      } catch (error) {
        return errorReply(res, error);
      }
    },
  );
  router.get(
    OAUTH_PATH + "/authorize",
    noStore,
    authorizationLimiter,
    async (req, res) => {
      try {
        // Bound browser cookies as well as database rows. Repeated public
        // initiation must not evict the normal sign-in cookie.
        if (
          Object.keys(req.cookies || {}).filter((name) =>
            name.startsWith("mcp-consent-"),
          ).length >= 8
        ) {
          throw oauthError("temporarily_unavailable", 429);
        }
        const created = await oauth.beginAuthorization(
          req.query,
          req.mcpRemoteConfig,
        );
        res.cookie(
          cookieName(created.id),
          created.browserNonce,
          cookieOptions(req.mcpRemoteConfig),
        );
        return res.redirect(
          303,
          req.mcpRemoteConfig.appUrl + "/mcp/authorize?request=" + created.id,
        );
      } catch (error) {
        return errorReply(res, error);
      }
    },
  );
  router.get(
    OAUTH_PATH + "/requests/:requestId",
    noStore,
    getApiLimiter(),
    requireAuth,
    sessionOnly,
    async (req, res) => {
      try {
        return res.json(
          await oauth.getConsentDetails(consentInput(req), req.mcpRemoteConfig),
        );
      } catch (error) {
        return errorReply(res, error);
      }
    },
  );
  router.post(
    OAUTH_PATH + "/requests/:requestId/decision",
    noStore,
    getApiLimiter(),
    requireAuth,
    sessionOnly,
    async (req, res) => {
      try {
        if (
          !req.body ||
          Object.keys(req.body).some(
            (key) =>
              ![
                "decision",
                "workspaceId",
                "lifetimeDays",
                "noExpiry",
                "inventoryImport",
                "inventoryUpdate",
                "contactCreate",
                "webhookCreate",
                "groupCreate",
                "memberInvite",
                "issuance",
                "renewals",
                "agentHealth",
              ].includes(key),
          )
        )
          throw oauthError("invalid_request");
        const result = await oauth.decideAuthorization(
          { ...req.body, ...consentInput(req) },
          { config: req.mcpRemoteConfig, admitWorkspace },
        );
        const { maxAge: _maxAge, ...clearOptions } = cookieOptions(
          req.mcpRemoteConfig,
        );
        res.clearCookie(cookieName(req.params.requestId), clearOptions);
        return res.json(result);
      } catch (error) {
        return errorReply(res, error);
      }
    },
  );
  router.post(
    OAUTH_PATH + "/token",
    noStore,
    tokenLimiter,
    machineOnly,
    async (req, res) => {
      try {
        return res.json(
          await oauth.exchangeToken(req.body, req.mcpRemoteConfig),
        );
      } catch (error) {
        return errorReply(res, error);
      }
    },
  );
  router.post(
    OAUTH_PATH + "/revoke",
    noStore,
    tokenLimiter,
    machineOnly,
    async (req, res) => {
      try {
        await oauth.revokeToken(req.body, req.mcpRemoteConfig);
        return res.sendStatus(200);
      } catch (error) {
        return errorReply(res, error);
      }
    },
  );

  router.all(MCP_PATH, noStore, getApiLimiter(), async (req, res) => {
    const config = req.mcpRemoteConfig,
      bearer = bearerFromRequest(req);
    try {
      const authenticated =
        !hasSessionIdentity(req) && bearer.raw
          ? await oauth.authenticateAccess({
              rawCredential: bearer.raw,
              config,
            })
          : { valid: false };
      if (!authenticated.valid) {
        res.set(
          "WWW-Authenticate",
          `Bearer resource_metadata="${new URL(config.resource).origin}${config.metadataPath}", scope="${OAUTH_SCOPE}"`,
        );
        return res.status(401).json({ error: "invalid_token" });
      }
      const address = req.socket.localAddress,
        port = req.socket.localPort;
      if (!isIP(address) || !Number.isInteger(port))
        throw new Error("The API listener address is unavailable");
      const apiOrigin = `http://${isIP(address) === 6 ? `[${address}]` : address}:${port}`;
      req.auth = {
        token: bearer.raw,
        clientId: authenticated.oauth.clientId,
        scopes: [OAUTH_SCOPE],
        expiresAt: authenticated.oauth.expiresAt,
        resource: new URL(config.resource),
        extra: {
          apiOrigin,
          operatorScopes: authenticated.authority.scopes,
          forwardingHeaders: forwardingHeaders(
            bearer.raw,
            authenticated.connection.id,
          ),
        },
      };
      if (!handler) handler = require("@tokentimer/mcp").createRemoteHandler();
      return await handler(req, res, req.body);
    } catch (error) {
      if (!res.headersSent) return errorReply(res, error);
      return res.end();
    }
  });
  return router;
}

module.exports = {
  createMcpRemoteRouter,
  remoteBodyParser,
  createRemoteBodyParser,
  remoteCors,
  isRemoteMcpPath,
};
