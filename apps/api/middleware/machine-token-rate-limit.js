"use strict";

const rateLimit = require("express-rate-limit");

const { CERTOPS_API_TOKEN_UNAUTHORIZED } = require("./api-token-auth");
const { logger, resolveClientIp } = require("../utils/logger");

const CERTOPS_MACHINE_RATE_LIMITED = "CERTOPS_MACHINE_RATE_LIMITED";
const CERTOPS_MACHINE_RATE_LIMIT_CONFIG_INVALID =
  "CERTOPS_MACHINE_RATE_LIMIT_CONFIG_INVALID";
const CERTOPS_MACHINE_RATE_LIMIT_STORE_REQUIRED =
  "CERTOPS_MACHINE_RATE_LIMIT_STORE_REQUIRED";

const DEFAULT_WINDOW_MS = 60_000;
const DEFAULT_MAX = 120;
const RAW_TOKEN_PATTERN = /^ttx_([a-f0-9]{16})_([a-f0-9]{64})$/;
const UUID_SEGMENT_PATTERN =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;

const AUTH_REQUIRED_RESPONSE = Object.freeze({
  error: "CertOps API token authentication required",
  code: CERTOPS_API_TOKEN_UNAUTHORIZED,
});

const RATE_LIMIT_RESPONSE = Object.freeze({
  error: "CertOps machine-token rate limit exceeded",
  code: CERTOPS_MACHINE_RATE_LIMITED,
});

function limiterError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function hasConfiguredValue(value) {
  return !(
    value === undefined ||
    value === null ||
    (typeof value === "string" && !value.trim())
  );
}

function configuredInteger(value, fallback, { allowZero = false } = {}) {
  if (!hasConfiguredValue(value)) return fallback;

  const parsed =
    typeof value === "number"
      ? value
      : typeof value === "string" && /^\d+$/.test(value.trim())
        ? Number(value.trim())
        : Number.NaN;
  if (
    !Number.isFinite(parsed) ||
    !Number.isInteger(parsed) ||
    (allowZero ? parsed < 0 : parsed <= 0)
  ) {
    throw limiterError(
      "CertOps machine-token rate limit configuration is invalid",
      CERTOPS_MACHINE_RATE_LIMIT_CONFIG_INVALID,
    );
  }
  return parsed;
}

function rateLimitOptions(options = {}) {
  const configuredLimit = hasConfiguredValue(options.limit)
    ? options.limit
    : options.max;

  return {
    limit: configuredInteger(configuredLimit, DEFAULT_MAX, {
      allowZero: true,
    }),
    windowMs: configuredInteger(options.windowMs, DEFAULT_WINDOW_MS),
  };
}

function requireSharedStoreIfConfigured(options = {}) {
  if (options.requireSharedStore === true && !options.store) {
    throw limiterError(
      "A shared store is required for CertOps machine-token rate limiting",
      CERTOPS_MACHINE_RATE_LIMIT_STORE_REQUIRED,
    );
  }
}

function safeKeyFragment(value, fallback = null) {
  if (typeof value !== "string") return fallback;
  const trimmed = value.trim();
  if (!trimmed) return fallback;
  return trimmed.replace(/[^A-Za-z0-9._:-]/g, "_").slice(0, 128) || fallback;
}

function isDynamicPathSegment(segment) {
  return (
    UUID_SEGMENT_PATTERN.test(segment) ||
    /^[0-9]+$/.test(segment) ||
    /^[a-f0-9]{16,}$/i.test(segment) ||
    /^ttx_/i.test(segment) ||
    segment.length > 64
  );
}

function normalizeRouteFamily(value) {
  if (typeof value !== "string") return "unknown";

  const pathOnly = value.split(/[?#]/, 1)[0].trim();
  if (!pathOnly) return "unknown";

  const segments = pathOnly
    .split("/")
    .filter(Boolean)
    .map((segment) => {
      const normalized = segment.replace(/[^A-Za-z0-9:_-]/g, "_").slice(0, 64);
      if (!normalized || isDynamicPathSegment(normalized)) return "id";
      return normalized.toLowerCase();
    });

  return safeKeyFragment(segments.join("_"), "unknown");
}

function defaultRouteFamilyResolver(req) {
  const routePath = typeof req.route?.path === "string" ? req.route.path : null;
  if (routePath) return `${req.baseUrl || ""}${routePath}`;
  return req.path || req.originalUrl || req.url || "";
}

function routeFamilyFromRequest(req, options = {}) {
  const resolver = options.routeFamilyResolver || defaultRouteFamilyResolver;
  return normalizeRouteFamily(resolver(req));
}

function safeRoutePattern(req, options = {}) {
  return routeFamilyFromRequest(req, options);
}

function defaultMachineIdResolver(req) {
  return req.apiToken?.agentId || req.apiToken?.executorId || null;
}

function machineTokenRateLimitKey(req, options = {}) {
  const identity = req.apiToken || {};
  const workspaceId = safeKeyFragment(identity.workspaceId);
  const tokenPrefix = safeKeyFragment(identity.tokenPrefix);

  if (!workspaceId || !tokenPrefix) return null;

  const resolveMachineId =
    options.machineIdResolver ||
    options.agentOrExecutorIdResolver ||
    defaultMachineIdResolver;
  const machineId = safeKeyFragment(resolveMachineId(req));

  // Shared per-token bucket across executor machine-write routes (no route segment).
  const baseKey = `certops-machine:${workspaceId}:${tokenPrefix}`;
  return machineId ? `${baseKey}:${machineId}` : baseKey;
}

function authorizationHeader(req) {
  const value =
    typeof req.get === "function"
      ? req.get("Authorization")
      : req.headers?.authorization;
  return typeof value === "string" ? value.trim() : "";
}

function tokenPrefixFromAuthorization(req) {
  const match = /^Bearer\s+(ttx_[a-f0-9]{16}_[a-f0-9]{64})$/i.exec(
    authorizationHeader(req),
  );
  if (!match || match[1] !== match[1].toLowerCase()) return null;

  const tokenMatch = RAW_TOKEN_PATTERN.exec(match[1]);
  return tokenMatch ? `ttx_${tokenMatch[1]}` : null;
}

function preAuthWorkspaceId(req, options = {}) {
  const paramName = options.workspaceIdParam || "workspaceId";
  return safeKeyFragment(req.params?.[paramName], "workspace-unknown");
}

function machineTokenPreAuthRateLimitKey(req, options = {}) {
  const workspaceId = preAuthWorkspaceId(req, options);
  const tokenPrefix = tokenPrefixFromAuthorization(req);
  const identity = tokenPrefix
    ? `prefix:${tokenPrefix}`
    : `ip:${safeKeyFragment(resolveClientIp(req), "unknown")}`;

  // Shared pre-auth budget across executor routes (prefix or IP fallback).
  return `certops-machine-preauth:${workspaceId}:${identity}`;
}

function retryAfterSeconds(req, windowMs) {
  const resetTime = req.rateLimit?.resetTime;
  if (resetTime instanceof Date) {
    return Math.max(1, Math.ceil((resetTime.getTime() - Date.now()) / 1000));
  }
  return Math.max(1, Math.ceil(windowMs / 1000));
}

function createRateLimitHandler({ windowMs, preAuth, options }) {
  return (req, res) => {
    const retryAfter = retryAfterSeconds(req, windowMs);

    logger.warn("RATE_LIMIT_EXCEEDED", {
      type: "certops_machine_token",
      phase: preAuth ? "pre_auth" : "post_auth",
      workspaceId: preAuth
        ? preAuthWorkspaceId(req, options)
        : safeKeyFragment(req.apiToken?.workspaceId),
      routeFamily: routeFamilyFromRequest(req, options),
      ip: resolveClientIp(req),
      retryAfterSeconds: retryAfter,
    });

    res.set("Retry-After", String(retryAfter));
    return res.status(429).json({
      ...RATE_LIMIT_RESPONSE,
      retryAfterSeconds: retryAfter,
    });
  };
}

function createLimiter(options, { preAuth, keyResolver }) {
  requireSharedStoreIfConfigured(options);
  const { windowMs, limit } = rateLimitOptions(options);
  const handler = createRateLimitHandler({ windowMs, preAuth, options });

  if (limit === 0) {
    return {
      limiter: (req, res) => handler(req, res),
      keyResolver,
    };
  }

  const limiter = rateLimit({
    windowMs,
    limit,
    standardHeaders: options.standardHeaders ?? true,
    legacyHeaders: options.legacyHeaders ?? false,
    skipSuccessfulRequests: options.skipSuccessfulRequests ?? false,
    skipFailedRequests: options.skipFailedRequests ?? false,
    ...(options.store ? { store: options.store } : {}),
    keyGenerator: (req) => keyResolver(req, options),
    handler,
  });

  return { limiter, keyResolver };
}

// Cloud overlays should pass a distributed store and set requireSharedStore.
// Core intentionally uses express-rate-limit's in-memory store by default.
function createCertOpsMachineTokenRateLimit(options = {}) {
  const keyResolver = options.keyResolver || machineTokenRateLimitKey;
  const { limiter } = createLimiter(options, { preAuth: false, keyResolver });

  return function certOpsMachineTokenRateLimit(req, res, next) {
    if (!keyResolver(req, options)) {
      return res.status(401).json(AUTH_REQUIRED_RESPONSE);
    }
    return limiter(req, res, next);
  };
}

function createCertOpsMachineTokenPreAuthRateLimit(options = {}) {
  const keyResolver = options.keyResolver || machineTokenPreAuthRateLimitKey;
  const { limiter } = createLimiter(options, { preAuth: true, keyResolver });

  return function certOpsMachineTokenPreAuthRateLimit(req, res, next) {
    return limiter(req, res, next);
  };
}

module.exports = {
  CERTOPS_MACHINE_RATE_LIMITED,
  CERTOPS_MACHINE_RATE_LIMIT_CONFIG_INVALID,
  CERTOPS_MACHINE_RATE_LIMIT_STORE_REQUIRED,
  DEFAULT_MAX,
  DEFAULT_WINDOW_MS,
  createCertOpsMachineTokenPreAuthRateLimit,
  createCertOpsMachineTokenRateLimit,
  createMachineTokenPreAuthRateLimit: createCertOpsMachineTokenPreAuthRateLimit,
  createMachineTokenRateLimit: createCertOpsMachineTokenRateLimit,
  machineTokenPreAuthRateLimitKey,
  machineTokenRateLimitKey,
  tokenPrefixFromAuthorization,
  _test: {
    configuredInteger,
    defaultMachineIdResolver,
    defaultRouteFamilyResolver,
    normalizeRouteFamily,
    rateLimitOptions,
    retryAfterSeconds,
    routeFamilyFromRequest,
    safeKeyFragment,
    safeRoutePattern,
  },
};
