"use strict";

const rateLimit = require("express-rate-limit");

const { CERTOPS_API_TOKEN_UNAUTHORIZED } = require("./api-token-auth");
const { logger, resolveClientIp } = require("../utils/logger");

const CERTOPS_MACHINE_RATE_LIMITED = "CERTOPS_MACHINE_RATE_LIMITED";

const DEFAULT_WINDOW_MS = 60_000;
const DEFAULT_MAX = 120;

const AUTH_REQUIRED_RESPONSE = Object.freeze({
  error: "CertOps API token authentication required",
  code: CERTOPS_API_TOKEN_UNAUTHORIZED,
});

const RATE_LIMIT_RESPONSE = Object.freeze({
  error: "CertOps machine-token rate limit exceeded",
  code: CERTOPS_MACHINE_RATE_LIMITED,
});

function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function safeRoutePattern(req) {
  return req.route?.path || req.baseUrl || null;
}

function defaultMachineIdResolver(req) {
  return (
    req.apiToken?.agentId ||
    req.apiToken?.executorId ||
    null
  );
}

function safeKeyFragment(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.replace(/[^A-Za-z0-9._:-]/g, "_").slice(0, 128);
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

  const baseKey = `certops-machine:${workspaceId}:${tokenPrefix}`;
  return machineId ? `${baseKey}:${machineId}` : baseKey;
}

function retryAfterSeconds(req, windowMs) {
  const resetTime = req.rateLimit?.resetTime;
  if (resetTime instanceof Date) {
    return Math.max(1, Math.ceil((resetTime.getTime() - Date.now()) / 1000));
  }
  return Math.max(1, Math.ceil(windowMs / 1000));
}

function createCertOpsMachineTokenRateLimit(options = {}) {
  const windowMs = positiveInteger(options.windowMs, DEFAULT_WINDOW_MS);
  const max = positiveInteger(options.max, DEFAULT_MAX);
  const keyResolver = options.keyResolver || machineTokenRateLimitKey;

  const limiter = rateLimit({
    windowMs,
    max,
    standardHeaders: options.standardHeaders ?? true,
    legacyHeaders: options.legacyHeaders ?? false,
    skipSuccessfulRequests: options.skipSuccessfulRequests ?? false,
    skipFailedRequests: options.skipFailedRequests ?? false,
    ...(options.store ? { store: options.store } : {}),
    keyGenerator: (req) => keyResolver(req, options),
    handler: (req, res) => {
      const retryAfter = retryAfterSeconds(req, windowMs);

      logger.warn("RATE_LIMIT_EXCEEDED", {
        type: "certops_machine_token",
        workspaceId: req.apiToken?.workspaceId || null,
        tokenPrefix: req.apiToken?.tokenPrefix || null,
        route: safeRoutePattern(req),
        ip: resolveClientIp(req),
        retryAfterSeconds: retryAfter,
      });

      res.set("Retry-After", String(retryAfter));
      return res.status(429).json({
        ...RATE_LIMIT_RESPONSE,
        retry_after_seconds: retryAfter,
      });
    },
  });

  return function certOpsMachineTokenRateLimit(req, res, next) {
    const key = keyResolver(req, options);
    if (!key) {
      return res.status(401).json(AUTH_REQUIRED_RESPONSE);
    }

    return limiter(req, res, next);
  };
}

module.exports = {
  CERTOPS_MACHINE_RATE_LIMITED,
  DEFAULT_MAX,
  DEFAULT_WINDOW_MS,
  createCertOpsMachineTokenRateLimit,
  createMachineTokenRateLimit: createCertOpsMachineTokenRateLimit,
  machineTokenRateLimitKey,
  _test: {
    defaultMachineIdResolver,
    retryAfterSeconds,
    safeKeyFragment,
    safeRoutePattern,
  },
};
