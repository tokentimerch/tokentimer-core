"use strict";

/**
 * Per-IP + provider_slug token-bucket rate limits for SSO browser routes.
 */

const DEFAULT_START_PER_MIN = 30;
const DEFAULT_START_BURST = 10;
const DEFAULT_CALLBACK_PER_MIN = 60;
const DEFAULT_CALLBACK_BURST = 20;
const DEFAULT_CALLBACK_FAILURE_WEIGHT = 2;

/** @type {Map<string, { tokens: number, lastRefill: number }>} */
const buckets = new Map();
const MAX_BUCKETS = 10_000;
const rejectedCallback = Symbol("rejectedSsoCallback");

function markSsoCallbackFailure(res) {
  res[rejectedCallback] = true;
}

function envInt(name, fallback) {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? Math.floor(v) : fallback;
}

function getLimits(phase) {
  if (phase === "callback") {
    return {
      perMin: envInt("SSO_RATE_LIMIT_CALLBACK_PER_MIN", DEFAULT_CALLBACK_PER_MIN),
      burst: envInt("SSO_RATE_LIMIT_CALLBACK_BURST", DEFAULT_CALLBACK_BURST),
      failureWeight: envInt(
        "SSO_RATE_LIMIT_CALLBACK_FAILURE_WEIGHT",
        DEFAULT_CALLBACK_FAILURE_WEIGHT,
      ),
    };
  }
  return {
    perMin: envInt("SSO_RATE_LIMIT_START_PER_MIN", DEFAULT_START_PER_MIN),
    burst: envInt("SSO_RATE_LIMIT_START_BURST", DEFAULT_START_BURST),
    failureWeight: 1,
  };
}

function pruneIfNeeded() {
  if (buckets.size <= MAX_BUCKETS) return;
  const drop = Math.floor(MAX_BUCKETS / 10);
  const keys = [...buckets.keys()].slice(0, drop);
  for (const k of keys) buckets.delete(k);
}

function clientIp(req) {
  if (req.ip) return req.ip;
  return req.socket?.remoteAddress || "unknown";
}

function extractProviderSlug(req) {
  const m = String(req.path || "").match(
    /^\/auth\/(?:oidc|saml)\/([^/]+)(?:\/|$)/i,
  );
  return m ? decodeURIComponent(m[1]) : "_unknown";
}

/**
 * @param {string} key
 * @param {{ perMin: number, burst: number }} limits
 * @param {number} [cost=1]
 * @returns {{ allowed: boolean, remaining: number, limit: number, retryAfterSec: number }}
 */
function consumeToken(key, limits, cost = 1) {
  const now = Date.now();
  const refillPerMs = limits.perMin / 60_000;
  let bucket = buckets.get(key);
  if (!bucket) {
    bucket = { tokens: limits.burst, lastRefill: now };
    buckets.set(key, bucket);
    pruneIfNeeded();
  }
  const elapsed = now - bucket.lastRefill;
  if (elapsed > 0) {
    bucket.tokens = Math.min(
      limits.burst,
      bucket.tokens + elapsed * refillPerMs,
    );
    bucket.lastRefill = now;
  }
  const limit = limits.burst;
  if (bucket.tokens < cost) {
    const deficit = cost - bucket.tokens;
    const retryAfterSec = Math.max(
      1,
      Math.ceil(deficit / refillPerMs / 1000),
    );
    return {
      allowed: false,
      remaining: 0,
      limit,
      retryAfterSec,
    };
  }
  bucket.tokens -= cost;
  return {
    allowed: true,
    remaining: Math.floor(bucket.tokens),
    limit,
    retryAfterSec: 0,
  };
}

function setRateLimitHeaders(res, result) {
  res.setHeader("RateLimit-Limit", String(result.limit));
  res.setHeader("RateLimit-Remaining", String(result.remaining));
  if (!result.allowed) {
    res.setHeader("Retry-After", String(result.retryAfterSec));
  }
}

/**
 * @param {{ phase?: 'start'|'callback' }} [opts]
 */
function createSsoRateLimitMiddleware(opts = {}) {
  const phase = opts.phase === "callback" ? "callback" : "start";
  const limits = getLimits(phase);

  return function ssoRateLimitMiddleware(req, res, next) {
    const slug = extractProviderSlug(req);
    const key = `${clientIp(req)}:${slug}:${phase}`;
    const result = consumeToken(key, limits, 1);
    setRateLimitHeaders(res, result);
    if (!result.allowed) {
      return res.status(429).json({
        error: "Too many SSO requests",
        code: "sso_rate_limited",
        retryAfterSec: result.retryAfterSec,
      });
    }
    if (phase === "callback" && limits.failureWeight > 1) {
      res.on("finish", () => {
        if (res[rejectedCallback] || res.statusCode >= 400) {
          const charged = consumeToken(key, limits, limits.failureWeight - 1);
          // The refusal already happened, so deduct as much of its surcharge as remains.
          if (!charged.allowed) buckets.get(key).tokens = 0;
        }
      });
    }
    return next();
  };
}

function _resetBucketsForTests() {
  buckets.clear();
}

module.exports = {
  createSsoRateLimitMiddleware,
  markSsoCallbackFailure,
  consumeToken,
  clientIp,
  extractProviderSlug,
  getLimits,
  _resetBucketsForTests,
};
