const rateLimit = require("express-rate-limit");
const { ipKeyGenerator } = require("express-rate-limit");
const slowDown = require("express-slow-down");
const { logger } = require("../utils/logger");
const { parseLimits } = require("../services/planLimits");
const { normalizeRootDomain } = require("../services/domainChecker");

function intEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === null || raw === "") return fallback;
  const parsed = Number.parseInt(String(raw), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

const isDevOrTest =
  process.env.NODE_ENV === "development" || process.env.NODE_ENV === "test";

/**
 * Normalize email for rate-limit key generation.
 * @param {string} [email]
 * @returns {string}
 */
function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

const globalLimiter = rateLimit({
  windowMs: intEnv("GLOBAL_RATE_LIMIT_WINDOW_MS", 1 * 60 * 1000),
  max: intEnv("GLOBAL_RATE_LIMIT_MAX", isDevOrTest ? 1000 : 300),
  message: "Too many requests from this IP, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: isDevOrTest,
  skipFailedRequests: false,
  keyGenerator: (req) => ipKeyGenerator(req),
});

const speedLimiter = slowDown({
  windowMs: intEnv("GLOBAL_SLOWDOWN_WINDOW_MS", 15 * 60 * 1000),
  delayAfter: intEnv("GLOBAL_SLOWDOWN_DELAY_AFTER", 50),
  delayMs: () => intEnv("GLOBAL_SLOWDOWN_DELAY_MS", 500),
  validate: { delayMs: false },
});

const loginLimiter = rateLimit({
  windowMs: intEnv("LOGIN_RATE_LIMIT_WINDOW_MS", 15 * 60 * 1000),
  max: intEnv("LOGIN_RATE_LIMIT_MAX", isDevOrTest ? 500 : 10),
  message: "Too many login attempts, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => {
    const ip = ipKeyGenerator(req);
    logger.info("Rate limiting key generated", { type: "login", ip });
    return ip;
  },
  handler: (req, res) => {
    logger.warn("RATE_LIMIT_EXCEEDED", {
      type: "login",
      ip: ipKeyGenerator(req),
      userAgent: req.get("User-Agent"),
    });
    res
      .status(429)
      .json({ error: "Too many login attempts, please try again later." });
  },
});

const loginEmailLimiter = rateLimit({
  windowMs: intEnv("LOGIN_RATE_LIMIT_WINDOW_MS", 15 * 60 * 1000),
  max: intEnv("LOGIN_EMAIL_RATE_LIMIT_MAX", isDevOrTest ? 500 : 5),
  message: "Too many login attempts for this account, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => {
    const email = normalizeEmail(req.body?.email);
    if (email) return `email:${email}`;
    return `ip:${ipKeyGenerator(req)}`;
  },
  handler: (req, res) => {
    logger.warn("RATE_LIMIT_EXCEEDED", {
      type: "login_email",
      email: normalizeEmail(req.body?.email) || null,
      ip: ipKeyGenerator(req),
      userAgent: req.get("User-Agent"),
    });
    res.status(429).json({
      error:
        "Too many login attempts for this account, please try again later.",
    });
  },
});

const passwordResetLimiter = rateLimit({
  windowMs: intEnv("PASSWORD_RESET_RATE_LIMIT_WINDOW_MS", 15 * 60 * 1000),
  max: intEnv("PASSWORD_RESET_RATE_LIMIT_MAX", isDevOrTest ? 100 : 5),
  message: "Too many password reset attempts, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => {
    const ip = ipKeyGenerator(req);
    logger.info("Rate limiting key generated", { type: "password_reset", ip });
    return ip;
  },
  handler: (req, res) => {
    logger.warn("RATE_LIMIT_EXCEEDED", {
      type: "password_reset",
      ip: ipKeyGenerator(req),
      userAgent: req.get("User-Agent"),
    });
    res.status(429).json({
      error: "Too many password reset attempts, please try again later.",
    });
  },
});

const passwordResetEmailLimiter = rateLimit({
  windowMs: intEnv("PASSWORD_RESET_RATE_LIMIT_WINDOW_MS", 15 * 60 * 1000),
  max: intEnv("PASSWORD_RESET_EMAIL_RATE_LIMIT_MAX", isDevOrTest ? 200 : 3),
  message:
    "Too many password reset requests for this email, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => `email:${normalizeEmail(req.body?.email)}`,
  handler: (req, res) => {
    logger.warn("RATE_LIMIT_EXCEEDED", {
      type: "password_reset_email",
      email: normalizeEmail(req.body?.email) || null,
      ip: ipKeyGenerator(req),
      userAgent: req.get("User-Agent"),
    });
    res.status(429).json({
      error:
        "Too many password reset requests for this email, please try again later.",
    });
  },
});

const authSlowdown = slowDown({
  windowMs: intEnv("AUTH_SLOWDOWN_WINDOW_MS", 15 * 60 * 1000),
  delayAfter: intEnv("AUTH_SLOWDOWN_DELAY_AFTER", isDevOrTest ? 1000 : 5),
  delayMs: () => intEnv("AUTH_SLOWDOWN_DELAY_MS", 500),
  maxDelayMs: intEnv("AUTH_SLOWDOWN_MAX_DELAY_MS", 10000),
  validate: { delayMs: false },
});

const emailVerificationLimiter = rateLimit({
  windowMs: intEnv("EMAIL_VERIFICATION_RATE_LIMIT_WINDOW_MS", 60 * 60 * 1000),
  max: intEnv("EMAIL_VERIFICATION_RATE_LIMIT_MAX", isDevOrTest ? 500 : 20),
  message: "Too many email verification attempts, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => {
    const ip = ipKeyGenerator(req);
    logger.info("Rate limiting key generated", {
      type: "email_verification",
      ip,
    });
    return ip;
  },
  handler: (req, res) => {
    logger.warn("RATE_LIMIT_EXCEEDED", {
      type: "email_verification",
      ip: ipKeyGenerator(req),
      userAgent: req.get("User-Agent"),
    });
    res.status(429).json({
      error: "Too many email verification attempts, please try again later.",
    });
  },
});

const API_LIMITS = parseLimits(process.env.PLAN_API_LIMITS, { oss: 6000 });

function createApiLimiter(max, label) {
  return rateLimit({
    windowMs: intEnv("API_RATE_LIMIT_WINDOW_MS", 15 * 60 * 1000),
    max,
    message: "Too many API requests, please try again later.",
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false,
    keyGenerator: (req) => {
      if (req.user && req.user.id) {
        logger.info("Rate limiting key generated", {
          type: `api_user_${label}`,
          userId: req.user.id,
        });
        return `user-${req.user.id}`;
      }
      const ip = ipKeyGenerator(req);
      logger.info("Rate limiting key generated", {
        type: `api_ip_${label}`,
        ip,
      });
      return ip;
    },
    handler: (req, res) => {
      if (req.user && req.user.id) {
        logger.warn("RATE_LIMIT_EXCEEDED", {
          type: `api_user_${label}`,
          userId: req.user.id,
          plan: "oss",
          ip: ipKeyGenerator(req),
          userAgent: req.get("User-Agent"),
        });
      } else {
        logger.warn("RATE_LIMIT_EXCEEDED", {
          type: `api_ip_${label}`,
          ip: ipKeyGenerator(req),
          userAgent: req.get("User-Agent"),
        });
      }
      res.status(429).json({
        error:
          "Too many API requests, please wait a few seconds and try again.",
      });
    },
  });
}

const ossLimiter = createApiLimiter(API_LIMITS.oss, "oss");
const planAwareApiLimiter = (req, res, next) => ossLimiter(req, res, next);

const testApiLimiter = rateLimit({
  windowMs: intEnv("TEST_API_RATE_LIMIT_WINDOW_MS", 15 * 60 * 1000),
  max: intEnv("TEST_API_RATE_LIMIT_MAX", isDevOrTest ? 10000 : 1000),
  message: "Too many API requests, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => {
    if (req.user && req.user.id) {
      logger.info("Rate limiting key generated", {
        type: "test_api_user",
        userId: req.user.id,
      });
      return `user-${req.user.id}`;
    }
    const ip = ipKeyGenerator(req);
    logger.info("Rate limiting key generated", { type: "test_api_ip", ip });
    return ip;
  },
  handler: (req, res) => {
    if (req.user && req.user.id) {
      logger.warn("RATE_LIMIT_EXCEEDED", {
        type: "test_api_user",
        userId: req.user.id,
        ip: ipKeyGenerator(req),
        userAgent: req.get("User-Agent"),
      });
    } else {
      logger.warn("RATE_LIMIT_EXCEEDED", {
        type: "test_api_ip",
        ip: ipKeyGenerator(req),
        userAgent: req.get("User-Agent"),
      });
    }
    res
      .status(429)
      .json({ error: "Too many API requests, please try again later." });
  },
});

const domainCheckerLookupLimiter = rateLimit({
  windowMs: intEnv("DOMAIN_CHECKER_LOOKUP_RATE_LIMIT_WINDOW_MS", 60 * 1000),
  max: Math.max(1, intEnv("DOMAIN_CHECKER_LOOKUP_RATE_LIMIT_MAX", 1)),
  message:
    "Domain checker lookup is rate limited. Please wait before trying again.",
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  skip: (req) => !normalizeRootDomain(req.body?.domain),
  keyGenerator: (req) => {
    const workspaceId = req.workspace?.id || req.params?.id || "unknown";
    if (req.user && req.user.id) {
      return `domain-checker:${workspaceId}:user-${req.user.id}`;
    }
    return `domain-checker:${workspaceId}:ip-${ipKeyGenerator(req)}`;
  },
  handler: (req, res) => {
    const windowMs = intEnv(
      "DOMAIN_CHECKER_LOOKUP_RATE_LIMIT_WINDOW_MS",
      60 * 1000,
    );
    const fallbackRetrySec = Math.max(1, Math.ceil(windowMs / 1000));
    const resetTime = req.rateLimit?.resetTime;
    const retryAfterSeconds =
      resetTime instanceof Date
        ? Math.max(1, Math.ceil((resetTime.getTime() - Date.now()) / 1000))
        : fallbackRetrySec;
    logger.warn("RATE_LIMIT_EXCEEDED", {
      type: "domain_checker_lookup",
      userId: req.user?.id || null,
      workspaceId: req.workspace?.id || req.params?.id || null,
      ip: ipKeyGenerator(req),
      userAgent: req.get("User-Agent"),
      retryAfterSeconds,
    });
    res.set("Retry-After", String(retryAfterSeconds));
    res.status(429).json({
      error:
        "Domain checker lookup is rate limited. Please wait before trying again.",
      code: "DOMAIN_CHECKER_RATE_LIMITED",
      retry_after_seconds: retryAfterSeconds,
    });
  },
});

let resolvedApiLimiter;
/**
 * Returns the API rate-limit middleware (resolved once per process).
 * @returns {import("express").RequestHandler}
 */
function getApiLimiter() {
  return function apiLimiterMiddleware(req, res, next) {
    if (!resolvedApiLimiter) {
      resolvedApiLimiter =
        process.env.NODE_ENV === "development" ||
        process.env.NODE_ENV === "test"
          ? testApiLimiter
          : planAwareApiLimiter;
    }
    return resolvedApiLimiter(req, res, next);
  };
}

const noRateLimit = (req, res, next) => next();

/**
 * Returns test API limiter (no limit in dev/test, otherwise plan-aware).
 * @returns {import("express").RequestHandler}
 */
const getTestApiLimiter = () => {
  return process.env.NODE_ENV === "development" ||
    process.env.NODE_ENV === "test"
    ? noRateLimit
    : planAwareApiLimiter;
};

function getDomainCheckerLookupLimiter() {
  return domainCheckerLookupLimiter;
}

/**
 * Apply global rate limit unless path is auth/session or user is authenticated.
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 * @param {import("express").NextFunction} next
 */
function applyGlobalRateLimit(req, res, next) {
  if (req.path.startsWith("/auth/")) return next();
  if (req.path === "/api/session" || req.path === "/api/csrf-token")
    return next();
  if (req.path.startsWith("/api/") && req.user && req.user.id) return next();
  if (
    (process.env.NODE_ENV === "development" ||
      process.env.NODE_ENV === "test") &&
    req.path.startsWith("/api/")
  )
    return next();
  return globalLimiter(req, res, next);
}

module.exports = {
  globalLimiter,
  speedLimiter,
  loginLimiter,
  loginEmailLimiter,
  passwordResetLimiter,
  passwordResetEmailLimiter,
  authSlowdown,
  emailVerificationLimiter,
  planAwareApiLimiter,
  getApiLimiter,
  getDomainCheckerLookupLimiter,
  getTestApiLimiter,
  noRateLimit,
  applyGlobalRateLimit,
  normalizeEmail,
};
