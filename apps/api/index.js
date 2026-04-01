try {
  require("dotenv").config();
} catch (_err) {
  logger.debug("Non-critical operation failed", { error: _err.message });
}
const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const passport = require("passport");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const { pool } = require("./db/database");
const { setPool: setEmailPool } = require("./services/emailService");
const { setPool: setTwilioPool } = require("./services/twilioWhatsApp");

// Pass pool to services that need DB-based settings resolution
setEmailPool(pool);
setTwilioPool(pool);
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");
const client = require("prom-client");
const { doubleCsrf } = require("csrf-csrf");
const { logger } = require("./utils/logger.js");
const { writeAudit } = require("./services/audit");
const {
  loadWorkspace,
  requireWorkspaceMembership,
} = require("./services/rbac");

const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "TokenTimer API",
      version: "1.0.0",
      description: "Secure token management API",
    },
    servers: [
      {
        url: "http://localhost:4000",
        description: "Development server",
      },
    ],
  },
  apis: ["./index.js"],
};

swaggerJsdoc(swaggerOptions);
const OPENAPI_RELATIVE_PATH = "packages/contracts/openapi/openapi.yaml";
const resolveOpenApiSpecPath = () => {
  const configuredPath = process.env.OPENAPI_SPEC_PATH;
  const candidates = [
    configuredPath,
    path.resolve(__dirname, "../../", OPENAPI_RELATIVE_PATH),
    path.resolve(__dirname, "../", OPENAPI_RELATIVE_PATH),
    path.resolve(process.cwd(), OPENAPI_RELATIVE_PATH),
    path.resolve(process.cwd(), "../", OPENAPI_RELATIVE_PATH),
    path.resolve(process.cwd(), "../../", OPENAPI_RELATIVE_PATH),
    path.resolve("/app", OPENAPI_RELATIVE_PATH),
  ];

  return candidates.find(
    (candidatePath) =>
      typeof candidatePath === "string" && fs.existsSync(candidatePath),
  );
};
const app = express();

// Prometheus metrics (shared module ensures counters are registered once)
const {
  httpRequestDuration,
  httpRequestsTotal,
  loginAttempts,
  login2faVerifications,
  rateLimitHits,
} = require("./utils/metrics");
const metricsEnabled = process.env.ENABLE_METRICS === "true";

// Metrics endpoint (Prometheus scrape)
if (metricsEnabled) {
  app.get("/metrics", async (_req, res) => {
    try {
      res.set("Content-Type", client.register.contentType);
      const body = await client.register.metrics();
      res.status(200).send(body);
    } catch (e) {
      logger.error("Metrics endpoint failed", { error: e.message });
      res.status(500).send("metrics error");
    }
  });
}

// Metrics middleware
if (metricsEnabled) {
  app.use((req, res, next) => {
    const start = process.hrtime.bigint();
    res.on("finish", () => {
      const route = req.route?.path || req.path || "unknown";
      const { method } = req;
      const status = String(res.statusCode);
      try {
        httpRequestsTotal.labels(method, route, status).inc();
      } catch (_) {
        logger.debug("Metrics recording failed", { error: _.message });
      }
      try {
        const end = process.hrtime.bigint();
        const seconds = Number(end - start) / 1e9;
        httpRequestDuration.labels(method, route, status).observe(seconds);
      } catch (_) {
        logger.debug("Metrics recording failed", { error: _.message });
      }
      // High-level auth/business event counters by route
      const success = res.statusCode >= 200 && res.statusCode < 300;
      try {
        if (route === "/auth/login") {
          loginAttempts.labels(success ? "success" : "failure").inc();
        } else if (route === "/auth/verify-2fa") {
          login2faVerifications.labels(success ? "success" : "failure").inc();
        }
      } catch (_) {
        logger.debug("Metrics recording failed", { error: _.message });
      }
      // Rate limit hits
      try {
        if (res.statusCode === 429) rateLimitHits.inc();
      } catch (_) {
        logger.debug("Metrics recording failed", { error: _.message });
      }
    });
    next();
  });
}

// Trust exactly 2 proxy hops (LB -> Traefik) so req.ip reflects the real client IP
app.set("trust proxy", 2);

// API docs are enabled in non-production by default.
// In production, opt-in explicitly with ENABLE_API_DOCS=true.
const apiDocsEnabled =
  process.env.ENABLE_API_DOCS === "true" || process.env.NODE_ENV !== "production";
if (apiDocsEnabled) {
  app.get("/api-docs/openapi.yaml", (_req, res) => {
    const openApiSpecFilePath = resolveOpenApiSpecPath();
    if (!openApiSpecFilePath) {
      return res.status(500).json({
        error: "OpenAPI spec file not found",
        code: "OPENAPI_SPEC_NOT_FOUND",
      });
    }
    return res.sendFile(openApiSpecFilePath);
  });
  app.use(
    "/api-docs",
    swaggerUi.serve,
    swaggerUi.setup(null, {
      swaggerOptions: {
        url: "/api-docs/openapi.yaml",
      },
    }),
  );
  logger.info("Swagger documentation available at /api-docs");
} else {
  logger.info("Swagger documentation disabled");
}

// --- CONFIG ---
const APP_URL = process.env.APP_URL || "http://localhost:5173";
const isProductionEnvironment =
  (process.env.NODE_ENV || "").trim().toLowerCase() === "production";
const parseBooleanEnv = (value) => {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  return null;
};
const sessionCookieSecureLocalhostOverride =
  parseBooleanEnv(process.env.SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE) === true;
const configuredPublicUrls = [
  process.env.API_URL?.trim(),
  process.env.APP_URL?.trim(),
  process.env.PUBLIC_BASE_URL?.trim(),
].filter(Boolean);
const hasLocalhostOrLoopbackUrl = configuredPublicUrls.some((url) =>
  /^https?:\/\/(localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0)(:\d+)?(\/|$)/i.test(url),
);
const hasNonHttpsUrl = configuredPublicUrls.some((url) => /^http:\/\//i.test(url));
const localInsecureUrlDetected = hasLocalhostOrLoopbackUrl || hasNonHttpsUrl;
const allowInsecureLocalProdCookie =
  isProductionEnvironment &&
  sessionCookieSecureLocalhostOverride &&
  localInsecureUrlDetected;
const sessionCookieSecure = isProductionEnvironment && !allowInsecureLocalProdCookie;


const { requireAuth, enforceEmailVerification } = require("./middleware/auth");

// 1. Helmet - Enhanced Security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'", APP_URL],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"], // Prevent clickjacking
      },
    },
    // Enhanced security headers
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true,
    },
    noSniff: true, // X-Content-Type-Options: nosniff
    frameguard: { action: "deny" }, // X-Frame-Options: DENY
    xssFilter: true, // X-XSS-Protection: 1; mode=block
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    crossOriginEmbedderPolicy: false, // Allow external resources
    crossOriginResourcePolicy: { policy: "cross-origin" },
  }),
);

// 2. CORS with strict configuration
app.use(
  cors({
    origin: [
      APP_URL,
      "http://localhost:3000",
      "http://localhost:5173",
      "http://127.0.0.1:5173",
    ], // Support multiple origins
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Requested-With",
      "X-CSRF-Token",
    ],
    maxAge: 86400, // 24 hours
  }),
);

app.options(/.*/, cors());

// 3. Request size limits
app.use(express.json({ limit: "10mb" })); // Limit JSON payload size (10mb for large integration scans)

// Initialize session and Passport BEFORE any routes that require authentication
// This ensures req.isAuthenticated and req.user are available in downstream handlers
app.use(
  session({
    store: new pgSession({
      pool,
      tableName: "session",
      createTableIfMissing: true, // Enable table creation if missing
    }),
    name: "sessionId",
    secret: process.env.SESSION_SECRET,
    resave: true, // Changed to true to ensure session is saved
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      // Use 'lax' to preserve session across top-level redirects
      sameSite: "lax",
      secure: sessionCookieSecure,
      maxAge: 2 * 60 * 60 * 1000, // 2 hours (reduced from 7 days for security)
    },
    // Security enhancements
    rolling: true, // Reset expiration on activity
    genid: () => {
      return crypto.randomBytes(32).toString("hex"); // Secure session ID generation
    },
  }),
);

// Ensure Passport is only initialized once
if (!app._passportInitialized) {
  app.use(passport.initialize());
  app.use(passport.session());
  app._passportInitialized = true;
}
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(cookieParser());

// --- CONTACTS (extracted to routes/contacts.js) ---
app.use(require("./routes/contacts"));
// --- WHATSAPP (extracted to routes/whatsapp.js) ---
app.use(require("./routes/whatsapp"));
app.use((error, req, res, next) => {
  if (error instanceof SyntaxError && error.status === 400 && "body" in error) {
    // Accept empty bodies for endpoints that don't require a JSON payload
    if (
      !req.body ||
      (typeof req.body === "object" && Object.keys(req.body).length === 0)
    ) {
      return next();
    }
    return res.status(400).json({ error: "Invalid JSON format" });
  }
  next(error);
});

// Rate limiters, testWebhookUrl, and API limiter helpers
// (extracted to middleware/rateLimit.js and config/constants.js)
const {
  speedLimiter,
  applyGlobalRateLimit,
  getApiLimiter,
} = require("./middleware/rateLimit");

// Apply global rate limiting (excluding auth routes)
app.use(applyGlobalRateLimit);
// Apply speed limiter only in production
if (process.env.NODE_ENV !== "development" && process.env.NODE_ENV !== "test") {
  app.use(speedLimiter);
}

// Remove duplicate later session initialization: session was already set up earlier

// Enforce workspace membership and write restrictions for all workspace routes
app.use(
  "/api/v1/workspaces/:id",
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  // Do not enforce a blanket admin-only write gate here; individual routes
  // apply fine-grained authorization (e.g., membership.invite, workspace.update,
  // alert-settings update allowing managers). This avoids blocking legitimate
  // manager actions like editing contact groups or inviting members.
  (req, res, next) => next(),
);

// Get current session (before CSRF protection)
app.get("/api/session", (req, res) => {
  try {
    logger.info("Session endpoint called");
    logger.info("Headers:", req.headers);
    logger.info("Session ID:", req.sessionID);
    logger.info("Is authenticated:", req.isAuthenticated());
    logger.info("Has user:", !!req.user);
    logger.info("User ID:", req.user?.id);

    logger.info("Session check detailed", {
      authenticated: req.isAuthenticated(),
      hasUser: !!req.user,
      userId: req.user?.id,
      sessionID: req.sessionID,
      cookies: req.headers.cookie ? "present" : "missing",
      ip: req.ip,
    });

    if (!req.isAuthenticated()) {
      logger.info("User not authenticated");
      return res.json({ loggedIn: false });
    }

    if (!req.user) {
      logger.info("No user object in request");
      return res.json({ loggedIn: false });
    }

    if (!req.user.id) {
      logger.info("User object missing ID", { user: req.user });
      return res.json({ loggedIn: false });
    }

    const displayEmail = req.user.email_original || req.user.email;
    logger.info("Valid session found", {
      userId: req.user.id,
      email: displayEmail,
      authMethod: req.user.auth_method,
      emailVerified: req.user.email_verified,
      sessionID: req.sessionID,
      ip: req.ip,
    });

    res.json({
      loggedIn: true,
      user: {
        id: req.user.id,
        email: displayEmail,
        displayName: req.user.display_name,
        plan: "oss",
        authMethod: req.user.auth_method || "local",
        loginMethod: "email",
        emailVerified: !!req.user.email_verified,
        needsVerification: !req.user.email_verified,
        twoFactorEnabled: !!req.user.two_factor_enabled,
      },
    });
  } catch (error) {
    logger.error("Session endpoint error:", {
      error: error.message,
      stack: error.stack,
    });
    res.status(500).json({ error: "Failed to get session" });
  }
});

// Manual retry of a failed alert channel
app.post(
  "/api/alert-queue/:id/retry",
  getApiLimiter(),
  requireAuth,
  async (req, res) => {
    const alertId = parseInt(req.params.id, 10);
    let { channel } = req.body || {};
    if (!Number.isFinite(alertId))
      return res.status(400).json({
        error: "We couldn't identify the alert to retry.",
        code: "INVALID_ALERT_ID",
      });
    try {
      const r = await pool.query(
        "SELECT * FROM alert_queue WHERE id = $1 AND user_id = $2",
        [alertId, req.user.id],
      );
      if (r.rows.length === 0)
        return res.status(404).json({
          error:
            "We couldn't find this alert. It may have been processed or deleted.",
          code: "ALERT_NOT_FOUND",
        });
      const alert = r.rows[0];

      // If alert is blocked due to plan limits, return informative message and reset date
      if (String(alert.status || "").toLowerCase() === "blocked") {
        const now = new Date();
        const reset = new Date(now.getFullYear(), now.getMonth() + 1, 1);
        const isPlanLimit = (alert.error_message || "").includes("PLAN_LIMIT");
        // If blocked due to max attempts, do not allow manual retry
        if (!isPlanLimit) {
          return res.status(400).json({
            error:
              "This alert has been permanently blocked due to too many failed attempts.",
            code: "MAX_ATTEMPTS_BLOCKED",
          });
        }
        return res.status(400).json({
          error: `Maximum monthly usage reached, please wait until ${reset
            .toISOString()
            .slice(0, 10)} to process or consider upgrading to higher plan`,
          code: "PLAN_ALERT_LIMIT",
          resetDate: reset.toISOString().slice(0, 10),
        });
      }

      // Determine remaining eligible channels from stored list
      let storedChannels = [];
      try {
        if (Array.isArray(alert.channels)) storedChannels = alert.channels;
        else if (typeof alert.channels === "string") {
          try {
            const parsed = JSON.parse(alert.channels);
            if (Array.isArray(parsed)) storedChannels = parsed;
          } catch (_err) {
            logger.debug("Parse failed", { error: _err.message });
          }
        }
      } catch (_err) {
        logger.debug("Parse failed", { error: _err.message });
      }
      const eligible = Array.from(new Set(storedChannels)).filter(Boolean);

      // If no channel provided, derive behavior
      if (!channel) {
        if (eligible.length === 0) {
          // Provide a friendly diagnostic
          let providerHint = null;
          try {
            const lastWh = await pool.query(
              `SELECT metadata->>'kind' AS kind
               FROM alert_delivery_log
               WHERE alert_queue_id = $1 AND channel = 'webhooks'
               ORDER BY sent_at DESC
               LIMIT 1`,
              [alert.id],
            );
            providerHint = (lastWh.rows?.[0]?.kind || "").toLowerCase() || null;
          } catch (_err) {
            logger.warn("DB operation failed", { error: _err.message });
          }
          const isWebhookIssue =
            (alert.error_message || "").toLowerCase().includes("webhooks") ||
            providerHint;
          const hint = isWebhookIssue
            ? `Please put a valid ${providerHint || "webhook"} before retrying (Preferences Ã¢â€ â€™ Webhooks).`
            : "No eligible channels to retry. Enable at least one channel in Preferences, then try again.";
          return res.status(400).json({
            error: hint,
            code: isWebhookIssue ? "WEBHOOK_REQUIRED" : "NO_ELIGIBLE_CHANNELS",
            ...(providerHint ? { provider: providerHint } : {}),
          });
        }
        if (eligible.length > 1) {
          return res.status(400).json({
            error:
              "Multiple channels are eligible for retry. Please specify a channel (e.g., 'email' or 'webhooks').",
            code: "CHANNEL_REQUIRED",
            eligible,
          });
        }
        channel = eligible[0];
      }

      // Respect cooldown window
      if (
        alert.next_attempt_at &&
        new Date(alert.next_attempt_at) > new Date()
      ) {
        const eta = new Date(alert.next_attempt_at).toISOString();
        return res
          .status(429)
          .json({ error: "Cooldown active", nextAttemptAt: eta });
      }

      // Ensure channel is among remaining channels
      if (!eligible.includes(channel)) {
        return res
          .status(400)
          .json({ error: "Channel is not eligible for retry", eligible });
      }

      // Set to pending and only this channel
      await pool.query(
        "UPDATE alert_queue SET status='pending', channels=$1, next_attempt_at=NOW(), updated_at=NOW() WHERE id=$2",
        [JSON.stringify([channel]), alertId],
      );
      await writeAudit({
        actorUserId: req.user?.id || null,
        subjectUserId: alert.user_id,
        action: "ALERT_MANUAL_RETRY",
        targetType: "alert",
        targetId: alertId,
        channel,
        workspaceId: null,
        metadata: { reason: "user_initiated" },
      });
      return res.json({ success: true });
    } catch (err) {
      logger.error("Manual retry error", {
        error: err.message,
        userId: req.user.id,
        alertId,
      });
      return res.status(500).json({ error: "Failed to queue manual retry" });
    }
  },
);

// CSRF Protection using Double Submit Cookie pattern (replaces deprecated csurf)
// __Host- prefix requires Secure flag; fall back to plain name when running
// production mode over plain HTTP (SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE).
const csrfCookieName =
  process.env.NODE_ENV === "production" && sessionCookieSecure
    ? "__Host-psifi.x-csrf-token"
    : "x-csrf-token";
const { generateToken: generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => {
    if (!process.env.SESSION_SECRET) {
      throw new Error("SESSION_SECRET environment variable is required");
    }
    return process.env.SESSION_SECRET;
  },
  cookieName: csrfCookieName,
  cookieOptions: {
    httpOnly: true,
    secure: sessionCookieSecure,
    sameSite: "lax",
    path: "/",
  },
  getTokenFromRequest: (req) => req.headers["x-csrf-token"],
});

// CSRF token endpoint
app.get("/api/csrf-token", (req, res) => {
  const csrfToken = generateCsrfToken(req, res);
  res.json({ csrfToken });
});

// Apply CSRF protection to API routes - Skip in development and test
if (process.env.NODE_ENV !== "development" && process.env.NODE_ENV !== "test") {
  const csrfExempt = (req, res, next) => {
    if (
      req.method === "OPTIONS" ||
      req.method === "GET" ||
      req.method === "HEAD"
    )
      return next();
    const path = req.path || "";
    if (path === "/logout") return next();
    return doubleCsrfProtection(req, res, next);
  };
  app.use("/api", csrfExempt);
}
// Apply email verification enforcement to all API routes
app.use("/api", enforceEmailVerification);
// --- WORKSPACES (extracted to routes/workspaces.js) ---
app.use(require("./routes/workspaces"));
// --- AUTH (extracted to routes/auth.js) ---
app.use(require("./routes/auth"));
// --- TOKENS (extracted to routes/tokens.js) ---
app.use(require("./routes/tokens"));
// --- HEALTH (extracted to routes/health.js) ---
app.use(require("./routes/health"));
// --- USAGE (extracted to routes/usage.js) ---
app.use(require("./routes/usage"));
// --- ALERTS (extracted to routes/alerts.js) ---
app.use(require("./routes/alerts"));
// --- ACCOUNT (extracted to routes/account.js) ---
app.use(require("./routes/account"));
// --- INTEGRATIONS (extracted to routes/integrations.js) ---
app.use(require("./routes/integrations"));
// --- ADMIN (extracted to routes/admin.js) ---
app.use(require("./routes/admin"));

/**
 * Centralized error handling middleware
 */
const errorHandler = (err, req, res, next) => {
  // If headers are already sent, delegate to the default Express handler
  if (res.headersSent) {
    return next(err);
  }
  // Log the error
  logger.error("Unhandled error:", {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get("User-Agent"),
    userId: req.user?.id,
  });

  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV !== "production";

  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).json({
      error: "Invalid CSRF token",
      code: "EBADCSRFTOKEN",
    });
  }

  if (err.code === "23505") {
    // PostgreSQL unique violation
    return res.status(409).json({
      error: "Resource already exists",
      code: "DUPLICATE_RESOURCE",
    });
  }

  if (err.code === "23503") {
    // PostgreSQL foreign key violation
    return res.status(400).json({
      error: "Invalid reference to related resource",
      code: "INVALID_REFERENCE",
    });
  }

  if (err.name === "ValidationError") {
    return res.status(400).json({
      error: "Validation failed",
      details: err.details || [],
    });
  }

  // Default error response
  res.status(err.status || 500).json({
    error: isDevelopment ? err.message : "Internal server error",
    code: err.code || "INTERNAL_ERROR",
    ...(isDevelopment && { stack: err.stack }),
  });
};

// Apply error handling middleware
app.use(errorHandler);

// 404 handler (must be last)
app.use((req, res) => {
  res.status(404).json({
    error: "Endpoint not found",
    code: "NOT_FOUND",
  });
});

// --- START SERVER ---
const PORT = process.env.PORT || 4000;
const HOST = process.env.HOST || "0.0.0.0"; // Bind to all interfaces for Docker

// Validate critical configs at startup
function validateStartupConfig() {
  // Validate Twilio WhatsApp config (warn only, not block startup)
  const twilioSid = process.env.TWILIO_ACCOUNT_SID;
  const twilioToken = process.env.TWILIO_AUTH_TOKEN;
  const twilioFrom = process.env.TWILIO_WHATSAPP_FROM;
  const anyTwilioEnvConfigured = [twilioSid, twilioToken, twilioFrom]
    .some((v) => typeof v === "string" && v.trim().length > 0);

  if (anyTwilioEnvConfigured && (!twilioSid || !twilioToken)) {
    logger.warn(
      "WhatsApp env vars are incomplete; service may still be configured via System Settings",
    );
  } else if (anyTwilioEnvConfigured && !twilioFrom) {
    logger.warn(
      "WhatsApp sender env vars are missing; sender may still be configured via System Settings",
    );
  } else if (anyTwilioEnvConfigured) {
    logger.info("WhatsApp configured", {
      provider: "twilio",
      sender: "phone",
    });
  } else {
    logger.info(
      "WhatsApp env vars not configured; this is expected unless Twilio is enabled via env or System Settings",
    );
  }

  // Validate PUBLIC_BASE_URL for webhook signatures
  const publicBaseUrl = process.env.PUBLIC_BASE_URL?.trim();
  const apiUrlFallback = process.env.API_URL?.trim();
  const usingApiFallbackForTwilio = anyTwilioEnvConfigured && !publicBaseUrl && !!apiUrlFallback;
  const twilioSignatureBaseUrlMissing =
    anyTwilioEnvConfigured && !publicBaseUrl && !apiUrlFallback;

  if (usingApiFallbackForTwilio) {
    logger.warn(
      "PUBLIC_BASE_URL not set; falling back to API_URL for Twilio signature verification",
    );
  } else if (twilioSignatureBaseUrlMissing) {
    logger.warn(
      "PUBLIC_BASE_URL not set; Twilio webhook signature verification may fail behind proxies",
    );
  }

  const nodeEnv = (process.env.NODE_ENV || "").trim().toLowerCase();
  const apiUrl = process.env.API_URL?.trim();
  const appUrl = process.env.APP_URL?.trim();
  const publicUrl = process.env.PUBLIC_BASE_URL?.trim();
  const configuredUrls = [apiUrl, appUrl, publicUrl].filter(Boolean);
  const hasLocalUrl = configuredUrls.some((url) =>
    /^https?:\/\/(localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0)(:\d+)?(\/|$)/i.test(url),
  );
  const hasNonHttpsUrlFromStartup = configuredUrls.some((url) => /^http:\/\//i.test(url));

  if (allowInsecureLocalProdCookie) {
    logger.warn(
      "SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE=true: secure session cookie is disabled for local non-TLS production troubleshooting only.",
    );
  }

  if (
    nodeEnv === "production" &&
    !allowInsecureLocalProdCookie &&
    (hasLocalUrl || hasNonHttpsUrlFromStartup)
  ) {
    logger.warn(
      "In local http://localhost with NODE_ENV=production, browser does not persist/send the secure session cookie correctly for auth flow. You need HTTPS in front of API/dashboard (reverse proxy with TLS), otherwise secure cookies are expected to fail in local HTTP.",
    );
  }
}

validateStartupConfig();

async function main() {
  const { waitForDatabase } = require("./db/database");
  const dbReady = await waitForDatabase();
  if (!dbReady) {
    logger.error("Database not reachable after retry loop, exiting");
    process.exit(1);
  }

  const { runMigrations } = require("./migrations/migrate");
  await runMigrations();

  if (process.env.DISABLE_ADMIN_BOOTSTRAP !== "true") {
    const { bootstrapAdmin } = require("./auth/bootstrap");
    try {
      await bootstrapAdmin(pool);
    } catch (err) {
      if (err.message.includes("Admin credentials required")) {
        process.exit(1);
      }
      logger.error("Admin bootstrap failed:", err.message);
    }
  }

  app.listen(PORT, HOST, () => {
    logger.info(`Backend server running on http://${HOST}:${PORT}`);
    logger.info(`Health check: http://${HOST}:${PORT}/`);
    logger.info(`Environment: ${process.env.NODE_ENV}`);
    logger.info(
      `Database: ${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`,
    );
  });
}

main().catch((err) => {
  logger.error("Startup failed", { error: err.message });
  process.exit(1);
});
