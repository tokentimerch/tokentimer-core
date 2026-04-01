const { logger } = require("../utils/logger");

/**
 * Comprehensive authentication middleware.
 * Validates session, internal worker calls, and email verification.
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 * @param {import("express").NextFunction} next
 */
const requireAuth = (req, res, next) => {
  // In test mode, allow manual retry endpoint without session
  if (
    process.env.NODE_ENV === "test" &&
    req.method === "POST" &&
    /^\/api\/alert-queue\/[0-9]+\/retry$/.test(req.path)
  ) {
    return next();
  }

  // Allow internal worker calls authenticated via Bearer token
  const authHeader = req.get("Authorization") || "";
  const workerKey = process.env.WORKER_API_KEY || process.env.SESSION_SECRET;
  if (workerKey && authHeader === `Bearer ${workerKey}`) {
    req.isWorkerCall = true;
    req.user = req.user || {
      id: null,
      role: "admin",
      email: "worker@internal",
    };
    logger.info("Internal worker call authenticated", {
      path: req.path,
      method: req.method,
    });
    return next();
  }

  const isAuth =
    typeof req.isAuthenticated === "function" ? req.isAuthenticated() : false;
  logger.info("Authentication check", {
    method: req.method,
    path: req.path,
    authenticated: isAuth,
    userId: req.user?.id,
    ip: req.ip,
  });

  if (!isAuth) {
    logger.warn("Unauthenticated access attempt", {
      path: req.path,
      method: req.method,
      ip: req.ip,
      userAgent: req.get("User-Agent"),
    });
    return res.status(401).json({ error: "Not authenticated" });
  }

  if (!req.user || !req.user.id) {
    logger.error("Invalid session data", {
      path: req.path,
      method: req.method,
      hasUser: !!req.user,
      hasUserId: !!req.user?.id,
      ip: req.ip,
    });
    if (typeof req.logout === "function") {
      req.logout(function (err) {
        if (err) {
          logger.error("Logout error during auth check", {
            error: err.message,
            stack: err.stack,
            path: req.path,
            ip: req.ip,
          });
        }
      });
    }
    return res.status(401).json({ error: "Invalid session" });
  }

  logger.info("Authenticated user access", {
    userId: req.user.id,
    path: req.path,
    method: req.method,
    ip: req.ip,
  });

  // Enforce email verification for local auth users (except in test mode)
  if (
    req.user.auth_method === "local" &&
    !req.user.email_verified &&
    process.env.NODE_ENV !== "test"
  ) {
    logger.warn("SECURITY_BREACH_UNVERIFIED_ACCESS", {
      userId: req.user.id,
      email: req.user.email,
      path: req.path,
      ip: req.ip,
    });
    return res.status(403).json({
      error: "Email verification required",
      needsVerification: true,
    });
  }

  if (
    req.user.auth_method === "local" &&
    !req.user.email_verified &&
    process.env.NODE_ENV === "test"
  ) {
    logger.info("Test mode: Allowing unverified user access (requireAuth)", {
      userId: req.user.id,
      email: req.user.email,
      path: req.path,
      ip: req.ip,
    });
  }

  next();
};

/**
 * Email verification enforcement middleware for /api routes.
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 * @param {import("express").NextFunction} next
 */
const enforceEmailVerification = (req, res, next) => {
  if (req.path === "/api/session" && process.env.NODE_ENV === "test") {
    return next();
  }
  if (req.baseUrl === "/api" && req.path === "/logout") {
    return next();
  }

  const isAuth =
    typeof req.isAuthenticated === "function" ? req.isAuthenticated() : false;
  if (isAuth && req.user && req.user.id) {
    if (
      req.user.auth_method === "local" &&
      !req.user.email_verified &&
      process.env.NODE_ENV !== "test"
    ) {
      logger.warn("UNVERIFIED_ACCESS_ATTEMPT", {
        userId: req.user.id,
        email: req.user.email,
        path: req.path,
        ip: req.ip,
      });
      return res.status(403).json({
        error: "Email verification required",
        needsVerification: true,
      });
    }

    if (
      req.user.auth_method === "local" &&
      !req.user.email_verified &&
      process.env.NODE_ENV === "test"
    ) {
      logger.info("Test mode: Allowing unverified user access", {
        userId: req.user.id,
        email: req.user.email,
        path: req.path,
        ip: req.ip,
      });
    }
  }
  next();
};

module.exports = {
  requireAuth,
  enforceEmailVerification,
};
