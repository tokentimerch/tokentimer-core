const { logger, resolveClientIp } = require("../utils/logger");
const {
  authenticateInternalWorkerRequest,
} = require("./internal-worker-auth");

/**
 * Comprehensive authentication middleware.
 * Validates session, internal worker calls, and email verification.
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 * @param {import("express").NextFunction} next
 */
const requireAuth = (req, res, next) => {
  // Allow internal worker calls authenticated via Bearer token
  if (authenticateInternalWorkerRequest(req)) {
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
    ip: resolveClientIp(req),
  });

  if (!isAuth) {
    logger.warn("Unauthenticated access attempt", {
      path: req.path,
      method: req.method,
      ip: resolveClientIp(req),
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
      ip: resolveClientIp(req),
    });
    if (typeof req.logout === "function") {
      req.logout(function (err) {
        if (err) {
          logger.error("Logout error during auth check", {
            error: err.message,
            stack: err.stack,
            path: req.path,
            ip: resolveClientIp(req),
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
    ip: resolveClientIp(req),
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
      ip: resolveClientIp(req),
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
      ip: resolveClientIp(req),
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
        ip: resolveClientIp(req),
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
        ip: resolveClientIp(req),
      });
    }
  }
  next();
};

module.exports = {
  requireAuth,
  enforceEmailVerification,
};
