const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { writeAudit } = require("../services/audit");
const { requireAuth } = require("../middleware/auth");
const {
  loginLimiter,
  loginEmailLimiter,
  authSlowdown,
  passwordResetLimiter,
  passwordResetEmailLimiter,
  emailVerificationLimiter,
  getApiLimiter,
  getTestApiLimiter,
} = require("../middleware/rateLimit");
const {
  validateLogin,
  handleValidationErrors,
} = require("../middleware/validation");
const { ensureInitialWorkspaceForUser } = require("../services/workspace");
const User = require("../db/models/User");
const bcrypt = require("bcryptjs");
const QRCode = require("qrcode");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const {
  generateVerificationToken,
  sendVerificationEmail,
  sendPasswordResetEmail,
} = require("../services/emailService");
const { APP_URL } = require("../config/constants");
const _otplib = require("otplib");
const generateSecret =
  _otplib.generateSecret ||
  _otplib.authenticator?.generateSecret ||
  _otplib.default?.authenticator?.generateSecret;
const verifyOtp =
  _otplib.verify ||
  _otplib.authenticator?.verify ||
  _otplib.default?.authenticator?.verify;
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

const router = require("express").Router();

// --- ENHANCED SECURITY MONITORING ---
router.use((req, res, next) => {
  const userAgent = req.get("User-Agent") || "";
  const ip = req.ip || req.socket?.remoteAddress;
  const requestMetadata = {
    ip,
    userAgent,
    method: req.method,
    path: req.path,
    userId: req.user?.id,
    sessionId: req.sessionID,
  };

  // Log authentication attempts
  if (req.path.includes("/auth/") && req.method === "POST") {
    logger.warn("AUTH_ATTEMPT", {
      ...requestMetadata,
      endpoint: req.path,
      email: req.body?.email ? "provided" : "missing",
    });
  }

  // Detect suspicious patterns
  const suspiciousPatterns = [
    /bot|crawler|spider/i,
    /scanner|exploit|hack/i,
    /sqlmap|nmap|burp/i,
    /nikto|dirb|gobuster/i,
  ];

  if (suspiciousPatterns.some((pattern) => pattern.test(userAgent))) {
    logger.warn("SUSPICIOUS_USER_AGENT", {
      ...requestMetadata,
      pattern: "suspicious_tool",
    });
  }

  // Detect potential path traversal attempts
  if (req.path.includes("../") || req.path.includes("..\\")) {
    logger.warn("PATH_TRAVERSAL_ATTEMPT", requestMetadata);
  }

  // Detect potential SQL injection in query parameters
  const queryString = req.url.split("?")[1];
  if (queryString) {
    const sqlPatterns = [
      /union.*select/i,
      /drop.*table/i,
      /insert.*into/i,
      /update.*set/i,
      /delete.*from/i,
      /'.*or.*'.*=/i,
    ];

    if (sqlPatterns.some((pattern) => pattern.test(queryString))) {
      logger.warn("SQL_INJECTION_ATTEMPT", {
        ...requestMetadata,
        queryString,
      });
    }
  }

  // Monitor failed authentication attempts
  res.on("finish", () => {
    if (req.path.includes("/auth/") && res.statusCode === 401) {
      logger.warn("AUTH_FAILURE", {
        ...requestMetadata,
        statusCode: res.statusCode,
      });
    }

    // Monitor suspicious status codes
    if ([403, 404, 429].includes(res.statusCode)) {
      logger.warn("SUSPICIOUS_RESPONSE", {
        ...requestMetadata,
        statusCode: res.statusCode,
      });
    }
  });

  next();
});

// Error handling is now centralized at the end of the file

// --- PASSPORT CONFIG ---
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
  try {
    const user = await User.findById(id);
    if (!user) {
      // User doesn't exist anymore (deleted, etc.)
      return done(null, null);
    }
    done(null, user);
  } catch (error) {
    logger.error("Deserialize user error:", {
      error: error.message,
      stack: error.stack,
    });
    done(error, null);
  }
});

// Local Strategy for Email/Password
passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    async (email, password, done) => {
      try {
        // Check if user exists
        const user =
          (await User.findByEmail(email)) ||
          (await User.findByEmailLoose(email));

        if (!user) {
          return done(null, false, { message: "Invalid credentials" });
        }

        // Block login for anonymized/deleted accounts
        try {
          const isTombstonedEmail =
            typeof user.email === "string" &&
            /@example\.invalid$/i.test(user.email);
          const isDeletedDisplay =
            typeof user.display_name === "string" &&
            user.display_name === "Deleted Account";
          if (isTombstonedEmail || isDeletedDisplay) {
            return done(null, false, { message: "Account deleted" });
          }
        } catch (_err) {
          logger.debug("Non-critical operation failed", {
            error: _err.message,
          });
        }

        // For local users, verify password
        if (!user.password_hash) {
          return done(null, false, { message: "Invalid credentials" });
        }

        const isValidPassword = await bcrypt.compare(
          password,
          user.password_hash,
        );

        if (!isValidPassword) {
          return done(null, false, { message: "Invalid credentials" });
        }

        // CRITICAL SECURITY: Check email verification for local auth users
        // Allow unverified users only in test mode for testing purposes
        if (
          user.auth_method === "local" &&
          !user.email_verified &&
          process.env.NODE_ENV !== "test"
        ) {
          logger.warn("UNVERIFIED_LOGIN_ATTEMPT", {
            email: process.env.NODE_ENV === "production" ? "REDACTED" : email,
            ip:
              process.env.NODE_ENV === "production" ? "REDACTED" : "localhost",
          });
          return done(null, false, {
            message: "Please verify your email before logging in",
            needsVerification: true,
          });
        }

        // In test mode, allow unverified users but log it
        if (
          user.auth_method === "local" &&
          !user.email_verified &&
          process.env.NODE_ENV === "test"
        ) {
          logger.info("Test mode: Allowing unverified user login", {
            email,
            authMethod: "local",
          });
        }

        done(null, user);
      } catch (error) {
        logger.error("Local auth error:", {
          error: error.message,
          stack: error.stack,
        });
        done(error);
      }
    },
  ),
);

// -- API ROUTES --

// --- AUTHENTICATION ROUTES ---

// Email/Password Login
router.post(
  "/auth/login",
  loginLimiter,
  loginEmailLimiter,
  authSlowdown,
  validateLogin,
  handleValidationErrors,
  (req, res, next) => {
    logger.info("Login attempt", {
      ip: req.ip || req.socket?.remoteAddress,
      userAgent: req.get("User-Agent"),
    });
    // Note: Validation is now handled by express-validator middleware

    passport.authenticate("local", async (err, user, info) => {
      if (err) {
        logger.error("Login authentication error", {
          ip: req.ip || req.socket?.remoteAddress,
          error: err.message,
        });
        return res.status(500).json({ error: "Authentication error" });
      }
      if (!user) {
        // Attempt to attribute failed login to a known user (by email) for audit trail
        try {
          const emailRaw = req.body?.email || null;
          const email =
            typeof emailRaw === "string" && emailRaw.trim().length > 0
              ? emailRaw.trim().toLowerCase()
              : null;
          if (email) {
            const found = await pool.query(
              "SELECT id FROM users WHERE LOWER(email) = $1",
              [email],
            );
            const subjectId = found.rows?.[0]?.id || null;
            if (subjectId) {
              await writeAudit({
                actorUserId: null,
                subjectUserId: subjectId,
                action: "LOGIN_FAILED",
                targetType: "user",
                targetId: subjectId,
                channel: null,
                workspaceId: null,
                metadata: {
                  email,
                  reason: info?.message || "Invalid credentials",
                },
              });
            }
          }
        } catch (err2) {
          logger.error("Audit insert failed", {
            action: "LOGIN_FAILED",
            error: err2.message,
          });
        }
        // Structured log for operational visibility
        logger.warn("FAILED_LOGIN_ATTEMPT", {
          ip: req.ip || req.socket?.remoteAddress,
          reason: info.message || "Invalid credentials",
          userAgent: req.get("User-Agent"),
        });
        // Pass through the info object which may contain needsVerification or oauthAccount
        return res.status(401).json({
          error: info.message || "Invalid credentials",
          ...(info.needsVerification && {
            needsVerification: info.needsVerification,
          }),
          ...(info.oauthAccount && { oauthAccount: info.oauthAccount }),
        });
      }

      logger.info("Successful login", {
        userId: user.id,
        ip: req.ip || req.socket?.remoteAddress,
        authMethod: "local",
      });
      // If 2FA is enabled, create pending challenge and respond
      if (user.two_factor_enabled) {
        req.session.pending2FA = { userId: user.id };
        return res.status(200).json({ requires2FA: true, authMethod: "local" });
      }

      req.login(user, (err) => {
        if (err) {
          logger.error("Login session error", {
            ip: req.ip || req.socket?.remoteAddress,
            error: err.message,
            userId: user.id,
          });
          return res.status(500).json({ error: "Login failed" });
        }
        // Audit: login success
        try {
          writeAudit({
            actorUserId: user.id,
            subjectUserId: user.id,
            action: "LOGIN_SUCCESS",
            targetType: "user",
            targetId: user.id,
            channel: null,
            workspaceId: null,
            metadata: { method: "local" },
          }).catch((_err) => {
            logger.warn("Audit write failed", { error: _err.message });
          });
        } catch (err) {
          logger.error("Audit insert failed", {
            action: "LOGIN_SUCCESS",
            error: err.message,
          });
        }
        res.json({
          message: "Login successful",
          user: {
            id: user.id,
            email: user.email_original || user.email,
            displayName: user.display_name,
          },
        });
      });
    })(req, res, next);
  },
);

// Invitation-only registration (requires a valid workspace invitation token)
router.post(
  "/auth/register",
  loginLimiter,
  loginEmailLimiter,
  authSlowdown,
  async (req, res) => {
    try {
      const token = String(req.body?.token || "").trim();
      const emailRaw = String(req.body?.email || "").trim();
      const email = emailRaw.toLowerCase();
      const password = String(req.body?.password || "");
      const firstName = String(req.body?.first_name || "").trim();
      const lastName = String(req.body?.last_name || "").trim();

      if (!token) {
        return res.status(400).json({
          error: "Invitation token is required",
          code: "INVITE_TOKEN_REQUIRED",
        });
      }
      if (!/.+@.+\..+/.test(email)) {
        return res.status(400).json({
          error: "Valid email is required",
          code: "VALIDATION_ERROR",
        });
      }
      const pwErrors = [];
      if (!password || password.length < 12) {
        pwErrors.push("Password must be at least 12 characters long");
      }
      if (password && !/[a-z]/.test(password)) {
        pwErrors.push("Password must contain at least one lowercase letter");
      }
      if (password && !/[A-Z]/.test(password)) {
        pwErrors.push("Password must contain at least one uppercase letter");
      }
      if (password && !/\d/.test(password)) {
        pwErrors.push("Password must contain at least one number");
      }
      if (password && !/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
        pwErrors.push("Password must contain at least one special character");
      }
      if (pwErrors.length > 0) {
        return res.status(400).json({
          error: pwErrors[0],
          details: pwErrors,
          code: "VALIDATION_ERROR",
        });
      }

      const inviteRes = await pool.query(
        `SELECT id, email, role, workspace_id, accepted_at
           FROM workspace_invitations
          WHERE token = $1
          LIMIT 1`,
        [token],
      );
      if (inviteRes.rowCount === 0) {
        return res.status(400).json({
          error: "Invalid invitation token",
          code: "INVITE_TOKEN_INVALID",
        });
      }

      const invitation = inviteRes.rows[0];
      if (invitation.accepted_at) {
        return res.status(409).json({
          error: "This invitation has already been used",
          code: "INVITE_ALREADY_ACCEPTED",
        });
      }

      const invitedCanonical = User.canonicalizeEmail(invitation.email);
      const requestedCanonical = User.canonicalizeEmail(email);
      if (invitedCanonical !== requestedCanonical) {
        return res.status(400).json({
          error: "You must register with the invited email address",
          code: "INVITE_EMAIL_MISMATCH",
        });
      }

      const existingUser = await User.findByEmail(email);
      if (existingUser) {
        return res.status(409).json({
          error: "An account with this email already exists",
          code: "ACCOUNT_EXISTS",
          existingAccount: true,
        });
      }

      const passwordHash = await bcrypt.hash(password, 12);
      const verificationToken = generateVerificationToken();
      const verificationTokenExpires = new Date(
        Date.now() + 24 * 60 * 60 * 1000,
      );
      const displayName =
        [firstName, lastName].filter(Boolean).join(" ").trim() || emailRaw;

      const user = await User.createLocal({
        email,
        emailOriginal: emailRaw,
        displayName,
        firstName: firstName || null,
        lastName: lastName || null,
        passwordHash,
        authMethod: "local",
        photo: null,
        verificationToken,
        verificationTokenExpires,
      });

      const emailResult = await sendVerificationEmail(
        email,
        verificationToken,
        displayName,
      );

      try {
        await writeAudit({
          actorUserId: user.id,
          subjectUserId: user.id,
          action: "REGISTRATION",
          targetType: "user",
          targetId: user.id,
          channel: null,
          workspaceId: invitation.workspace_id || null,
          metadata: { method: "invite_token", invited_role: invitation.role },
        });
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }

      return res.status(201).json({
        success: true,
        message: "Account created successfully",
        emailSent: emailResult.success,
        requiresEmailVerification: process.env.NODE_ENV !== "test",
        user: {
          id: user.id,
          email: user.email_original || user.email,
          displayName: user.display_name,
          emailVerified: user.email_verified,
        },
      });
    } catch (error) {
      logger.error("Invite registration error", {
        error: error.message,
        stack: error.stack,
      });
      return res
        .status(500)
        .json({
          error: "Failed to complete registration",
          code: "INTERNAL_ERROR",
        });
    }
  },
);

// Second step: verify TOTP for 2FA
router.post(
  "/auth/verify-2fa",
  loginLimiter,
  authSlowdown,
  async (req, res) => {
    try {
      const { token } = req.body || {};
      const pending = req.session.pending2FA;
      if (!pending?.userId) {
        return res.status(400).json({ error: "No pending 2FA challenge" });
      }
      if (!token)
        return res.status(400).json({ error: "2FA token is required" });

      const user = await User.findById(pending.userId);
      if (!user || !user.two_factor_enabled || !user.two_factor_secret) {
        return res
          .status(400)
          .json({ error: "2FA is not enabled for this account" });
      }

      const result = await verifyOtp({
        token,
        secret: user.two_factor_secret,
      });
      if (!result || !result.valid) {
        return res.status(401).json({ error: "Invalid 2FA code" });
      }

      req.login(user, (err) => {
        if (err) {
          logger.error("2FA login session error", {
            error: err.message,
            stack: err.stack,
          });
          return res.status(500).json({ error: "Failed to finalize login" });
        }
        delete req.session.pending2FA;

        try {
          writeAudit({
            actorUserId: user.id,
            subjectUserId: user.id,
            action: "LOGIN_SUCCESS_2FA",
            targetType: "user",
            targetId: user.id,
            channel: null,
            workspaceId: null,
            metadata: {},
          }).catch((_err) => {
            logger.warn("Audit write failed", { error: _err.message });
          });
        } catch (_err) {
          logger.warn("Audit write failed", { error: _err.message });
        }

        res.json({ success: true });
      });
    } catch (error) {
      logger.error("Verify 2FA error:", {
        error: error.message,
        stack: error.stack,
      });
      res.status(500).json({ error: "Failed to verify 2FA" });
    }
  },
);

// Account 2FA management
router.post(
  "/api/account/2fa/setup",
  getTestApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      const secret = generateSecret();
      const label = encodeURIComponent(
        `TokenTimer:${req.user.email_original || req.user.email}`,
      );
      const issuer = encodeURIComponent("TokenTimer");
      const otpauth = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}`;
      req.session.setup2FA = { secret };
      let qr = null;
      try {
        qr = await QRCode.toDataURL(otpauth);
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
      res.json({ secret, otpauth, qr });
    } catch (error) {
      logger.error("2FA setup error:", {
        error: error.message,
        stack: error.stack,
      });
      res.status(500).json({ error: "Failed to start 2FA setup" });
    }
  },
);

router.post(
  "/api/account/2fa/enable",
  getTestApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      const { token } = req.body || {};
      const setup = req.session.setup2FA;
      if (!setup?.secret)
        return res.status(400).json({ error: "No 2FA setup in progress" });
      if (!token)
        return res.status(400).json({ error: "2FA token is required" });

      const enableResult = await verifyOtp({ token, secret: setup.secret });
      if (!enableResult || !enableResult.valid)
        return res.status(400).json({ error: "Invalid 2FA token" });

      await pool.query(
        "UPDATE users SET two_factor_enabled = TRUE, two_factor_secret = $2, updated_at = NOW() WHERE id = $1",
        [req.user.id, setup.secret],
      );

      delete req.session.setup2FA;
      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "TWO_FACTOR_ENABLED",
          targetType: "user",
          targetId: req.user.id,
          channel: null,
          workspaceId: null,
          metadata: {},
        });
      } catch (_err) {
        logger.warn("Audit write failed (TWO_FACTOR_ENABLED)", {
          error: _err.message,
        });
      }
      res.json({ message: "Two-factor authentication enabled" });
    } catch (error) {
      logger.error("2FA enable error:", {
        error: error.message,
        stack: error.stack,
      });
      res.status(500).json({ error: "Failed to enable 2FA" });
    }
  },
);

router.post(
  "/api/account/2fa/disable",
  getTestApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      const { currentPassword } = req.body || {};
      if (!currentPassword)
        return res.status(400).json({ error: "Current password is required" });
      const user = await User.findById(req.user.id);
      if (!user?.password_hash)
        return res
          .status(400)
          .json({ error: "Password account required to disable 2FA" });
      const matches = await bcrypt.compare(currentPassword, user.password_hash);
      if (!matches)
        return res.status(400).json({ error: "Current password is incorrect" });

      await pool.query(
        "UPDATE users SET two_factor_enabled = FALSE, two_factor_secret = NULL, updated_at = NOW() WHERE id = $1",
        [req.user.id],
      );
      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "TWO_FACTOR_DISABLED",
          targetType: "user",
          targetId: req.user.id,
          channel: null,
          workspaceId: null,
          metadata: {},
        });
      } catch (_err) {
        logger.warn("Audit write failed (TWO_FACTOR_DISABLED)", {
          error: _err.message,
        });
      }
      res.json({ message: "Two-factor authentication disabled" });
    } catch (error) {
      logger.error("2FA disable error:", {
        error: error.message,
        stack: error.stack,
      });
      res.status(500).json({ error: "Failed to disable 2FA" });
    }
  },
);

router.get("/auth/verify-email/", (req, res) => {
  res.status(404).json({ error: "Verification token is required" });
});
// Email verification endpoint
router.get(
  "/auth/verify-email/:token",
  emailVerificationLimiter,
  async (req, res) => {
    try {
      const { token } = req.params;

      const user = await User.verifyEmail(token);

      if (!user) {
        // Redirect to frontend with error
        return res.redirect(`${APP_URL}/login?error=invalid_verification`);
      }

      // Audit: email verified
      try {
        await writeAudit({
          actorUserId: user.id,
          subjectUserId: user.id,
          action: "EMAIL_VERIFIED",
          targetType: "user",
          targetId: user.id,
          channel: null,
          workspaceId: null,
          metadata: {},
        });
      } catch (err) {
        logger.error("Audit insert failed", {
          action: "EMAIL_VERIFIED",
          error: err.message,
        });
      }

      // Best-effort: accept any pending workspace invitations now that email is verified
      try {
        await ensureInitialWorkspaceForUser(
          user.id,
          user.email,
          user.display_name,
        );
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }

      // Auto-login after successful verification and redirect to dashboard.
      req.login(user, (loginErr) => {
        const displayEmailAfterVerify = user.email_original || user.email;
        if (loginErr) {
          logger.error("Auto-login after verification failed", {
            error: loginErr.message,
            userId: user.id,
          });
          return res.redirect(
            `${APP_URL}/login?verification_success=true&first_login=true&email=${encodeURIComponent(displayEmailAfterVerify)}`,
          );
        }
        req.session.save((sessionErr) => {
          if (sessionErr) {
            logger.warn("Session save after verification failed", {
              error: sessionErr.message,
              userId: user.id,
            });
          }
          return res.redirect(
            `${APP_URL}/dashboard?verification_success=true&first_login=true&new_user=true`,
          );
        });
      });
    } catch (error) {
      logger.error("Email verification error", {
        error: error.message,
        stack: error.stack,
      });
      // Redirect to frontend with error
      res.redirect(`${APP_URL}/login?error=verification_failed`);
    }
  },
);

// Resend verification email
router.post(
  "/auth/resend-verification",
  emailVerificationLimiter,
  async (req, res) => {
    try {
      const emailFromSession = req.user?.email;
      const email = emailFromSession || req.body?.email;

      if (!email) {
        return res.status(400).json({ error: "Email is required" });
      }

      const user = await User.findByEmail(email);

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      if (user.email_verified) {
        return res.status(400).json({ error: "Email is already verified" });
      }

      // Generate new verification token
      const verificationToken = generateVerificationToken();
      const verificationTokenExpires = new Date(
        Date.now() + 24 * 60 * 60 * 1000,
      ); // 24 hours

      await User.setVerificationToken(
        email,
        verificationToken,
        verificationTokenExpires,
      );

      const emailResult = await sendVerificationEmail(
        email,
        verificationToken,
        user.display_name,
      );

      if (!emailResult.success) {
        logger.error(
          "Failed to send verification email to:",
          email,
          emailResult.error,
        );
        // Do not block user flow with 500; respond with emailSent=false
        return res.status(200).json({
          message: "Email service unavailable. Please try again later.",
          emailSent: false,
          error: emailResult.error,
        });
      }

      res.json({
        message: "Verification email sent successfully",
        emailSent: emailResult.success,
      });
      // Audit: verification email resent
      try {
        await writeAudit({
          actorUserId: user.id,
          subjectUserId: user.id,
          action: "EMAIL_VERIFICATION_RESENT",
          targetType: "user",
          targetId: user.id,
          channel: null,
          workspaceId: null,
          metadata: {},
        });
      } catch (err) {
        logger.error("Audit insert failed", {
          action: "EMAIL_VERIFICATION_RESENT",
          error: err.message,
        });
      }
    } catch (error) {
      logger.error("Resend verification error:", {
        error: error.message,
        stack: error.stack,
      });
      res.status(500).json({ error: "Failed to resend verification email" });
    }
  },
);

// Request password reset
router.post(
  "/auth/request-password-reset",
  passwordResetLimiter,
  async (req, res) => {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ error: "Email is required" });
      }

      const user = await User.findByEmail(email);

      if (!user) {
        // Don't reveal if user exists or not (security best practice)
        return res.json({
          message:
            "If an account with this email exists, a password reset link has been sent.",
        });
      }

      if (user.auth_method !== "local") {
        return res.status(400).json({
          error: "Password reset is only available for email/password accounts",
        });
      }

      // Generate password reset token (expires in 5 minutes)
      const resetToken = generateVerificationToken();
      const resetTokenExpires = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

      const updatedUserForReset = await User.setResetTokenByUserId(
        user.id,
        resetToken,
        resetTokenExpires,
      );
      if (!updatedUserForReset) {
        logger.warn(
          "Password reset token update affected 0 users (email mismatch or missing user)",
          {
            emailNormalized: String(email || "")
              .toLowerCase()
              .trim(),
          },
        );
      }

      logger.info("Attempting to send password reset email:", {
        email,
        tokenLength: resetToken.length,
        displayName: user.display_name,
      });

      const emailResult = await sendPasswordResetEmail(
        email,
        resetToken,
        user.display_name,
      );

      logger.info("Password reset email result:", emailResult);

      if (!emailResult.success) {
        logger.error(
          "Failed to send password reset email to:",
          email,
          emailResult.error,
        );
        return res.status(500).json({
          error: "Failed to send password reset email",
          details: emailResult.error,
        });
      }

      res.json({
        message:
          "If an account with this email exists, a password reset link has been sent.",
      });
      // Audit: password reset requested
      try {
        if (user) {
          await writeAudit({
            actorUserId: user.id,
            subjectUserId: user.id,
            action: "PASSWORD_RESET_REQUESTED",
            targetType: "user",
            targetId: user.id,
            channel: null,
            workspaceId: null,
            metadata: {},
          });
        }
      } catch (err) {
        logger.error("Audit insert failed", {
          action: "PASSWORD_RESET_REQUESTED",
          error: err.message,
        });
      }
    } catch (error) {
      logger.error("Password reset request error", {
        error: error.message,
        stack: error.stack,
      });
      res
        .status(500)
        .json({ error: "Failed to process password reset request" });
    }
  },
);
// Reset password with token
router.post(
  "/auth/reset-password",
  passwordResetLimiter,
  passwordResetEmailLimiter,
  authSlowdown,
  async (req, res) => {
    try {
      const { token, newPassword } = req.body;

      if (!token || !newPassword) {
        return res
          .status(400)
          .json({ error: "Token and new password are required" });
      }

      // Enforce same password policy as change-password and registration
      const pwErrors = [];
      if (!newPassword || newPassword.length < 12)
        pwErrors.push("Password must be at least 12 characters long");
      if (newPassword && !/[a-z]/.test(newPassword))
        pwErrors.push("Password must contain at least one lowercase letter");
      if (newPassword && !/[A-Z]/.test(newPassword))
        pwErrors.push("Password must contain at least one uppercase letter");
      if (newPassword && !/\d/.test(newPassword))
        pwErrors.push("Password must contain at least one number");
      if (
        newPassword &&
        !/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(newPassword)
      )
        pwErrors.push("Password must contain at least one special character");
      if (newPassword) {
        const commonPatterns = [
          /^password/i,
          /^123456/,
          /^qwerty/i,
          /^admin/i,
          /^letmein/i,
          /^welcome/i,
          /^monkey/i,
          /^dragon/i,
        ];
        for (const pattern of commonPatterns) {
          if (pattern.test(newPassword)) {
            pwErrors.push(
              "Password contains common patterns and is not secure",
            );
            break;
          }
        }
        if (/(.)\1{2,}/.test(newPassword)) {
          pwErrors.push(
            "Password cannot contain more than 2 consecutive identical characters",
          );
        }
      }
      if (pwErrors.length > 0) {
        return res.status(400).json({
          error: pwErrors[0],
          details: pwErrors,
        });
      }

      const user = await User.findByResetToken(token);

      if (!user) {
        return res
          .status(400)
          .json({ error: "Invalid or expired password reset token" });
      }

      // Hash new password
      const saltRounds = 12;
      const passwordHash = await bcrypt.hash(newPassword, saltRounds);

      // Update password and clear reset token
      await User.resetPassword(token, passwordHash);

      res.json({
        message:
          "Password reset successfully! You can now log in with your new password.",
      });
      // Audit: password reset completed
      try {
        await writeAudit({
          actorUserId: user.id,
          subjectUserId: user.id,
          action: "PASSWORD_RESET_COMPLETED",
          targetType: "user",
          targetId: user.id,
          channel: null,
          workspaceId: null,
          metadata: {},
        });
      } catch (err) {
        logger.error("Audit insert failed", {
          action: "PASSWORD_RESET_COMPLETED",
          error: err.message,
        });
      }
    } catch (error) {
      logger.error("Password reset error:", {
        error: error.message,
        stack: error.stack,
      });
      res.status(500).json({ error: "Failed to reset password" });
    }
  },
);

// Change password for logged-in users
router.post(
  "/api/account/change-password",
  getTestApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body || {};
      if (!currentPassword || !newPassword) {
        return res
          .status(400)
          .json({ error: "Current password and new password are required" });
      }

      if (
        !/[A-Z]/.test(newPassword) ||
        !/[a-z]/.test(newPassword) ||
        !/\d/.test(newPassword) ||
        !/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(newPassword) ||
        newPassword.length < 12
      ) {
        return res.status(400).json({
          error:
            "Password must be at least 12 characters long, at least one uppercase letter, at least one number, at least one special character",
        });
      }

      const user = await User.findById(req.user.id);
      if (!user) return res.status(404).json({ error: "User not found" });

      if (!user.password_hash) {
        return res.status(400).json({
          error:
            "Your account does not have a password set. Use password reset to create one.",
        });
      }

      const matches = await bcrypt.compare(currentPassword, user.password_hash);
      if (!matches) {
        return res.status(400).json({ error: "Current password is incorrect" });
      }

      const saltRounds = 12;
      const newHash = await bcrypt.hash(newPassword, saltRounds);
      await pool.query(
        "UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1",
        [req.user.id, newHash],
      );

      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "PASSWORD_CHANGED",
          targetType: "user",
          targetId: req.user.id,
          channel: null,
          workspaceId: null,
          metadata: {},
        });
      } catch (_err) {
        logger.warn("Audit write failed (PASSWORD_CHANGED)", {
          error: _err.message,
        });
      }

      res.json({ message: "Password changed successfully" });
    } catch (error) {
      logger.error("Change password error:", {
        error: error.message,
        stack: error.stack,
      });
      res.status(500).json({ error: "Failed to change password" });
    }
  },
);

// Removed OAuth disconnect in favor of 2FA feature

// Logout
router.post("/api/logout", getApiLimiter(), (req, res) => {
  logger.info("Logout request received", {
    sessionID: req.sessionID,
    authenticated: req.isAuthenticated(),
    userId: req.user?.id,
    ip: req.ip,
  });

  // Logout and destroy session properly through Passport.js
  req.logout(function (err) {
    if (err) {
      logger.error("Logout error", { error: err.message, stack: err.stack });
    }

    // Destroy the session completely
    req.session.destroy((destroyErr) => {
      if (destroyErr) {
        logger.error("Session destroy error:", {
          error: destroyErr.message,
          stack: destroyErr.stack,
        });
      }

      logger.info("Session destroyed successfully", {
        sessionID: req.sessionID,
        ip: req.ip,
      });

      // Audit: logout (only if user id available)
      try {
        const uid = req.user?.id || null;
        if (uid) {
          writeAudit({
            actorUserId: uid,
            subjectUserId: uid,
            action: "LOGOUT",
            targetType: "user",
            targetId: uid,
            channel: null,
            workspaceId: null,
            metadata: {},
          }).catch((_err) => {
            logger.warn("Audit write failed", { error: _err.message });
          });
        }
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }

      // Clear the session cookie in both dev and prod settings
      const cookieOptions = {
        httpOnly: true,
        sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
        secure: sessionCookieSecure,
        path: "/",
      };
      res.clearCookie("sessionId", cookieOptions);
      res.json({ success: true });
    });
  });
});

// Auth logout endpoint (for compatibility with tests)
router.post("/auth/logout", getApiLimiter(), (req, res) => {
  // Logout and destroy session properly through Passport.js
  req.logout(function (err) {
    if (err) {
      logger.error("Logout error:", {
        error: err.message,
        stack: err.stack,
      });
    }
    // Clear the session cookie in both dev and prod settings
    const cookieOptions = {
      httpOnly: true,
      sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
      secure: sessionCookieSecure,
      path: "/",
    };
    res.clearCookie("sessionId", cookieOptions);
    res.json({ message: "logged out successfully" });
  });
});

module.exports = router;
