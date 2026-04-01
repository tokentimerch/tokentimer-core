/**
 * @tokentimer/config
 *
 * Shared configuration for TokenTimer.
 * All configuration is environment-driven for self-host flexibility.
 */

export { getNetworkConfig, isAllowedHost } from "./network.js";
export { getDatabaseConfig } from "./database.js";

/**
 * Get the application configuration
 * @returns {Object} Configuration object with mode, environment, URLs, branding, features, security, and rate limiting settings
 */
export function getConfig() {
  return {
    // Mode
    mode: process.env.TT_MODE || "oss",
    environment: process.env.NODE_ENV || "development",

    // URLs
    baseUrl: process.env.APP_URL || "http://localhost:5173",
    apiUrl: process.env.API_URL || "http://localhost:4000",

    // Product identity
    brandName: "TokenTimer",
    brandEmail:
      process.env.FROM_EMAIL ||
      process.env.SMTP_USER ||
      "support@your-company.com",

    // Security
    sessionSecret: process.env.SESSION_SECRET,
    csrfEnabled: process.env.CSRF_ENABLED !== "false",

    // Rate limiting
    rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW || "60000", 10),
    rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX || "100", 10),
  };
}

/**
 * Get authentication configuration
 * @returns {Object} Authentication configuration object with local auth, session, password policy, and 2FA settings
 */
export function getAuthConfig() {
  return {
    // Local auth
    localAuthEnabled: process.env.LOCAL_AUTH_ENABLED !== "false",
    requireEmailVerification:
      process.env.REQUIRE_EMAIL_VERIFICATION !== "false",

    // Session
    sessionSecret: process.env.SESSION_SECRET,
    sessionMaxAge: parseInt(process.env.SESSION_MAX_AGE || "86400000", 10), // 24 hours

    // Password policy
    minPasswordLength: parseInt(process.env.MIN_PASSWORD_LENGTH || "8", 10),
    requireUppercase: process.env.REQUIRE_UPPERCASE !== "false",
    requireNumbers: process.env.REQUIRE_NUMBERS !== "false",

    // 2FA
    twoFactorEnabled: process.env.TWO_FACTOR_ENABLED !== "false",
  };
}

/**
 * Get email/SMTP configuration
 * @returns {Object} Email configuration object with SMTP settings, accounts array for round-robin, sender info, and TLS settings
 */
export function getEmailConfig() {
  // Support multiple SMTP accounts (comma-separated)
  const smtpHosts = (process.env.SMTP_HOST || "localhost")
    .split(",")
    .map((s) => s.trim());
  const smtpPorts = (process.env.SMTP_PORT || "587")
    .split(",")
    .map((s) => parseInt(s.trim(), 10));
  const smtpUsers = (process.env.SMTP_USER || "")
    .split(",")
    .map((s) => s.trim());
  const smtpPasses = (process.env.SMTP_PASS || "")
    .split(",")
    .map((s) => s.trim());

  return {
    enabled: !!process.env.SMTP_HOST,

    // Primary SMTP settings
    host: smtpHosts[0],
    port: smtpPorts[0],
    user: smtpUsers[0],
    pass: smtpPasses[0],

    // All SMTP accounts (for round-robin)
    accounts: smtpHosts.map((host, i) => ({
      host,
      port: smtpPorts[i] || smtpPorts[0],
      user: smtpUsers[i] || smtpUsers[0],
      pass: smtpPasses[i] || smtpPasses[0],
    })),

    // Sender info
    fromEmail: process.env.FROM_EMAIL || process.env.SMTP_USER,
    fromName: process.env.FROM_EMAIL_NAME || "TokenTimer",

    // TLS
    secure: process.env.SMTP_SECURE === "true",
    requireTls: process.env.SMTP_REQUIRE_TLS !== "false",
  };
}

/**
 * Get alerting configuration
 * @returns {Object} Alert configuration object with thresholds, delivery windows, and retry settings
 */
export function getAlertConfig() {
  return {
    // Default thresholds (days before expiration)
    thresholds: (process.env.ALERT_THRESHOLDS || "30,14,7,1,0")
      .split(",")
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => !isNaN(n)),

    // Delivery windows
    deliveryWindowStart: process.env.DELIVERY_WINDOW_DEFAULT_START || "00:00",
    deliveryWindowEnd: process.env.DELIVERY_WINDOW_DEFAULT_END || "23:59",
    deliveryWindowTz: process.env.DELIVERY_WINDOW_DEFAULT_TZ || "UTC",

    // Retry settings
    maxAttempts: parseInt(process.env.ALERT_MAX_ATTEMPTS || "20", 10),
    retryDelayMs: parseInt(process.env.ALERT_RETRY_DELAY_MS || "300000", 10), // 5 minutes
  };
}

/**
 * Validate required configuration
 * @returns {void}
 * @throws {Error} If required config is missing
 */
export function validateConfig() {
  const errors = [];

  // Required in production
  if (process.env.NODE_ENV === "production") {
    if (!process.env.SESSION_SECRET) {
      errors.push("SESSION_SECRET is required in production");
    }
    if (!process.env.DB_PASSWORD) {
      errors.push("DB_PASSWORD is required in production");
    }
  }

  if (errors.length > 0) {
    throw new Error(`Configuration errors:\n${errors.join("\n")}`);
  }
}
