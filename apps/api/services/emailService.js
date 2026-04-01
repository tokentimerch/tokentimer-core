const nodemailer = require("nodemailer");
const client = require("prom-client");
const crypto = require("crypto");
const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const { logger } = require("../utils/logger.js");
const systemSettings = require("./systemSettings");

// Pool reference for system settings resolver (set via setPool)
let _pool = null;
/**
 * Set the database pool for system settings resolution
 * @param {Object} pool - PostgreSQL connection pool
 * @returns {void}
 */
function setPool(pool) {
  _pool = pool;
}

// Support contact used in email footers
function getSupportEmail() {
  return (
    process.env.FROM_EMAIL ||
    process.env.SMTP_USER ||
    "support@your-company.com"
  );
}

function parseBool(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
}

function resolveSmtpSecurity(port, secureOverride, requireTlsOverride) {
  return {
    secure: parseBool(secureOverride, String(port || "") === "465"),
    requireTLS: parseBool(requireTlsOverride, true),
  };
}

// Email configuration
const emailConfig = {
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  ...resolveSmtpSecurity(
    process.env.SMTP_PORT,
    process.env.SMTP_SECURE,
    process.env.SMTP_REQUIRE_TLS,
  ),
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
  // Add timeout and connection settings
  connectionTimeout: 60000, // 60 seconds
  greetingTimeout: 30000, // 30 seconds
  socketTimeout: 60000, // 60 seconds
  tls: {
    rejectUnauthorized: process.env.SMTP_REJECT_UNAUTHORIZED !== "false",
  },
};

// Standard email footer (uses configurable support email)
function getEmailFooterText() {
  return `Please do not reply to this email. If you have any questions, contact ${getSupportEmail()}.`;
}

// Cache for logo buffer to avoid fetching it on every email
let logoBufferCache = null;
let logoMimeTypeCache = null;

// Fetch logo as buffer for email attachments
const getLogoBuffer = () => {
  if (logoBufferCache) {
    logger.debug("Using cached logo buffer");
    return { buffer: logoBufferCache, mimeType: logoMimeTypeCache };
  }

  // Try filesystem first - prioritize backend assets folder
  try {
    const possiblePaths = [
      // Backend assets folder (most reliable)
      path.join(__dirname, "../assets/Branding/logo.png"),
      path.join(process.cwd(), "assets/Branding/logo.png"),
      // Frontend paths (for development)
      path.join(__dirname, "../../frontend/public/Branding/logo.png"),
      path.join(__dirname, "../frontend/public/Branding/logo.png"),
      path.join(process.cwd(), "frontend/public/Branding/logo.png"),
      path.join(process.cwd(), "../frontend/public/Branding/logo.png"),
    ];

    for (const logoPath of possiblePaths) {
      try {
        if (fs.existsSync(logoPath)) {
          const buffer = fs.readFileSync(logoPath);
          logoBufferCache = buffer;
          logoMimeTypeCache = "image/png";
          logger.info(`Logo loaded from filesystem: ${logoPath}`);
          return { buffer, mimeType: "image/png" };
        }
      } catch (_err) {
        logger.debug("Logo path read failed", {
          path: logoPath,
          error: _err?.message,
        });
      }
    }
    logger.debug("Logo not found in filesystem, trying HTTP fetch");
  } catch (err) {
    logger.debug("Filesystem logo check failed, trying HTTP:", err.message);
  }

  // Fallback to HTTP fetch
  const frontendUrl = process.env.APP_URL || "http://localhost:5173";
  const baseUrl = frontendUrl.replace(/\/$/, "");
  const logoUrl = `${baseUrl}/Branding/logo.png`;

  try {
    return new Promise((resolve) => {
      logger.info(`Attempting to fetch logo from: ${logoUrl}`);
      const url = new URL(logoUrl);
      const client = url.protocol === "https:" ? https : http;

      const request = client.get(url, (res) => {
        if (res.statusCode !== 200) {
          logger.warn(
            `Failed to fetch logo: HTTP ${res.statusCode} from ${logoUrl}`,
          );
          resolve(null);
          return;
        }

        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          try {
            const buffer = Buffer.concat(chunks);
            const mimeType = res.headers["content-type"] || "image/png";
            logoBufferCache = buffer;
            logoMimeTypeCache = mimeType;
            logger.info(
              `Logo fetched successfully via HTTP (${buffer.length} bytes)`,
            );
            resolve({ buffer, mimeType });
          } catch (err) {
            logger.warn("Error processing logo buffer", {
              error: err?.message,
              stack: err?.stack,
            });
            resolve(null);
          }
        });
      });

      request.on("error", (err) => {
        logger.warn(`Error fetching logo from ${logoUrl}:`, err.message);
        resolve(null);
      });

      request.setTimeout(5000, () => {
        logger.warn(`Timeout fetching logo from ${logoUrl}`);
        request.destroy();
        resolve(null);
      });
    });
  } catch (err) {
    logger.warn("Error in getLogoBuffer", {
      error: err?.message,
      stack: err?.stack,
    });
    return null;
  }
};

// Get logo URL for emails - fallback to URL if buffer fetch fails
const getLogoUrl = () => {
  const frontendUrl = process.env.APP_URL || "http://localhost:5173";
  const baseUrl = frontendUrl.replace(/\/$/, "");
  return `${baseUrl}/Branding/logo.png`;
};

/**
 * Generate HTML and plain text email templates with consistent styling
 * @param {Object} options - Template options
 * @param {string} [options.title] - Email title/heading
 * @param {string} [options.greeting] - Greeting text
 * @param {string} options.content - Main HTML content
 * @param {string} [options.buttonText] - Text for call-to-action button
 * @param {string} [options.buttonUrl] - URL for call-to-action button
 * @param {string} [options.footerNote] - Additional footer note
 * @param {string} [options.plainTextContent] - Custom plain text content (auto-generated if not provided)
 * @returns {Object} Object with html, text, and useEmbeddedLogo properties
 */
const generateEmailTemplate = (options) => {
  const {
    title,
    greeting,
    content,
    buttonText,
    buttonUrl,
    footerNote,
    plainTextContent,
  } = options;

  // Use CID reference for embedded logo attachment
  const logoUrl = getLogoUrl();
  const logoSrc = "cid:logo"; // Use CID reference for embedded attachment
  const frontendUrl = process.env.APP_URL || "http://localhost:5173";

  // Build button HTML if provided
  let buttonHtml = "";
  if (buttonText && buttonUrl) {
    buttonHtml = `
      <div style="text-align: center; margin: 30px 0;">
        <a href="${buttonUrl}" 
           style="background-color: #2B6CB0; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: 600; font-size: 16px;">
          ${buttonText}
        </a>
      </div>`;
  }

  // Build footer note if provided
  let footerNoteHtml = "";
  if (footerNote) {
    footerNoteHtml = `
      <p style="color: #666; font-size: 14px; line-height: 1.6; margin-top: 20px;">
        ${footerNote}
      </p>`;
  }

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title || "TokenTimer"}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f5f5f5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
  <table role="presentation" style="width: 100%; border-collapse: collapse; background-color: #f5f5f5;">
    <tr>
      <td style="padding: 40px 20px;">
        <table role="presentation" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
          <!-- Content -->
          <tr>
            <td style="padding: 40px;">
              <h1 style="color: #1a202c; font-size: 24px; font-weight: 600; margin: 0 0 20px; line-height: 1.3;">
                ${title || "TokenTimer"}
              </h1>
              
              ${greeting ? `<p style="color: #4a5568; font-size: 16px; line-height: 1.6; margin: 0 0 20px;">${greeting}</p>` : ""}
              
              <div style="color: #4a5568; font-size: 16px; line-height: 1.6;">
                ${content}
              </div>
              
              ${buttonHtml}
              
              ${footerNoteHtml}
            </td>
          </tr>
          
          <!-- Footer -->
          <tr>
            <td style="padding: 30px 40px; background-color: #f7fafc; border-top: 1px solid #e2e8f0;">
              <table role="presentation" style="width: 100%; border-collapse: collapse;">
                <tr>
                  <td style="text-align: center; padding-bottom: 20px;">
                    <!--[if mso]>
                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                      <tr>
                        <td style="text-align: center;">
                          <img src="${logoUrl}" alt="TokenTimer" width="80" height="auto" style="max-width: 80px; height: auto; opacity: 0.8;" />
                        </td>
                      </tr>
                    </table>
                    <![endif]-->
                    <!--[if !mso]><!-->
                    <img src="${logoSrc}" alt="TokenTimer" width="80" height="auto" style="max-width: 80px; height: auto; opacity: 0.8; border: 0; outline: none; text-decoration: none; -ms-interpolation-mode: bicubic;" />
                    <!--<![endif]-->
                  </td>
                </tr>
                <tr>
                  <td style="text-align: center; padding-bottom: 15px;">
                    <p style="color: #718096; font-size: 14px; margin: 0; line-height: 1.6;">
                      <strong style="color: #2d3748;">TokenTimer</strong><br />
                    </p>
                  </td>
                </tr>
                <tr>
                  <td style="text-align: center;">
                    <p style="color: #a0aec0; font-size: 12px; margin: 0; line-height: 1.5;">
                      Please do not reply to this email. If you have any questions, contact<br />
                      <a href="mailto:${getSupportEmail()}" style="color: #2B6CB0; text-decoration: none;">${getSupportEmail()}</a>
                    </p>
                  </td>
                </tr>
                <tr>
                  <td style="text-align: center; padding-top: 20px;">
                    <p style="color: #cbd5e0; font-size: 11px; margin: 0;">
                      <a href="${frontendUrl}" style="color: #cbd5e0; text-decoration: none;">Visit TokenTimer</a>
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

  // Generate plain text version
  const text =
    plainTextContent ||
    `
${title || "TokenTimer"}

${greeting || ""}

${content.replace(/<[^>]*>/g, "").replace(/\n\s*\n/g, "\n\n")}

${buttonText && buttonUrl ? `${buttonText}: ${buttonUrl}` : ""}

${footerNote ? footerNote.replace(/<[^>]*>/g, "") : ""}

TokenTimer
${getEmailFooterText()}
  `.trim();

  return { html, text, useEmbeddedLogo: true };
};

function appendFooterToParts(parts) {
  const out = { ...parts };
  if (out.text) out.text = `${out.text}\n\n${getEmailFooterText()}`;
  if (out.html) out.html = `${out.html}`;
  return out;
}

// Classify SMTP errors, increment metrics, and return standardized response fields
function classifySmtpErrorAndRecord(kind, error) {
  const msg = String(error?.message || "");
  const codeStr = String(error?.code || "");
  const isRateLimit =
    /451\b/.test(msg) ||
    /rate[- ]?limit|maximum number of sent emails/i.test(msg);
  let outcome = "other_error";
  let code = "SMTP_ERROR";
  const supportEmail = getSupportEmail();
  let userError = `Failed to send email. If the problem persists, contact ${supportEmail}.`;

  if (isRateLimit) {
    outcome = "rate_limited";
    code = "SMTP_RATE_LIMIT";
    userError = `Email rate limit reached. Please try again later or contact ${supportEmail} if this persists.`;
  } else if (
    /ECONNECTION|ECONNREFUSED/i.test(codeStr) ||
    /ECONNECTION|ECONNREFUSED/i.test(msg)
  ) {
    outcome = "connection_error";
    code = "SMTP_CONNECTION";
    userError = `SMTP connection failed. Please try again later or contact ${supportEmail} if this persists.`;
  } else if (/EAUTH/i.test(codeStr) || /EAUTH/i.test(msg)) {
    outcome = "auth_error";
    code = "SMTP_AUTH";
    userError = `SMTP authentication failed. If the problem persists, contact ${supportEmail}.`;
  } else if (/ETIMEDOUT/i.test(codeStr) || /ETIMEDOUT/i.test(msg)) {
    outcome = "timeout";
    code = "SMTP_TIMEOUT";
    userError = `SMTP connection timeout. Please try again or contact ${supportEmail} if this persists.`;
  } else if (/all recipients were rejected/i.test(msg)) {
    outcome = "temporary_failure";
    code = "SMTP_TEMPORARY_FAILURE";
    userError = `Email service temporarily unavailable. Please try again later or contact ${supportEmail} if this persists.`;
  }

  try {
    smtpSends.labels(kind, outcome).inc();
  } catch (_) {
    logger.debug("SMTP metric inc failed", { error: _?.message });
  }

  return { code, error: userError, providerError: msg };
}

// Support multiple SMTP users (comma-separated). Passwords may be a single value or comma-separated to match indices.
function parseList(value) {
  return String(value || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

const SMTP_USERS = parseList(process.env.SMTP_USER);
const SMTP_PASS = parseList(process.env.SMTP_PASS);

const transportersCache = [];
function getTransporterForIndex(index) {
  const user = SMTP_USERS[index] || process.env.SMTP_USER;
  // Use password matching the same index when multiple credentials are provided
  const pass = SMTP_PASS[index] || SMTP_PASS[0] || process.env.SMTP_PASS;
  if (!user || !pass || !process.env.SMTP_HOST) return null;
  if (transportersCache[index]) return transportersCache[index];
  const smtpSecurity = resolveSmtpSecurity(
    process.env.SMTP_PORT,
    process.env.SMTP_SECURE,
    process.env.SMTP_REQUIRE_TLS,
  );
  const tx = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: smtpSecurity.secure,
    requireTLS: smtpSecurity.requireTLS,
    auth: { user, pass },
    connectionTimeout: 60000,
    greetingTimeout: 30000,
    socketTimeout: 60000,
    tls: {
      rejectUnauthorized: process.env.SMTP_REJECT_UNAUTHORIZED !== "false",
    },
  });
  transportersCache[index] = tx;
  return tx;
}

function getFromForIndex(index) {
  const addr = SMTP_USERS[index] || process.env.SMTP_USER;
  if (!addr) return null;
  const displayName = process.env.FROM_EMAIL_NAME || "TokenTimer";
  return `"${displayName}" <${addr}>`;
}

/**
 * Check if SMTP is configured via environment variables (synchronous check)
 * @returns {boolean} True if SMTP_HOST, SMTP_USER, and SMTP_PASS are all set
 */
const isSMTPConfigured = () => {
  const configured =
    process.env.SMTP_USER && process.env.SMTP_PASS && process.env.SMTP_HOST;
  logger.info("SMTP Configuration check:", {
    SMTP_HOST: process.env.SMTP_HOST ? "SET" : "NOT SET",
    SMTP_PORT: process.env.SMTP_PORT ? "SET" : "NOT SET",
    SMTP_USER: process.env.SMTP_USER ? "SET" : "NOT SET",
    SMTP_PASS: process.env.SMTP_PASS ? "SET" : "NOT SET",
    configured,
  });
  return configured;
};

/**
 * Check if SMTP is configured via environment variables or database settings (async check)
 * @returns {Promise<boolean>} True if SMTP is configured via env vars or database
 */
async function isSMTPConfiguredAsync() {
  if (isSMTPConfigured()) return true;
  if (_pool) return await systemSettings.isSmtpConfigured(_pool);
  return false;
}

/**
 * Get a nodemailer transporter using resolved settings (environment variables or database)
 * Creates transporter on demand and caches it based on configuration key
 * @returns {Promise<Object|null>} Nodemailer transporter instance or null if not configured
 */
let _resolvedTransporter = null;
let _resolvedTransporterKey = null;
async function getResolvedTransporter() {
  if (!_pool) return transporter; // fallback to env-based transporter
  const host = await systemSettings.getSettingValue(_pool, "smtp_host");
  const port = await systemSettings.getSettingValue(_pool, "smtp_port");
  const user = await systemSettings.getSettingValue(_pool, "smtp_user");
  const pass = await systemSettings.getSettingValue(_pool, "smtp_pass");
  const secureSetting = await systemSettings.getSettingValue(_pool, "smtp_secure");
  const requireTlsSetting = await systemSettings.getSettingValue(
    _pool,
    "smtp_require_tls",
  );
  if (!host || !user || !pass) return transporter; // fallback
  const key = `${host}:${port}:${user}:${secureSetting || ""}:${requireTlsSetting || ""}`;
  if (_resolvedTransporter && _resolvedTransporterKey === key)
    return _resolvedTransporter;
  const smtpSecurity = resolveSmtpSecurity(
    port,
    secureSetting,
    requireTlsSetting,
  );
  _resolvedTransporter = nodemailer.createTransport({
    host,
    port: parseInt(port || "0", 10) || undefined,
    secure: smtpSecurity.secure,
    requireTLS: smtpSecurity.requireTLS,
    auth: { user, pass },
    connectionTimeout: 60000,
    greetingTimeout: 30000,
    socketTimeout: 60000,
    tls: {
      rejectUnauthorized: process.env.SMTP_REJECT_UNAUTHORIZED !== "false",
    },
  });
  _resolvedTransporterKey = key;
  return _resolvedTransporter;
}

// Create default transporter only in single-account mode to avoid invalid creds when using lists
let transporter = null;
const multipleAccountsDetected =
  (Array.isArray(SMTP_USERS) && SMTP_USERS.length > 1) ||
  String(process.env.SMTP_USER || "").includes(",");
if (isSMTPConfigured()) {
  if (!multipleAccountsDetected) {
    try {
      transporter = nodemailer.createTransport(emailConfig);
      logger.info("SMTP transporter created successfully");
    } catch (error) {
      logger.error("Failed to create SMTP transporter", {
        error: error?.message,
        stack: error?.stack,
      });
      transporter = null;
    }
  } else {
    logger.info(
      "Multiple SMTP users detected; using per-account transporters and skipping default transporter.",
    );
  }
} else {
  if (process.env.NODE_ENV === "production") {
    logger.warn("SMTP not configured. Email verification will be disabled.");
  } else {
    logger.info(
      "SMTP not configured. Email verification is disabled until SMTP is configured.",
    );
  }
}

// Verify SMTP connectivity for each configured account on startup (best-effort)
async function verifyAllSmtpAccountsOnStartup() {
  try {
    if (!isSMTPConfigured()) return;
    if (process.env.NODE_ENV === "test") return;
    if (multipleAccountsDetected) {
      const total = SMTP_USERS.length || 1;
      for (let i = 0; i < total; i++) {
        const tx = getTransporterForIndex(i);
        if (!tx) {
          logger.warn(
            `SMTP account #${i + 1} is not fully configured; skipping verification.`,
          );
          continue;
        }
        try {
          await tx.verify();
          logger.info(
            `SMTP account #${i + 1} (${SMTP_USERS[i] || process.env.SMTP_USER}) verified successfully.`,
          );
        } catch (e) {
          logger.warn(
            `SMTP account #${i + 1} (${SMTP_USERS[i] || process.env.SMTP_USER}) verification failed: ${String(
              e?.message || "",
            )}`,
          );
        }
      }
    } else if (transporter) {
      try {
        await transporter.verify();
        logger.info("Default SMTP account verified successfully.");
      } catch (e) {
        logger.warn(
          `Default SMTP account verification failed: ${String(e?.message || "")}`,
        );
      }
    }
  } catch (_) {
    logger.debug("SMTP startup verify failed", { error: _?.message });
  }
}

// Fire and forget (must use .catch to handle async rejections)
verifyAllSmtpAccountsOnStartup().catch((err) => {
  logger.warn("SMTP startup verification failed", { error: err?.message });
});

// SMTP metrics
const smtpLatency = new client.Histogram({
  name: "tokentimer_api_smtp_latency_seconds",
  help: "SMTP send latency in seconds",
  labelNames: ["kind"],
  buckets: [0.1, 0.25, 0.5, 1, 2, 5, 10],
});
const smtpSends = new client.Counter({
  name: "tokentimer_api_smtp_sends_total",
  help: "SMTP send attempts",
  labelNames: ["kind", "outcome"],
});

/**
 * Generate a cryptographically secure verification token
 * @returns {string} Hexadecimal token string (64 characters)
 */
const generateVerificationToken = () => {
  return crypto.randomBytes(32).toString("hex");
};

async function sendWithDbSmtpFallback({ kind, to, baseMail }) {
  if (!_pool) return null;
  try {
    const hostSetting = await systemSettings.getSetting(_pool, "smtp_host");
    const userSetting = await systemSettings.getSetting(_pool, "smtp_user");
    const passSetting = await systemSettings.getSetting(_pool, "smtp_pass");
    const dbHost =
      hostSetting?.source === "database" ? hostSetting.value : null;
    const dbUser =
      userSetting?.source === "database" ? userSetting.value : null;
    const dbPass =
      passSetting?.source === "database" ? passSetting.value : null;
    if (!dbHost || !dbUser || !dbPass) return null;

    const tx = await getResolvedTransporter();
    const dbFromEmail =
      (await systemSettings.getSettingValue(_pool, "smtp_from_email")) ||
      dbUser;
    const dbFromName =
      (await systemSettings.getSettingValue(_pool, "smtp_from_name")) ||
      process.env.FROM_EMAIL_NAME ||
      "TokenTimer";
    const safeDbFromName = String(dbFromName || "").replace(/[\r\n"]/g, "");

    await tx.verify();
    const end = smtpLatency.labels(kind).startTimer();
    const info = await tx.sendMail({
      from: `"${safeDbFromName}" <${dbFromEmail}>`,
      ...baseMail,
    });
    try {
      end();
    } catch (_) {
      logger.debug("Metrics recording failed", { error: _.message });
    }
    const acceptedCount = Array.isArray(info?.accepted)
      ? info.accepted.length
      : 0;
    const responseText = String(info?.response || "");
    const responseIndicatesRateLimit =
      /451\b/i.test(responseText) ||
      /rate[- ]?limit|maximum number of sent emails/i.test(responseText);

    if (acceptedCount > 0 && !responseIndicatesRateLimit) {
      try {
        smtpSends.labels(kind, "success").inc();
      } catch (_) {
        logger.debug("Metrics recording failed", { error: _.message });
      }
      logger.info(`Email sent to ${to} using DB SMTP settings`);
      return { success: true };
    }

    const classified = classifySmtpErrorAndRecord(
      kind,
      new Error(responseText || "SMTP did not accept recipient(s)"),
    );
    return { success: false, ...classified };
  } catch (error) {
    const classified = classifySmtpErrorAndRecord(kind, error);
    return { success: false, ...classified };
  }
}

/**
 * Send email verification email to a user
 * @param {string} email - Recipient email address
 * @param {string} token - Verification token
 * @param {string} displayName - User's display name for personalization
 * @returns {Promise<Object>} Result object with success boolean and optional error fields
 */
const sendVerificationEmail = async (email, token, displayName) => {
  const verificationBaseUrl = process.env.API_URL || "http://localhost:4000";
  const verificationUrl = `${verificationBaseUrl}/auth/verify-email/${token}`;

  const { html, text, useEmbeddedLogo } = generateEmailTemplate({
    title: "Verify your TokenTimer account",
    greeting: `Hi ${displayName},`,
    content: `
      <p>Thank you for registering with TokenTimer. To complete your registration, please verify your email address by clicking the button below:</p>
      
      <p style="margin-top: 20px; color: #718096; font-size: 14px;">If the button doesn't work, you can copy and paste this link into your browser:</p>
      <p style="word-break: break-all; color: #4a5568; font-size: 14px; background-color: #f7fafc; padding: 12px; border-radius: 4px; font-family: monospace;">${verificationUrl}</p>
      
      <p style="margin-top: 20px; color: #718096; font-size: 14px;">This link will expire in 24 hours.</p>
      
      <p style="margin-top: 20px; color: #718096; font-size: 14px;">If you didn't create this account, you can safely ignore this email.</p>
    `,
    buttonText: "Verify Email Address",
    buttonUrl: verificationUrl,
    plainTextContent: `
Hi ${displayName},

Thank you for registering with TokenTimer. To complete your registration, please verify your email address by clicking the link below:

${verificationUrl}

This link will expire in 24 hours.

If you didn't create this account, you can safely ignore this email.
    `,
  });

  // Get logo attachment if using embedded logo
  const attachments = [];
  if (useEmbeddedLogo) {
    const logoData = await getLogoBuffer();
    if (logoData) {
      attachments.push({
        filename: "logo.png",
        content: logoData.buffer,
        cid: "logo",
        contentType: logoData.mimeType,
        disposition: "inline",
      });
      logger.info(
        `Logo attachment added (${logoData.buffer.length} bytes, CID: logo)`,
      );
    } else {
      logger.warn(
        "Logo buffer is null, email will be sent without embedded logo",
      );
    }
  }

  const baseMail = {
    to: email,
    subject: "Verify your TokenTimer account",
    html,
    text,
    attachments,
  };

  logger.info(`Sending verification email to ${email}`);
  // Try each configured SMTP user until success or all fail
  const total = SMTP_USERS.length || 1;
  let lastError = null;
  for (let i = 0; i < total; i++) {
    const tx = getTransporterForIndex(i);
    if (!tx) continue;
    const mailOptions = {
      from: getFromForIndex(i),
      ...baseMail,
    };
    if (baseMail.attachments && baseMail.attachments.length > 0) {
      logger.debug(
        `Sending email with ${baseMail.attachments.length} attachment(s)`,
      );
    }
    try {
      await tx.verify();
      const end = smtpLatency.labels("verification").startTimer();
      const info = await tx.sendMail(mailOptions);
      try {
        end();
      } catch (_) {
        logger.debug("Metrics recording failed", { error: _.message });
      }
      const acceptedCount = Array.isArray(info?.accepted)
        ? info.accepted.length
        : 0;
      const responseText = String(info?.response || "");
      const responseIndicatesRateLimit =
        /451\b/i.test(responseText) ||
        /rate[- ]?limit|maximum number of sent emails/i.test(responseText);
      if (acceptedCount > 0 && !responseIndicatesRateLimit) {
        try {
          smtpSends.labels("verification", "success").inc();
        } catch (_) {
          logger.debug("Metrics recording failed", { error: _.message });
        }
        logger.info(
          `Verification email sent to ${email} using account #${i + 1}`,
        );
        return { success: true };
      }
      const classified = classifySmtpErrorAndRecord(
        "verification",
        new Error(responseText || "SMTP did not accept recipient(s)"),
      );
      lastError = { success: false, ...classified };
      continue;
    } catch (error) {
      const classified = classifySmtpErrorAndRecord("verification", error);
      lastError = { success: false, ...classified };
      continue;
    }
  }
  const dbResult = await sendWithDbSmtpFallback({
    kind: "verification",
    to: email,
    baseMail,
  });
  if (dbResult?.success) return dbResult;
  if (dbResult) lastError = dbResult;
  return lastError || { success: false, error: "SMTP not configured" };
};

/**
 * Send password reset email to a user
 * @param {string} email - Recipient email address
 * @param {string} token - Password reset token
 * @param {string} displayName - User's display name for personalization
 * @returns {Promise<Object>} Result object with success boolean and optional error fields
 */
const sendPasswordResetEmail = async (email, token, displayName) => {
  const appUrl = process.env.APP_URL || "http://localhost:5173";
  const resetUrl = `${appUrl}/reset-password?token=${token}&email=${encodeURIComponent(email)}`;

  const { html, text, useEmbeddedLogo } = generateEmailTemplate({
    title: "Reset your TokenTimer password",
    greeting: `Hi ${displayName},`,
    content: `
      <p>We received a request to reset your password. Click the button below to create a new password:</p>
      
      <p style="margin-top: 20px; color: #718096; font-size: 14px;">If the button doesn't work, you can copy and paste this link into your browser:</p>
      <p style="word-break: break-all; color: #4a5568; font-size: 14px; background-color: #f7fafc; padding: 12px; border-radius: 4px; font-family: monospace;">${resetUrl}</p>
      
      <p style="margin-top: 20px; color: #718096; font-size: 14px;">This link will expire in 5 minutes.</p>
      
      <p style="margin-top: 20px; color: #718096; font-size: 14px;">If you didn't request a password reset, you can safely ignore this email.</p>
    `,
    buttonText: "Reset Password",
    buttonUrl: resetUrl,
    plainTextContent: `
Hi ${displayName},

We received a request to reset your password. Click the link below to create a new password:

${resetUrl}

This link will expire in 5 minutes.

If you didn't request a password reset, you can safely ignore this email.
    `,
  });

  // Get logo attachment if using embedded logo
  const attachments = [];
  if (useEmbeddedLogo) {
    const logoData = await getLogoBuffer();
    if (logoData) {
      attachments.push({
        filename: "logo.png",
        content: logoData.buffer,
        cid: "logo",
        contentType: logoData.mimeType,
        disposition: "inline",
      });
      logger.info(
        `Logo attachment added (${logoData.buffer.length} bytes, CID: logo)`,
      );
    } else {
      logger.warn(
        "Logo buffer is null, email will be sent without embedded logo",
      );
    }
  }

  const baseMail = {
    to: email,
    subject: "Reset your TokenTimer password",
    html,
    text,
    attachments,
  };

  logger.info(`Sending password reset email to ${email}`);
  const total = SMTP_USERS.length || 1;
  let lastError = null;
  for (let i = 0; i < total; i++) {
    const tx = getTransporterForIndex(i);
    if (!tx) continue;
    const mailOptions = {
      from: getFromForIndex(i),
      ...baseMail,
    };
    if (baseMail.attachments && baseMail.attachments.length > 0) {
      logger.debug(
        `Sending email with ${baseMail.attachments.length} attachment(s)`,
      );
    }
    try {
      await tx.verify();
      const end = smtpLatency.labels("reset").startTimer();
      const info = await tx.sendMail(mailOptions);
      try {
        end();
      } catch (_) {
        logger.debug("Metrics recording failed", { error: _.message });
      }
      const acceptedCount = Array.isArray(info?.accepted)
        ? info.accepted.length
        : 0;
      const responseText = String(info?.response || "");
      const responseIndicatesRateLimit =
        /451\b/i.test(responseText) ||
        /rate[- ]?limit|maximum number of sent emails/i.test(responseText);
      if (acceptedCount > 0 && !responseIndicatesRateLimit) {
        try {
          smtpSends.labels("reset", "success").inc();
        } catch (_) {
          logger.debug("Metrics recording failed", { error: _.message });
        }
        logger.info(
          `Password reset email sent to ${email} using account #${i + 1}`,
        );
        return { success: true };
      }
      const classified = classifySmtpErrorAndRecord(
        "reset",
        new Error(responseText || "SMTP did not accept recipient(s)"),
      );
      lastError = { success: false, ...classified };
      continue;
    } catch (error) {
      const classified = classifySmtpErrorAndRecord("reset", error);
      lastError = { success: false, ...classified };
      continue;
    }
  }
  const dbResult = await sendWithDbSmtpFallback({
    kind: "reset",
    to: email,
    baseMail,
  });
  if (dbResult?.success) return dbResult;
  if (dbResult) lastError = dbResult;
  return lastError || { success: false, error: "SMTP not configured" };
};

/**
 * Send a generic email with custom content
 * @param {Object} options - Email options
 * @param {string} options.to - Recipient email address
 * @param {string} options.subject - Email subject
 * @param {string} [options.text] - Plain text email body
 * @param {string} [options.html] - HTML email body
 * @param {boolean} [options.useEmbeddedLogo] - Whether to embed logo as attachment
 * @returns {Promise<Object>} Result object with success boolean and optional error fields
 */
const sendEmail = async (options) => {
  const { to, subject, text, html, useEmbeddedLogo } = options;

  // Check if HTML already contains the full template (with footer)
  // If so, don't append footer again
  const hasFullTemplate = html && html.includes("<!-- Footer -->");
  const withFooter = hasFullTemplate
    ? { text, html }
    : appendFooterToParts({ text, html });

  // Get logo attachment if using embedded logo and template includes footer
  const attachments = [];
  if (
    useEmbeddedLogo ||
    (hasFullTemplate && html && html.includes("cid:logo"))
  ) {
    const logoData = await getLogoBuffer();
    if (logoData) {
      attachments.push({
        filename: "logo.png",
        content: logoData.buffer,
        cid: "logo",
        contentType: logoData.mimeType,
        disposition: "inline",
      });
      logger.debug(
        `Logo attachment added to generic email (${logoData.buffer.length} bytes, CID: logo)`,
      );
    }
  }

  logger.info(`Sending email to ${to}`);
  const total = SMTP_USERS.length || 1;
  let lastError = null;
  for (let i = 0; i < total; i++) {
    const tx = getTransporterForIndex(i);
    if (!tx) continue;
    const mailOptions = {
      from: getFromForIndex(i),
      to,
      subject,
      text: withFooter.text,
      html: withFooter.html,
      attachments: attachments.length > 0 ? attachments : undefined,
    };
    try {
      await tx.verify();
      const end = smtpLatency.labels("generic").startTimer();
      const info = await tx.sendMail(mailOptions);
      try {
        end();
      } catch (_) {
        logger.debug("Metrics recording failed", { error: _.message });
      }
      const acceptedCount = Array.isArray(info?.accepted)
        ? info.accepted.length
        : 0;
      const responseText = String(info?.response || "");
      const responseIndicatesRateLimit =
        /451\b/i.test(responseText) ||
        /rate[- ]?limit|maximum number of sent emails/i.test(responseText);
      if (acceptedCount > 0 && !responseIndicatesRateLimit) {
        try {
          smtpSends.labels("generic", "success").inc();
        } catch (_) {
          logger.debug("Metrics recording failed", { error: _.message });
        }
        logger.info(`Email sent to ${to} using account #${i + 1}`);
        return { success: true };
      }
      const classified = classifySmtpErrorAndRecord(
        "generic",
        new Error(responseText || "SMTP did not accept recipient(s)"),
      );
      lastError = { success: false, ...classified };
      continue;
    } catch (error) {
      const classified = classifySmtpErrorAndRecord("generic", error);
      lastError = { success: false, ...classified };
      continue;
    }
  }
  // Fallback for deployments that configure SMTP in System Settings (DB) only.
  // The admin SMTP test route already uses DB settings; generic email should too.
  if (_pool) {
    try {
      const dbHost = await systemSettings.getSettingValue(_pool, "smtp_host");
      const dbUser = await systemSettings.getSettingValue(_pool, "smtp_user");
      const dbPass = await systemSettings.getSettingValue(_pool, "smtp_pass");
      if (dbHost && dbUser && dbPass) {
        const tx = await getResolvedTransporter();
        const dbFromEmail =
          (await systemSettings.getSettingValue(_pool, "smtp_from_email")) ||
          dbUser;
        const dbFromName =
          (await systemSettings.getSettingValue(_pool, "smtp_from_name")) ||
          process.env.FROM_EMAIL_NAME ||
          "TokenTimer";
        const safeDbFromName = String(dbFromName || "").replace(/[\r\n"]/g, "");
        const mailOptions = {
          from: `"${safeDbFromName}" <${dbFromEmail}>`,
          to,
          subject,
          text: withFooter.text,
          html: withFooter.html,
          attachments: attachments.length > 0 ? attachments : undefined,
        };

        await tx.verify();
        const end = smtpLatency.labels("generic").startTimer();
        const info = await tx.sendMail(mailOptions);
        try {
          end();
        } catch (_) {
          logger.debug("Metrics recording failed", { error: _.message });
        }
        const acceptedCount = Array.isArray(info?.accepted)
          ? info.accepted.length
          : 0;
        const responseText = String(info?.response || "");
        const responseIndicatesRateLimit =
          /451\b/i.test(responseText) ||
          /rate[- ]?limit|maximum number of sent emails/i.test(responseText);
        if (acceptedCount > 0 && !responseIndicatesRateLimit) {
          try {
            smtpSends.labels("generic", "success").inc();
          } catch (_) {
            logger.debug("Metrics recording failed", { error: _.message });
          }
          logger.info(`Email sent to ${to} using DB SMTP settings`);
          return { success: true };
        }
        const classified = classifySmtpErrorAndRecord(
          "generic",
          new Error(responseText || "SMTP did not accept recipient(s)"),
        );
        lastError = { success: false, ...classified };
      }
    } catch (error) {
      const classified = classifySmtpErrorAndRecord("generic", error);
      lastError = { success: false, ...classified };
    }
  }
  return lastError || { success: false, error: "SMTP not configured" };
};

/**
 * Send welcome email with product tour invitation to a new user
 * @param {string} email - Recipient email address
 * @param {string} displayName - User's display name for personalization
 * @returns {Promise<Object>} Result object with success boolean and optional error fields
 */
const sendWelcomeEmail = async (email, displayName) => {
  const frontendUrl = process.env.APP_URL || "http://localhost:5173";
  const tourUrl = `${frontendUrl}/dashboard?tour=dashboard`;

  const { html, text, useEmbeddedLogo } = generateEmailTemplate({
    title: "Welcome to TokenTimer!",
    greeting: `Hi ${displayName},`,
    content: `
      <p>Thank you for joining TokenTimer! We're excited to have you on board.</p>
      
      <p>TokenTimer helps you stay on top of your expiring assets by automatically monitoring your API keys, certificates, licenses, and other tokens. Never miss a renewal deadline again.</p>
      
      <p style="margin-top: 20px;"><strong>With TokenTimer you can:</strong></p>
      <ul style="color: #4a5568; line-height: 1.8; padding-left: 20px;">
        <li>Track expiration dates for all your tokens and certificates in one place</li>
        <li>Receive timely alerts via email, webhooks (including Slack, Teams, Discord, and PagerDuty), or WhatsApp</li>
        <li>Organize your assets by workspace and category with your team</li>
        <li>Set up custom contact groups for team-wide notifications</li>
        <li>Integrate with popular services like AWS, Azure, GitHub, and more</li>
      </ul>
      
      <p style="margin-top: 20px;">Ready to get started? Head to your <a href="${frontendUrl}/dashboard" style="color: #2B6CB0; text-decoration: none;">dashboard</a> to add your first token or certificate and configure your alerts.</p>
      
      <p style="margin-top: 30px; padding-top: 30px; border-top: 1px solid #e2e8f0; color: #4a5568; font-size: 16px;">
        If you did not already, you can take our interactive product tour to see the key features in action. During the tour, you'll learn how to:
      </p>
      <ul style="color: #4a5568; font-size: 16px; line-height: 1.8; padding-left: 20px; margin-top: 10px;">
        <li>Add and manage your tokens</li>
        <li>Set up alert preferences and contact groups</li>
        <li>Configure webhooks for Slack, Teams, Discord, PagerDuty, and more</li>
        <li>Monitor token expiration dates from your dashboard</li>
      </ul>
      
      <div style="text-align: center; margin: 20px 0;">
        <a href="${tourUrl}" style="background-color: #2B6CB0; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: 600; font-size: 14px;">
          Start Product Tour
        </a>
      </div>
      
      <p style="margin-top: 15px; color: #a0aec0; font-size: 12px; text-align: center;">
        If the button doesn't work, copy and paste this link into your browser:<br/>
        <span style="word-break: break-all; font-family: monospace;">${tourUrl}</span>
      </p>
      
      <p style="margin-top: 20px; color: #718096; font-size: 14px;">
        If you have any questions, just reply to this email or reach out to our support team.
      </p>
    `,
    plainTextContent: `
Hi ${displayName},

Thank you for joining TokenTimer! We're excited to have you on board.

TokenTimer helps you stay on top of your expiring assets by automatically monitoring your API keys, certificates, licenses, and other tokens. Never miss a renewal deadline again.

With TokenTimer you can:
- Track expiration dates for all your tokens and certificates in one place
- Receive timely alerts via email, webhooks (including Slack, Teams, Discord, and PagerDuty), or WhatsApp
- Organize your assets by workspace and category with your team
- Set up custom contact groups for team-wide notifications
- Integrate with popular services like AWS, Azure, GitHub, and more

Ready to get started? Head to your dashboard to add your first token or certificate and configure your alerts: ${frontendUrl}/dashboard

If you did not already, you can take our interactive product tour to see the key features in action. During the tour, you'll learn how to:
- Add and manage your tokens
- Set up alert preferences and contact groups
- Configure webhooks for Slack, Teams, Discord, and more
- Monitor token expiration dates from your dashboard

Start the product tour: ${tourUrl}

If the button doesn't work, copy and paste this link into your browser: ${tourUrl}

If you have any questions, just reply to this email or reach out to our support team.
    `,
  });

  // Get logo attachment if using embedded logo
  const attachments = [];
  if (useEmbeddedLogo) {
    const logoData = await getLogoBuffer();
    if (logoData) {
      attachments.push({
        filename: "logo.png",
        content: logoData.buffer,
        cid: "logo",
        contentType: logoData.mimeType,
        disposition: "inline",
      });
      logger.info(
        `Logo attachment added (${logoData.buffer.length} bytes, CID: logo)`,
      );
    } else {
      logger.warn(
        "Logo buffer is null, email will be sent without embedded logo",
      );
    }
  }

  const baseMail = {
    to: email,
    subject: "Welcome to TokenTimer!",
    html,
    text,
    attachments,
  };

  logger.info(`Sending welcome email to ${email}`);
  // Try each configured SMTP user until success or all fail
  const total = SMTP_USERS.length || 1;
  let lastError = null;
  for (let i = 0; i < total; i++) {
    const tx = getTransporterForIndex(i);
    if (!tx) continue;
    const mailOptions = {
      from: getFromForIndex(i),
      ...baseMail,
    };
    if (baseMail.attachments && baseMail.attachments.length > 0) {
      logger.debug(
        `Sending email with ${baseMail.attachments.length} attachment(s)`,
      );
    }
    try {
      await tx.verify();
      const end = smtpLatency.labels("welcome").startTimer();
      const info = await tx.sendMail(mailOptions);
      try {
        end();
      } catch (_) {
        logger.debug("Metrics recording failed", { error: _.message });
      }
      const acceptedCount = Array.isArray(info?.accepted)
        ? info.accepted.length
        : 0;
      const responseText = String(info?.response || "");
      const responseIndicatesRateLimit =
        /451\b/i.test(responseText) ||
        /rate[- ]?limit|maximum number of sent emails/i.test(responseText);
      if (acceptedCount > 0 && !responseIndicatesRateLimit) {
        try {
          smtpSends.labels("welcome", "success").inc();
        } catch (_) {
          logger.debug("Metrics recording failed", { error: _.message });
        }
        logger.info(`Welcome email sent to ${email} using account #${i + 1}`);
        return { success: true };
      }
      const classified = classifySmtpErrorAndRecord(
        "welcome",
        new Error(responseText || "SMTP did not accept recipient(s)"),
      );
      lastError = { success: false, ...classified };
      continue;
    } catch (error) {
      const classified = classifySmtpErrorAndRecord("welcome", error);
      lastError = { success: false, ...classified };
      continue;
    }
  }
  const dbResult = await sendWithDbSmtpFallback({
    kind: "welcome",
    to: email,
    baseMail,
  });
  if (dbResult?.success) return dbResult;
  if (dbResult) lastError = dbResult;
  return lastError || { success: false, error: "SMTP not configured" };
};

module.exports = {
  generateVerificationToken,
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendEmail,
  sendWelcomeEmail,
  generateEmailTemplate,
  isSMTPConfigured,
  isSMTPConfiguredAsync,
  getResolvedTransporter,
  setPool,
};
