import nodemailer from "nodemailer";
import fs from "fs";
import path from "path";
import crypto from "node:crypto";
import { fileURLToPath } from "url";
import { logger } from "../logger.js";
import { pool } from "../db.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let transporter = null;

// --- DB-based SMTP config fallback (mirrors systemSettings.js in the API) ---

let _dbSmtpCache = null;
let _dbSmtpCacheTime = 0;
const DB_SMTP_CACHE_TTL = 30000; // 30 seconds

// Salt for key derivation (must match the API's systemSettings.js)
const KDF_SALT = "tokentimer-settings-encryption";

function decryptWithKey(ciphertext, key) {
  const parts = ciphertext.split(":");
  if (parts.length !== 3) return null;
  const iv = Buffer.from(parts[0], "hex");
  const tag = Buffer.from(parts[1], "hex");
  const encrypted = parts[2];
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

function decryptSetting(ciphertext) {
  if (!ciphertext) return null;
  const secret = process.env.SESSION_SECRET || "";
  // Try current scrypt KDF first, then fall back to legacy SHA-256 KDF
  try {
    return decryptWithKey(ciphertext, crypto.scryptSync(secret, KDF_SALT, 32));
  } catch (_) {
    try {
      return decryptWithKey(
        ciphertext,
        crypto.createHash("sha256").update(secret).digest(),
      );
    } catch (_e) {
      return null;
    }
  }
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

async function getDbSmtpConfig() {
  const now = Date.now();
  if (_dbSmtpCache && now - _dbSmtpCacheTime < DB_SMTP_CACHE_TTL) {
    return _dbSmtpCache;
  }
  try {
    const { rows } = await pool.query(
      "SELECT smtp_host, smtp_port, smtp_user, smtp_pass_encrypted, smtp_from_email, smtp_from_name, smtp_secure, smtp_require_tls FROM system_settings WHERE id = 1",
    );
    const row = rows[0] || null;
    if (!row) {
      _dbSmtpCache = null;
      _dbSmtpCacheTime = now;
      return null;
    }
    const config = {
      host: row.smtp_host || null,
      port: row.smtp_port ? parseInt(row.smtp_port, 10) : null,
      user: row.smtp_user || null,
      pass: decryptSetting(row.smtp_pass_encrypted),
      fromEmail: row.smtp_from_email || null,
      fromName: row.smtp_from_name || null,
      secure: row.smtp_secure || null,
      requireTls: row.smtp_require_tls || null,
    };
    // Only cache if we have the minimum required fields
    if (config.host && config.user && config.pass) {
      _dbSmtpCache = config;
      _dbSmtpCacheTime = now;
      return config;
    }
    _dbSmtpCache = null;
    _dbSmtpCacheTime = now;
    return null;
  } catch (e) {
    logger.warn("Failed to read SMTP config from DB:", e.message);
    return null;
  }
}

// Support contact used in email footers
function getSupportEmail() {
  return (
    process.env.FROM_EMAIL ||
    process.env.SMTP_USER ||
    "support@your-company.com"
  );
}

function getEmailFooterText() {
  return `Please do not reply to this email. If you have any questions, contact ${getSupportEmail()}.`;
}

// Get logo URL for emails
function getLogoUrl() {
  const frontendUrl = process.env.APP_URL || "http://localhost:5173";
  const baseUrl = frontendUrl.replace(/\/$/, "");
  return `${baseUrl}/Branding/logo.png`;
}

// Generate email template matching the welcome email format
export function generateEmailTemplate({
  title,
  greeting,
  content,
  buttonText,
  buttonUrl,
  footerNote,
  plainTextContent,
  useEmbeddedLogo,
}) {
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
  let text;
  if (plainTextContent) {
    // Use provided plain text, but ensure it has the footer
    text = plainTextContent.trim();
    if (!text.includes("Please do not reply to this email")) {
      text = `${text}\n\nTokenTimer\n${getEmailFooterText()}`;
    }
  } else {
    // Generate default plain text with footer
    text = `
${title || "TokenTimer"}

${greeting || ""}

${content.replace(/<[^>]*>/g, "").replace(/\n\s*\n/g, "\n\n")}

${buttonText && buttonUrl ? `${buttonText}: ${buttonUrl}` : ""}

${footerNote ? footerNote.replace(/<[^>]*>/g, "") : ""}

TokenTimer
${getEmailFooterText()}
    `.trim();
  }

  return { html, text, useEmbeddedLogo: useEmbeddedLogo !== false };
}

// Cache for logo buffer to avoid reading it on every email
let logoBufferCache = null;

// Get logo buffer for email attachments
function getLogoBuffer() {
  // Return cached version if available
  if (logoBufferCache) {
    return logoBufferCache;
  }

  // Try filesystem paths
  const possiblePaths = [
    path.join(__dirname, "../../assets/Branding/logo.png"),
    path.join(process.cwd(), "assets/Branding/logo.png"),
  ];

  for (const logoPath of possiblePaths) {
    try {
      if (fs.existsSync(logoPath)) {
        const buffer = fs.readFileSync(logoPath);
        logoBufferCache = buffer;
        logger.debug(`Logo loaded from filesystem: ${logoPath}`);
        return buffer;
      }
    } catch (_err) {
      logger.warn("File operation failed", { error: _err.message });
    }
  }

  logger.warn("Logo not found in filesystem");
  return null;
}

// Legacy function for backwards compatibility - now templates include footer
function appendFooter({ text, html }) {
  let newHtml = html;
  let newText = text;

  // If html already contains the full template structure, don't append footer again
  if (html && !html.includes("<!-- Footer -->")) {
    const supportEmail = getSupportEmail();
    newHtml = `${html}<hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;"><p style="color: #666; font-size: 12px;">Please do not reply to this email. If you have any questions, contact <a href="mailto:${supportEmail}">${supportEmail}</a>.</p>`;
  }

  // Ensure plain text also has the footer
  if (text && !text.includes("Please do not reply to this email")) {
    newText = `${text}\n\n${getEmailFooterText()}`;
  }

  return {
    text: newText,
    html: newHtml,
  };
}

function parseList(value) {
  try {
    if (Array.isArray(value)) {
      return value.map((s) => String(s).trim()).filter(Boolean);
    }
    const str = String(value || "").trim();
    if (!str) return [];
    // Support JSON array format
    if ((str.startsWith("[") && str.endsWith("]")) || str.includes('"')) {
      try {
        const parsed = JSON.parse(str);
        if (Array.isArray(parsed)) {
          return parsed.map((s) => String(s).trim()).filter(Boolean);
        }
      } catch (_err) {
        logger.debug("Parse failed", { error: _err.message });
      }
    }
    // Support comma, semicolon, whitespace and newlines as separators
    return str
      .split(/[;,\s\n\r]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  } catch (_) {
    return String(value || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
}

const SMTP_USERS = parseList(process.env.SMTP_USER);
const SMTP_PASS = parseList(process.env.SMTP_PASS);

const transporters = [];
// Allow self-signed certs via env var for development/air-gapped deployments
const SMTP_REJECT_UNAUTHORIZED =
  String(process.env.SMTP_REJECT_UNAUTHORIZED ?? "true").toLowerCase() !==
  "false";

function getTransporterForIndex(index) {
  const host = process.env.SMTP_HOST;
  const port = parseInt(process.env.SMTP_PORT || "0", 10) || undefined;
  const smtpSecurity = resolveSmtpSecurity(
    process.env.SMTP_PORT,
    process.env.SMTP_SECURE,
    process.env.SMTP_REQUIRE_TLS,
  );
  const user = SMTP_USERS[index] || process.env.SMTP_USER;
  const pass = SMTP_PASS[index] || SMTP_PASS[0] || process.env.SMTP_PASS;
  if (!host || !user || !pass) return null;
  if (transporters[index]) return transporters[index];
  const tx = nodemailer.createTransport({
    host,
    port,
    secure: smtpSecurity.secure,
    requireTLS: smtpSecurity.requireTLS,
    auth: { user, pass },
    connectionTimeout: 30000,
    socketTimeout: 30000,
    tls: { rejectUnauthorized: SMTP_REJECT_UNAUTHORIZED },
  });
  transporters[index] = tx;
  return tx;
}

export function getTransporter() {
  // Backwards-compatible: return index 0 transporter (env-based only, sync)
  if (transporter) return transporter;
  transporter = getTransporterForIndex(0);
  return transporter;
}

// Async version that also checks DB fallback
export function getTransporterAsync() {
  const envTx = getTransporter();
  if (envTx) return envTx;
  return getDbTransporter();
}

function getFromForIndex(index) {
  const addr = SMTP_USERS[index] || process.env.SMTP_USER;
  if (!addr) return null;
  const displayName = process.env.FROM_EMAIL_NAME || "TokenTimer";
  // Format as display name + address so recipient sees the brand name
  return `${JSON.stringify(displayName)} <${addr}>`;
}

// Cached DB-based transporter
let _dbTransporter = null;
let _dbTransporterTime = 0;

async function getDbTransporter() {
  const now = Date.now();
  if (_dbTransporter && now - _dbTransporterTime < DB_SMTP_CACHE_TTL)
    return _dbTransporter;
  const config = await getDbSmtpConfig();
  if (!config) return null;
  const port = config.port || undefined;
  const smtpSecurity = resolveSmtpSecurity(
    port,
    config.secure,
    config.requireTls,
  );
  _dbTransporter = nodemailer.createTransport({
    host: config.host,
    port,
    secure: smtpSecurity.secure,
    requireTLS: smtpSecurity.requireTLS,
    auth: { user: config.user, pass: config.pass },
    connectionTimeout: 30000,
    socketTimeout: 30000,
    tls: { rejectUnauthorized: SMTP_REJECT_UNAUTHORIZED },
  });
  _dbTransporterTime = now;
  return _dbTransporter;
}

function getDbFrom(config) {
  const addr = config.fromEmail || config.user;
  if (!addr) return null;
  const displayName =
    config.fromName || process.env.FROM_EMAIL_NAME || "TokenTimer";
  return `${JSON.stringify(displayName)} <${addr}>`;
}

// Reset cached DB transporter when config changes (called after settings save)
export function invalidateDbSmtpCache() {
  _dbSmtpCache = null;
  _dbSmtpCacheTime = 0;
  _dbTransporter = null;
  _dbTransporterTime = 0;
}

export async function sendEmailNotification({
  to,
  subject,
  text,
  html,
  useEmbeddedLogo,
  attachments: providedAttachments,
}) {
  // In test mode, short-circuit to success for deterministic runs
  if (process.env.NODE_ENV === "test") {
    return { success: true };
  }
  const total = SMTP_USERS.length || 1;
  const fromEnv = process.env.FROM_EMAIL; // optional explicit from
  try {
    // Check if HTML already contains the full template (with footer)
    // appendFooter handles checking both HTML and Text versions independently
    const withFooter = appendFooter({ text, html });

    // Use provided attachments if available, otherwise generate logo attachment if needed
    const attachments = providedAttachments || [];
    if (
      attachments.length === 0 &&
      (useEmbeddedLogo || (html && html.includes("cid:logo")))
    ) {
      const logoBuffer = getLogoBuffer();
      if (logoBuffer) {
        attachments.push({
          filename: "logo.png",
          content: logoBuffer,
          cid: "logo",
          contentType: "image/png",
          disposition: "inline",
        });
      }
    }

    let last = null;
    for (let i = 0; i < total; i++) {
      const tx = getTransporterForIndex(i);
      if (!tx) continue;
      const from = fromEnv
        ? `${JSON.stringify(process.env.FROM_EMAIL_NAME || "TokenTimer")} <${fromEnv}>`
        : getFromForIndex(i);
      try {
        await tx.verify();
        const info = await tx.sendMail({
          from,
          to,
          subject,
          text: withFooter.text,
          html: withFooter.html,
          attachments: attachments.length > 0 ? attachments : undefined,
        });
        const acceptedCount = Array.isArray(info?.accepted)
          ? info.accepted.length
          : 0;
        const responseText = String(info?.response || "");
        // Some providers may not throw but include soft-fail/rate-limit hints in the response
        const responseIndicatesRateLimit =
          /\b451\b/i.test(responseText) ||
          /rate[- ]?limit|maximum number of sent emails/i.test(responseText);
        if (acceptedCount > 0 && !responseIndicatesRateLimit) {
          try {
            logger.info(
              JSON.stringify({
                level: "INFO",
                message: "email-send-succeeded",
                to,
                subject,
                accountIndex: i + 1,
              }),
            );
          } catch (_err) {
            logger.debug("Non-critical operation failed", {
              error: _err.message,
            });
          }
          return { success: true };
        }
        // Treat non-accepted or rate-limited responses as a failure for this account and try next
        const raw = responseText || "SMTP did not accept recipient(s)";
        // Emit error log for observability and to align with failure semantics
        try {
          logger.error(
            JSON.stringify({
              level: "ERROR",
              message: "email-send-failed",
              code: responseIndicatesRateLimit
                ? "SMTP_RATE_LIMIT"
                : "SMTP_TEMPORARY_FAILURE",
              error: responseIndicatesRateLimit
                ? `Email rate limit reached. Please try again later or contact ${getSupportEmail()} if this persists.`
                : `Email service temporarily unavailable. Please try again later or contact ${getSupportEmail()} if this persists.`,
              providerError: raw,
              to,
              subject,
              accountIndex: i + 1,
            }),
          );
        } catch (_err) {
          logger.debug("Non-critical operation failed", {
            error: _err.message,
          });
        }
        last = {
          success: false,
          error: responseIndicatesRateLimit
            ? `Email rate limit reached. Please try again later or contact ${getSupportEmail()} if this persists.`
            : `Email service temporarily unavailable. Please try again later or contact ${getSupportEmail()} if this persists.`,
          code: responseIndicatesRateLimit
            ? "SMTP_RATE_LIMIT"
            : "SMTP_TEMPORARY_FAILURE",
          providerError: raw,
        };
        continue;
      } catch (e) {
        const raw = String(e?.message || "").trim();
        let error = `Failed to send email. If the problem persists, contact ${getSupportEmail()}.`;
        let code = "SMTP_ERROR";
        const isRateLimit =
          /\b451\b/.test(raw) ||
          /rate[- ]?limit|maximum number of sent emails/i.test(raw);
        if (isRateLimit) {
          error = `Email rate limit reached. Please try again later or contact ${getSupportEmail()} if this persists.`;
          code = "SMTP_RATE_LIMIT";
        } else if (
          /ECONNECTION|ECONNREFUSED|ETIMEDOUT|EAUTH/i.test(raw) ||
          /\b(4\d\d|5\d\d)\b/.test(raw)
        ) {
          error = `Email service temporarily unavailable. Please try again later or contact ${getSupportEmail()} if this persists.`;
          code = "SMTP_TEMPORARY_FAILURE";
        }
        // Log provider error to stdout for observability (runner logs)
        try {
          logger.error(
            JSON.stringify({
              level: "ERROR",
              message: "email-send-failed",
              code,
              error,
              providerError: raw,
              to,
              subject,
              accountIndex: i + 1,
            }),
          );
        } catch (_err) {
          logger.debug("Non-critical operation failed", {
            error: _err.message,
          });
        }
        last = { success: false, error, code, providerError: raw };
        // try next account
        continue;
      }
    }

    // Fallback: when env transport is unavailable or had transient errors, try DB-configured SMTP
    const shouldTryDbFallback =
      !last ||
      last.code === "SMTP_TEMPORARY_FAILURE" ||
      last.code === "SMTP_ERROR";
    if (shouldTryDbFallback) {
      try {
        const dbTx = await getDbTransporter();
        if (dbTx) {
          const dbConfig = await getDbSmtpConfig();
          const from = fromEnv
            ? `${JSON.stringify(process.env.FROM_EMAIL_NAME || "TokenTimer")} <${fromEnv}>`
            : getDbFrom(dbConfig);
          try {
            await dbTx.verify();
            const info = await dbTx.sendMail({
              from,
              to,
              subject,
              text: withFooter.text,
              html: withFooter.html,
              attachments: attachments.length > 0 ? attachments : undefined,
            });
            const acceptedCount = Array.isArray(info?.accepted)
              ? info.accepted.length
              : 0;
            if (acceptedCount > 0) {
              try {
                logger.info(
                  JSON.stringify({
                    level: "INFO",
                    message: "email-send-succeeded",
                    to,
                    subject,
                    source: "database",
                  }),
                );
              } catch (_err) {
                logger.debug("Non-critical operation failed", {
                  error: _err.message,
                });
              }
              return { success: true };
            }
            last = {
              success: false,
              error: `Email service temporarily unavailable. Please try again later or contact ${getSupportEmail()} if this persists.`,
              code: "SMTP_TEMPORARY_FAILURE",
              providerError: String(
                info?.response || "SMTP did not accept recipient(s)",
              ),
            };
          } catch (e) {
            const raw = String(e?.message || "").trim();
            let error = `Failed to send email. If the problem persists, contact ${getSupportEmail()}.`;
            let code = "SMTP_ERROR";
            if (/ECONNECTION|ECONNREFUSED|ETIMEDOUT|EAUTH/i.test(raw)) {
              error = `Email service temporarily unavailable. Please try again later or contact ${getSupportEmail()} if this persists.`;
              code = "SMTP_TEMPORARY_FAILURE";
            }
            try {
              logger.error(
                JSON.stringify({
                  level: "ERROR",
                  message: "email-send-failed",
                  code,
                  error,
                  providerError: raw,
                  to,
                  subject,
                  source: "database",
                }),
              );
            } catch (_err) {
              logger.debug("Non-critical operation failed", {
                error: _err.message,
              });
            }
            last = { success: false, error, code, providerError: raw };
          }
        }
      } catch (dbErr) {
        logger.warn("DB SMTP fallback failed:", dbErr.message);
      }
    }

    return last || { success: false, error: "SMTP not configured" };
  } catch (e) {
    const raw = String(e?.message || "").trim();
    let error = `Failed to send email. If the problem persists, contact ${getSupportEmail()}.`;
    let code = "SMTP_ERROR";
    const isRateLimit =
      /\b451\b/.test(raw) ||
      /rate[- ]?limit|maximum number of sent emails/i.test(raw);
    if (isRateLimit) {
      error = `Email rate limit reached. Please try again later or contact ${getSupportEmail()} if this persists.`;
      code = "SMTP_RATE_LIMIT";
    } else if (
      /ECONNECTION|ECONNREFUSED|ETIMEDOUT|EAUTH/i.test(raw) ||
      /\b(4\d\d|5\d\d)\b/.test(raw)
    ) {
      error = `Email service temporarily unavailable. Please try again later or contact ${getSupportEmail()} if this persists.`;
      code = "SMTP_TEMPORARY_FAILURE";
    }
    // Do not expose provider-specific details to callers; include raw for internal logs if needed
    return { success: false, error, code, providerError: raw };
  }
}
