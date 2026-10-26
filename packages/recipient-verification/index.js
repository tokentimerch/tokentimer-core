"use strict";

const crypto = require("crypto");
const { isValidEmail } = require("./emailCheck");

const CONSENT_POLICY_VERSION = "2026-10-25";
const DEFAULT_DEPLOYMENT = "self-hosted";
const EMAIL_TTL_SECONDS = 48 * 60 * 60;
const WHATSAPP_TTL_SECONDS = 60 * 60;
const WA_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const ELIGIBILITY_CODES = new Set([
  "NO_VERIFIED_RECIPIENTS",
  "RECIPIENT_NOT_VERIFIED",
  "RECIPIENT_OPTED_OUT",
  "RECIPIENT_REVOKED",
  "RECIPIENT_SUPPRESSED",
]);

const DELIVERY_POLICIES = Object.freeze({
  account_verification: "platform_transactional",
  password_reset: "platform_transactional",
  welcome: "platform_transactional",
  billing: "platform_transactional",
  waitlist: "platform_transactional",
  workspace_invite: "platform_transactional",
  operator_incident: "operator_configuration",
  admin_smtp_probe: "operator_configuration",
  admin_whatsapp_probe: "operator_configuration",
  recipient_verification_invite: "verification_invitation",
  workspace_alert_email: "recipient_consent_required",
  workspace_alert_whatsapp: "recipient_consent_required",
  weekly_digest_email: "recipient_consent_required",
  weekly_digest_whatsapp: "recipient_consent_required",
  workspace_test_whatsapp: "recipient_consent_required",
  webhook: "not_a_recipient_destination",
});

function positiveInt(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) return fallback;
  return Math.floor(parsed);
}

function limits(env = process.env) {
  return {
    emailDestPerDay: positiveInt(env.RECIPIENT_VERIFY_EMAIL_DEST_PER_DAY, 1),
    emailDestPerWeek: positiveInt(env.RECIPIENT_VERIFY_EMAIL_DEST_PER_WEEK, 3),
    whatsappDestPerDay: positiveInt(env.RECIPIENT_VERIFY_WHATSAPP_DEST_PER_DAY, 1),
    whatsappDestPerWeek: positiveInt(env.RECIPIENT_VERIFY_WHATSAPP_DEST_PER_WEEK, 3),
    workspacePerDay: positiveInt(env.RECIPIENT_VERIFY_WORKSPACE_PER_DAY, 50),
    userPerDay: positiveInt(env.RECIPIENT_VERIFY_USER_PER_DAY, 20),
    testPerContactPerDay: positiveInt(env.RECIPIENT_TEST_PER_CONTACT_PER_DAY, 3),
    testCooldownSeconds: positiveInt(env.RECIPIENT_TEST_COOLDOWN_SECONDS, 120),
    publicPerWindow: positiveInt(env.RECIPIENT_VERIFY_PUBLIC_PER_WINDOW, 60),
    publicWindowSeconds: positiveInt(env.RECIPIENT_VERIFY_PUBLIC_WINDOW_SECONDS, 10 * 60),
  };
}

function resolveEnforcementMode(env = process.env) {
  const deployment = String(env.TT_DEPLOYMENT || DEFAULT_DEPLOYMENT).trim().toLowerCase();
  const raw = String(env.RECIPIENT_VERIFICATION_MODE || "").trim().toLowerCase();
  if (deployment === "cloud") {
    return raw === "shadow" ? "shadow" : "enforce";
  }
  if (raw === "enforce" || raw === "off" || raw === "shadow") return raw;
  return "shadow";
}

function fingerprintSecret(env = process.env) {
  return String(
    env.RECIPIENT_FINGERPRINT_SECRET || env.PHONE_HASH_SALT || env.SESSION_SECRET || "",
  ).trim();
}

function publicApiBase(env = process.env) {
  return String(env.PUBLIC_BASE_URL || env.API_URL || "").replace(/\/$/, "");
}

function coded(status, code, message, extra) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  if (extra) Object.assign(error, extra);
  return error;
}

function normalizeEmail(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!isValidEmail(normalized)) return { ok: false, value: "" };
  return { ok: true, value: normalized };
}

function normalizePhone(value) {
  const trimmed = String(value || "").trim().replace(/^whatsapp:/i, "");
  if (!/^\+?[1-9]\d{6,14}$/.test(trimmed)) return { ok: false, value: "" };
  return { ok: true, value: trimmed.startsWith("+") ? trimmed : `+${trimmed}` };
}

function normalizeDestination(channel, value) {
  if (channel === "email") return normalizeEmail(value);
  if (channel === "whatsapp") return normalizePhone(value);
  return { ok: false, value: "" };
}

function destinationFingerprint(channel, normalized, env = process.env) {
  const secret = fingerprintSecret(env);
  if (!secret) return null;
  return crypto
    .createHmac("sha256", secret)
    .update(`${channel}\n${normalized}`, "utf8")
    .digest("hex");
}

function hashToken(token, env = process.env) {
  const secret = fingerprintSecret(env);
  const material = secret ? `hmac:${secret}` : "sha256";
  if (secret) {
    return crypto.createHmac("sha256", secret).update(String(token), "utf8").digest("hex");
  }
  return crypto.createHash("sha256").update(`${material}:${token}`, "utf8").digest("hex");
}

function randomToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function randomWhatsAppCode() {
  // 32 symbols, a power of two. A byte masked to the low 5 bits is uniform.
  // Modulo would also be uniform here because 256 divides evenly by 32.
  const bytes = crypto.randomBytes(10);
  const mask = WA_ALPHABET.length - 1;
  let out = "";
  for (let i = 0; i < 10; i += 1) out += WA_ALPHABET[bytes[i] & mask];
  return out;
}

function sealCode(code, env = process.env) {
  const secret = fingerprintSecret(env);
  if (!secret) return null;
  const iv = crypto.randomBytes(12);
  const key = crypto.createHash("sha256").update(secret, "utf8").digest();
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(String(code), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("base64url");
}

function openCode(payload, env = process.env) {
  try {
    const secret = fingerprintSecret(env);
    if (!secret || !payload) return null;
    const buf = Buffer.from(String(payload), "base64url");
    if (buf.length < 29) return null;
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const encrypted = buf.subarray(28);
    const key = crypto.createHash("sha256").update(secret, "utf8").digest();
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
  } catch (_) {
    return null;
  }
}

function maskEmail(email) {
  const value = String(email || "");
  const at = value.indexOf("@");
  if (at <= 0) return "***";
  return `${value.slice(0, 1)}***${value.slice(at)}`;
}

function maskPhone(phone) {
  const digits = String(phone || "").replace(/\D/g, "");
  if (digits.length < 4) return "***";
  return `***${digits.slice(-4)}`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function isMissingSchema(error) {
  return Boolean(error && (error.code === "42P01" || error.code === "42703"));
}

function finishForMode(mode, decision) {
  if (mode === "off" || mode === "shadow") {
    return {
      allowed: true,
      mode,
      shadowBlocked: mode === "shadow" ? decision.allowed !== true : false,
      code: decision.allowed ? null : decision.code,
    };
  }
  return {
    allowed: decision.allowed === true,
    mode,
    shadowBlocked: false,
    code: decision.allowed ? null : decision.code || "RECIPIENT_NOT_VERIFIED",
  };
}

async function withTransaction(pool, fn) {
  if (!pool || typeof pool.connect !== "function") return fn(pool);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_) {
      /* rollback is best-effort */
    }
    throw error;
  } finally {
    client.release();
  }
}

async function evaluateRecipient({ client, workspaceId, contactId, channel, destination }) {
  const normalized = normalizeDestination(channel, destination);
  if (!normalized.ok || !contactId || !workspaceId) {
    return { allowed: false, code: "RECIPIENT_NOT_VERIFIED" };
  }
  const fingerprint = destinationFingerprint(channel, normalized.value);
  if (!fingerprint) return { allowed: false, code: "RECIPIENT_VERIFICATION_UNAVAILABLE" };
  try {
    const suppressed = await client.query(
      `-- RV_SUPPRESSION_LOOKUP
       SELECT reason FROM notification_suppressions
        WHERE channel = $1
          AND destination_fingerprint = $2
          AND (expires_at IS NULL OR expires_at > NOW())
          AND (scope = 'global' OR (scope = 'workspace' AND workspace_id = $3))
        ORDER BY CASE WHEN scope = 'global' THEN 0 ELSE 1 END
        LIMIT 1`,
      [channel, fingerprint, workspaceId],
    );
    if (suppressed.rows[0]) {
      const reason = suppressed.rows[0].reason;
      return {
        allowed: false,
        code: reason === "recipient_declined" ? "RECIPIENT_OPTED_OUT" : "RECIPIENT_SUPPRESSED",
      };
    }
    const found = await client.query(
      `-- RV_DELIVERY_LOOKUP
       SELECT v.status, v.consent_at
         FROM contact_channel_verifications v
         JOIN workspace_contacts c
           ON c.id = v.contact_id AND c.workspace_id = v.workspace_id
        WHERE v.workspace_id = $1
          AND v.contact_id = $2
          AND v.channel = $3
          AND v.destination_normalized = $4
          AND (
            ($3 = 'email' AND lower(btrim(COALESCE(c.details->>'email', ''))) = $4)
            OR ($3 = 'whatsapp' AND c.phone_e164 = $4)
          )
        LIMIT 1`,
      [workspaceId, contactId, channel, normalized.value],
    );
    const row = found.rows[0];
    if (!row || row.status === "pending") return { allowed: false, code: "RECIPIENT_NOT_VERIFIED" };
    if (row.status === "opted_out") return { allowed: false, code: "RECIPIENT_OPTED_OUT" };
    if (row.status === "revoked") return { allowed: false, code: "RECIPIENT_REVOKED" };
    if (row.status !== "verified" || !row.consent_at) {
      return { allowed: false, code: "RECIPIENT_NOT_VERIFIED" };
    }
    return { allowed: true, code: null };
  } catch (error) {
    if (isMissingSchema(error)) return { allowed: false, code: "RECIPIENT_VERIFICATION_UNAVAILABLE" };
    throw error;
  }
}

async function canDeliverToRecipient(args) {
  const mode = resolveEnforcementMode();
  if (mode === "off") return { allowed: true, mode, shadowBlocked: false, code: null };
  try {
    const decision = await evaluateRecipient(args);
    return finishForMode(mode, decision);
  } catch (error) {
    if (mode === "shadow") {
      return { allowed: true, mode, shadowBlocked: true, code: "RECIPIENT_VERIFICATION_UNAVAILABLE" };
    }
    return { allowed: false, mode, shadowBlocked: false, code: "RECIPIENT_VERIFICATION_UNAVAILABLE", error };
  }
}

async function canDeliverToDestination({ client, workspaceId, channel, destination }) {
  const mode = resolveEnforcementMode();
  if (mode === "off") return { allowed: true, mode, shadowBlocked: false, code: null };
  const normalized = normalizeDestination(channel, destination);
  if (!normalized.ok) return finishForMode(mode, { allowed: false, code: "RECIPIENT_NOT_VERIFIED" });
  let contacts;
  try {
    contacts = await client.query(
      `-- RV_DESTINATION_CONTACTS
       SELECT id FROM workspace_contacts
        WHERE workspace_id = $1
          AND (
            ($2 = 'email' AND lower(btrim(COALESCE(details->>'email', ''))) = $3)
            OR ($2 = 'whatsapp' AND phone_e164 = $3)
          )`,
      [workspaceId, channel, normalized.value],
    );
  } catch (error) {
    if (isMissingSchema(error) || mode === "shadow") {
      return finishForMode(mode, { allowed: false, code: "RECIPIENT_VERIFICATION_UNAVAILABLE" });
    }
    return { allowed: false, mode, code: "RECIPIENT_VERIFICATION_UNAVAILABLE" };
  }
  if (!contacts.rows.length) {
    return finishForMode(mode, { allowed: false, code: "RECIPIENT_NOT_VERIFIED" });
  }
  let last = { allowed: false, code: "RECIPIENT_NOT_VERIFIED" };
  for (const row of contacts.rows) {
    const decision = await canDeliverToRecipient({
      client,
      workspaceId,
      contactId: row.id,
      channel,
      destination: normalized.value,
    });
    if (mode !== "enforce") return decision;
    if (decision.allowed) return decision;
    last = decision;
  }
  return last;
}

async function filterDeliveryRecipients({ client, workspaceId, channel, recipients }) {
  const mode = resolveEnforcementMode();
  const allowed = [];
  const blocked = [];
  for (const recipient of Array.isArray(recipients) ? recipients : []) {
    if (mode === "off") {
      allowed.push(recipient);
      continue;
    }
    const decision = await canDeliverToRecipient({
      client,
      workspaceId,
      contactId: recipient.contactId,
      channel,
      destination: recipient.destination,
    });
    if (decision.allowed && !decision.shadowBlocked) {
      allowed.push(recipient);
    } else if (decision.shadowBlocked) {
      allowed.push(recipient);
      blocked.push({ ...recipient, code: decision.code, shadow: true });
    } else {
      blocked.push({ ...recipient, code: decision.code, shadow: false });
    }
  }
  const enforcedBlocked = blocked.filter((row) => !row.shadow);
  let code = null;
  if (allowed.length === 0 && enforcedBlocked.length > 0) {
    code = enforcedBlocked.every((row) => row.code === "RECIPIENT_OPTED_OUT")
      ? "RECIPIENT_OPTED_OUT"
      : "NO_VERIFIED_RECIPIENTS";
  }
  return { allowed, blocked, enforced: mode === "enforce", mode, code };
}

function deliveryDisposition(results) {
  const list = Array.isArray(results) ? results : [];
  const unsuccessful = list.filter((row) => row && row.success !== true);
  const retryable = unsuccessful.filter((row) => row && !row.eligibilityTerminal && !row.terminal && !row.providerTerminal);
  const anySuccess = list.some((row) => row && (row.success === true || row.partialSuccess === true));
  const eligibilityRows = unsuccessful.filter((row) => row && row.eligibilityTerminal);
  const providerFailure = unsuccessful.some((row) => row && row.providerTerminal);
  const terminalCode = eligibilityRows.length
    ? (eligibilityRows.every((row) => row.errorCode === "RECIPIENT_OPTED_OUT") ? "RECIPIENT_OPTED_OUT" : "NO_VERIFIED_RECIPIENTS")
    : (providerFailure ? "PERMANENT_DELIVERY_FAILURE" : null);
  if (unsuccessful.length === 0) return { status: "sent", retry: false, channels: [] };
  if (retryable.length === 0) {
    if (anySuccess) {
      return { status: "partial", retry: false, channels: [], code: terminalCode };
    }
    return { status: "blocked", retry: false, channels: [], code: terminalCode };
  }
  return {
    status: anySuccess ? "partial" : "failed",
    retry: true,
    channels: retryable.map((row) => row.channel),
  };
}

function queueDeliveryOutcome(results, options = {}) {
  const disposition = deliveryDisposition(results);
  let status = disposition.status;
  if (status === "sent" && options.hasPartialIssues) status = "partial";
  const forcedBlock = options.whatsappPermanentFailure === true || options.reachedMaxAttempts === true;
  if (forcedBlock) status = "blocked";
  const retry = !forcedBlock && disposition.retry === true && status !== "sent" && status !== "blocked";
  return {
    status,
    retry,
    channels: retry ? disposition.channels : [],
    code: disposition.code || null,
    notifyUnverified: (Array.isArray(results) ? results : []).some((row) => row && row.eligibilityTerminal),
    notifyProviderTerminal: (Array.isArray(results) ? results : []).some((row) => row && row.providerTerminal),
  };
}

const DELIVERY_CLAIM_EXCLUSION_SQL = `
AND NOT (
  aq.status = 'partial'
  AND (
    aq.channels IS NULL
    OR aq.channels = '[]'::jsonb
    OR (
      jsonb_typeof(aq.channels) = 'object'
      AND COALESCE(aq.channels->'retry', '[]'::jsonb) = '[]'::jsonb
    )
  )
)`;

function metadataObject(value) {
  if (!value) return {};
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return parsed && typeof parsed === "object" ? parsed : {};
    } catch {
      return {};
    }
  }
  return typeof value === "object" ? value : {};
}

function parseDeliveryLedger(value) {
  let parsed = value;
  if (typeof value === "string") {
    try {
      parsed = JSON.parse(value);
    } catch {
      parsed = [];
    }
  }
  if (Array.isArray(parsed)) {
    return { version: 0, retry: parsed.map(String), required: [], outcomes: {}, legacy: true };
  }
  if (parsed && typeof parsed === "object" && Number(parsed.version) === 1) {
    return {
      version: 1,
      retry: Array.isArray(parsed.retry) ? parsed.retry.map(String) : [],
      required: Array.isArray(parsed.required) ? parsed.required.map(String) : [],
      outcomes: parsed.outcomes && typeof parsed.outcomes === "object" ? parsed.outcomes : {},
      legacy: false,
    };
  }
  return { version: 0, retry: [], required: [], outcomes: {}, legacy: true };
}

function foldDeliveryLog(rows) {
  const outcomes = {};
  for (const row of Array.isArray(rows) ? rows : []) {
    const channel = String(row && row.channel || "");
    if (!channel) continue;
    const current = outcomes[channel] || { state: "failed", terminal: false, endpoints: {} };
    const meta = metadataObject(row.metadata);
    if (channel === "webhooks" && meta.urlHash) {
      if (row.status === "success") current.endpoints[meta.urlHash] = "sent";
      else if (row.status === "blocked" || meta.terminal === true || meta.terminal === "true") {
        current.endpoints[meta.urlHash] = "permanent";
      } else current.endpoints[meta.urlHash] = "failed";
      const values = Object.values(current.endpoints);
      const pending = values.filter((item) => item === "failed");
      if (pending.length) {
        current.state = "failed";
        current.terminal = false;
      } else if (values.every((item) => item === "sent")) {
        current.state = "sent";
        current.terminal = true;
      } else if (values.some((item) => item === "sent")) {
        current.state = "partial";
        current.terminal = true;
      } else {
        current.state = "blocked";
        current.terminal = true;
      }
      current.reason = "provider";
    } else if (row.status === "success") {
      current.state = "sent";
      current.terminal = true;
    } else if (row.status === "blocked") {
      if (current.state !== "sent") {
        current.state = "blocked";
        current.terminal = true;
        current.code = row.error_message || current.code || null;
        current.reason = ELIGIBILITY_CODES.has(current.code) ? "eligibility" : "provider";
      }
    } else if (current.state !== "sent" && !(current.state === "blocked" && current.reason === "eligibility")) {
      current.state = "failed";
      current.terminal = false;
      current.code = row.error_message || null;
    }
    outcomes[channel] = current;
  }
  return outcomes;
}

function isEligibilityOutcome(outcome) {
  if (!outcome || typeof outcome !== "object") return false;
  if (outcome.reason === "provider") return false;
  if (outcome.reason === "eligibility") return true;
  if (ELIGIBILITY_CODES.has(outcome.code)) return true;
  const endpoints = outcome.endpoints && typeof outcome.endpoints === "object" ? Object.keys(outcome.endpoints) : [];
  return outcome.state === "blocked" && outcome.terminal === true && !outcome.code && endpoints.length === 0;
}

function resultFromOutcome(channel, outcome) {
  if (!outcome) return { channel, success: false, eligibilityTerminal: false, terminal: false, providerTerminal: false };
  if (outcome.state === "sent") {
    return { channel, success: true, eligibilityTerminal: false, terminal: false, providerTerminal: false };
  }
  const eligibility = isEligibilityOutcome(outcome);
  const terminal = Boolean(outcome.terminal || outcome.state === "blocked");
  if (outcome.state === "partial") {
    return {
      channel,
      success: false,
      partialSuccess: true,
      eligibilityTerminal: eligibility && terminal,
      terminal,
      providerTerminal: terminal && !eligibility,
      errorCode: outcome.code || null,
    };
  }
  if (terminal) {
    return {
      channel,
      success: false,
      eligibilityTerminal: eligibility,
      terminal: true,
      providerTerminal: !eligibility,
      errorCode: eligibility ? (outcome.code || "NO_VERIFIED_RECIPIENTS") : (outcome.code || "PERMANENT_DELIVERY_FAILURE"),
    };
  }
  return { channel, success: false, eligibilityTerminal: false, terminal: false, providerTerminal: false, errorCode: outcome.code || null };
}

function sameStringList(left, right) {
  const a = [...(left || [])].map(String).sort();
  const b = [...(right || [])].map(String).sort();
  return a.length === b.length && a.every((item, index) => item === b[index]);
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map((item) => stableJson(item)).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function reconcileDeliveryChannels(stored, configuredChannels) {
  const live = Array.isArray(configuredChannels) ? configuredChannels.map(String).filter(Boolean) : [];
  const ledger = parseDeliveryLedger(stored);
  if (ledger.legacy) {
    const storedList = Array.isArray(stored)
      ? stored.map(String)
      : (typeof stored === "string" ? ledger.retry : null);
    let next = live.slice();
    if (Array.isArray(storedList) && storedList.length > 0) {
      next = live.filter((channel) => storedList.includes(channel));
      if (next.length === 0) next = storedList.slice();
    }
    return {
      format: "legacy",
      channels: next,
      changed: !Array.isArray(storedList) || !sameStringList(next, storedList),
    };
  }
  const outcomes = {};
  for (const channel of live) {
    if (ledger.outcomes[channel]) outcomes[channel] = ledger.outcomes[channel];
  }
  const retry = [];
  for (const channel of live) {
    const outcome = outcomes[channel];
    if (!outcome) {
      retry.push(channel);
      continue;
    }
    if (outcome.state === "sent" || outcome.terminal === true || outcome.state === "blocked") continue;
    retry.push(channel);
  }
  const next = { version: 1, retry, required: live.slice(), outcomes };
  return {
    format: "ledger",
    channels: next,
    changed: !sameStringList(retry, ledger.retry)
      || !sameStringList(live, ledger.required)
      || stableJson(outcomes) !== stableJson(ledger.outcomes),
  };
}

function providerTerminalOutcome(outcome) {
  if (!outcome || outcome.state === "sent" || isEligibilityOutcome(outcome)) return false;
  return outcome.terminal === true || outcome.state === "blocked";
}

function planManualRetry(stored, requestedChannel) {
  const ledger = parseDeliveryLedger(stored);
  if (ledger.legacy) {
    const eligible = ledger.retry.filter(Boolean);
    const channel = String(requestedChannel || "").trim() || (eligible.length === 1 ? eligible[0] : "");
    if (!channel) {
      return { ok: false, code: eligible.length ? "CHANNEL_REQUIRED" : "NO_ELIGIBLE_CHANNELS", eligible, format: "legacy" };
    }
    if (!eligible.includes(channel)) return { ok: false, code: "CHANNEL_NOT_ELIGIBLE", eligible, format: "legacy" };
    return { ok: true, channel, eligible, format: "legacy", channels: [channel] };
  }
  const outcomes = { ...(ledger.outcomes || {}) };
  const known = ledger.required.length ? ledger.required.slice() : Object.keys(outcomes);
  const eligible = ledger.retry.filter((channel) => {
    const outcome = outcomes[channel];
    return !outcome || (outcome.state !== "sent" && outcome.terminal !== true && outcome.state !== "blocked");
  });
  const permanent = known.filter((channel) => providerTerminalOutcome(outcomes[channel]));
  const channel = String(requestedChannel || "").trim() || (eligible.length === 1 ? eligible[0] : "");
  if (!channel) {
    if (eligible.length > 1) return { ok: false, code: "CHANNEL_REQUIRED", eligible, format: "ledger" };
    if (permanent.length) return { ok: false, code: "CHANNEL_PERMANENT", eligible: permanent, format: "ledger" };
    return { ok: false, code: "NO_ELIGIBLE_CHANNELS", eligible, format: "ledger" };
  }
  const outcome = outcomes[channel];
  if (outcome && outcome.state === "sent") return { ok: false, code: "ALREADY_DELIVERED", eligible, format: "ledger" };
  if (isEligibilityOutcome(outcome)) {
    return { ok: false, code: outcome.code || "RECIPIENT_NOT_VERIFIED", eligible, format: "ledger" };
  }
  if (!known.includes(channel) && !eligible.includes(channel)) {
    return { ok: false, code: "CHANNEL_NOT_ELIGIBLE", eligible, format: "ledger" };
  }
  if (providerTerminalOutcome(outcome)) {
    outcomes[channel] = {
      ...outcome,
      state: "failed",
      terminal: false,
      reopened: true,
      reason: "provider",
    };
  }
  return {
    ok: true,
    channel,
    eligible,
    format: "ledger",
    channels: {
      version: 1,
      retry: [channel],
      required: known.includes(channel) ? known : [...known, channel],
      outcomes,
    },
  };
}

function publicDeliveryChannels(stored) {
  const ledger = parseDeliveryLedger(stored);
  if (ledger.legacy) return ledger.retry.map((channel) => ({ channel, channel_state: null }));
  const names = ledger.required.length ? ledger.required : Object.keys(ledger.outcomes || {});
  return names.map((channel) => ({
    channel,
    channel_state: ledger.outcomes[channel]?.state || "pending",
  }));
}

function webhookChannelReopened(stored) {
  const ledger = parseDeliveryLedger(stored);
  return ledger.outcomes?.webhooks?.reopened === true;
}

function requeueWebhookChannel(stored) {
  const ledger = parseDeliveryLedger(stored);
  if (ledger.legacy) return Array.from(new Set([...ledger.retry, "webhooks"]));
  const outcome = ledger.outcomes.webhooks;
  if (outcome && (outcome.state === "sent" || isEligibilityOutcome(outcome))) return null;
  const required = Array.from(new Set([...(ledger.required.length ? ledger.required : Object.keys(ledger.outcomes)), "webhooks"]));
  const retry = Array.from(new Set([...ledger.retry, "webhooks"]));
  const outcomes = { ...ledger.outcomes };
  if (outcome && (outcome.terminal === true || outcome.state === "blocked" || outcome.state === "partial")) {
    outcomes.webhooks = { ...outcome, state: "failed", terminal: false, reopened: true, reason: "provider" };
  }
  return { version: 1, retry, required, outcomes };
}

function outcomeFromAttempt(row) {
  const eligibility = row.eligibilityTerminal === true;
  const provider = Boolean(row.terminal) && !eligibility;
  if (row.success === true) {
    return { state: "sent", terminal: true, code: null, reason: null, endpoints: row.endpoints || {} };
  }
  if (row.partialSuccess === true) {
    const terminal = Boolean(row.terminal || eligibility);
    return {
      state: "partial",
      terminal,
      code: row.errorCode || null,
      reason: eligibility ? "eligibility" : (terminal ? "provider" : null),
      endpoints: row.endpoints || {},
    };
  }
  const terminal = Boolean(eligibility || row.terminal);
  return {
    state: terminal ? "blocked" : "failed",
    terminal,
    reason: eligibility ? "eligibility" : (provider ? "provider" : null),
    code: row.errorCode || null,
    endpoints: row.endpoints || {},
  };
}

function mergeDeliveryAttempt({ prior, logRows, attempted, liveChannels } = {}) {
  const ledger = parseDeliveryLedger(prior);
  const outcomes = { ...ledger.outcomes, ...foldDeliveryLog(logRows) };
  for (const row of Array.isArray(attempted) ? attempted : []) {
    if (!row || !row.channel) continue;
    outcomes[String(row.channel)] = outcomeFromAttempt(row);
  }
  const configured = Array.isArray(liveChannels) ? liveChannels.map(String).filter(Boolean) : [];
  const required = configured.length ? configured : Object.keys(outcomes);
  const results = required.map((channel) => resultFromOutcome(channel, outcomes[channel]));
  const disposition = queueDeliveryOutcome(results);
  const stored = {};
  for (const channel of required) {
    if (outcomes[channel]) stored[channel] = outcomes[channel];
  }
  return {
    ledger: { version: 1, retry: disposition.channels, required, outcomes: stored },
    outcome: disposition,
    results,
  };
}

function selectDeliverableDestinations(rows) {
  const seen = new Set();
  const destinations = [];
  const contactIdByDestination = new Map();
  for (const row of Array.isArray(rows) ? rows : []) {
    const destination = row && row.destination;
    if (!destination || seen.has(destination)) continue;
    seen.add(destination);
    destinations.push(destination);
    contactIdByDestination.set(destination, row.contactId);
  }
  return { destinations, contactIdByDestination };
}

function isEligibilityTerminal(code) {
  return ELIGIBILITY_CODES.has(code);
}

async function takeBucket(client, { key, limit, windowSeconds, workspaceId }) {
  if (!limit) return { ok: true, retryAfter: 0 };
  await client.query(
    `-- RV_PRUNE
     DELETE FROM recipient_verification_events
      WHERE bucket_key = $1 AND created_at < NOW() - INTERVAL '8 days'`,
    [key],
  );
  const count = await client.query(
    `-- RV_COUNT_EVENTS
     SELECT COUNT(*)::int AS n
       FROM recipient_verification_events
      WHERE bucket_key = $1
        AND created_at > NOW() - ($2::int * INTERVAL '1 second')`,
    [key, windowSeconds],
  );
  if ((count.rows[0]?.n || 0) >= limit) return { ok: false, retryAfter: windowSeconds };
  await client.query(
    `-- RV_INSERT_EVENT
     INSERT INTO recipient_verification_events (bucket_key, workspace_id) VALUES ($1, $2)`,
    [key, workspaceId || null],
  );
  return { ok: true, retryAfter: 0 };
}

async function assertInvitationBudget(client, { channel, fingerprint, workspaceId, actorUserId }) {
  const config = limits();
  const dayLimit = channel === "email" ? config.emailDestPerDay : config.whatsappDestPerDay;
  const weekLimit = channel === "email" ? config.emailDestPerWeek : config.whatsappDestPerWeek;
  const lockKeys = [
    `verify:dest:${channel}:${fingerprint}`,
    `verify:ws:${workspaceId || "none"}`,
    `verify:user:${actorUserId || "unknown"}`,
  ].sort();
  for (const key of lockKeys) {
    await client.query(`SELECT pg_advisory_xact_lock(hashtext($1))`, [key]);
  }
  const day = await takeBucket(client, {
    key: `dest:${channel}:${fingerprint}:24h`,
    limit: dayLimit,
    windowSeconds: 24 * 60 * 60,
    workspaceId,
  });
  if (!day.ok) {
    const error = coded(429, "RECIPIENT_VERIFICATION_RATE_LIMITED", "Verification invitation limit reached for this destination", {
      retryAfter: day.retryAfter,
    });
    throw error;
  }
  const week = await takeBucket(client, {
    key: `dest:${channel}:${fingerprint}:7d`,
    limit: weekLimit,
    windowSeconds: 7 * 24 * 60 * 60,
    workspaceId,
  });
  if (!week.ok) {
    const distinct = await client.query(
      `-- RV_DISTINCT_WORKSPACES
       SELECT COUNT(DISTINCT workspace_id)::int AS n
         FROM recipient_verification_events
        WHERE bucket_key = $1 AND created_at > NOW() - INTERVAL '7 days'`,
      [`dest:${channel}:${fingerprint}:7d`],
    );
    const limited = coded(429, "RECIPIENT_VERIFICATION_RATE_LIMITED", "Verification invitation limit reached for this destination", {
      retryAfter: week.retryAfter,
    });
    if ((distinct.rows[0]?.n || 0) >= 3) {
      limited.recordAbuse = { channel, fingerprint };
    }
    throw limited;
  }
  const workspace = await takeBucket(client, {
    key: `ws:${workspaceId}:24h`,
    limit: config.workspacePerDay,
    windowSeconds: 24 * 60 * 60,
    workspaceId,
  });
  if (!workspace.ok) {
    throw coded(429, "RECIPIENT_VERIFICATION_RATE_LIMITED", "Workspace verification limit reached", {
      retryAfter: workspace.retryAfter,
    });
  }
  const user = await takeBucket(client, {
    key: `user:${actorUserId || "unknown"}:24h`,
    limit: config.userPerDay,
    windowSeconds: 24 * 60 * 60,
    workspaceId,
  });
  if (!user.ok) {
    throw coded(429, "RECIPIENT_VERIFICATION_RATE_LIMITED", "Too many verification invitations from this user", {
      retryAfter: user.retryAfter,
    });
  }
}

async function recordAbuseSuppression(pool, { channel, fingerprint }) {
  await pool.query(
    `-- RV_INSERT_SUPPRESSION
     INSERT INTO notification_suppressions
       (channel, destination_fingerprint, scope, workspace_id, reason, expires_at)
     VALUES ($1, $2, 'global', NULL, 'verification_abuse', NOW() + INTERVAL '24 hours')
     ON CONFLICT (channel, destination_fingerprint, reason) WHERE scope = 'global'
     DO UPDATE SET expires_at = GREATEST(notification_suppressions.expires_at, EXCLUDED.expires_at)`,
    [channel, fingerprint],
  );
}

async function createInvitation({ pool, workspaceId, contactId, channel, actorUserId, recipientInitiated = false }) {
  if (channel !== "email" && channel !== "whatsapp") {
    throw coded(400, "VALIDATION_ERROR", "Unsupported channel");
  }
  try {
    return await withTransaction(pool, async (client) => {
    const contact = await client.query(
      `-- RV_CONTACT
       SELECT id, phone_e164, details FROM workspace_contacts WHERE workspace_id = $1 AND id = $2`,
      [workspaceId, contactId],
    );
    if (!contact.rows[0]) throw coded(404, "CONTACT_NOT_FOUND", "Contact not found");
    const raw = channel === "email" ? contact.rows[0].details?.email : contact.rows[0].phone_e164;
    const destination = normalizeDestination(channel, raw);
    if (!destination.ok) throw coded(400, "DESTINATION_MISSING", "This contact has no destination for that channel");
    const fingerprint = destinationFingerprint(channel, destination.value);
    if (!fingerprint) throw coded(503, "RECIPIENT_VERIFICATION_UNAVAILABLE", "Recipient verification is not configured");
    const abuse = await client.query(
      `-- RV_SUPPRESSION_LOOKUP
       SELECT reason FROM notification_suppressions
        WHERE channel = $1 AND destination_fingerprint = $2 AND reason = 'verification_abuse'
          AND (expires_at IS NULL OR expires_at > NOW())
          AND (scope = 'global' OR workspace_id = $3)
        LIMIT 1`,
      [channel, fingerprint, workspaceId],
    );
    if (abuse.rows[0]) {
      throw coded(429, "RECIPIENT_SUPPRESSED", "Verification is temporarily unavailable for this destination", {
        retryAfter: 24 * 60 * 60,
      });
    }
    const declined = await client.query(
      `-- RV_SUPPRESSION_LOOKUP
       SELECT reason FROM notification_suppressions
        WHERE channel = $1 AND destination_fingerprint = $2 AND reason = 'recipient_declined'
          AND (expires_at IS NULL OR expires_at > NOW())
          AND scope = 'workspace' AND workspace_id = $3
        LIMIT 1`,
      [channel, fingerprint, workspaceId],
    );
    if (declined.rows[0] && !recipientInitiated) {
      return {
        token: null,
        code: null,
        channel,
        destination: destination.value,
        expiresAt: null,
        challengeId: null,
        withholdDelivery: true,
      };
    }
    await assertInvitationBudget(client, { channel, fingerprint, workspaceId, actorUserId });
    await client.query(
      `-- RV_SUPERSEDE
       UPDATE contact_verification_challenges
          SET status = 'superseded'
        WHERE workspace_id = $1 AND contact_id = $2 AND channel = $3 AND status = 'pending'`,
      [workspaceId, contactId, channel],
    );
    const token = randomToken();
    const code = channel === "whatsapp" ? randomWhatsAppCode() : null;
    const ttl = channel === "email" ? EMAIL_TTL_SECONDS : WHATSAPP_TTL_SECONDS;
    const inserted = await client.query(
      `-- RV_INSERT_CHALLENGE
       INSERT INTO contact_verification_challenges
         (workspace_id, contact_id, channel, destination_normalized, destination_fingerprint,
          token_hash, code_hash, code_ciphertext, status, expires_at, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending', NOW() + ($9::int * INTERVAL '1 second'), $10)
       RETURNING id, expires_at`,
      [
        workspaceId,
        contactId,
        channel,
        destination.value,
        fingerprint,
        hashToken(token),
        code ? hashToken(code) : null,
        code ? sealCode(code) : null,
        ttl,
        actorUserId || null,
      ],
    );
    return {
      token,
      code,
      channel,
      destination: destination.value,
      expiresAt: inserted.rows[0].expires_at,
      challengeId: inserted.rows[0].id,
      withholdDelivery: false,
    };
    });
  } catch (error) {
    if (error && error.recordAbuse) {
      await recordAbuseSuppression(pool, error.recordAbuse);
    }
    throw error;
  }
}

async function requestEmailResubscribe({ pool, email }) {
  const normalized = normalizeEmail(email);
  if (!normalized.ok) return [];
  const fingerprint = destinationFingerprint("email", normalized.value);
  if (!fingerprint) return [];
  const matches = await pool.query(
    `-- RV_RESUBSCRIBE_TARGETS
     SELECT s.workspace_id, c.id AS contact_id, w.name AS workspace_name
       FROM notification_suppressions s
       JOIN workspace_contacts c ON c.workspace_id = s.workspace_id
       JOIN workspaces w ON w.id = s.workspace_id
      WHERE s.channel = 'email'
        AND s.destination_fingerprint = $1
        AND s.reason = 'recipient_declined'
        AND s.scope = 'workspace'
        AND (s.expires_at IS NULL OR s.expires_at > NOW())
        AND lower(btrim(COALESCE(c.details->>'email', ''))) = $2`,
    [fingerprint, normalized.value],
  );
  const invitations = [];
  for (const row of matches.rows) {
    try {
      const invitation = await createInvitation({
        pool,
        workspaceId: row.workspace_id,
        contactId: row.contact_id,
        channel: "email",
        actorUserId: null,
        recipientInitiated: true,
      });
      if (invitation && invitation.token) {
        invitations.push({
          ...invitation,
          workspaceId: row.workspace_id,
          workspaceName: row.workspace_name,
        });
      }
    } catch (error) {
      if (error && error.status === 429) continue;
      throw error;
    }
  }
  return invitations;
}

async function loadChallenge(pool, token) {
  if (!token || String(token).length < 20) return { state: "invalid" };
  let rows;
  try {
    const result = await pool.query(
      `-- RV_LOAD_CHALLENGE
       SELECT c.channel, c.status, c.expires_at, c.destination_normalized, c.workspace_id,
              c.code_ciphertext, w.name AS workspace_name, v.status AS verification_status
         FROM contact_verification_challenges c
         JOIN workspaces w ON w.id = c.workspace_id
         LEFT JOIN contact_channel_verifications v
           ON v.workspace_id = c.workspace_id
          AND v.contact_id = c.contact_id
          AND v.channel = c.channel
          AND v.destination_normalized = c.destination_normalized
        WHERE c.token_hash = $1`,
      [hashToken(token)],
    );
    rows = result.rows;
  } catch (error) {
    if (isMissingSchema(error)) return { state: "invalid" };
    throw error;
  }
  const row = rows[0];
  if (!row) return { state: "invalid" };
  if (row.status === "pending" && new Date(row.expires_at).getTime() > Date.now()) {
    return {
      state: "pending",
      channel: row.channel,
      workspaceName: row.workspace_name,
      expiresAt: row.expires_at,
      code: row.channel === "whatsapp" ? openCode(row.code_ciphertext) : null,
    };
  }
  if (row.verification_status === "verified") {
    return { state: "accepted", channel: row.channel, workspaceName: row.workspace_name };
  }
  if (row.verification_status === "opted_out" || row.status === "declined") {
    return { state: "declined", channel: row.channel, workspaceName: row.workspace_name };
  }
  return { state: "invalid" };
}

async function upsertVerification(client, row, status, method) {
  await client.query(
    `-- RV_UPSERT_VERIFICATION
     INSERT INTO contact_channel_verifications
       (workspace_id, contact_id, channel, destination_normalized, destination_fingerprint, status,
        verified_at, consent_at, consent_method, consent_policy_version, opted_out_at, opt_out_method, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,
        CASE WHEN $6 = 'verified' THEN NOW() ELSE NULL END,
        CASE WHEN $6 = 'verified' THEN NOW() ELSE NULL END,
        CASE WHEN $6 = 'verified' THEN $7 ELSE NULL END,
        CASE WHEN $6 = 'verified' THEN $8 ELSE NULL END,
        CASE WHEN $6 = 'opted_out' THEN NOW() ELSE NULL END,
        CASE WHEN $6 = 'opted_out' THEN $7 ELSE NULL END,
        NOW())
     ON CONFLICT (workspace_id, contact_id, channel) DO UPDATE
       SET destination_normalized = EXCLUDED.destination_normalized,
           destination_fingerprint = EXCLUDED.destination_fingerprint,
           status = EXCLUDED.status,
           verified_at = CASE WHEN EXCLUDED.status = 'verified' THEN NOW() ELSE NULL END,
           consent_at = CASE WHEN EXCLUDED.status = 'verified' THEN NOW() ELSE NULL END,
           consent_method = CASE WHEN EXCLUDED.status = 'verified' THEN $7 ELSE contact_channel_verifications.consent_method END,
           consent_policy_version = CASE WHEN EXCLUDED.status = 'verified' THEN $8 ELSE contact_channel_verifications.consent_policy_version END,
           opted_out_at = CASE WHEN EXCLUDED.status = 'opted_out' THEN NOW() ELSE NULL END,
           opt_out_method = CASE WHEN EXCLUDED.status = 'opted_out' THEN $7 ELSE NULL END,
           revoked_at = NULL,
           updated_at = NOW()`,
    [
      row.workspace_id,
      row.contact_id,
      row.channel,
      row.destination_normalized,
      row.destination_fingerprint,
      status,
      method,
      CONSENT_POLICY_VERSION,
    ],
  );
  const nowVerified = status === "verified";
  const optedOut = status === "opted_out";
  if (nowVerified) {
    await client.query(
      `-- RV_CLEAR_DECLINE
       DELETE FROM notification_suppressions
        WHERE channel = $1 AND destination_fingerprint = $2
          AND scope = 'workspace' AND workspace_id = $3 AND reason = 'recipient_declined'`,
      [row.channel, row.destination_fingerprint, row.workspace_id],
    );
  }
  if (optedOut) {
    await client.query(
      `-- RV_INSERT_SUPPRESSION
       INSERT INTO notification_suppressions
         (channel, destination_fingerprint, scope, workspace_id, reason)
       VALUES ($1, $2, 'workspace', $3, 'recipient_declined')
       ON CONFLICT (channel, destination_fingerprint, workspace_id, reason) WHERE scope = 'workspace'
       DO NOTHING`,
      [row.channel, row.destination_fingerprint, row.workspace_id],
    );
  }
}

async function consumeEmailChallenge({ pool, token, decision }) {
  if (decision !== "accept" && decision !== "decline") {
    return { ok: false };
  }
  return withTransaction(pool, async (client) => {
    const pending = await client.query(
      `-- RV_PREVIEW_CHALLENGE
       SELECT workspace_id, contact_id, channel, destination_normalized, destination_fingerprint
         FROM contact_verification_challenges
        WHERE token_hash = $1
          AND channel = 'email'
          AND status = 'pending'
          AND expires_at > NOW()`,
      [hashToken(token)],
    );
    const preview = pending.rows[0];
    if (!preview) return { ok: false };
    await client.query(
      `-- RV_LOCK_CONTACT
       SELECT id FROM workspace_contacts WHERE workspace_id = $1 AND id = $2 FOR UPDATE`,
      [preview.workspace_id, preview.contact_id],
    );
    const contact = await client.query(
      `-- RV_CONTACT
       SELECT details FROM workspace_contacts WHERE workspace_id = $1 AND id = $2`,
      [preview.workspace_id, preview.contact_id],
    );
    const current = normalizeEmail(contact.rows[0]?.details?.email);
    if (!current.ok || current.value !== preview.destination_normalized) {
      return { ok: false, stale: true };
    }
    const consumed = await client.query(
      `-- RV_CONSUME_CHALLENGE
       UPDATE contact_verification_challenges
          SET status = $2, consumed_at = NOW(), attempt_count = attempt_count + 1
        WHERE token_hash = $1
          AND channel = 'email'
          AND status = 'pending'
          AND expires_at > NOW()
        RETURNING workspace_id, contact_id, channel, destination_normalized, destination_fingerprint`,
      [hashToken(token), decision === "decline" ? "declined" : "consumed"],
    );
    const row = consumed.rows[0];
    if (!row) return { ok: false };
    await upsertVerification(
      client,
      row,
      decision === "decline" ? "opted_out" : "verified",
      decision === "decline" ? "recipient_declined" : "email_link_confirm",
    );
    return { ok: true, outcome: decision === "decline" ? "declined" : "accepted" };
  });
}

async function confirmWhatsAppInbound({ pool, from, body, messageSid }) {
  const code = parseConfirmCode(body);
  const sender = normalizePhone(from);
  if (!code || !sender.ok || !messageSid) return { ok: false, reason: "ignored" };
  return withTransaction(pool, async (client) => {
    const inserted = await client.query(
      `-- RV_INBOUND_DEDUPE
       INSERT INTO twilio_inbound_messages (message_sid) VALUES ($1)
       ON CONFLICT (message_sid) DO NOTHING
       RETURNING message_sid`,
      [String(messageSid).slice(0, 128)],
    );
    if (!inserted.rows[0]) return { ok: false, duplicate: true, reason: "duplicate" };
    const pending = await client.query(
      `-- RV_PREVIEW_CHALLENGE
       SELECT workspace_id, contact_id, destination_normalized
         FROM contact_verification_challenges
        WHERE code_hash = $1
          AND channel = 'whatsapp'
          AND status = 'pending'
          AND expires_at > NOW()
          AND destination_normalized = $2`,
      [hashToken(code), sender.value],
    );
    const preview = pending.rows[0];
    if (!preview) return { ok: false, reason: "invalid" };
    await client.query(
      `-- RV_LOCK_CONTACT
       SELECT id FROM workspace_contacts WHERE workspace_id = $1 AND id = $2 FOR UPDATE`,
      [preview.workspace_id, preview.contact_id],
    );
    const currentContact = await client.query(
      `-- RV_CONTACT
       SELECT phone_e164 FROM workspace_contacts WHERE workspace_id = $1 AND id = $2`,
      [preview.workspace_id, preview.contact_id],
    );
    const current = normalizePhone(currentContact.rows[0]?.phone_e164);
    if (!current.ok || current.value !== sender.value) return { ok: false, reason: "stale" };
    const consumed = await client.query(
      `-- RV_CONSUME_CHALLENGE
       UPDATE contact_verification_challenges
          SET status = 'consumed', consumed_at = NOW(), attempt_count = attempt_count + 1
        WHERE code_hash = $1
          AND channel = 'whatsapp'
          AND status = 'pending'
          AND expires_at > NOW()
          AND destination_normalized = $2
        RETURNING workspace_id, contact_id, channel, destination_normalized, destination_fingerprint`,
      [hashToken(code), sender.value],
    );
    const row = consumed.rows[0];
    if (!row) return { ok: false, reason: "invalid" };
    await upsertVerification(client, row, "verified", "whatsapp_inbound_confirm");
    return { ok: true, outcome: "accepted", workspaceId: row.workspace_id };
  });
}

function parseConfirmCode(body) {
  const match = String(body || "").trim().match(/^CONFIRM\s+([A-Z0-9]{8,12})$/i);
  return match ? match[1].toUpperCase() : null;
}

function verifyTwilioSignature({ url, params, signature, authToken }) {
  try {
    if (!url || !authToken || !signature) return false;
    const keys = Object.keys(params || {}).sort();
    let data = url;
    for (const key of keys) data += key + String(params[key] ?? "");
    const computed = crypto.createHmac("sha1", authToken).update(Buffer.from(data, "utf8")).digest("base64");
    const left = Buffer.from(String(signature));
    const right = Buffer.from(computed);
    if (left.length !== right.length) return false;
    return crypto.timingSafeEqual(left, right);
  } catch (_) {
    return false;
  }
}

function whatsAppDeepLink(fromValue, code) {
  const digits = String(fromValue || "").replace(/\D/g, "");
  if (!digits || !code) return null;
  return `https://wa.me/${digits}?text=${encodeURIComponent(`CONFIRM ${code}`)}`;
}

function renderPage(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow"><title>${escapeHtml(title)}</title><style>body{font-family:Georgia,serif;background:#f6f3ec;color:#1d1a16;margin:0}main{max-width:38rem;margin:8vh auto;background:#fff;padding:2rem;border:1px solid #e6dfd2}button,a.button{display:inline-block;margin:.5rem .5rem 0 0;background:#1d1a16;color:#fff;text-decoration:none;border:0;padding:.7rem 1rem;font:inherit}button.secondary{background:#fff;color:#1d1a16;border:1px solid #1d1a16}</style></head><body><main>${body}</main></body></html>`;
}

function renderChallengePage({ state, token, workspaceName, channel, code, fromNumber }) {
  if (state === "accepted") {
    return renderPage("Confirmed", "<h1>Confirmed</h1><p>This destination can receive TokenTimer notifications for that workspace. You can close this page.</p>");
  }
  if (state === "declined") {
    return renderPage("Declined", "<h1>Declined</h1><p>TokenTimer will not send notifications to this destination for that workspace.</p>");
  }
  if (state !== "pending") {
    return renderPage("Invitation unavailable", "<h1>This invitation is unavailable</h1><p>The link is invalid, expired, or already used. Ask the workspace administrator for a new invitation.</p>");
  }
  const name = escapeHtml(workspaceName || "A TokenTimer workspace");
  const purpose = channel === "whatsapp"
    ? "WhatsApp alerts about certificate, credential, and endpoint expiration"
    : "email alerts about certificate, credential, and endpoint expiration, including weekly digests";
  if (channel === "whatsapp") {
    const link = whatsAppDeepLink(fromNumber, code);
    const button = link
      ? `<a class="button" href="${escapeHtml(link)}">Open WhatsApp and send confirmation</a>`
      : "<p>WhatsApp confirmation is not available because the official number is not configured.</p>";
    return renderPage(
      "Confirm WhatsApp alerts",
      `<h1>Confirm WhatsApp alerts</h1><p><strong>${name}</strong> asked TokenTimer to send ${purpose} to your WhatsApp number.</p><p>TokenTimer will only do that after you send the confirmation from this number to TokenTimer's official WhatsApp account. Sending the message is your consent.</p>${button}<p>After you send it, refresh this page.</p><form method="post" action="/verify/recipient/${encodeURIComponent(token)}/decline"><button class="secondary" type="submit">Do not notify me</button></form>`,
    );
  }
  return renderPage(
    "Confirm email alerts",
    `<h1>Confirm email alerts</h1><p><strong>${name}</strong> asked TokenTimer to send ${purpose} to this email address.</p><p>Nothing is confirmed until you choose below. Opening this page does not opt you in.</p><form method="post" action="/verify/recipient/${encodeURIComponent(token)}/accept"><button type="submit">Yes, send me these notifications</button></form><form method="post" action="/verify/recipient/${encodeURIComponent(token)}/decline"><button class="secondary" type="submit">Do not notify me</button></form>`,
  );
}

function renderResubscribeForm() {
  return renderPage(
    "Re-subscribe",
    "<h1>Request email alerts again</h1><p>If you previously declined TokenTimer email alerts, enter that email address. When it matches, TokenTimer sends a confirmation link to that mailbox. Opening this page does not restore consent.</p><form method=\"post\" action=\"/verify/recipient/resubscribe\"><label>Email<br><input name=\"email\" type=\"email\" autocomplete=\"email\" required></label><br><button type=\"submit\">Email me a confirmation link</button></form>",
  );
}

function renderResubscribeAccepted() {
  return renderPage(
    "Check your email",
    "<h1>Check your email</h1><p>If this address previously declined TokenTimer alerts, a confirmation link is on its way. The link works only for that address, and nothing is confirmed until you accept it.</p>",
  );
}

function renderDone(result) {
  if (result === "accepted") {
    return renderPage("Confirmed", "<h1>Confirmed</h1><p>You will receive TokenTimer notifications at this destination. You can close this page.</p>");
  }
  if (result === "declined") {
    return renderPage("Declined", "<h1>Declined</h1><p>TokenTimer will not send workspace notifications to this destination.</p>");
  }
  return renderPage("Invitation unavailable", "<h1>This invitation is unavailable</h1><p>The link is invalid, expired, or already used.</p>");
}

async function invalidateChangedDestination({ client, workspaceId, contactId, channel, previousDestination, nextDestination }) {
  const previous = normalizeDestination(channel, previousDestination);
  const next = normalizeDestination(channel, nextDestination);
  if (previous.ok && next.ok && previous.value === next.value) return;
  await client.query(
    `-- RV_LOCK_CONTACT
     SELECT id FROM workspace_contacts WHERE workspace_id = $1 AND id = $2 FOR UPDATE`,
    [workspaceId, contactId],
  );
  await client.query(
    `-- RV_SUPERSEDE
     UPDATE contact_verification_challenges
        SET status = 'superseded'
      WHERE workspace_id = $1 AND contact_id = $2 AND channel = $3 AND status = 'pending'`,
    [workspaceId, contactId, channel],
  );
  if (!next.ok) {
    await client.query(
      `-- RV_DELETE_VERIFICATION
       DELETE FROM contact_channel_verifications
        WHERE workspace_id = $1 AND contact_id = $2 AND channel = $3`,
      [workspaceId, contactId, channel],
    );
    return;
  }
  const fingerprint = destinationFingerprint(channel, next.value);
  if (!fingerprint) return;
  await client.query(
    `-- RV_INVALIDATE
     UPDATE contact_channel_verifications
        SET status = 'pending', verified_at = NULL, consent_at = NULL, revoked_at = NULL,
            opted_out_at = NULL, destination_normalized = $4, destination_fingerprint = $5, updated_at = NOW()
      WHERE workspace_id = $1 AND contact_id = $2 AND channel = $3
        AND destination_normalized IS DISTINCT FROM $4`,
    [workspaceId, contactId, channel, next.value, fingerprint],
  );
}

async function revokeChannel({ pool, workspaceId, contactId, channel, actorUserId }) {
  return withTransaction(pool, async (client) => {
    const contact = await client.query(
      `-- RV_CONTACT
       SELECT phone_e164, details FROM workspace_contacts WHERE workspace_id = $1 AND id = $2 FOR UPDATE`,
      [workspaceId, contactId],
    );
    if (!contact.rows[0]) throw coded(404, "CONTACT_NOT_FOUND", "Contact not found");
    const raw = channel === "email" ? contact.rows[0].details?.email : contact.rows[0].phone_e164;
    const destination = normalizeDestination(channel, raw);
    if (!destination.ok) throw coded(400, "DESTINATION_MISSING", "This contact has no destination for that channel");
    const fingerprint = destinationFingerprint(channel, destination.value);
    if (!fingerprint) throw coded(503, "RECIPIENT_VERIFICATION_UNAVAILABLE", "Recipient verification is not configured");
    await client.query(
      `-- RV_SUPERSEDE
       UPDATE contact_verification_challenges SET status = 'superseded'
        WHERE workspace_id = $1 AND contact_id = $2 AND channel = $3 AND status = 'pending'`,
      [workspaceId, contactId, channel],
    );
    await client.query(
      `-- RV_UPSERT_VERIFICATION
       INSERT INTO contact_channel_verifications
         (workspace_id, contact_id, channel, destination_normalized, destination_fingerprint, status, revoked_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,'revoked', NOW(), NOW())
       ON CONFLICT (workspace_id, contact_id, channel) DO UPDATE
         SET status = 'revoked', revoked_at = NOW(), verified_at = NULL, consent_at = NULL,
             destination_normalized = EXCLUDED.destination_normalized,
             destination_fingerprint = EXCLUDED.destination_fingerprint,
             updated_at = NOW()`,
      [workspaceId, contactId, channel, destination.value, fingerprint],
    );
    return { status: "revoked", actorUserId: actorUserId || null };
  });
}

async function attachVerification(db, workspaceId, contacts) {
  const list = Array.isArray(contacts) ? contacts : [];
  const empty = {
    email: { pending: 0, verified: 0, revoked: 0, opted_out: 0 },
    whatsapp: { pending: 0, verified: 0, revoked: 0, opted_out: 0 },
  };
  if (!list.length) return { items: list, verification_summary: { mode: resolveEnforcementMode(), ...empty } };
  let rows = [];
  let challenges = [];
  try {
    const status = await db.query(
      `-- RV_LIST_STATUS
       SELECT contact_id, channel, status, verified_at, consent_at
         FROM contact_channel_verifications
        WHERE workspace_id = $1 AND contact_id = ANY($2::uuid[])`,
      [workspaceId, list.map((contact) => contact.id)],
    );
    rows = status.rows;
    const pending = await db.query(
      `-- RV_LIST_CHALLENGES
       SELECT contact_id, channel, expires_at
         FROM contact_verification_challenges
        WHERE workspace_id = $1 AND contact_id = ANY($2::uuid[])
          AND status = 'pending' AND expires_at > NOW()`,
      [workspaceId, list.map((contact) => contact.id)],
    );
    challenges = pending.rows;
  } catch (error) {
    if (!isMissingSchema(error)) throw error;
  }
  const byContact = new Map();
  for (const row of rows) {
    if (!byContact.has(String(row.contact_id))) byContact.set(String(row.contact_id), {});
    byContact.get(String(row.contact_id))[row.channel] = {
      status: row.status,
      verified_at: row.verified_at,
      consent_at: row.consent_at,
    };
  }
  const challengeByContact = new Map();
  for (const row of challenges) {
    if (!challengeByContact.has(String(row.contact_id))) challengeByContact.set(String(row.contact_id), {});
    challengeByContact.get(String(row.contact_id))[row.channel] = { expires_at: row.expires_at };
  }
  const items = list.map((contact) => {
    const stored = byContact.get(String(contact.id)) || {};
    const invites = challengeByContact.get(String(contact.id)) || {};
    const email = normalizeEmail(contact.details?.email);
    const phone = normalizePhone(contact.phone_e164);
    const verification = {
      email: email.ok ? { status: stored.email?.status || "pending", ...(stored.email || {}), invitation: invites.email || null } : null,
      whatsapp: phone.ok ? { status: stored.whatsapp?.status || "pending", ...(stored.whatsapp || {}), invitation: invites.whatsapp || null } : null,
    };
    for (const channel of ["email", "whatsapp"]) {
      const entry = verification[channel];
      if (!entry) continue;
      empty[channel][entry.status] = (empty[channel][entry.status] || 0) + 1;
    }
    return { ...contact, verification };
  });
  return { items, verification_summary: { mode: resolveEnforcementMode(), ...empty } };
}

async function authorizeWorkspaceTest({ pool, workspaceId, contactId, channel, destination }) {
  if (!contactId) throw coded(400, "CONTACT_REQUIRED", "Test a saved, verified contact");
  const contact = await pool.query(
    `-- RV_CONTACT
     SELECT id, phone_e164, details FROM workspace_contacts WHERE workspace_id = $1 AND id = $2`,
    [workspaceId, contactId],
  );
  if (!contact.rows[0]) throw coded(404, "CONTACT_NOT_FOUND", "Contact not found");
  const actual = normalizeDestination(channel, channel === "email" ? contact.rows[0].details?.email : contact.rows[0].phone_e164);
  const requested = normalizeDestination(channel, destination);
  if (!actual.ok || !requested.ok || actual.value !== requested.value) {
    throw coded(400, "DESTINATION_MISMATCH", "The test destination must match the saved contact");
  }
  let decision;
  try {
    decision = await evaluateRecipient({
      client: pool,
      workspaceId,
      contactId,
      channel,
      destination: actual.value,
    });
  } catch (error) {
    if (isMissingSchema(error)) throw coded(503, "RECIPIENT_VERIFICATION_UNAVAILABLE", "Recipient verification is not available");
    throw error;
  }
  if (!decision.allowed) {
    throw coded(403, decision.code || "RECIPIENT_NOT_VERIFIED", "This destination is not verified for notifications");
  }
  await withTransaction(pool, async (client) => {
    await client.query(`SELECT pg_advisory_xact_lock(hashtext($1))`, [`test:${workspaceId}:${contactId}:${channel}`]);
    const config = limits();
    const daily = await takeBucket(client, {
      key: `test:${workspaceId}:${contactId}:${channel}:24h`,
      limit: config.testPerContactPerDay,
      windowSeconds: 24 * 60 * 60,
      workspaceId,
    });
    if (!daily.ok) {
      throw coded(429, "TEST_WHATSAPP_COOLDOWN", "Test message limit reached for this contact", { retryAfter: daily.retryAfter });
    }
    const cool = await takeBucket(client, {
      key: `test:${workspaceId}:${contactId}:${channel}:cool`,
      limit: 1,
      windowSeconds: config.testCooldownSeconds,
      workspaceId,
    });
    if (!cool.ok) {
      throw coded(429, "TEST_WHATSAPP_COOLDOWN", "Please wait before testing this contact again", { retryAfter: cool.retryAfter });
    }
  });
  return { destination: actual.value };
}

function verificationResponseHeaders(res) {
  res.set("Cache-Control", "no-store");
  res.set("Referrer-Policy", "no-referrer");
  res.set("X-Robots-Tag", "noindex, nofollow");
  res.set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'");
}

async function assertPublicVerificationBudget(pool, key) {
  const config = limits();
  return withTransaction(pool, async (client) => {
    await client.query(`SELECT pg_advisory_xact_lock(hashtext($1))`, [`verify:public:${key}`]);
    const bucket = await takeBucket(client, {
      key: `public:${key}`,
      limit: config.publicPerWindow,
      windowSeconds: config.publicWindowSeconds,
      workspaceId: null,
    });
    if (!bucket.ok) {
      throw coded(429, "RECIPIENT_VERIFICATION_RATE_LIMITED", "Please wait before trying again", {
        retryAfter: bucket.retryAfter,
      });
    }
  });
}

module.exports = {
  CONSENT_POLICY_VERSION,
  DELIVERY_POLICIES,
  DEFAULT_DEPLOYMENT,
  limits,
  resolveEnforcementMode,
  fingerprintSecret,
  publicApiBase,
  normalizeEmail,
  normalizePhone,
  normalizeDestination,
  destinationFingerprint,
  hashToken,
  randomToken,
  sealCode,
  openCode,
  maskEmail,
  maskPhone,
  escapeHtml,
  evaluateRecipient,
  canDeliverToRecipient,
  canDeliverToDestination,
  filterDeliveryRecipients,
  deliveryDisposition,
  queueDeliveryOutcome,
  mergeDeliveryAttempt,
  parseDeliveryLedger,
  reconcileDeliveryChannels,
  planManualRetry,
  publicDeliveryChannels,
  webhookChannelReopened,
  requeueWebhookChannel,
  selectDeliverableDestinations,
  isEligibilityTerminal,
  createInvitation,
  requestEmailResubscribe,
  loadChallenge,
  consumeEmailChallenge,
  confirmWhatsAppInbound,
  parseConfirmCode,
  verifyTwilioSignature,
  whatsAppDeepLink,
  renderChallengePage,
  renderResubscribeForm,
  renderResubscribeAccepted,
  renderDone,
  invalidateChangedDestination,
  revokeChannel,
  attachVerification,
  authorizeWorkspaceTest,
  verificationResponseHeaders,
  assertPublicVerificationBudget,
  DELIVERY_CLAIM_EXCLUSION_SQL,
  withTransaction,
};
