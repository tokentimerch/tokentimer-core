"use strict";

const { pool } = require("../db/database");
const {
  evaluateAlertEligibility,
} = require("@tokentimer/alert-eligibility");

const DEFAULT_THRESHOLDS = (process.env.ALERT_THRESHOLDS || "30,14,7,1,0")
  .split(",")
  .map((value) => Number.parseInt(value.trim(), 10))
  .filter((value) => Number.isFinite(value));

function parseChannels(value) {
  if (Array.isArray(value)) return value;
  if (typeof value !== "string") return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch (_) {
    return value
      .split(/[,\s]+/)
      .map((channel) => channel.trim())
      .filter(Boolean);
  }
}

function deliveryReason(row) {
  if (!row.alert_id) return null;
  const status = String(row.alert_status || "").toLowerCase();
  const error = String(row.alert_error_message || "");
  if (error === "OUT_OF_WINDOW") return "delivery_window";
  if (status === "limit_exceeded" || /PLAN_LIMIT/i.test(error)) {
    return "monthly_plan_limit";
  }
  if (status === "blocked" && /MAX_ATTEMPTS/i.test(error)) {
    return "max_attempts";
  }
  if (
    row.next_attempt_at &&
    ["pending", "failed", "partial"].includes(status)
  ) {
    return "retry_scheduled";
  }
  return null;
}

function buildDeliveryState(row) {
  if (!row.alert_id) return null;
  const latestAttempt = row.delivery_attempt_id
    ? {
        id: row.delivery_attempt_id,
        channel: row.delivery_attempt_channel,
        status: row.delivery_attempt_status,
        attempted_at: row.delivery_attempt_at,
        error_message: row.delivery_attempt_error || null,
      }
    : row.last_attempt
      ? {
          id: null,
          channel: null,
          status: row.alert_status,
          attempted_at: row.last_attempt,
          error_message: row.alert_error_message || null,
        }
      : null;

  return {
    alert_id: row.alert_id,
    status: row.alert_status,
    reason: deliveryReason(row),
    threshold_days: row.alert_threshold_days,
    due_date: row.alert_due_date,
    channels: parseChannels(row.alert_channels),
    attempts: row.alert_attempts,
    attempts_email: row.alert_attempts_email,
    attempts_webhooks: row.alert_attempts_webhooks,
    attempts_whatsapp: row.alert_attempts_whatsapp,
    error_message: row.alert_error_message || null,
    created_at: row.alert_created_at,
    updated_at: row.alert_updated_at,
    last_attempt_at: row.last_attempt || null,
    next_attempt_at: row.next_attempt_at || null,
    latest_attempt: latestAttempt,
  };
}

function buildAlertState(row, referenceDate) {
  return {
    eligibility: evaluateAlertEligibility(row, {
      defaultThresholds: DEFAULT_THRESHOLDS,
      referenceDate,
    }),
    delivery: buildDeliveryState(row),
  };
}

async function loadAlertStates(tokenIds, { queryable = pool, referenceDate } = {}) {
  const ids = [
    ...new Set(
      (Array.isArray(tokenIds) ? tokenIds : [])
        .map((id) => Number.parseInt(String(id), 10))
        .filter((id) => Number.isFinite(id)),
    ),
  ];
  if (ids.length === 0) return new Map();

  const result = await queryable.query(
    `SELECT
       t.id AS token_id,
       t.expiration::date AS expiration,
       t.imported_at,
       t.contact_group_id,
       t.cert_lifecycle_status,
       COALESCE(ws.alert_thresholds, wsf.alert_thresholds, wjj.alert_thresholds) AS alert_thresholds,
       COALESCE(ws.webhook_urls, wsf.webhook_urls, wjj.webhook_urls) AS webhook_urls,
       COALESCE(ws.contact_groups, wsf.contact_groups, wjj.contact_groups) AS contact_groups,
       COALESCE(ws.default_contact_group_id, wsf.default_contact_group_id, wjj.default_contact_group_id) AS default_contact_group_id,
       COALESCE(ws.email_alerts_enabled, wsf.email_alerts_enabled, wjj.email_alerts_enabled) AS ws_email_alerts_enabled,
       aq.id AS alert_id,
       aq.threshold_days AS alert_threshold_days,
       aq.due_date AS alert_due_date,
       aq.status AS alert_status,
       aq.channels AS alert_channels,
       aq.attempts AS alert_attempts,
       aq.attempts_email AS alert_attempts_email,
       aq.attempts_webhooks AS alert_attempts_webhooks,
       aq.attempts_whatsapp AS alert_attempts_whatsapp,
       aq.error_message AS alert_error_message,
       aq.created_at AS alert_created_at,
       aq.updated_at AS alert_updated_at,
       aq.last_attempt,
       aq.next_attempt_at,
       attempt.id AS delivery_attempt_id,
       attempt.channel AS delivery_attempt_channel,
       attempt.status AS delivery_attempt_status,
       attempt.sent_at AS delivery_attempt_at,
       attempt.error_message AS delivery_attempt_error
     FROM tokens t
     LEFT JOIN workspaces w ON w.id = t.workspace_id
     LEFT JOIN LATERAL (
       SELECT w2.*
       FROM workspaces w2
       WHERE w2.created_by = t.user_id
       ORDER BY w2.created_at ASC
       LIMIT 1
     ) wf ON TRUE
     LEFT JOIN LATERAL (
       SELECT w3.*
       FROM workspaces w3
       JOIN workspace_memberships wm3
         ON wm3.workspace_id = w3.id AND wm3.user_id = t.user_id
       WHERE wm3.role IN ('admin', 'workspace_manager')
       ORDER BY w3.created_at ASC
       LIMIT 1
     ) wj ON TRUE
     LEFT JOIN workspace_settings ws ON ws.workspace_id = w.id
     LEFT JOIN workspace_settings wsf ON wsf.workspace_id = wf.id
     LEFT JOIN workspace_settings wjj ON wjj.workspace_id = wj.id
     LEFT JOIN LATERAL (
       SELECT aq1.*
       FROM alert_queue aq1
       WHERE aq1.token_id = t.id
         AND aq1.alert_key LIKE 'token_expiry:%'
       ORDER BY aq1.created_at DESC, aq1.id DESC
       LIMIT 1
     ) aq ON TRUE
     LEFT JOIN LATERAL (
       SELECT log.id, log.channel, log.status, log.sent_at, log.error_message
       FROM alert_delivery_log log
       WHERE log.alert_queue_id = aq.id
       ORDER BY log.sent_at DESC, log.id DESC
       LIMIT 1
     ) attempt ON TRUE
     WHERE t.id = ANY($1::int[])`,
    [ids],
  );

  return new Map(
    result.rows.map((row) => [
      String(row.token_id),
      buildAlertState(row, referenceDate),
    ]),
  );
}

async function enrichTokensWithAlertState(tokens, options = {}) {
  const source = Array.isArray(tokens) ? tokens : [];
  const states = await loadAlertStates(
    source.map((token) => token.id),
    options,
  );
  return source.map((token) => ({
    ...token,
    alert_state: states.get(String(token.id)) || null,
  }));
}

async function enrichTokenWithAlertState(token, options = {}) {
  if (!token) return token;
  const [enriched] = await enrichTokensWithAlertState([token], options);
  return enriched;
}

async function countWorkspaceAlertEligibility(
  workspaceId,
  { queryable = pool, referenceDate } = {},
) {
  const result = await queryable.query(
    "SELECT id FROM tokens WHERE workspace_id = $1 ORDER BY id",
    [workspaceId],
  );
  const states = await loadAlertStates(
    result.rows.map((row) => row.id),
    { queryable, referenceDate },
  );
  const counts = { outside_threshold: 0, due: 0, suppressed: 0 };
  for (const state of states.values()) {
    const status = state.eligibility?.status;
    if (Object.hasOwn(counts, status)) counts[status]++;
  }
  return { total: result.rows.length, counts };
}

module.exports = {
  buildAlertState,
  buildDeliveryState,
  loadAlertStates,
  enrichTokensWithAlertState,
  enrichTokenWithAlertState,
  countWorkspaceAlertEligibility,
};
