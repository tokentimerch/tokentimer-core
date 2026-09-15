"use strict";

const { pool } = require("../db/database");
const { formatThresholdDate } = require("@tokentimer/alert-eligibility");
const { safeAlertErrorMessage } = require("./alertErrorRedaction");
const { discardedAlertReason } = require("./alertDeliveryDisposition");

const PAGE_SIZE_DEFAULT = 20;
const PAGE_SIZE_MAX = 100;
const SUPPORTED_AUDIT_ACTIONS = Object.freeze([
  "ALERT_QUEUED",
  "ALERT_SENT",
  "ALERT_SEND_FAILED",
  "ALERT_DELIVERY_DEFERRED",
  "ALERT_NOT_QUEUED_NO_CHANNEL",
  "ALERT_RETRY_SCHEDULED",
  "ALERT_MANUAL_RETRY",
  "ALERTS_BULK_REQUEUED",
  "ALERT_PARTIAL_SUCCESS",
  "ALERT_BLOCKED_MAX_ATTEMPTS",
  "ALERT_BLOCKED_WHATSAPP_ERROR",
]);

const TYPE_ORDER = Object.freeze({
  threshold_reached: 10,
  alert_not_queued: 15,
  alert_queued: 20,
  alert_discarded: 25,
  delivery_deferred: 30,
  delivery_attempted: 40,
  delivery_failed: 50,
  delivery_succeeded: 50,
  delivery_partial: 55,
  delivery_blocked: 60,
  retry_scheduled: 70,
  alert_requeued: 80,
});

const ALLOWED_CHANNELS = new Set(["email", "webhooks", "whatsapp"]);

function clampLimit(value) {
  return Math.max(
    1,
    Math.min(PAGE_SIZE_MAX, Math.trunc(Number(value)) || PAGE_SIZE_DEFAULT),
  );
}

function clampOffset(value) {
  return Math.max(0, Math.trunc(Number(value)) || 0);
}

function finiteInteger(value) {
  if (value === null || value === undefined || value === "") return null;
  const number = Number(value);
  return Number.isInteger(number) ? number : null;
}

function isoDate(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function safeChannel(value) {
  const channel = String(value || "").toLowerCase();
  return ALLOWED_CHANNELS.has(channel) ? channel : null;
}

function safeChannels(value) {
  let source = value;
  if (typeof source === "string") {
    try {
      source = JSON.parse(source);
    } catch (_) {
      source = [];
    }
  }
  if (!Array.isArray(source)) return [];
  return [...new Set(source.map(safeChannel).filter(Boolean))];
}

const safeErrorMessage = safeAlertErrorMessage;

function queueAlertReason(alertKey) {
  if (alertKey.startsWith("token_expiry:")) return "threshold_reached";
  if (alertKey.startsWith("endpoint_health:")) return "endpoint_health";
  if (alertKey.startsWith("cert_renewal_failed:")) {
    return "certificate_renewal_failure";
  }
  if (alertKey.startsWith("agent_health:")) return "agent_health";
  return "other_alert";
}

function baseEvent(row, overrides) {
  const event = {
    id: overrides.id,
    type: overrides.type,
    occurred_at: isoDate(overrides.occurred_at),
    token_id: finiteInteger(row.token_id),
    token_name: row.token_name || null,
    workspace_id: row.workspace_id || null,
    alert_id: finiteInteger(overrides.alert_id),
    threshold_days: finiteInteger(overrides.threshold_days),
    channel: safeChannel(overrides.channel),
    status: overrides.status || null,
    reason: overrides.reason || null,
    error_message: safeErrorMessage(overrides.error_message),
    metadata: overrides.metadata || {},
    source: overrides.source,
  };
  // Correlation provenance is internal; the viewer timeline does not need to
  // expose alert keys or raw audit metadata to match persisted records.
  Object.defineProperty(event, "_alert_key", {
    value: String(overrides.alert_key ?? row.alert_key ?? ""),
  });
  return event;
}

function normalizeQueueRow(row) {
  const alertId = finiteInteger(row.alert_id ?? row.id);
  const alertKey = String(row.alert_key || "");
  const isExpiry = alertKey.startsWith("token_expiry:");
  const thresholdDays = isExpiry ? finiteInteger(row.threshold_days) : null;
  const reason = queueAlertReason(alertKey);
  const events = [];
  const thresholdDate = isExpiry
    ? formatThresholdDate(row.expiration, thresholdDays)
    : null;
  if (thresholdDate) {
    events.push(
      baseEvent(row, {
        id: `threshold:${alertId}`,
        type: "threshold_reached",
        occurred_at: `${thresholdDate}T00:00:00.000Z`,
        alert_id: alertId,
        threshold_days: thresholdDays,
        status: "reached",
        reason:
          thresholdDays < 0
            ? "post_expiry_threshold_reached"
            : thresholdDays === 0
              ? "expiry_day_threshold_reached"
              : "pre_expiry_threshold_reached",
        source: "derived_from_alert_queue",
      }),
    );
  }

  events.push(
    baseEvent(row, {
      id: `queue:${alertId}`,
      type: "alert_queued",
      occurred_at: row.created_at,
      alert_id: alertId,
      threshold_days: thresholdDays,
      status: "queued",
      reason,
      source: "alert_queue",
    }),
  );
  return events;
}

function deliveryType(status) {
  switch (String(status || "").toLowerCase()) {
    case "success":
      return ["delivery_succeeded", "succeeded", null];
    case "failed":
      return ["delivery_failed", "failed", "delivery_error"];
    case "blocked":
      return ["delivery_blocked", "blocked", "delivery_blocked"];
    case "deferred":
      return ["delivery_deferred", "deferred", "delivery_window"];
    default:
      return null;
  }
}

function normalizeDeliveryRow(row) {
  const mapping = deliveryType(row.delivery_status ?? row.status);
  if (!mapping) return null;
  const [type, status, mappedReason] = mapping;
  const reason =
    type === "delivery_blocked" && row.queue_status === "limit_exceeded"
      ? "monthly_limit"
      : mappedReason;
  return baseEvent(row, {
    id: `delivery:${row.delivery_id ?? row.id}`,
    type,
    occurred_at: row.sent_at,
    alert_id: row.alert_id ?? row.alert_queue_id,
    threshold_days: String(row.alert_key || "").startsWith("token_expiry:")
      ? row.threshold_days
      : null,
    channel: row.channel,
    status,
    reason,
    error_message: row.error_message,
    source: "alert_delivery_log",
  });
}

function auditMapping(action) {
  switch (action) {
    case "ALERT_QUEUED":
      return ["alert_queued", "queued", "threshold_reached"];
    case "ALERT_SENT":
      return ["delivery_succeeded", "succeeded", null];
    case "ALERT_SEND_FAILED":
      return ["delivery_failed", "failed", "delivery_error"];
    case "ALERT_DELIVERY_DEFERRED":
      return ["delivery_deferred", "deferred", "delivery_window"];
    case "ALERT_NOT_QUEUED_NO_CHANNEL":
      return ["alert_not_queued", "not_queued", "no_eligible_channels"];
    case "ALERT_RETRY_SCHEDULED":
      return ["retry_scheduled", "scheduled", "delivery_retry"];
    case "ALERT_MANUAL_RETRY":
      return ["alert_requeued", "queued", "manual_retry"];
    case "ALERTS_BULK_REQUEUED":
      return ["alert_requeued", "queued", "bulk_requeue"];
    case "ALERT_PARTIAL_SUCCESS":
      return ["delivery_partial", "partial", "partial_delivery"];
    case "ALERT_BLOCKED_MAX_ATTEMPTS":
      return ["delivery_blocked", "blocked", "max_attempts"];
    case "ALERT_BLOCKED_WHATSAPP_ERROR":
      return ["delivery_blocked", "blocked", "permanent_channel_failure"];
    default:
      return null;
  }
}

function normalizeAuditRow(row) {
  const mapping = auditMapping(row.action);
  if (!mapping) return null;
  const metadata = row.audit_metadata || row.metadata || {};
  const [type, status, mappedReason] = mapping;
  const alertKey = String(row.alert_key || metadata.alert_key || "");
  const isNonExpiry = alertKey && !alertKey.startsWith("token_expiry:");
  const reason = type === "alert_queued" && isNonExpiry
    ? queueAlertReason(alertKey)
    : mappedReason;
  const nextAttemptAt = isoDate(metadata.next_attempt_at);
  const updatedCount = finiteInteger(metadata.updated);
  const safeMetadata = {};
  if (nextAttemptAt) safeMetadata.next_attempt_at = nextAttemptAt;
  const channels = safeChannels(
    metadata.channels_to_retry || metadata.channels,
  );
  if (channels.length > 0) safeMetadata.channels = channels;
  if (updatedCount !== null) safeMetadata.updated_count = updatedCount;

  const auditThreshold =
    finiteInteger(metadata.threshold) ?? finiteInteger(metadata.days);
  const auditError = Array.isArray(metadata.errors)
    ? metadata.errors.join("; ")
    : metadata.error;
  return baseEvent(row, {
    id: `audit:${row.audit_id ?? row.id}`,
    type,
    occurred_at: row.occurred_at,
    alert_id: finiteInteger(metadata.alert_id) ?? row.alert_id,
    alert_key: metadata.alert_key ?? row.alert_key,
    threshold_days: isNonExpiry ? null : auditThreshold ?? row.threshold_days,
    channel: row.channel || metadata.channel,
    status,
    reason,
    error_message: auditError,
    metadata: safeMetadata,
    source: "audit_events",
  });
}

function hasEvidence(events, type, row) {
  const alertId = finiteInteger(row.alert_id ?? row.id);
  const alertKey = String(row._alert_key ?? row.alert_key ?? "");
  return events.some(
    (event) =>
      event.type === type &&
      (alertId !== null && event.alert_id !== null
        ? event.alert_id === alertId
        : alertKey && event._alert_key
          ? event._alert_key === alertKey
          : false),
  );
}

function queueFallbackEvent(row, auditEvents, deliveryEvents) {
  const alertId = finiteInteger(row.alert_id ?? row.id);
  const thresholdDays = String(row.alert_key || "").startsWith("token_expiry:")
    ? finiteInteger(row.threshold_days)
    : null;
  const discardReason = discardedAlertReason(row.status, row.error_message);
  let details = null;
  if (row.status === "limit_exceeded") {
    details = ["delivery_blocked", "blocked", "monthly_limit"];
  } else if (row.status === "blocked") {
    details = ["delivery_blocked", "blocked", "delivery_blocked"];
  } else if (row.status === "partial") {
    details = ["delivery_partial", "partial", "partial_delivery"];
  } else if (
    row.status === "pending" &&
    row.error_message === "OUT_OF_WINDOW"
  ) {
    details = ["delivery_deferred", "deferred", "delivery_window"];
  } else if (discardReason) {
    details = ["alert_discarded", "discarded", discardReason];
  } else if (row.status === "failed") {
    details = ["delivery_failed", "failed", "delivery_error"];
  }
  if (
    !details ||
    hasEvidence(auditEvents, details[0], row) ||
    hasEvidence(deliveryEvents, details[0], row)
  ) {
    return null;
  }
  const [type, status, reason] = details;
  const metadata = {};
  const nextAttemptAt = isoDate(row.next_attempt_at);
  if (nextAttemptAt) metadata.next_attempt_at = nextAttemptAt;
  return baseEvent(row, {
    id: `queue-state:${alertId}:${type}`,
    type,
    occurred_at:
      row.state_occurred_at || row.last_attempt || row.updated_at || row.created_at,
    alert_id: alertId,
    threshold_days: thresholdDays,
    status,
    reason,
    error_message: row.error_message,
    metadata,
    source: "alert_queue",
  });
}

function compareEventsNewestFirst(left, right) {
  const timeDiff =
    new Date(right.occurred_at).getTime() -
    new Date(left.occurred_at).getTime();
  if (timeDiff !== 0) return timeDiff;
  const orderDiff =
    (TYPE_ORDER[right.type] || 0) - (TYPE_ORDER[left.type] || 0);
  if (orderDiff !== 0) return orderDiff;
  return String(right.id).localeCompare(String(left.id));
}

function buildAlertLifecycleEvents({
  queueRows = [],
  queueStateRows = queueRows,
  deliveryRows = [],
  auditRows = [],
} = {}) {
  const queueEvents = queueRows.flatMap(normalizeQueueRow);
  const deliveryEvents = deliveryRows.map(normalizeDeliveryRow).filter(Boolean);
  const auditEvents = auditRows
    .map(normalizeAuditRow)
    .filter(Boolean)
    .filter((event) => {
      if (event.type === "alert_queued") {
        return !hasEvidence(queueEvents, event.type, event);
      }
      if (
        event.type === "delivery_succeeded" ||
        event.type === "delivery_failed"
      ) {
        return !hasEvidence(deliveryEvents, event.type, event);
      }
      return true;
    });
  const sorted = [
    ...queueEvents,
    ...deliveryEvents,
    ...auditEvents,
    ...queueStateRows
      .map((row) => queueFallbackEvent(row, auditEvents, deliveryEvents))
      .filter(Boolean),
  ]
    .filter((event) => event.occurred_at)
    .sort(compareEventsNewestFirst);
  const repeatedDiscoveryEvents = new Set();
  return sorted.filter((event) => {
    if (event.type !== "alert_not_queued") return true;
    const key = `${event.type}:${event.token_id}:${event.threshold_days}`;
    if (repeatedDiscoveryEvents.has(key)) return false;
    repeatedDiscoveryEvents.add(key);
    return true;
  });
}

function queueSql(scope, state = false) {
  // Queue has no workspace_id. A matching enqueue audit or delivery records
  // historical ownership; current token ownership is a legacy-only fallback.
  const historicalOwner = `COALESCE(queued_audit.workspace_id, first_delivery.workspace_id, t.workspace_id)`;
  const where = scope === "token" ? "t.id = $1" : `${historicalOwner} = $1`;
  const stateTime = `CASE
      WHEN aq.status = 'pending' AND aq.error_message = 'OUT_OF_WINDOW'
        THEN aq.updated_at
      WHEN aq.status IN ('limit_exceeded', 'blocked', 'partial')
        OR (aq.status = 'sent' AND aq.error_message ILIKE 'Discarded:%')
        THEN aq.updated_at
      ELSE COALESCE(aq.last_attempt, aq.updated_at)
    END`;
  return `/* alert-lifecycle:${state ? "queue-state" : "queue"} */
    SELECT aq.id AS alert_id, aq.alert_key, aq.threshold_days, aq.status,
           aq.error_message, aq.created_at, aq.updated_at, aq.last_attempt,
           aq.next_attempt_at, t.id AS token_id, t.name AS token_name,
           t.expiration, ${historicalOwner} AS workspace_id
           ${state ? `, ${stateTime} AS state_occurred_at` : ""}
      FROM alert_queue aq
      JOIN tokens t ON t.id = aq.token_id
      LEFT JOIN LATERAL (
        SELECT ae.workspace_id
          FROM audit_events ae
         WHERE ae.action = 'ALERT_QUEUED' AND ae.target_type = 'token'
           AND ae.target_id = aq.token_id AND ae.workspace_id IS NOT NULL
           AND (ae.metadata->>'alert_id' = aq.id::text OR
             (ae.metadata->>'alert_id' IS NULL AND
              ae.metadata->>'alert_key' = aq.alert_key) OR
             (ae.metadata->>'alert_id' IS NULL AND
              ae.metadata->>'alert_key' IS NULL AND
              aq.alert_key LIKE 'token_expiry:%' AND
              ae.metadata->>'threshold' = aq.threshold_days::text))
           AND ae.occurred_at BETWEEN aq.created_at - INTERVAL '1 minute'
                                  AND aq.created_at + INTERVAL '1 minute'
         ORDER BY ABS(EXTRACT(EPOCH FROM (ae.occurred_at - aq.created_at))), ae.id
         LIMIT 1
      ) queued_audit ON TRUE
      LEFT JOIN LATERAL (
        SELECT d.workspace_id FROM alert_delivery_log d
         WHERE d.alert_queue_id = aq.id AND d.workspace_id IS NOT NULL
         ORDER BY d.sent_at ASC, d.id ASC LIMIT 1
      ) first_delivery ON TRUE
     WHERE ${where}
       ${state ? `AND (aq.status IN ('failed', 'blocked', 'limit_exceeded', 'partial')
               OR (aq.status = 'pending' AND aq.error_message = 'OUT_OF_WINDOW')
               OR (aq.status = 'sent' AND aq.error_message ILIKE 'Discarded:%'))` : ""}
     ORDER BY ${state ? stateTime : "aq.created_at"} DESC, aq.id DESC
     LIMIT $2`;
}

function deliverySql(scope) {
  const where = scope === "token" ? "t.id" : "COALESCE(d.workspace_id, t.workspace_id)";
  return `/* alert-lifecycle:delivery */
    SELECT d.id AS delivery_id, d.alert_queue_id AS alert_id,
           d.status AS delivery_status, d.channel, d.sent_at, d.error_message,
           aq.alert_key, aq.threshold_days, aq.status AS queue_status,
           t.id AS token_id, t.name AS token_name,
           COALESCE(d.workspace_id, t.workspace_id) AS workspace_id
      FROM alert_delivery_log d
      JOIN tokens t ON t.id = d.token_id
      LEFT JOIN alert_queue aq ON aq.id = d.alert_queue_id
     WHERE ${where} = $1
     ORDER BY d.sent_at DESC, d.id DESC
     LIMIT $2`;
}

function auditSql(scope) {
  const where =
    scope === "token"
      ? "COALESCE(direct_token.id, alert_token.id) = $1"
      : "COALESCE(ae.workspace_id, direct_token.workspace_id, alert_token.workspace_id) = $1";
  return `/* alert-lifecycle:audit */
    SELECT ae.id AS audit_id, ae.occurred_at, ae.action, ae.channel,
           ae.metadata AS audit_metadata, targeted_alert.id AS alert_id,
           targeted_alert.alert_key, targeted_alert.threshold_days,
           COALESCE(direct_token.id, alert_token.id) AS token_id,
           COALESCE(direct_token.name, alert_token.name) AS token_name,
           COALESCE(ae.workspace_id, direct_token.workspace_id, alert_token.workspace_id) AS workspace_id
      FROM audit_events ae
      LEFT JOIN alert_queue targeted_alert
        ON ae.target_type = 'alert' AND targeted_alert.id = ae.target_id
      LEFT JOIN tokens direct_token
        ON ae.target_type = 'token' AND direct_token.id = ae.target_id
      LEFT JOIN tokens alert_token ON alert_token.id = targeted_alert.token_id
     WHERE ae.action = ANY($2::text[])
       AND ${where}
     ORDER BY ae.occurred_at DESC, ae.id DESC
     LIMIT $3`;
}

async function fetchAlertLifecycle(
  { tokenId = null, workspaceId = null, limit, offset } = {},
  query = pool.query.bind(pool),
) {
  const scope = tokenId !== null ? "token" : "workspace";
  const scopeId = tokenId !== null ? tokenId : workspaceId;
  if (scopeId === null || scopeId === undefined || scopeId === "") {
    throw new TypeError("tokenId or workspaceId is required");
  }
  const pageLimit = clampLimit(limit);
  const pageOffset = clampOffset(offset);
  const candidateLimit = pageOffset + pageLimit + 1;
  const [queueResult, queueStateResult, deliveryResult, auditResult] = await Promise.all([
    query(queueSql(scope), [scopeId, candidateLimit]),
    query(queueSql(scope, true), [scopeId, candidateLimit]),
    query(deliverySql(scope), [scopeId, candidateLimit]),
    query(auditSql(scope), [scopeId, SUPPORTED_AUDIT_ACTIONS, candidateLimit]),
  ]);
  const events = buildAlertLifecycleEvents({
    queueRows: queueResult.rows,
    queueStateRows: queueStateResult.rows,
    deliveryRows: deliveryResult.rows,
    auditRows: auditResult.rows,
  });
  const items = events.slice(pageOffset, pageOffset + pageLimit);
  return {
    items,
    pagination: {
      limit: pageLimit,
      offset: pageOffset,
      hasMore: events.length > pageOffset + pageLimit,
    },
  };
}

module.exports = {
  PAGE_SIZE_DEFAULT,
  PAGE_SIZE_MAX,
  SUPPORTED_AUDIT_ACTIONS,
  buildAlertLifecycleEvents,
  fetchAlertLifecycle,
  safeErrorMessage,
};
