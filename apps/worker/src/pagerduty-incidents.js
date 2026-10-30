import crypto from "node:crypto";
import alertEligibility from "@tokentimer/alert-eligibility";
import { postJson } from "./notify/webhooks.js";
import { logger } from "./logger.js";
import { cDelivery, hLatency } from "./metrics.js";
import {
  resolveContactGroupsForAsset,
  effectiveThresholds,
  getWebhookNames,
  unionGroupsForThresholdWindow,
  unionContactIds,
  deliveryChannelsFromEligibleGroups,
} from "./shared/contactGroups.js";
import {
  uniqueWebhookDestinations,
  webhookDestinationId,
} from "./shared/webhookDestinations.js";
import { webhookDeliveryEvidence } from "./shared/deliveryEvidence.js";
import emailAddress from "../../../packages/email-address/index.js";
import { deliveryWindowAdmission } from "./shared/deliveryWindow.js";
import { notificationDeliveryState } from "./shared/notificationDeliveryState.js";
import {
  pagerDutyDestinationId,
  pagerDutyDedupKey,
} from "./shared/webhookDestinations.js";

const {
  computeDaysLeft,
  isRetiredCertLifecycleStatus,
  resolvedTokenWorkspaceSql,
} = alertEligibility;
const RECHECK_MS = 5 * 60 * 1000;
const LEASE_MS = 60 * 1000; // HTTP safety layer bounds requests to five seconds.
const DEFAULT_THRESHOLDS = (process.env.ALERT_THRESHOLDS || "30,14,7,1,0")
  .split(",")
  .map((value) => parseInt(value.trim(), 10))
  .filter(Number.isFinite);
export const MAX_PAGERDUTY_ATTEMPTS = 8;

export function pagerDutyRetryDelay(attempt) {
  return Math.min(60 * 1000 * 2 ** Math.max(0, attempt - 1), 60 * 60 * 1000);
}

// Provider response bodies, URLs, exception messages and routing keys must never
// enter operational errors. Only fixed codes and a bounded HTTP status do.
export function classifyPagerDutyResult(result) {
  if (result?.success === true)
    return { success: true, error: null, retryable: false };
  const status = Number(result?.status);
  if (Number.isInteger(status) && status >= 100 && status <= 599) {
    return {
      success: false,
      error: `pagerduty_http_${status}`,
      retryable:
        status === 408 || status === 425 || status === 429 || status >= 500,
    };
  }
  return {
    success: false,
    error: "pagerduty_transport_failure",
    retryable: true,
  };
}

function authorityFor(context) {
  if (context.managed_backed) return "certificate";
  if (context.monitored_backed) return "monitor";
  if (
    context.auto_sync_managed ||
    (context.source_provider &&
      ["ssl_cert", "tls_cert", "code_signing", "client_cert"].includes(
        context.type,
      ))
  )
    return "provider";
  return "manual";
}

export function hasPagerDutyExpiryEvidence(incident, context) {
  if (
    !context?.token_id ||
    !Number.isFinite(computeDaysLeft(context.expiration))
  )
    return false;
  // Retiring/deleting/stopping monitoring is not proof of renewal.
  if (isRetiredCertLifecycleStatus(context.cert_lifecycle_status)) return false;
  if (context.managed_backed || incident.expiry_authority === "certificate") {
    return context.managed_expiry_verified === true;
  }
  if (context.monitored_backed || incident.expiry_authority === "monitor") {
    return context.monitored_expiry_verified === true;
  }
  if (
    incident.expiry_authority === "provider" ||
    authorityFor(context) === "provider"
  ) {
    return Boolean(
      context.source_provider &&
      context.source_observed_at &&
      context.expiration !== "2099-12-31",
    );
  }
  return true;
}

export function isPagerDutyRecovery(
  incident,
  context,
  currentThreshold = null,
  now = new Date(),
) {
  if (!hasPagerDutyExpiryEvidence(incident, context)) return false;
  if (
    incident.expiry_authority === "provider" &&
    incident.original_source_observed_at &&
    !(
      new Date(context.source_observed_at) >
      new Date(incident.original_source_observed_at)
    )
  )
    return false;
  const original = alertEligibility.formatCalendarDay(
    incident.original_expiration,
  );
  const days = computeDaysLeft(context.expiration, now);
  const threshold = Math.max(
    incident.risk_threshold_days,
    currentThreshold ?? -Infinity,
  );
  return context.expiration > original && days > threshold;
}

async function loadContext(client, workspaceId, tokenId) {
  const result = await client.query(
    `SELECT t.id AS token_id, t.expiration::text, t.name, t.type, t.renewal_url,
            t.cert_lifecycle_status, t.source_provider, t.source_observed_at::text, t.auto_sync_managed,
            ws.webhook_urls, ws.contact_groups, ws.default_contact_group_id, ws.alert_thresholds,
            ws.email_alerts_enabled,
            ws.delivery_window_start, ws.delivery_window_end, ws.delivery_window_tz,
            COALESCE(groups.ids, ARRAY[]::text[]) AS assigned_ids,
            EXISTS (SELECT 1 FROM managed_certificates mc
              WHERE mc.workspace_id = w.id AND mc.token_id = t.id) AS managed_backed,
            EXISTS (SELECT 1 FROM managed_certificates mc
              WHERE mc.workspace_id = w.id AND mc.token_id = t.id
                AND (mc.not_after AT TIME ZONE 'UTC')::date = t.expiration
                AND mc.status NOT IN ('revoked','decommissioned')) AS managed_expiry_verified,
            EXISTS (SELECT 1 FROM domain_monitors dm
              WHERE dm.workspace_id = w.id AND dm.token_id = t.id) AS monitored_backed,
            EXISTS (SELECT 1 FROM domain_monitors dm
              WHERE dm.workspace_id = w.id AND dm.token_id = t.id
                AND (dm.ssl_valid_to AT TIME ZONE 'UTC')::date = t.expiration
                AND dm.ssl_fingerprint IS NOT NULL) AS monitored_expiry_verified
       FROM workspaces w
       LEFT JOIN workspace_settings ws ON ws.workspace_id = w.id
       LEFT JOIN tokens t ON t.id = $2 AND ${resolvedTokenWorkspaceSql("t")} = w.id
       LEFT JOIN LATERAL (SELECT array_agg(contact_group_id ORDER BY contact_group_id) AS ids
         FROM token_contact_groups WHERE workspace_id = w.id AND token_id = t.id) groups ON TRUE
      WHERE w.id = $1`,
    [workspaceId, tokenId],
  );
  return result.rows[0] || null;
}

// Compare the decision's committed facts/settings again in the same statement
// that records resolve intent or authorizes a trigger. A concurrent renewal,
// new risk, group reassignment or wider window must invalidate a stale read.
// Placeholder offsets are internal integer constants; all data is parameterized.
function snapshotCondition(start) {
  const p = (offset) => `$${start + offset}`;
  return `EXISTS (
    SELECT 1 FROM tokens live
    LEFT JOIN LATERAL (SELECT configuration.* FROM workspace_settings configuration
      WHERE configuration.workspace_id = ${p(0)} FOR SHARE SKIP LOCKED) settings ON TRUE
    WHERE ${resolvedTokenWorkspaceSql("live")} = ${p(0)} AND live.id = ${p(1)} AND live.expiration = ${p(2)}::date
      AND settings.contact_groups IS NOT DISTINCT FROM ${p(3)}::jsonb
      AND settings.alert_thresholds IS NOT DISTINCT FROM ${p(4)}::jsonb
      AND settings.webhook_urls IS NOT DISTINCT FROM ${p(5)}::jsonb
      AND COALESCE((SELECT array_agg(contact_group_id ORDER BY contact_group_id)
        FROM token_contact_groups WHERE workspace_id = ${p(0)} AND token_id = live.id),
        ARRAY[]::text[]) = ${p(6)}::text[]
      AND live.source_observed_at IS NOT DISTINCT FROM ${p(7)}::timestamptz
      AND live.cert_lifecycle_status IS NOT DISTINCT FROM ${p(8)}::text
      AND settings.default_contact_group_id IS NOT DISTINCT FROM ${p(9)}::text
      AND settings.email_alerts_enabled IS NOT DISTINCT FROM ${p(10)}::boolean
      AND settings.delivery_window_start IS NOT DISTINCT FROM ${p(11)}::text
      AND settings.delivery_window_end IS NOT DISTINCT FROM ${p(12)}::text
      AND settings.delivery_window_tz IS NOT DISTINCT FROM ${p(13)}::text
    FOR SHARE OF live SKIP LOCKED
  )`;
}

function snapshotValues(incident, context) {
  return [
    incident.workspace_id,
    incident.token_id_snapshot,
    context.expiration,
    context.contact_groups == null
      ? null
      : JSON.stringify(context.contact_groups),
    context.alert_thresholds == null
      ? null
      : JSON.stringify(context.alert_thresholds),
    context.webhook_urls == null ? null : JSON.stringify(context.webhook_urls),
    context.assigned_ids,
    context.source_observed_at,
    context.cert_lifecycle_status,
    context.default_contact_group_id,
    context.email_alerts_enabled,
    context.delivery_window_start,
    context.delivery_window_end,
    context.delivery_window_tz,
  ];
}

function resolvedGroups(context) {
  return resolveContactGroupsForAsset({
    contactGroups: context.contact_groups,
    assignedIds: context.assigned_ids,
    defaultContactGroupId: context.default_contact_group_id,
  });
}

function destinationConfig(context, workspaceId, destinationId) {
  return (
    (Array.isArray(context?.webhook_urls) ? context.webhook_urls : []).find(
      (webhook) =>
        pagerDutyDestinationId(workspaceId, webhook) === destinationId,
    ) || null
  );
}

function destinationThreshold(context, workspaceId, destinationId) {
  const configs = (
    Array.isArray(context?.webhook_urls) ? context.webhook_urls : []
  ).filter(
    (webhook) => pagerDutyDestinationId(workspaceId, webhook) === destinationId,
  );
  const names = new Set(
    configs.map((webhook) => String(webhook.name || "").trim()),
  );
  const thresholds = resolvedGroups(context)
    .filter((group) => getWebhookNames(group).some((name) => names.has(name)))
    .flatMap((group) =>
      effectiveThresholds(
        group,
        context.alert_thresholds || DEFAULT_THRESHOLDS,
      ),
    )
    .filter(Number.isFinite);
  return thresholds.length ? Math.ceil(Math.max(...thresholds)) : null;
}

function deferred(error) {
  return { success: false, deferred: true, error };
}

async function hasAmbiguousLegacyDelivery(
  client,
  workspaceId,
  alertId,
  webhook,
) {
  if (!alertId) return false;
  const history = await client.query(
    `SELECT channel, status, workspace_id, metadata FROM alert_delivery_log
     WHERE alert_queue_id=$1 AND channel='webhooks' AND status='success'
       AND (workspace_id=$2 OR workspace_id IS NULL)`,
    [alertId, workspaceId],
  );
  return (
    webhookDeliveryEvidence(workspaceId, webhook, null, history.rows) ===
    "legacy_ambiguous"
  );
}

// Record intent before any send, following ADR-0009. The partial unique index
// joins repeated thresholds into the same episode. UUID episode identity also
// isolates independently installed tenants, even if their asset ids coincide.
export async function enqueuePagerDutyIncident(client, { alert, webhook }) {
  const destinationId = pagerDutyDestinationId(alert.workspace_id, webhook);
  if (
    !destinationId ||
    !String(alert.alert_key || "").startsWith("token_expiry:") ||
    String(alert.alert_key).includes(":previous_expiration:")
  )
    return null;
  const context = await loadContext(client, alert.workspace_id, alert.token_id);
  if (!context?.token_id)
    throw new PagerDutyEnqueueError("pagerduty_asset_workspace_unavailable");
  const threshold = destinationThreshold(
    context,
    alert.workspace_id,
    destinationId,
  );
  if (threshold === null || computeDaysLeft(context.expiration) > threshold)
    return null;
  if (
    await hasAmbiguousLegacyDelivery(
      client,
      alert.workspace_id,
      alert.id,
      webhook,
    )
  )
    throw new PagerDutyEnqueueError("pagerduty_legacy_destination_ambiguous");
  const episodeId = crypto.randomUUID();
  const dedupKey = pagerDutyDedupKey({
    workspaceId: alert.workspace_id,
    tokenId: alert.token_id,
    destinationId,
    episodeId,
  });
  const result = await client.query(
    `INSERT INTO pagerduty_incidents
       (id, workspace_id, token_id, token_id_snapshot, destination_id, dedup_key,
        original_expiration, expiry_authority, risk_threshold_days, trigger_alert_queue_id, original_source_observed_at)
     SELECT $1,$2,CASE WHEN t.workspace_id = $2 THEN t.id END,$3,$4,$5,t.expiration,$6,$7,aq.id,t.source_observed_at
       FROM tokens t JOIN alert_queue aq ON aq.token_id = t.id AND aq.id = $8
      WHERE ${resolvedTokenWorkspaceSql("t")} = $2 AND t.id = $3 AND t.expiration = $9::date
        AND aq.alert_key LIKE 'token_expiry:%' AND aq.alert_key NOT LIKE '%:previous_expiration:%'
        AND aq.expiration_snapshot = t.expiration
        AND aq.status IN ('pending','failed','partial')
     ON CONFLICT (workspace_id, token_id_snapshot, destination_id)
       WHERE state IN ('trigger_pending','open')
     DO UPDATE SET risk_threshold_days = GREATEST(pagerduty_incidents.risk_threshold_days,
                                                  EXCLUDED.risk_threshold_days)
     RETURNING *`,
    [
      episodeId,
      alert.workspace_id,
      alert.token_id,
      destinationId,
      dedupKey,
      authorityFor(context),
      threshold,
      alert.id,
      context.expiration,
    ],
  );
  if (result.rows[0]) return result.rows[0];
  const current = (
    await client.query(
      "SELECT status, alert_key FROM alert_queue WHERE id=$1 AND token_id=$2",
      [alert.id, alert.token_id],
    )
  ).rows[0];
  if (
    current?.status === "sent" ||
    current?.alert_key?.includes(":previous_expiration:")
  )
    return null;
  throw new PagerDutyEnqueueError("pagerduty_enqueue_snapshot_changed");
}

class PagerDutyEnqueueError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

// Repair aggregate queue state from accepted delivery evidence, without another
// send or synthetic success log. A live normal-worker claim, archived cycle,
// changed routing snapshot or unrelated failure must remain authoritative.
export async function reconcilePagerDutyParentAlert(
  client,
  incident,
  { deliveryState = notificationDeliveryState } = {},
) {
  await client.query("BEGIN");
  try {
    const parent = (
      await client.query(
        `SELECT aq.* FROM alert_queue aq JOIN pagerduty_incidents p
         ON p.trigger_alert_queue_id = aq.id AND p.token_id_snapshot = aq.token_id
       WHERE p.id = $1 AND p.workspace_id = $2 AND p.trigger_accepted_at IS NOT NULL
         AND aq.status IN ('pending','failed','partial','blocked')
         AND aq.delivery_claim_id IS NULL
         AND aq.alert_key LIKE 'token_expiry:%' AND aq.alert_key NOT LIKE '%:previous_expiration:%'
         AND COALESCE(aq.error_message, '') !~* 'PLAN_LIMIT|limit_exceeded'
       FOR UPDATE OF aq SKIP LOCKED`,
        [incident.id, incident.workspace_id],
      )
    ).rows[0];
    if (!parent) {
      await client.query("COMMIT");
      return false;
    }
    const context = await loadContext(
      client,
      incident.workspace_id,
      incident.token_id_snapshot,
    );
    if (
      !context?.token_id ||
      alertEligibility.formatCalendarDay(parent.expiration_snapshot) !==
        context.expiration
    ) {
      await client.query("COMMIT");
      return false;
    }
    const groups = unionGroupsForThresholdWindow(
      resolvedGroups(context),
      context.alert_thresholds || DEFAULT_THRESHOLDS,
      parent.threshold_days,
    );
    const liveChannels = deliveryChannelsFromEligibleGroups(groups, {
      emailAlertsEnabled: context.email_alerts_enabled,
      alertKey: parent.alert_key,
    });
    const parsed = deliveryState.parse(parent.channels);
    const storedChannels = deliveryState.channels(parent.channels);
    if (
      !Array.isArray(storedChannels) ||
      storedChannels.some(
        (channel) => !["email", "webhooks", "whatsapp"].includes(channel),
      )
    ) {
      await client.query("COMMIT");
      return false;
    }
    const channels = [...new Set([...storedChannels, ...liveChannels])];
    const history = (
      await client.query(
        `SELECT channel, status, workspace_id, metadata FROM alert_delivery_log
        WHERE alert_queue_id = $1 AND (workspace_id = $2 OR workspace_id IS NULL)`,
        [parent.id, incident.workspace_id],
      )
    ).rows;
    const names = new Set(groups.flatMap(getWebhookNames));
    const webhooks = uniqueWebhookDestinations(
      (context.webhook_urls || []).filter((webhook) =>
        names.has(String(webhook?.name || "").trim()),
      ),
      incident.workspace_id,
    );
    const webhookEvidence = webhooks.map(
      (webhook) =>
        webhookDeliveryEvidence(
          incident.workspace_id,
          webhook,
          context.webhook_urls,
          history,
        ) === "delivered",
    );
    const complete = {
      webhooks: webhookEvidence.length > 0 && webhookEvidence.every(Boolean),
    };
    const endpointOutcomes = Object.fromEntries(
      webhooks.map((webhook, index) => [
        webhookDestinationId(incident.workspace_id, webhook),
        webhookEvidence[index] ? "sent" : "failed",
      ]),
    );
    const eligibility = {};
    for (const channel of ["email", "whatsapp"].filter((channel) =>
      channels.includes(channel),
    )) {
      const ids = unionContactIds(
        groups,
        channel === "email" ? "email_contact_ids" : "whatsapp_contact_ids",
      );
      const contacts = ids.length
        ? (
            await client.query(
              "SELECT id, details, phone_e164 FROM workspace_contacts WHERE workspace_id=$1 AND id=ANY($2::uuid[]) FOR SHARE NOWAIT",
              [incident.workspace_id, ids],
            )
          ).rows
        : [];
      const recipients = contacts
        .map((contact) => ({
          contactId: contact.id,
          destination:
            channel === "email"
              ? String(contact.details?.email || "")
                  .trim()
                  .toLowerCase()
              : String(contact.phone_e164 || "").trim(),
        }))
        .filter((row) =>
          channel === "email"
            ? emailAddress.isValidEmail(row.destination)
            : Boolean(row.destination),
        );
      const gated = await deliveryState.recipients(
        client,
        incident.workspace_id,
        channel,
        recipients,
      );
      if (
        gated.unavailable ||
        gated.blocked.some(
          (row) =>
            !row.shadow && row.code === "RECIPIENT_VERIFICATION_UNAVAILABLE",
        )
      ) {
        await client.query("ROLLBACK");
        return false;
      }
      complete[channel] =
        parsed.outcomes[channel]?.state === "sent" ||
        deliveryState.recipientComplete(
          channel,
          gated.allowed.map((row) => row.destination),
          history,
        );
      if (
        !complete[channel] &&
        recipients.length &&
        !gated.allowed.length &&
        gated.enforced
      )
        eligibility[channel] = {
          channel,
          success: false,
          terminal: true,
          eligibilityTerminal: true,
          errorCode: gated.code || "NO_VERIFIED_RECIPIENTS",
        };
    }
    // Never add a new channel/recipient to a retry or claim it was delivered.
    if (
      !webhookEvidence.some(Boolean) ||
      channels.some(
        (channel) => !complete[channel] && !storedChannels.includes(channel),
      )
    ) {
      await client.query("COMMIT");
      return false;
    }
    const attempted = channels.flatMap((channel) => {
      if (complete[channel])
        return [
          {
            channel,
            success: true,
            ...(channel === "webhooks" ? { endpoints: endpointOutcomes } : {}),
          },
        ];
      if (eligibility[channel]) return [eligibility[channel]];
      if (channel === "webhooks")
        return [
          {
            channel,
            success: false,
            partialSuccess: true,
            terminal: parsed.outcomes[channel]?.terminal === true,
            endpoints: endpointOutcomes,
          },
        ];
      return parsed.outcomes[channel] ? [] : [{ channel, success: false }];
    });
    const settlement = deliveryState.settle({
      prior: parent.channels,
      attempted,
      liveChannels: channels,
    });
    // Background acceptance may settle an existing requirement, never reopen a
    // channel the foreground ledger removed from its durable retry set.
    settlement.ledger.retry = settlement.ledger.retry.filter((channel) =>
      parsed.retry.includes(channel),
    );
    const remaining = channels.filter((channel) => !complete[channel]);
    const status =
      remaining.length &&
      parent.status === "blocked" &&
      settlement.outcome.retry
        ? "blocked"
        : remaining.length
          ? settlement.outcome.status
          : "sent";
    const stored = parsed.legacy
      ? remaining.length
        ? remaining
        : storedChannels
      : settlement.ledger;
    const changed = await client.query(
      `UPDATE alert_queue SET status=$2::varchar(20), channels=$3::jsonb,
         attempts_webhooks=CASE WHEN $6 THEN 0 ELSE attempts_webhooks END,
         attempts_email=CASE WHEN $4 THEN 0 ELSE attempts_email END,
         attempts_whatsapp=CASE WHEN $5 THEN 0 ELSE attempts_whatsapp END,
         error_message=CASE WHEN $2 = 'sent' THEN NULL ELSE error_message END,
         next_attempt_at=CASE WHEN $2 IN ('sent','blocked') OR $23 THEN NULL ELSE next_attempt_at END,
         updated_at=NOW()
       WHERE id=$1 AND delivery_claim_id IS NULL AND status=$7 AND alert_key=$8
         AND ${snapshotCondition(9)} RETURNING id`,
      [
        parent.id,
        status,
        JSON.stringify(stored),
        complete.email === true,
        complete.whatsapp === true,
        complete.webhooks,
        parent.status,
        parent.alert_key,
        ...snapshotValues(incident, context),
        !parsed.legacy && settlement.ledger.retry.length === 0,
      ],
    );
    if (changed.rowCount && status === "sent") {
      await client.query(
        `UPDATE operational_notifications SET resolved_at=NOW(), updated_at=NOW()
        WHERE workspace_id=$1 AND dedupe_key=ANY($2::text[]) AND resolved_at IS NULL
          AND type IN ('delivery_blocked','delivery_degraded','delivery_no_contacts')`,
        [
          incident.workspace_id,
          [`delivery_blocked:${parent.id}`, `delivery_degraded:${parent.id}`],
        ],
      );
    }
    await client.query("COMMIT");
    return changed.rowCount > 0;
  } catch (error) {
    await client.query("ROLLBACK");
    if (error.code === "55P03") return false;
    throw error;
  }
}

async function repairParent(client, incident, deliveryState) {
  try {
    await reconcilePagerDutyParentAlert(client, incident, { deliveryState });
  } catch (error) {
    logger.warn("PagerDuty parent reconciliation deferred", {
      incidentId: incident.id,
      reason: /^[0-9A-Z]{5}$/.test(String(error.code || ""))
        ? error.code
        : "parent_reconciliation_failed",
    });
  }
}

async function postpone(
  client,
  incident,
  claimId,
  error,
  { cancel = false, exhausted = false } = {},
) {
  const updated = await client.query(
    `UPDATE pagerduty_incidents SET state = CASE WHEN $4 THEN 'cancelled' ELSE state END,
       last_error = $3, retry_exhausted = retry_exhausted OR $5,
       next_attempt_at = NOW() + ($6 * INTERVAL '1 millisecond'),
       claim_id = NULL, claimed_until = NULL, updated_at = NOW()
     WHERE id = $1 AND claim_id = $2`,
    [incident.id, claimId, error, cancel, exhausted, RECHECK_MS],
  );
  if (!updated.rowCount) return deferred("pagerduty_ownership_lost");
  if (!cancel && error && error !== incident.last_error) {
    logger.warn("PagerDuty incident remains unresolved", {
      incidentId: incident.id,
      reason: error,
    });
  }
  return cancel || !error
    ? { success: true, skipped: cancel }
    : deferred(error);
}

function triggerPayload(incident, context, webhook) {
  const days = computeDaysLeft(context.expiration);
  const name = context.name || `Token #${incident.token_id_snapshot}`;
  const severity = ["critical", "error", "warning", "info"].includes(
    webhook.severity,
  )
    ? webhook.severity
    : days < 30
      ? "critical"
      : "warning";
  return {
    routing_key: String(webhook.routingKey).trim(),
    event_action: "trigger",
    dedup_key: incident.dedup_key,
    payload: {
      summary:
        webhook.template ||
        `${name} ${days <= 0 ? `expired ${Math.abs(days)} day(s) ago` : `expires in ${days} day(s)`} (on ${context.expiration}).`,
      source: "TokenTimer",
      severity,
      timestamp: new Date().toISOString(),
      custom_details: {
        token_id: incident.token_id_snapshot,
        name: context.name,
        type: context.type,
        expiration: context.expiration,
        daysLeft: days,
        ...(context.renewal_url && { renewal_url: context.renewal_url }),
      },
    },
  };
}

// The advisory lock is SESSION scoped, with no transaction across HTTP. It
// prevents a paused live worker from dispatching after a lease takeover; the
// claim id independently fences every write and recovers a dead connection.
export async function processPagerDutyIncident(
  client,
  incidentId,
  { send = postJson, now = new Date(), deliveryState } = {},
) {
  const lock = await client.query(
    "SELECT pg_try_advisory_lock(hashtextextended('pagerduty:' || $1::text, 0)) AS owned",
    [incidentId],
  );
  if (!lock.rows[0]?.owned) return deferred("pagerduty_incident_busy");
  const claimId = crypto.randomUUID();
  try {
    const claim = await client.query(
      `UPDATE pagerduty_incidents SET claim_id = $2,
         claimed_until = NOW() + ($3 * INTERVAL '1 millisecond')
       WHERE id = $1 AND state IN ('trigger_pending','open','resolve_pending')
         AND next_attempt_at <= NOW() AND (claimed_until IS NULL OR claimed_until <= NOW())
       RETURNING *`,
      [incidentId, claimId, LEASE_MS],
    );
    let incident = claim.rows[0];
    if (!incident) {
      const existing = (
        await client.query(
          "SELECT state, trigger_accepted_at FROM pagerduty_incidents WHERE id=$1",
          [incidentId],
        )
      ).rows[0];
      return existing?.state === "open"
        ? { success: true }
        : deferred("pagerduty_delivery_pending");
    }
    // Reload committed facts/settings after acquiring ownership, not the queue
    // batch's possibly stale asset or contact-group snapshot.
    const context = await loadContext(
      client,
      incident.workspace_id,
      incident.token_id_snapshot,
    );
    if (!context?.token_id)
      return await postpone(client, incident, claimId, "asset_unavailable");
    if (incident.trigger_accepted_at)
      await repairParent(client, incident, deliveryState);
    const threshold = destinationThreshold(
      context,
      incident.workspace_id,
      incident.destination_id,
    );
    if (incident.state !== "resolve_pending") {
      if (!hasPagerDutyExpiryEvidence(incident, context)) {
        return await postpone(
          client,
          incident,
          claimId,
          "expiry_evidence_unavailable",
        );
      }
      if (isPagerDutyRecovery(incident, context, threshold)) {
        if (!incident.trigger_accepted_at) {
          // A timeout or send/commit crash can mean acceptance is unknown.
          // Do not fabricate acceptance, send a stale trigger, or claim a
          // resolve. Retain the uncertainty for operator reconciliation.
          return await postpone(
            client,
            incident,
            claimId,
            incident.trigger_delivery_uncertain
              ? "trigger_acceptance_unknown"
              : "recovered_before_trigger",
            {
              cancel: !incident.trigger_delivery_uncertain,
              exhausted: incident.trigger_delivery_uncertain,
            },
          );
        }
        const transition = await client.query(
          `UPDATE pagerduty_incidents SET state = 'resolve_pending', recovery_expiration = $3,
             resolve_requested_at = NOW(), retry_exhausted = FALSE, action_attempts = 0,
             last_error = NULL, updated_at = NOW()
           WHERE id = $1 AND claim_id = $2 AND ${snapshotCondition(4)} RETURNING *`,
          [
            incident.id,
            claimId,
            context.expiration,
            ...snapshotValues(incident, context),
          ],
        );
        if (!transition.rowCount)
          return await postpone(
            client,
            incident,
            claimId,
            "reconciliation_snapshot_changed",
          );
        incident = transition.rows[0];
      } else if (incident.state === "open") {
        return await postpone(
          client,
          incident,
          claimId,
          destinationConfig(
            context,
            incident.workspace_id,
            incident.destination_id,
          )
            ? null
            : "original_destination_unavailable",
        );
      } else if (
        threshold === null ||
        computeDaysLeft(context.expiration) > threshold
      ) {
        return await postpone(
          client,
          incident,
          claimId,
          "destination_no_longer_eligible",
          { cancel: !incident.trigger_delivery_uncertain },
        );
      }
    }
    const webhook = destinationConfig(
      context,
      incident.workspace_id,
      incident.destination_id,
    );
    if (!webhook)
      return await postpone(
        client,
        incident,
        claimId,
        "original_destination_unavailable",
      );
    // An older pending intent is not evidence that its routing key received a
    // URL-only historical delivery. Park it without sending or spending budget.
    if (
      !incident.trigger_accepted_at &&
      (await hasAmbiguousLegacyDelivery(
        client,
        incident.workspace_id,
        incident.trigger_alert_queue_id,
        webhook,
      ))
    )
      return await postpone(
        client,
        incident,
        claimId,
        "pagerduty_legacy_destination_ambiguous",
        { exhausted: true },
      );
    if (!/^[a-zA-Z0-9]{32}$/.test(String(webhook.routingKey || "").trim())) {
      return await postpone(
        client,
        incident,
        claimId,
        "invalid_pagerduty_configuration",
      );
    }
    if (incident.retry_exhausted)
      return await postpone(client, incident, claimId, incident.last_error, {
        exhausted: true,
      });
    if (incident.action_attempts >= MAX_PAGERDUTY_ATTEMPTS)
      return await postpone(
        client,
        incident,
        claimId,
        "retry_budget_exhausted",
        { exhausted: true },
      );
    const resolving = incident.state === "resolve_pending";
    // Quiet hours gate every unaccepted trigger attempt. A validated resolve
    // for an already accepted incident bypasses quiet hours to clear stale risk.
    if (!resolving && !deliveryWindowAdmission(context, now).allowed)
      return await postpone(
        client,
        incident,
        claimId,
        "pagerduty_out_of_window",
      );
    // Resolve intents are immutable once decided: a later risk episode uses a
    // different key, so this delayed resolution cannot close its replacement.
    const payload = resolving
      ? {
          routing_key: String(webhook.routingKey).trim(),
          event_action: "resolve",
          dedup_key: incident.dedup_key,
        }
      : triggerPayload(incident, context, webhook);
    const attemptColumn = resolving ? "resolve_attempts" : "trigger_attempts";
    const attempt = await client.query(
      `UPDATE pagerduty_incidents SET ${attemptColumn} = ${attemptColumn} + 1,
         action_attempts = action_attempts + 1,
         trigger_delivery_uncertain = CASE WHEN $3 THEN trigger_delivery_uncertain ELSE TRUE END,
         last_attempt_at = NOW(), updated_at = NOW()
       WHERE id = $1 AND claim_id = $2 AND claimed_until > NOW()
         AND ($3 OR ${snapshotCondition(4)}) RETURNING action_attempts AS attempts`,
      [incident.id, claimId, resolving, ...snapshotValues(incident, context)],
    );
    if (!attempt.rowCount)
      return await postpone(
        client,
        incident,
        claimId,
        "dispatch_snapshot_changed",
      );
    let rawResult;
    let endTimer;
    try {
      endTimer = hLatency.labels("webhooks", "pagerduty").startTimer();
    } catch {
      /* Metrics cannot gate delivery. */
    }
    try {
      rawResult = await send(String(webhook.url).trim(), payload, "pagerduty");
    } catch {
      rawResult = { success: false };
    } finally {
      try {
        endTimer?.();
      } catch {
        /* Preserve provider acceptance. */
      }
    }
    const outcome = classifyPagerDutyResult(rawResult);
    try {
      cDelivery
        .labels("webhooks", "pagerduty", outcome.success ? "success" : "failed")
        .inc();
    } catch {
      /* Metrics cannot gate acceptance persistence. */
    }
    // A definite 4xx rejection rules out acceptance for this attempt, but
    // cannot erase uncertainty from an earlier timeout/5xx/crash.
    const triggerUncertain =
      !resolving &&
      !outcome.success &&
      (incident.trigger_delivery_uncertain ||
        !(Number(rawResult?.status) >= 400 && Number(rawResult?.status) < 500));
    const exhausted =
      !outcome.success &&
      (!outcome.retryable ||
        attempt.rows[0].attempts >= MAX_PAGERDUTY_ATTEMPTS);
    const nextDelay =
      outcome.success || exhausted
        ? RECHECK_MS
        : pagerDutyRetryDelay(attempt.rows[0].attempts);
    // Acceptance and its historical evidence commit together. External sends
    // are at-least-once across a send/commit crash, with the same Events key.
    await client.query("BEGIN");
    try {
      const updated = await client.query(
        `UPDATE pagerduty_incidents SET
           state = CASE WHEN $3 THEN $4 ELSE state END,
           trigger_accepted_at = CASE WHEN $3 AND NOT $5 THEN COALESCE(trigger_accepted_at, NOW()) ELSE trigger_accepted_at END,
           resolved_at = CASE WHEN $3 AND $5 THEN NOW() ELSE resolved_at END,
           trigger_delivery_uncertain = CASE WHEN $5 THEN trigger_delivery_uncertain ELSE $9 END,
           original_source_observed_at = CASE WHEN $3 AND NOT $5
             THEN COALESCE(original_source_observed_at, $10::timestamptz) ELSE original_source_observed_at END,
           retry_exhausted = $6, last_error = $7,
           next_attempt_at = NOW() + ($8 * INTERVAL '1 millisecond'),
           claim_id = NULL, claimed_until = NULL, updated_at = NOW()
         WHERE id = $1 AND claim_id = $2 RETURNING id`,
        [
          incident.id,
          claimId,
          outcome.success,
          resolving ? "resolved" : "open",
          resolving,
          exhausted,
          outcome.error,
          nextDelay,
          triggerUncertain,
          context.source_observed_at,
        ],
      );
      if (updated.rowCount) {
        await client.query(
          `INSERT INTO alert_delivery_log
             (alert_queue_id, user_id, token_id, workspace_id, channel, status, error_message, metadata)
           SELECT p.trigger_alert_queue_id, w.created_by, delivered_asset.id, p.workspace_id,
                  'webhooks', $2, $3, $4::jsonb
             FROM pagerduty_incidents p JOIN workspaces w ON w.id = p.workspace_id
             LEFT JOIN tokens delivered_asset ON delivered_asset.id = p.token_id_snapshot
               AND ${resolvedTokenWorkspaceSql("delivered_asset")} = p.workspace_id
            WHERE p.id = $1`,
          [
            incident.id,
            outcome.success ? "success" : "failed",
            outcome.error,
            JSON.stringify({
              kind: "pagerduty",
              payload_type: "token_expiry",
              event_action: resolving ? "resolve" : "trigger",
              incident_id: incident.id,
              destination_id: incident.destination_id,
              dedup_key: incident.dedup_key,
            }),
          ],
        );
      }
      await client.query("COMMIT");
      if (!updated.rowCount) return deferred("pagerduty_ownership_lost");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }
    if (!outcome.success)
      logger.warn("PagerDuty incident delivery failed", {
        incidentId,
        error: outcome.error,
        exhausted,
      });
    if (outcome.success) await repairParent(client, incident, deliveryState);
    return { success: outcome.success, error: outcome.error };
  } finally {
    await client.query(
      "SELECT pg_advisory_unlock(hashtextextended('pagerduty:' || $1::text, 0))",
      [incidentId],
    );
  }
}

export async function deliverPagerDutyExpiration(
  client,
  { alert, webhook, send = postJson, deliveryState },
) {
  let incident;
  try {
    incident = await enqueuePagerDutyIncident(client, { alert, webhook });
  } catch (error) {
    if (error instanceof PagerDutyEnqueueError) return deferred(error.code);
    throw error;
  }
  if (!incident) return { success: true, skipped: true };
  return processPagerDutyIncident(client, incident.id, { send, deliveryState });
}

export async function reconcilePagerDutyIncidents(
  client,
  { send = postJson, batchSize = 100, deliveryState, now } = {},
) {
  const limit = Math.max(
    1,
    Math.min(500, Math.floor(Number(batchSize) || 100)),
  );
  const due = await client.query(
    `SELECT id FROM pagerduty_incidents
      WHERE state IN ('trigger_pending','open','resolve_pending') AND next_attempt_at <= NOW()
        AND (claimed_until IS NULL OR claimed_until <= NOW())
      ORDER BY next_attempt_at, id LIMIT $1`,
    [limit],
  );
  for (const { id } of due.rows)
    await processPagerDutyIncident(client, id, { send, deliveryState, now });
  return due.rowCount;
}
