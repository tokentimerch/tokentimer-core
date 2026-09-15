"use strict";

/**
 * agent_health alert resolution (down / recovered).
 *
 * One alert_key exists per agent transition. Recovery is only notified when
 * the paired down alert reached status='sent'; every intentional suppression
 * still closes the old incident so a future outage can alert again.
 *
 * Anchor: unlike endpoint_health/cert_renewal_failed, an agent has no linked
 * tokens row to hang the required alert_queue.token_id off of. Migration 46
 * widens alert_queue to accept certops_agent_id as an alternate anchor
 * (token_id stays NOT NULL in spirit -- the CHECK requires exactly one of the
 * two -- every pre-existing alert type keeps using token_id unchanged).
 * alert_queue.user_id remains genuinely NOT NULL (unchanged), so this uses
 * the workspace's own creator as a deterministic non-actor anchor rather
 * than attributing the event to an arbitrary admin; see the comment at the
 * lookup below and ADR-0011 (machine-initiated audit) for why no human is
 * named as having caused the outage.
 *
 * Zero-custody: metadata carries only agent identity, timestamps, and
 * impacted-certificate labels/ids -- never key material, never raw evidence.
 */

const { pool } = require("../../db/database");

// Duplicated (not imported) for the same reason renewalFailureAlerts.js
// duplicates them: apps/worker/src/shared/contactGroups.js is ESM and this
// CommonJS API service cannot require it. Keep in sync by hand; the rules
// are small and stable.
function resolveContactGroup({ contactGroups, contactGroupId, defaultContactGroupId }) {
  try {
    const groups = Array.isArray(contactGroups) ? contactGroups : [];
    const pickId =
      contactGroupId && String(contactGroupId).trim().length > 0
        ? String(contactGroupId)
        : defaultContactGroupId
          ? String(defaultContactGroupId)
          : null;
    if (!pickId) return null;
    let resolvedGroup = groups.find((g) => String(g.id) === pickId) || null;
    if (!resolvedGroup && contactGroupId && defaultContactGroupId) {
      resolvedGroup =
        groups.find((g) => String(g.id) === String(defaultContactGroupId)) || null;
    }
    return resolvedGroup;
  } catch (_err) {
    return null;
  }
}

function hasEmailContacts(contactGroup) {
  if (!contactGroup) return false;
  return (
    Array.isArray(contactGroup.email_contact_ids) &&
    contactGroup.email_contact_ids.length > 0
  );
}

function hasWebhookNames(contactGroup) {
  if (!contactGroup) return false;
  return Boolean(
    contactGroup.webhook_name ||
      (Array.isArray(contactGroup.webhook_names) && contactGroup.webhook_names.length > 0),
  );
}

function getWebhookNames(contactGroup) {
  if (!contactGroup) return [];
  if (Array.isArray(contactGroup.webhook_names)) {
    return contactGroup.webhook_names.filter(Boolean).map((n) => String(n).trim());
  }
  if (contactGroup.webhook_name) return [String(contactGroup.webhook_name).trim()];
  return [];
}

const AGENT_HEALTH_ALERT_PREFIX = "agent_health:";
// The API/UI can show the full impacted list; notification bodies stay bounded.
const MAX_IMPACTED_CERTIFICATES_IN_ALERT = 10;

function agentHealthAlertKey(agentRowId, transitionType) {
  return `${AGENT_HEALTH_ALERT_PREFIX}${agentRowId}:${transitionType}`;
}

/**
 * Queue an agent_health alert for a liveness transition.
 *
 * @param {object} options
 * @param {object} options.client - pg client/pool (defaults to the shared pool).
 * @param {object} options.agent - { id, workspaceId, agentId, name, hostname,
 *   platform, lastSeenAt, downtimeAlertsEnabled, contactGroupId }.
 * @param {'down'|'recovered'} options.transitionType
 * @param {Array<object>} [options.impactedCertificates] - [{ id, commonName,
 *   renewalPathState }], only meaningful for 'down' (recovery summarizes the
 *   same set as "recovered" without re-deriving a fresh dependency graph).
 * @param {number} [options.offlineAfterMs]
 * @returns {Promise<{queued:boolean, reason?:string, alertKey?:string, channels?:string[]}>}
 */
async function queueAgentHealthAlert({
  client = pool,
  agent,
  transitionType,
  impactedCertificates = [],
  offlineAfterMs = null,
} = {}) {
  if (!agent?.id || !agent?.workspaceId) {
    return { queued: false, reason: "agent_or_workspace_missing" };
  }
  if (transitionType !== "down" && transitionType !== "recovered") {
    return { queued: false, reason: "invalid_transition" };
  }
  const downKey = agentHealthAlertKey(agent.id, "down");
  const recoveredKey = agentHealthAlertKey(agent.id, "recovered");
  const alertKey = transitionType === "down" ? downKey : recoveredKey;

  if (agent.downtimeAlertsEnabled === false) {
    if (transitionType === "recovered") {
      await client.query(
        "DELETE FROM alert_queue WHERE alert_key = $1 AND certops_agent_id = $2",
        [downKey, agent.id],
      );
      await client.query(
        "DELETE FROM alert_queue WHERE alert_key = $1 AND certops_agent_id = $2",
        [recoveredKey, agent.id],
      );
      return { queued: false, reason: "alerts_disabled_incident_closed" };
    }
    return { queued: false, reason: "alerts_disabled" };
  }

  if (transitionType === "down") {
    // A recovered key is reusable across outages. Retire the prior outage's
    // terminal row in the same transaction that records this new DOWN edge,
    // otherwise its unique alert_key would suppress this outage's recovery.
    await client.query(
      "DELETE FROM alert_queue WHERE alert_key = $1 AND certops_agent_id = $2",
      [recoveredKey, agent.id],
    );
  }

  if (transitionType === "recovered") {
    const downState = await client.query(
      `SELECT id, status, delivery_claim_id
         FROM alert_queue
        WHERE alert_key = $1
          AND certops_agent_id = $2
        FOR UPDATE`,
      [downKey, agent.id],
    );
    if (downState.rows[0]?.delivery_claim_id) {
      return {
        queued: false,
        retry: true,
        reason: "down_delivery_in_progress",
      };
    }
    if (downState.rows[0]?.status !== "sent") {
      await client.query(
        "DELETE FROM alert_queue WHERE alert_key = $1 AND certops_agent_id = $2",
        [downKey, agent.id],
      );
      await client.query(
        "DELETE FROM alert_queue WHERE alert_key = $1 AND certops_agent_id = $2",
        [recoveredKey, agent.id],
      );
      return { queued: false, reason: "down_never_delivered" };
    }
  }

  // alert_queue.user_id is NOT NULL for every alert type (endpoint_health,
  // cert_renewal_failed, this one); it long predates certops_agent_id and
  // widening it is a bigger schema change than this feature needs, since
  // every consumer of alert_queue/alert_delivery_log across Core/Cloud/
  // Enterprise currently assumes a real integer.
  //
  // This is a required anchor, not the notification recipient: actual email
  // recipients are resolved from the contact group's email_contact_ids
  // below (delivery-worker.js's "group emails only; no fallback" rule), so
  // userId itself never determines who gets notified. Its only remaining
  // effects are alert_delivery_log.user_id bookkeeping and, on a partial
  // delivery failure, audit_events.subject_user_id.
  //
  // renewalFailureAlerts.js and endpoint-check-worker.js resolve this same
  // required anchor by picking any workspace admin (`role = 'admin' LIMIT 1`,
  // unordered) for their own machine-initiated alert types; that
  // pre-existing pattern is left as-is here since fixing it is a separate,
  // cross-cutting change. For this new alert type, an unordered LIMIT 1
  // would also make the anchor nondeterministic across the paired down/
  // recovered rows. The workspace's own creator is used instead: every
  // workspace has exactly one (workspaces.created_by is NOT NULL), so it is
  // deterministic, and it is the same value delivery-worker.js's own
  // owner_user_id COALESCE already prefers for every alert type when a
  // direct workspace link exists -- so this does not introduce a second,
  // competing notion of "the alert's owner." The agent identity that
  // actually caused the event lives in `metadata` (agentId/agentRowId
  // below), consistent with the null-actor-plus-metadata pattern ADR-0011
  // establishes for CertOps machine-initiated events.
  const userRes = await client.query(
    `SELECT created_by AS user_id FROM workspaces WHERE id = $1`,
    [agent.workspaceId],
  );
  if (userRes.rows.length === 0 || !userRes.rows[0].user_id) {
    if (transitionType === "recovered") {
      await client.query(
        "DELETE FROM alert_queue WHERE alert_key = $1 AND certops_agent_id = $2",
        [downKey, agent.id],
      );
      await client.query(
        "DELETE FROM alert_queue WHERE alert_key = $1 AND certops_agent_id = $2",
        [recoveredKey, agent.id],
      );
    }
    return { queued: false, reason: "no_recipient" };
  }
  const userId = userRes.rows[0].user_id;

  const settingsRes = await client.query(
    "SELECT email_alerts_enabled, contact_groups, default_contact_group_id, webhook_urls FROM workspace_settings WHERE workspace_id = $1",
    [agent.workspaceId],
  );
  const settings = settingsRes.rows[0] || {};
  const resolvedGroup = resolveContactGroup({
    contactGroups: settings.contact_groups,
    contactGroupId: agent.contactGroupId || null,
    defaultContactGroupId: settings.default_contact_group_id,
  });

  const channels = [];
  if (settings.email_alerts_enabled !== false && hasEmailContacts(resolvedGroup)) {
    channels.push("email");
  }
  if (resolvedGroup && hasWebhookNames(resolvedGroup)) {
    const selectedWebhookNames = getWebhookNames(resolvedGroup);
    const workspaceWebhooks = Array.isArray(settings.webhook_urls) ? settings.webhook_urls : [];
    const matchingWebhookCount = workspaceWebhooks.filter((webhook) =>
      selectedWebhookNames.includes(String(webhook?.name || "").trim()),
    ).length;
    if (matchingWebhookCount > 0) channels.push("webhooks");
  }
  // WhatsApp intentionally not queued, same reasoning as cert_renewal_failed:
  // the WhatsApp path selects a per-alert-type Twilio ContentSid template and
  // none exists for agent_health. Email + webhooks only.

  if (channels.length === 0) {
    if (transitionType === "recovered") {
      await client.query(
        "DELETE FROM alert_queue WHERE alert_key = $1 AND certops_agent_id = $2",
        [downKey, agent.id],
      );
      await client.query(
        "DELETE FROM alert_queue WHERE alert_key = $1 AND certops_agent_id = $2",
        [recoveredKey, agent.id],
      );
    }
    return { queued: false, reason: "no_channels" };
  }

  const cappedImpacted = Array.isArray(impactedCertificates)
    ? impactedCertificates.slice(0, MAX_IMPACTED_CERTIFICATES_IN_ALERT)
    : [];

  const metadata = {
    agentRowId: agent.id,
    agentId: agent.agentId || null,
    agentName: agent.name || null,
    hostname: agent.hostname || null,
    platform: agent.platform || null,
    lastSeenAt: agent.lastSeenAt || null,
    offlineAfterMs: offlineAfterMs || null,
    transitionType,
    impactedCertificates: cappedImpacted.map((cert) => ({
      id: cert.id,
      commonName: cert.commonName || null,
      renewalPathState: cert.renewalPathState || null,
    })),
    impactedCertificateTotalCount: Array.isArray(impactedCertificates)
      ? impactedCertificates.length
      : 0,
  };

  const inserted = await client.query(
    `INSERT INTO alert_queue (
       user_id, token_id, certops_agent_id, alert_key, threshold_days,
       due_date, channels, status, metadata
     )
     VALUES ($1, NULL, $2, $3, $4, CURRENT_DATE, $5::jsonb, 'pending', $6::jsonb)
     ON CONFLICT (alert_key) DO NOTHING`,
    [userId, agent.id, alertKey, 0, JSON.stringify(channels), JSON.stringify(metadata)],
  );

  if (transitionType === "recovered") {
    await client.query(
      "DELETE FROM alert_queue WHERE alert_key = $1 AND certops_agent_id = $2",
      [downKey, agent.id],
    );
  }

  const queued = inserted.rowCount !== 0;
  return {
    queued,
    ...(queued ? {} : { reason: "already_queued" }),
    alertKey,
    channels,
  };
}

module.exports = {
  AGENT_HEALTH_ALERT_PREFIX,
  MAX_IMPACTED_CERTIFICATES_IN_ALERT,
  agentHealthAlertKey,
  queueAgentHealthAlert,
};
