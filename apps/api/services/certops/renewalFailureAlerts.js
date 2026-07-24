"use strict";

/**
 * cert_renewal_failed alert emission.
 *
 * When a renew job reaches a terminal 'failed' status, queue exactly one
 * cert_renewal_failed alert through the existing alert pipeline. CertOps
 * alerts ride the pipeline anchored on the linked token row
 * (alert_queue.token_id INTEGER NOT NULL): the anchor comes from the job's
 * subject managed_certificate row (managed_certificates.token_id). Jobs with
 * no managed_certificate subject or an unlinked certificate skip the insert
 * (never violate the NOT NULL) and return a reason instead.
 *
 * Idempotency mirrors the endpoint_health pattern in
 * apps/worker/src/endpoint-check-worker.js: one alert_key per job
 * (cert_renewal_failed:<jobId>), existence-checked before insert. A retry
 * wave that fails again creates a new job, so no date suffix is needed.
 *
 * Zero-custody: alert rows carry only ids and the frozen error code; the
 * delivery worker renders name/type from the joined token row. No payload
 * contents ever reach the queue.
 *
 * Callers MUST wrap this in try/catch: an alert failure must never fail
 * result ingestion or the lease reaper (see agentDispatch.ingestResult and
 * certops-worker.js call sites).
 */

const { pool } = require("../../db/database");

// Contact-group eligibility helpers. These mirror
// apps/worker/src/shared/contactGroups.js exactly; that module is ESM and
// cannot be required from this CommonJS service, so the (small, stable)
// resolution rules are duplicated here.
function resolveContactGroup({
  contactGroups,
  contactGroupId,
  defaultContactGroupId,
}) {
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
        groups.find((g) => String(g.id) === String(defaultContactGroupId)) ||
        null;
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
      (Array.isArray(contactGroup.webhook_names) &&
        contactGroup.webhook_names.length > 0),
  );
}

function getWebhookNames(contactGroup) {
  if (!contactGroup) return [];
  if (Array.isArray(contactGroup.webhook_names)) {
    return contactGroup.webhook_names
      .filter(Boolean)
      .map((n) => String(n).trim());
  }
  if (contactGroup.webhook_name) {
    return [String(contactGroup.webhook_name).trim()];
  }
  return [];
}

const CERT_RENEWAL_FAILED_ALERT_PREFIX = "cert_renewal_failed:";

function certRenewalFailedAlertKey(jobId) {
  return `${CERT_RENEWAL_FAILED_ALERT_PREFIX}${jobId}`;
}

/**
 * Queue a cert_renewal_failed alert for a terminally failed renew job.
 *
 * Accepts either a preloaded job row/object ({ id, workspaceId | workspace_id,
 * operation, subjectType | subject_type, subjectId | subject_id }) or a bare
 * jobId (+ workspaceId), in which case the job row is fetched.
 *
 * Returns { queued: boolean, reason?: string, alertKey?: string }.
 * Never throws for expected skip conditions; DB errors propagate so the
 * caller's try/catch can log them.
 */
async function queueCertRenewalFailedAlert({
  client = pool,
  job = null,
  jobId = null,
  workspaceId = null,
  errorCode = null,
} = {}) {
  let jobRow = job;
  const resolvedWorkspaceId =
    workspaceId || job?.workspaceId || job?.workspace_id || null;
  const resolvedJobId = jobId || job?.id || null;

  if (!resolvedJobId || !resolvedWorkspaceId) {
    return { queued: false, reason: "job_or_workspace_missing" };
  }

  if (!jobRow || jobRow.operation === undefined) {
    const jobRes = await client.query(
      `SELECT id, workspace_id, operation, subject_type, subject_id
         FROM certificate_jobs
        WHERE id = $1
          AND workspace_id = $2
        LIMIT 1`,
      [resolvedJobId, resolvedWorkspaceId],
    );
    jobRow = jobRes.rows[0] || null;
    if (!jobRow) return { queued: false, reason: "job_not_found" };
  }

  const operation = jobRow.operation;
  if (operation !== "renew") {
    return { queued: false, reason: "not_renew_operation" };
  }

  const subjectType = jobRow.subjectType ?? jobRow.subject_type ?? null;
  const subjectId = jobRow.subjectId ?? jobRow.subject_id ?? null;
  if (subjectType !== "managed_certificate" || !subjectId) {
    return { queued: false, reason: "no_managed_certificate_subject" };
  }

  // Anchor token: the linked token row of the subject managed certificate.
  const certRes = await client.query(
    `SELECT id, token_id
       FROM managed_certificates
      WHERE id = $1
        AND workspace_id = $2
      LIMIT 1`,
    [subjectId, resolvedWorkspaceId],
  );
  const cert = certRes.rows[0] || null;
  if (!cert) return { queued: false, reason: "managed_certificate_not_found" };
  if (!cert.token_id) return { queued: false, reason: "no_linked_token" };
  const tokenId = cert.token_id;

  const alertKey = certRenewalFailedAlertKey(resolvedJobId);

  // Idempotency: exactly one alert row per job (endpoint_health pattern).
  const existing = await client.query(
    "SELECT id FROM alert_queue WHERE alert_key = $1",
    [alertKey],
  );
  if (existing.rows.length > 0) {
    return { queued: false, reason: "already_queued", alertKey };
  }

  // Recipient: workspace admin, same resolution as endpoint-check-worker.
  const userRes = await client.query(
    `SELECT wm.user_id FROM workspace_memberships wm
     WHERE wm.workspace_id = $1 AND wm.role = 'admin'
     LIMIT 1`,
    [resolvedWorkspaceId],
  );
  if (userRes.rows.length === 0) {
    return { queued: false, reason: "no_recipient" };
  }
  const userId = userRes.rows[0].user_id;

  // Channels: same contact-group eligibility rules as endpoint alerts.
  const settingsRes = await client.query(
    "SELECT email_alerts_enabled, contact_groups, default_contact_group_id, webhook_urls FROM workspace_settings WHERE workspace_id = $1",
    [resolvedWorkspaceId],
  );
  const settings = settingsRes.rows[0] || {};
  let tokenContactGroupId = null;
  const tokenRes = await client.query(
    "SELECT contact_group_id FROM tokens WHERE id = $1 LIMIT 1",
    [tokenId],
  );
  tokenContactGroupId = tokenRes.rows[0]?.contact_group_id || null;

  const resolvedGroup = resolveContactGroup({
    contactGroups: settings.contact_groups,
    contactGroupId: tokenContactGroupId,
    defaultContactGroupId: settings.default_contact_group_id,
  });

  const channels = [];
  if (
    settings.email_alerts_enabled !== false &&
    hasEmailContacts(resolvedGroup)
  ) {
    channels.push("email");
  }

  if (resolvedGroup && hasWebhookNames(resolvedGroup)) {
    const selectedWebhookNames = getWebhookNames(resolvedGroup);
    const workspaceWebhooks = Array.isArray(settings.webhook_urls)
      ? settings.webhook_urls
      : [];
    const matchingWebhookCount = workspaceWebhooks.filter((webhook) =>
      selectedWebhookNames.includes(String(webhook?.name || "").trim()),
    ).length;
    if (matchingWebhookCount > 0) {
      channels.push("webhooks");
    }
  }

  // WhatsApp is intentionally NOT queued: the WhatsApp delivery path picks a
  // per-alert-type Twilio content template (see endpoint_health ContentSid
  // handling in delivery-worker.js) and none exists for cert_renewal_failed.
  // Email + webhooks only.

  if (channels.length === 0) {
    return { queued: false, reason: "no_channels" };
  }

  await client.query(
    `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date, channels, status)
     VALUES ($1, $2, $3, $4, CURRENT_DATE, $5::jsonb, 'pending')`,
    [
      userId,
      tokenId,
      alertKey,
      0, // threshold_days not applicable for renewal failure alerts, use 0
      JSON.stringify(channels),
    ],
  );

  return { queued: true, alertKey, tokenId, errorCode: errorCode || null };
}

module.exports = {
  CERT_RENEWAL_FAILED_ALERT_PREFIX,
  certRenewalFailedAlertKey,
  queueCertRenewalFailedAlert,
};
