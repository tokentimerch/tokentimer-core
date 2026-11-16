import { createRequire } from "node:module";
import { randomUUID } from "node:crypto";
import recipientVerification from "../../../../packages/recipient-verification/index.js";
import { deliveryWindowAdmission } from "./deliveryWindow.js";
import {
  buildOperationalIncidentEmail,
  sendEmailNotification,
} from "../notify/email.js";
import { logger } from "../logger.js";

const require = createRequire(import.meta.url);
export const ADCS_PREFLIGHT_INCIDENT_TYPE = "adcs_preflight_blocked";
export const INCIDENT_EMAIL_CAP_SQL = `SELECT COUNT(*)::int AS c FROM operational_notifications
  WHERE workspace_id=$1 AND (email_sent_at>NOW()-INTERVAL '24 hours'
    OR (category='certops' AND type='adcs_preflight_blocked'
      AND COALESCE(metadata->'emailDelivery'->>'lastAcceptedAt','') >
        to_char((NOW()-INTERVAL '24 hours') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')))`;
const UUID =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;

export function adcsEmailPolicyAllows(settings, now = new Date()) {
  return Boolean(
    settings &&
    settings.email_alerts_enabled !== false &&
    !settings.certops_paused &&
    deliveryWindowAdmission(settings, now).allowed,
  );
}

export async function loadAdcsIncidentRecipients(client, workspaceId) {
  if (
    !(await require("../../../api/services/certops/settings.js").isCertOpsEnabled(
      { dbPool: client },
    ))
  )
    return [];
  const settings = (
    await client.query(
      `SELECT w.certops_paused,COALESCE(s.email_alerts_enabled,TRUE) AS email_alerts_enabled,
    s.delivery_window_start,s.delivery_window_end,s.delivery_window_tz FROM workspaces w
    LEFT JOIN workspace_settings s ON s.workspace_id=w.id WHERE w.id=$1`,
      [workspaceId],
    )
  ).rows[0];
  if (!adcsEmailPolicyAllows(settings)) return [];
  // Same operational owners as existing incidents, but this new route requires
  // a verified current destination. The implicit owner need not have a member row.
  const users = await client.query(
    `SELECT DISTINCT u.id,u.email_original AS email
    FROM workspaces w JOIN users u ON (u.id=w.created_by OR EXISTS (
      SELECT 1 FROM workspace_memberships m WHERE m.workspace_id=w.id AND m.user_id=u.id AND m.role='admin'))
    WHERE w.id=$1 AND u.email_verified=TRUE AND u.email IS NOT NULL
      AND lower(btrim(u.email))=lower(btrim(u.email_original))
      AND (u.auth_method='local' OR lower(btrim(u.recipient_verified_email))=lower(btrim(u.email_original)))`,
    [workspaceId],
  );
  const result = new Map();
  for (const user of users.rows) {
    const email = recipientVerification.normalizeEmail(user.email);
    const key =
      email.ok &&
      recipientVerification.destinationFingerprint("email", email.value);
    if (!key) continue; // Missing verification configuration fails closed.
    const suppression = await client.query(
      `SELECT 1 FROM notification_suppressions
      WHERE channel='email' AND destination_fingerprint=$2 AND (expires_at IS NULL OR expires_at>NOW())
        AND (scope='global' OR (scope='workspace' AND workspace_id=$1))
      UNION ALL SELECT 1 FROM contact_channel_verifications WHERE workspace_id=$1 AND channel='email'
        AND destination_normalized=$3 AND status IN ('opted_out','revoked') LIMIT 1`,
      [workspaceId, key, email.value],
    );
    if (suppression.rows.length) continue;
    const decision = await recipientVerification.canDeliverToDestination({
      client,
      workspaceId,
      channel: "email",
      destination: email.value,
    });
    if (decision.allowed) result.set(key, { key, email: email.value });
  }
  return [...result.values()];
}

// Called by the existing delivery worker on its dedicated autocommit client.
// Reconciliation commits before this function claims delivery; SMTP never runs
// inside an API scheduling transaction or an incident reconciliation transaction.
export async function sendAdcsPreflightIncidentEmail(
  client,
  { notificationId, workspaceId },
  sendEmail = sendEmailNotification,
  {
    dailyCap = 10,
    reconcile,
    loadRecipients = loadAdcsIncidentRecipients,
  } = {},
) {
  if (!UUID.test(String(notificationId)) || !UUID.test(String(workspaceId)))
    return;
  const scope = (
    await client.query(
      `SELECT metadata->>'issuerId' AS issuer_id FROM operational_notifications
    WHERE id=$1 AND workspace_id=$2 AND category='certops' AND type='adcs_preflight_blocked'
      AND severity='critical' AND resolved_at IS NULL AND email_sent_at IS NULL`,
      [notificationId, workspaceId],
    )
  ).rows[0];
  if (!UUID.test(scope?.issuer_id || "")) return;
  await (
    reconcile ||
    require("../../../api/services/certops/adcsPreflightIncidents.js")
      .reconcileIssuerPreflightIncident
  )({ db: client, workspaceId, issuerId: scope.issuer_id });
  const claimId = randomUUID();
  let locked = false,
    claimed = false,
    complete = false;
  try {
    await client.query(
      "SELECT pg_advisory_lock(hashtextextended($1::text, 140))",
      [workspaceId],
    );
    locked = true;
    const incident = (
      await client.query(
        `UPDATE operational_notifications SET email_claim_id=$3,email_claimed_at=NOW()
      WHERE id=$1 AND workspace_id=$2 AND category='certops' AND type='adcs_preflight_blocked'
        AND severity='critical' AND resolved_at IS NULL AND email_sent_at IS NULL
        AND (email_claim_id IS NULL OR email_claimed_at<NOW()-INTERVAL '10 minutes')
      RETURNING title,message,metadata`,
        [notificationId, workspaceId, claimId],
      )
    ).rows[0];
    if (!incident) return;
    claimed = true;
    const progress = incident.metadata?.emailDelivery || {};
    const accepted = Object.fromEntries(
      Object.entries(progress.accepted || {})
        .filter(([key, value]) => /^[a-f0-9]{64}$/.test(key) && value === true)
        .slice(0, 64),
    );
    const recentlyCounted =
      Date.parse(progress.lastAcceptedAt) > Date.now() - 86400000;
    const cap =
      (await client.query(INCIDENT_EMAIL_CAP_SQL, [workspaceId])).rows[0]?.c ||
      0;
    if (cap >= dailyCap && !recentlyCounted) return;
    const recipients = await loadRecipients(client, workspaceId);
    if (!recipients.length) return;
    const content = buildOperationalIncidentEmail({
      category: "certops",
      title: incident.title,
      message: incident.message,
      metadata: incident.metadata,
    });
    const stillAllowed = async (recipient) => {
      const current = await client.query(
        `SELECT id FROM operational_notifications WHERE id=$1 AND workspace_id=$2
        AND category='certops' AND type='adcs_preflight_blocked' AND resolved_at IS NULL AND severity='critical' AND email_claim_id=$3`,
        [notificationId, workspaceId, claimId],
      );
      return (
        current.rows.length > 0 &&
        (await loadRecipients(client, workspaceId)).some(
          (r) => r.key === recipient.key && r.email === recipient.email,
        )
      );
    };
    for (const recipient of recipients) {
      if (accepted[recipient.key] || !(await stillAllowed(recipient))) continue;
      const outcome = await sendEmail({
        to: recipient.email,
        ...content,
        onBeforeAttempt: async () => {
          if (!(await stillAllowed(recipient)))
            throw new Error("ADCS_INCIDENT_DELIVERY_NO_LONGER_ALLOWED");
        },
      });
      if (!outcome?.success) continue;
      accepted[recipient.key] = true;
      const receipt = { accepted, lastAcceptedAt: new Date().toISOString() };
      const saved = await client.query(
        `UPDATE operational_notifications SET metadata=jsonb_set(metadata,'{emailDelivery}',$4::jsonb,TRUE)
        WHERE id=$1 AND workspace_id=$2 AND email_claim_id=$3`,
        [notificationId, workspaceId, claimId, JSON.stringify(receipt)],
      );
      if (saved.rowCount !== 1)
        throw new Error("ADCS_INCIDENT_DELIVERY_RECEIPT_NOT_SAVED");
    }
    const remaining = await loadRecipients(client, workspaceId);
    complete = remaining.length > 0 && remaining.every((r) => accepted[r.key]);
  } catch (error) {
    logger.warn("AD CS operational email delivery remains pending", {
      notificationId,
      code: error.code || "ADCS_INCIDENT_DELIVERY_FAILED",
    });
  } finally {
    try {
      if (claimed)
        await client.query(
          `UPDATE operational_notifications SET email_sent_at=CASE WHEN $4 THEN NOW() ELSE email_sent_at END,
        email_claim_id=NULL,email_claimed_at=CASE WHEN $4 THEN NULL ELSE NOW() END WHERE id=$1 AND workspace_id=$2 AND email_claim_id=$3`,
          [notificationId, workspaceId, claimId, complete],
        );
    } finally {
      if (locked)
        await client.query(
          "SELECT pg_advisory_unlock(hashtextextended($1::text, 140))",
          [workspaceId],
        );
    }
  }
}
