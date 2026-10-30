import { buildOperationalIncidentEmail } from "../notify/email.js";
import { formatPayload } from "../notify/webhooks.js";

const UUID =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
export const isDistributionAlert = (alert) =>
  String(alert?.alert_key || "").startsWith("cert_distribution:");
export async function loadDistributionAlertContext(client, alert) {
  const id = alert.metadata?.incidentId;
  if (!UUID.test(id || "")) return false;
  const row = (
    await client.query(
      `SELECT i.*,p.policy FROM certops_distribution_incidents i
    JOIN certops_distribution_policies p ON p.workspace_id=i.workspace_id AND p.group_id=i.group_id
    JOIN certops_distribution_groups g ON g.workspace_id=i.workspace_id AND g.id=i.group_id
    JOIN certops_management_periods m ON m.workspace_id=g.workspace_id AND m.id=g.management_period_id
    WHERE i.workspace_id=$1 AND i.id=$2 AND g.state='active' AND m.ended_at IS NULL`,
      [alert.workspace_id, id],
    )
  ).rows[0];
  const transition = alert.metadata?.transition;
  if (
    !row ||
    !row.policy.alerts.enabled ||
    !["opened", "updated", "resolved"].includes(transition) ||
    (transition === "resolved") !== Boolean(row.resolved_at)
  )
    return false;
  alert.assigned_ids = row.policy.alerts.contactGroupIds;
  alert.distributionContext = {
    incidentId: row.id,
    groupId: row.group_id,
    code: row.code,
    transition,
    severity: row.severity,
    evidence: row.evidence,
  };
  return true;
}
export function distributionContent(alert) {
  const c = alert.distributionContext || alert.metadata || {};
  const code = /^[a-z_]{1,64}$/.test(c.code || "")
    ? c.code
    : "distribution_incident";
  const transition = ["opened", "updated", "resolved"].includes(c.transition)
    ? c.transition
    : "opened";
  const subject = `Certificate distribution ${transition}: ${code.replaceAll("_", " ")}`;
  const base = (process.env.APP_URL || "http://localhost:5173").replace(
    /\/$/,
    "",
  );
  const href = UUID.test(c.groupId || "")
    ? `${base}/certops/distribution?workspace=${encodeURIComponent(alert.workspace_id)}&group=${c.groupId}`
    : `${base}/certops/distribution`;
  return {
    subject,
    href,
    message: `${subject}. Publication, installed files and live verification are separate. Review signed job evidence and obtain fresh verification. ${href}`,
  };
}
export function buildDistributionEmailContent(alert) {
  const c = distributionContent(alert);
  return buildOperationalIncidentEmail({
    category: "certops",
    title: c.subject,
    message: c.message,
    metadata: {},
  });
}
export function buildDistributionWebhookPayload(
  kind,
  alert,
  { routingKey, title } = {},
) {
  const c = alert.distributionContext || alert.metadata || {},
    content = distributionContent(alert);
  const facts = {
    type: "certops_distribution",
    incident_id: c.incidentId,
    group_id: c.groupId,
    condition: c.code,
    transition: c.transition,
    evidence: c.evidence,
    evidence_url: content.href,
  };
  if (kind === "pagerduty")
    return {
      routing_key: routingKey,
      event_action: c.transition === "resolved" ? "resolve" : "trigger",
      dedup_key: `distribution:${c.incidentId}`,
      ...(c.transition !== "resolved"
        ? {
            payload: {
              summary: title || content.subject,
              source: "TokenTimer",
              severity: c.severity || "warning",
              custom_details: facts,
            },
          }
        : {}),
    };
  return formatPayload(kind, content.message, facts, {
    severity: c.transition === "resolved" ? "info" : c.severity || "warning",
    title: title || content.subject,
  });
}
export function distributionWhatsAppVariables(alert, recipientName) {
  const c = distributionContent(alert);
  return {
    recipient_name: recipientName || "User",
    incident: c.subject,
    evidence_url: c.href,
  };
}
