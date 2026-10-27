import crypto from "node:crypto";
import { resolveWebhookProviderKind } from "./webhookProviderKind.js";
import { webhookDestinationId } from "./webhookDestinations.js";

export function webhookUrlHash(webhook) {
  return crypto
    .createHash("sha256")
    .update(String(webhook?.url || "").trim())
    .digest("hex");
}

// Old URL-only acceptance is evidence of a completed legacy notification,
// never evidence for a newly correlated episode or a recoverable routing key.
export function webhookDeliveryEvidence(
  workspaceId,
  webhook,
  configuredWebhooks,
  history,
) {
  const successes = (Array.isArray(history) ? history : []).filter(
    (row) =>
      row.channel === "webhooks" &&
      row.status === "success" &&
      (row.workspace_id == null ||
        String(row.workspace_id) === String(workspaceId)) &&
      (row.metadata?.event_action || "trigger") === "trigger",
  );
  const identity = webhookDestinationId(workspaceId, webhook);
  if (resolveWebhookProviderKind(webhook) !== "pagerduty") {
    return successes.some((row) => row.metadata?.urlHash === identity)
      ? "delivered"
      : "pending";
  }
  if (successes.some((row) => row.metadata?.destination_id === identity))
    return "delivered";
  const urlHash = webhookUrlHash(webhook);
  if (
    !successes.some(
      (row) =>
        row.metadata?.kind === "pagerduty" &&
        !row.metadata?.destination_id &&
        row.metadata?.urlHash === urlHash,
    )
  )
    return "pending";
  const identities = new Set(
    (Array.isArray(configuredWebhooks) ? configuredWebhooks : [])
      .filter(
        (candidate) =>
          resolveWebhookProviderKind(candidate) === "pagerduty" &&
          webhookUrlHash(candidate) === urlHash,
      )
      .map((candidate) => webhookDestinationId(workspaceId, candidate)),
  );
  return identities.size === 1 ? "legacy_delivered" : "legacy_ambiguous";
}

export function recipientDeliveryComplete(channel, recipients, history) {
  const normalize = (value) =>
    channel === "email"
      ? String(value || "")
          .trim()
          .toLowerCase()
      : String(value || "").trim();
  const targets = new Set(recipients.map(normalize).filter(Boolean));
  if (!targets.size) return false;
  const delivered = new Set(
    history
      .filter((row) => row.channel === channel && row.status === "success")
      .map((row) => normalize(row.metadata?.recipient))
      .filter(Boolean),
  );
  return [...targets].every((target) => delivered.has(target));
}
