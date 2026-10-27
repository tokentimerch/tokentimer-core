import crypto from "node:crypto";
import { resolveWebhookProviderKind } from "./webhookProviderKind.js";
import { webhookDestinationId } from "./webhookDestinations.js";

export function webhookUrlHash(webhook) {
  return crypto
    .createHash("sha256")
    .update(String(webhook?.url || "").trim())
    .digest("hex");
}

// An endpoint hash cannot prove the historical routing key, even with only one
// current integration. Only exact destination evidence can establish delivery.
export function webhookDeliveryEvidence(
  workspaceId,
  webhook,
  _configuredWebhooks,
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
  return "legacy_ambiguous";
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
