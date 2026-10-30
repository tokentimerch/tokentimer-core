import crypto from "node:crypto";
import { resolveWebhookProviderKind } from "./webhookProviderKind.js";

// Routing keys have high entropy. Store only this tenant-scoped digest; no
// credential or credential-bearing URL enters the incident ledger/history.
export function pagerDutyDestinationId(workspaceId, webhook) {
  if (resolveWebhookProviderKind(webhook) !== "pagerduty") return null;
  return crypto
    .createHash("sha256")
    .update(
      JSON.stringify([
        "pagerduty-destination-v1",
        String(workspaceId),
        String(webhook?.url || "").trim(),
        String(webhook?.routingKey || "").trim(),
      ]),
    )
    .digest("hex");
}

export function pagerDutyDedupKey({
  workspaceId,
  tokenId,
  destinationId,
  episodeId,
}) {
  return (
    "tt:expiry:v1:" +
    crypto
      .createHash("sha256")
      .update(
        JSON.stringify([
          String(workspaceId),
          String(tokenId),
          destinationId,
          episodeId,
        ]),
      )
      .digest("hex")
  );
}

export function webhookDestinationId(workspaceId, webhook) {
  return (
    pagerDutyDestinationId(workspaceId, webhook) ||
    crypto
      .createHash("sha256")
      .update(String(webhook?.url || "").trim())
      .digest("hex")
  );
}

export function uniqueWebhookDestinations(webhooks, workspaceId) {
  const seen = new Set();
  return (Array.isArray(webhooks) ? webhooks : []).filter((webhook) => {
    if (!String(webhook?.url || "").trim()) return false;
    const id = webhookDestinationId(workspaceId, webhook);
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}
