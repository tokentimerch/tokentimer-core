"use strict";

const { webhookHostAllowed, shouldEnforcePrivateIpCheck, isPrivateOrReservedIP } = require("../../utils/webhookSafety");
const { assertSafe, invalid } = require("./tokenInventory");

// The destination can contain a provider secret in its path. It is stored
// like an ordinary webhook URL but is never echoed in the preview or result.
function normalizeWebhook(input) {
  if (!input || typeof input !== "object" || Array.isArray(input) ||
      Object.keys(input).some((key) => !["name", "url", "kind", "routingKey"].includes(key))) throw invalid();
  if (typeof input.name !== "string" || !input.name.trim() || input.name.trim().length > 100 || /[<>\u0000-\u001f\u007f]/.test(input.name)) throw invalid();
  if (typeof input.url !== "string" || input.url.length > 2048) throw invalid();
  const name = input.name.trim(), url = input.url.trim(), kind = input.kind ?? "generic";
  if (!["generic", "slack", "teams", "discord", "pagerduty"].includes(kind)) throw invalid();
  if (input.routingKey != null && typeof input.routingKey !== "string") throw invalid();
  const routingKey = input.routingKey?.trim() || "";
  if (kind === "pagerduty" ? !routingKey || routingKey.length > 256 || /[\u0000-\u001f\u007f]/.test(routingKey) : Boolean(routingKey)) throw invalid();
  assertSafe(name);
  let parsed;
  try { parsed = new URL(url); } catch { throw invalid(); }
  if (parsed.protocol !== "https:" || parsed.hash || parsed.username || parsed.password) throw invalid();
  if (kind !== "generic" && !webhookHostAllowed(parsed.hostname)) throw failWebhook();
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  if (shouldEnforcePrivateIpCheck() && (host.toLowerCase() === "localhost" || isPrivateOrReservedIP(host))) throw failWebhook();
  return { name, url, kind, routingKey };
}
function failWebhook() {
  return Object.assign(new Error("Webhook destination is not allowed"), { code: "OPERATOR_VALIDATION_ERROR" });
}

module.exports = { normalizeWebhook };
