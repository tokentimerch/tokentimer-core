export function detectWebhookProviderKind(host) {
  const h = String(host || "").toLowerCase();
  if (h === "hooks.slack.com") return "slack";
  if (
    h === "discord.com" ||
    h.endsWith(".discord.com") ||
    h === "discordapp.com" ||
    h.endsWith(".discordapp.com")
  ) {
    return "discord";
  }
  if (
    h === "outlook.office.com" ||
    h === "webhook.office.com" ||
    h === "office365.com" ||
    h.endsWith(".office365.com") ||
    h.endsWith(".office.com")
  ) {
    return "teams";
  }
  if (h === "pagerduty.com" || h.endsWith(".pagerduty.com")) {
    return "pagerduty";
  }
  return null;
}
