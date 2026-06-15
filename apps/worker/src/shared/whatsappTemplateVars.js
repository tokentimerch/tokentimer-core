// Twilio/WhatsApp approved templates reject newlines, long runs of spaces, and
// unknown or overlong variable keys (max 16 chars). See DocsAlerts placeholder contracts.
export const WHATSAPP_TEMPLATE_VALUE_MAX_LEN = 250;

// tokens_list can enumerate many tokens; sanitize chars only, do not truncate.
export const WHATSAPP_WEEKLY_DIGEST_TOKENS_LIST_MAX_LEN = 0;

/** Strip chars and length that make ContentVariables invalid for WhatsApp templates. */
export function sanitizeForWhatsApp(
  value,
  maxLen = WHATSAPP_TEMPLATE_VALUE_MAX_LEN,
) {
  if (value === null || value === undefined) return "";
  let s = String(value)
    .replace(/[\r\n\t]+/g, " ")
    .replace(/ {5,}/g, "    ");
  s = s.trim();
  if (maxLen > 0 && s.length > maxLen) {
    s = `${s.slice(0, maxLen - 3)}...`;
  }
  return s;
}

/** Build the JSON blob passed as Twilio ContentVariables; omit empty values. */
export function sanitizeWhatsAppTemplateVars(obj, { maxLens = {} } = {}) {
  const out = {};
  for (const [k, v] of Object.entries(obj || {})) {
    const maxLen = Object.hasOwn(maxLens, k)
      ? maxLens[k]
      : WHATSAPP_TEMPLATE_VALUE_MAX_LEN;
    const s = sanitizeForWhatsApp(v, maxLen);
    if (!s) continue;
    out[k] = s;
  }
  return out;
}

/**
 * WEEKLY_DIGEST template placeholders (see DocsAlerts).
 * tokens_list stays on one line; no length cap so all tokens can appear.
 */
export function buildWeeklyDigestWhatsAppTemplateVariables({
  recipientName,
  workspaceName,
  contactGroupName,
  tokensCount,
  tokensListText,
}) {
  return {
    recipient_name: recipientName || "User",
    workspace_name: workspaceName,
    contact_group_name: contactGroupName,
    tokens_count: String(tokensCount),
    tokens_list: tokensListText,
  };
}
