"use strict";

const { assertSafe, invalid } = require("./tokenInventory");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function normalizeContactGroup(input) {
  const allowed = ["name", "emailContactIds", "whatsappContactIds", "webhookNames", "weeklyDigest"];
  if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).some((key) => !allowed.includes(key))) throw invalid();
  if (typeof input.name !== "string" || !input.name.trim() || input.name.trim().length > 100 || /[<>\u0000-\u001f\u007f]/.test(input.name)) throw invalid();
  const ids = (value) => {
    if (value === undefined) return [];
    if (!Array.isArray(value) || value.length > 50 || value.some((item) => typeof item !== "string" || !UUID.test(item))) throw invalid();
    return [...new Set(value.map((item) => item.toLowerCase()))].sort();
  };
  const emailContactIds = ids(input.emailContactIds), whatsappContactIds = ids(input.whatsappContactIds);
  const names = input.webhookNames === undefined ? [] : input.webhookNames;
  if (!Array.isArray(names) || names.length > 50 || names.some((item) => typeof item !== "string" || !item.trim() || item.trim().length > 100 || /[<>\u0000-\u001f\u007f]/.test(item))) throw invalid();
  const webhookNames = [...new Set(names.map((item) => item.trim()))].sort();
  if (!emailContactIds.length && !whatsappContactIds.length && !webhookNames.length) throw invalid();
  const requested = input.weeklyDigest ?? {};
  if (!requested || typeof requested !== "object" || Array.isArray(requested) || Object.keys(requested).some((key) => !["email", "whatsapp", "webhooks"].includes(key)) ||
      Object.values(requested).some((value) => typeof value !== "boolean")) throw invalid();
  const group = { name: input.name.trim(), emailContactIds, whatsappContactIds, webhookNames,
    weeklyDigest: { email: requested.email === true, whatsapp: requested.whatsapp === true, webhooks: requested.webhooks === true } };
  assertSafe({ name: group.name, webhookNames });
  return group;
}
module.exports = { normalizeContactGroup };
