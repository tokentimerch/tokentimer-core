"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { normalizeContactGroup } = require("../../apps/api/services/operator/contactGroupValidation");
const id = "b6b7a2c6-c57d-4c31-b699-9dd90e1e8e29";
test("normalizes recipient and digest choices", () => {
  const group = normalizeContactGroup({ name: " Ops ", emailContactIds: [id, id], webhookNames: [" Alerts "], weeklyDigest: { email: true } });
  assert.deepEqual(group, { name: "Ops", emailContactIds: [id], whatsappContactIds: [], webhookNames: ["Alerts"], weeklyDigest: { email: true, whatsapp: false, webhooks: false } });
});
test("rejects empty, malformed or over-wide group input", () => {
  for (const input of [
    { name: "Ops" }, { name: "Ops", emailContactIds: ["bad"] },
    { name: "Ops", webhookNames: ["x"], weeklyDigest: { email: "true" } },
    { name: "Ops", webhookNames: ["x"], workspaceId: "other" },
  ]) assert.throws(() => normalizeContactGroup(input), { code: "OPERATOR_VALIDATION_ERROR" });
});
