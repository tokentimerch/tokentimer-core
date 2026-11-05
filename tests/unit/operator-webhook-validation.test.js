"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { normalizeWebhook } = require("../../apps/api/services/operator/webhookValidation");

test("normalizes an HTTPS webhook without exposing or interpreting its opaque path", () => {
  assert.deepEqual(normalizeWebhook({ name: " Alerts ", url: "https://example.test/opaque", kind: "generic" }),
    { name: "Alerts", url: "https://example.test/opaque", kind: "generic", routingKey: "" });
});

test("rejects unsafe webhook schemes, credentials, fragments and unsupported fields", () => {
  for (const value of [
    { name: "A", url: "http://example.test" },
    { name: "A", url: "https://name:password@example.test" },
    { name: "A", url: "https://example.test/#fragment" },
    { name: "A", url: "https://example.test", kind: "pagerduty" },
    { name: "A", url: "https://example.test", workspaceId: "other" },
  ]) assert.throws(() => normalizeWebhook(value), { code: "OPERATOR_VALIDATION_ERROR" });
});
