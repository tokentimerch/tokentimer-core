"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { normalizeInvite } = require("../../apps/api/services/operator/memberInviteValidation");
test("normalizes an email-only invitation", () => {
  assert.deepEqual(normalizeInvite({ email: " Person@Example.Test " }), { email: "person@example.test" });
});
test("refuses role, user ID, malformed addresses and extra fields", () => {
  for (const value of [{ email: "x" }, { email: "person@example.test", role: "admin" }, { email: "person@example.test", userId: 1 }, {}]) {
    assert.throws(() => normalizeInvite(value), { code: "OPERATOR_VALIDATION_ERROR" });
  }
});
