"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { normalizeContact } = require("../../apps/api/services/operator/contactValidation");

test("normalizes a contact's reviewed email and phone", () => {
  assert.deepEqual(normalizeContact({ firstName: " Ada ", lastName: " Example ", email: "ADA@EXAMPLE.TEST", phoneE164: "41791234567" }),
    { firstName: "Ada", lastName: "Example", email: "ada@example.test", phoneE164: "+41791234567" });
});

test("refuses missing channels, invalid contact details and extra authority", () => {
  for (const input of [
    { firstName: "Ada", lastName: "Example" },
    { firstName: "Ada", lastName: "Example", email: "bad" },
    { firstName: "Ada", lastName: "Example", phoneE164: "123" },
    { firstName: "Ada", lastName: "Example", email: "ada@example.test", workspaceId: "other" },
  ]) assert.throws(() => normalizeContact(input), { code: "OPERATOR_VALIDATION_ERROR" });
});
