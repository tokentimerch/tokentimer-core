"use strict";
const { isValidEmail } = require("../../utils/emailAddress");
const { invalid, assertSafe } = require("./tokenInventory");

// The assistant can invite a viewer by email, not supply a role or user ID.
function normalizeInvite(input) {
  if (!input || typeof input !== "object" || Array.isArray(input) ||
      Object.keys(input).length !== 1 || typeof input.email !== "string") throw invalid();
  const email = input.email.trim().toLowerCase();
  if (!email || email.length > 254 || !isValidEmail(email)) throw invalid();
  assertSafe(email);
  return { email };
}
module.exports = { normalizeInvite };
