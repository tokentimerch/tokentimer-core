"use strict";

const { isValidEmail } = require("../../utils/emailAddress");
const { assertSafe, invalid } = require("./tokenInventory");

// Assistant input is deliberately narrower than the workspace contact JSON:
// only the contact details the user can review are accepted.
function normalizeContact(input) {
  const fields = new Set(["firstName", "lastName", "email", "phoneE164"]);
  if (!input || typeof input !== "object" || Array.isArray(input) ||
      Object.keys(input).some((key) => !fields.has(key))) throw invalid();
  const name = (value) => {
    if (typeof value !== "string" || !value.trim() || value.trim().length > 100 || /[<>\u0000-\u001f\u007f]/.test(value)) throw invalid();
    return value.trim();
  };
  const firstName = name(input.firstName), lastName = name(input.lastName);
  if (input.email != null && typeof input.email !== "string") throw invalid();
  if (input.phoneE164 != null && typeof input.phoneE164 !== "string") throw invalid();
  const email = input.email?.trim().toLowerCase() || null;
  const rawPhone = input.phoneE164?.trim() || null;
  if (email && (email.length > 254 || !isValidEmail(email))) throw invalid();
  if (rawPhone && !/^\+?[1-9]\d{6,14}$/.test(rawPhone)) throw invalid();
  if (!email && !rawPhone) throw invalid();
  const phoneE164 = rawPhone && (rawPhone.startsWith("+") ? rawPhone : "+" + rawPhone);
  const result = { firstName, lastName, email, phoneE164 };
  assertSafe(result);
  return result;
}

module.exports = { normalizeContact };
