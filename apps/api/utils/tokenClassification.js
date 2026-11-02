"use strict";

/**
 * Single source of truth for token type/category rules, shared by create,
 * edit and the integration imports. Mirrors the dashboard category table and
 * the tokens.type / tokens.category CHECK constraints.
 */
const TOKEN_TYPES_BY_CATEGORY = Object.freeze({
  cert: Object.freeze(["ssl_cert", "tls_cert", "code_signing", "client_cert"]),
  key_secret: Object.freeze([
    "api_key",
    "secret",
    "password",
    "encryption_key",
    "ssh_key",
  ]),
  license: Object.freeze([
    "software_license",
    "service_subscription",
    "domain_registration",
  ]),
  general: Object.freeze(["other", "document", "membership"]),
});

const TOKEN_CATEGORIES = Object.freeze(Object.keys(TOKEN_TYPES_BY_CATEGORY));
const TOKEN_TYPES = Object.freeze(
  Object.values(TOKEN_TYPES_BY_CATEGORY).flat(),
);

const INVALID_TYPE_MESSAGE = "Invalid token type";
const INVALID_CATEGORY_MESSAGE = "Invalid category";
const TYPE_CATEGORY_MISMATCH_MESSAGE =
  "Invalid token type for selected category";

function isKnownType(type) {
  return TOKEN_TYPES.includes(type);
}

function isKnownCategory(category) {
  return TOKEN_CATEGORIES.includes(category);
}

function isTypeAllowedForCategory(type, category) {
  return (TOKEN_TYPES_BY_CATEGORY[category] || []).includes(type);
}

/**
 * Validate a type/category pair for an edit. Only a pair that actually
 * changes is held to the compatibility table, so rows saved before create
 * enforced it can still be edited. Returns an error message or null.
 */
function validateTypeCategoryUpdate({ type, category }, existing) {
  if (type !== undefined && type !== null && !isKnownType(type)) {
    return INVALID_TYPE_MESSAGE;
  }
  if (
    category !== undefined &&
    category !== null &&
    !isKnownCategory(category)
  ) {
    return INVALID_CATEGORY_MESSAGE;
  }
  const nextType = type || existing.type;
  const nextCategory = category || existing.category;
  const unchanged =
    nextType === existing.type && nextCategory === existing.category;
  if (unchanged) return null;
  return isTypeAllowedForCategory(nextType, nextCategory)
    ? null
    : TYPE_CATEGORY_MISMATCH_MESSAGE;
}

module.exports = {
  TOKEN_TYPES_BY_CATEGORY,
  TOKEN_CATEGORIES,
  TOKEN_TYPES,
  INVALID_TYPE_MESSAGE,
  INVALID_CATEGORY_MESSAGE,
  TYPE_CATEGORY_MISMATCH_MESSAGE,
  isKnownType,
  isKnownCategory,
  isTypeAllowedForCategory,
  validateTypeCategoryUpdate,
};
