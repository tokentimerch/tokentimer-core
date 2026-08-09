"use strict";

const CERTOPS_AGENT_ALERTS_ENABLED_INVALID =
  "CERTOPS_AGENT_ALERTS_ENABLED_INVALID";

function invalidBoolean() {
  const error = new Error("downtimeAlertsEnabled must be a boolean");
  error.code = CERTOPS_AGENT_ALERTS_ENABLED_INVALID;
  error.statusCode = 400;
  return error;
}

function normalizeDowntimeAlertsEnabled(value, { allowOmitted = true } = {}) {
  if (value === undefined || value === null) {
    if (allowOmitted) return null;
    throw invalidBoolean();
  }
  if (typeof value !== "boolean") throw invalidBoolean();
  return value;
}

module.exports = {
  CERTOPS_AGENT_ALERTS_ENABLED_INVALID,
  normalizeDowntimeAlertsEnabled,
};
