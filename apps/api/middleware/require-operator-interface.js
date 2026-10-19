"use strict";

// Rollout gate for the whole operator interface (connections and the operator
// namespace). Dark by default, like CertOps: a deployment opts in explicitly.

const OPERATOR_INTERFACE_DISABLED = "OPERATOR_INTERFACE_DISABLED";

function isOperatorInterfaceEnabled(env = process.env) {
  return String(env.MCP_OPERATOR_INTERFACE_ENABLED || "").trim().toLowerCase() === "true";
}

function createRequireOperatorInterfaceEnabled({ env = process.env } = {}) {
  return function requireOperatorInterfaceEnabled(_req, res, next) {
    if (isOperatorInterfaceEnabled(env)) return next();
    return res.status(404).json({
      error: "Not found",
      code: OPERATOR_INTERFACE_DISABLED,
    });
  };
}

module.exports = {
  OPERATOR_INTERFACE_DISABLED,
  createRequireOperatorInterfaceEnabled,
  isOperatorInterfaceEnabled,
  requireOperatorInterfaceEnabled: createRequireOperatorInterfaceEnabled(),
};
