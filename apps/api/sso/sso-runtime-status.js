"use strict";

const { validateProviderConfig } = require("./provider-config-schema.js");
const { SECRET_NAMES } = require("./secret-names.js");

/** @type {Map<string, {
 *   registered: boolean,
 *   reason?: string,
 *   lastReloadAt?: string,
 *   appliedConfigVersion?: number|null,
 *   signInReady?: boolean,
 *   type?: string,
 *   lastTestChecks?: object[],
 * }>} */
const providerRuntimeStatuses = new Map();

/**
 * @param {object} row sso_providers row shape
 * @param {object|null} runtimeStatus
 */
function deriveSignInReady(row, runtimeStatus) {
  if (!row?.enabled) return false;
  const st = runtimeStatus || providerRuntimeStatuses.get(row.slug);
  if (!st) return false;
  if (st.signInReady === true) return true;
  if (st.registered === true) return true;
  return false;
}

/**
 * @param {string} slug
 * @param {object} status
 */
function setProviderRuntimeStatus(slug, status) {
  const entry = {
    registered: !!status?.registered,
    reason:
      status?.reason ||
      (status?.registered ? undefined : "not_registered"),
    lastReloadAt: status?.lastReloadAt || new Date().toISOString(),
    appliedConfigVersion:
      status?.appliedConfigVersion != null
        ? Number(status.appliedConfigVersion)
        : null,
    signInReady: status?.signInReady ?? !!status?.registered,
    type: status?.type,
    lastTestChecks: status?.lastTestChecks,
  };
  providerRuntimeStatuses.set(slug, entry);
}

function removeProviderRuntimeStatus(slug) {
  providerRuntimeStatuses.delete(slug);
}

function getProviderRuntimeStatus(slug) {
  const st = providerRuntimeStatuses.get(slug);
  if (!st) {
    return {
      registered: false,
      reason: "not_configured",
      signInReady: false,
      appliedConfigVersion: null,
    };
  }
  return { ...st };
}

function getAllProviderRuntimeStatuses() {
  return new Map(providerRuntimeStatuses);
}

/**
 * Lightweight readiness probe used when passport strategies are not registered yet.
 * @param {object} row
 * @param {string[]} secretsSet
 */
function probeProviderReadiness(row, secretsSet = []) {
  if (!row.enabled) {
    return { registered: false, reason: "disabled", signInReady: false };
  }
  const schema = validateProviderConfig(row.type, row.config || {});
  if (!schema.ok) {
    return { registered: false, reason: schema.errors[0], signInReady: false };
  }
  const requiredSecrets = SECRET_NAMES[row.type] || [];
  const hasRequiredSecret = requiredSecrets.every((n) => secretsSet.includes(n));
  if (row.type === "oidc" && !hasRequiredSecret) {
    return {
      registered: false,
      reason: "client_secret_missing",
      signInReady: false,
    };
  }
  return { registered: true, signInReady: true };
}

function recordLastTestChecks(slug, checks) {
  const prev = providerRuntimeStatuses.get(slug) || {};
  providerRuntimeStatuses.set(slug, {
    ...prev,
    lastTestChecks: checks,
  });
}

function _resetForTests() {
  providerRuntimeStatuses.clear();
}

module.exports = {
  setProviderRuntimeStatus,
  removeProviderRuntimeStatus,
  getProviderRuntimeStatus,
  getAllProviderRuntimeStatuses,
  deriveSignInReady,
  probeProviderReadiness,
  recordLastTestChecks,
  providerRuntimeStatuses,
  _resetForTests,
};
