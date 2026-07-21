"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { containsPrivateKeyMaterial } = require("@tokentimer/log-scrub");

const RFC1123_LABEL = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const DEFAULT_RECONCILE_INTERVAL_MS = 30_000;
const DEFAULT_HEALTH_PORT = 8080;
const DEFAULT_SHUTDOWN_TIMEOUT_MS = 10_000;
const MACHINE_TOKEN_PATTERN = /^ttx_[a-f0-9]{16}_[a-f0-9]{64}$/;

class ControllerConfigError extends Error {
  constructor(code, field) {
    super(`Invalid controller configuration: ${field}`);
    this.name = "ControllerConfigError";
    this.code = code;
    this.field = field;
  }
}

function requiredString(env, field) {
  const value = env[field];
  if (typeof value !== "string" || value.trim() === "") {
    throw new ControllerConfigError("CONTROLLER_CONFIG_REQUIRED", field);
  }
  return value.trim();
}

function parseApiUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch (_error) {
    throw new ControllerConfigError("CONTROLLER_CONFIG_INVALID_URL", "TOKENTIMER_API_URL");
  }
  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password
  ) {
    throw new ControllerConfigError("CONTROLLER_CONFIG_INVALID_URL", "TOKENTIMER_API_URL");
  }
  return parsed.toString();
}

function parseClusterId(value) {
  if (value.length > 63 || !RFC1123_LABEL.test(value)) {
    throw new ControllerConfigError(
      "CONTROLLER_CONFIG_INVALID_CLUSTER_ID",
      "TOKENTIMER_CLUSTER_ID",
    );
  }
  return value;
}

function parseBoolean(value, field, defaultValue = false) {
  if (value === undefined || value === "") return defaultValue;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new ControllerConfigError("CONTROLLER_CONFIG_INVALID_BOOLEAN", field);
}

function parseInterval(value, field, defaultValue) {
  if (value === undefined || value === "") return defaultValue;
  const match = /^(\d+)(ms|s|m|h)?$/.exec(value);
  if (!match || Number(match[1]) === 0) {
    throw new ControllerConfigError("CONTROLLER_CONFIG_INVALID_INTERVAL", field);
  }
  const multiplier = {
    ms: 1,
    s: 1_000,
    m: 60_000,
    h: 3_600_000,
  }[match[2] || "ms"];
  const interval = Number(match[1]) * multiplier;
  if (!Number.isSafeInteger(interval) || interval > 86_400_000) {
    throw new ControllerConfigError("CONTROLLER_CONFIG_INVALID_INTERVAL", field);
  }
  return interval;
}

function parsePort(value, field, defaultValue) {
  if (value === undefined || value === "") return defaultValue;
  if (!/^\d+$/.test(value)) {
    throw new ControllerConfigError("CONTROLLER_CONFIG_INVALID_PORT", field);
  }
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new ControllerConfigError("CONTROLLER_CONFIG_INVALID_PORT", field);
  }
  return port;
}

function parseNamespaces(value) {
  if (value === undefined || value.trim() === "") return [];
  const namespaces = value.split(",").map((item) => item.trim());
  const unique = new Set();
  for (const namespace of namespaces) {
    if (
      namespace === "" ||
      namespace.length > 63 ||
      !RFC1123_LABEL.test(namespace) ||
      unique.has(namespace)
    ) {
      throw new ControllerConfigError(
        "CONTROLLER_CONFIG_INVALID_NAMESPACES",
        "CERTOPS_WATCH_NAMESPACES",
      );
    }
    unique.add(namespace);
  }
  return namespaces;
}

function parseMode(value) {
  if (value === undefined || value === "" || value === "observe") return "observe";
  if (value === "provision") return "provision";
  throw new ControllerConfigError(
    "CONTROLLER_CONFIG_INVALID_MODE",
    "CERTOPS_CONTROLLER_MODE",
  );
}

function loadApiTokenFromFile(
  tokenFile,
  { fsImpl = fs, platform = process.platform } = {},
) {
  if (!path.isAbsolute(tokenFile)) {
    throw new ControllerConfigError(
      "CONTROLLER_CONFIG_INVALID_TOKEN_FILE",
      "TOKENTIMER_API_TOKEN_FILE",
    );
  }

  let stats;
  try {
    stats = fsImpl.statSync(tokenFile);
  } catch (_error) {
    throw new ControllerConfigError(
      "CONTROLLER_CONFIG_TOKEN_FILE_UNREADABLE",
      "TOKENTIMER_API_TOKEN_FILE",
    );
  }
  if (!stats.isFile() || (platform !== "win32" && (stats.mode & 0o022) !== 0)) {
    throw new ControllerConfigError(
      "CONTROLLER_CONFIG_UNSAFE_TOKEN_FILE",
      "TOKENTIMER_API_TOKEN_FILE",
    );
  }

  let contents;
  try {
    contents = fsImpl.readFileSync(tokenFile, "utf8");
  } catch (_error) {
    throw new ControllerConfigError(
      "CONTROLLER_CONFIG_TOKEN_FILE_UNREADABLE",
      "TOKENTIMER_API_TOKEN_FILE",
    );
  }
  const token = String(contents).trim();
  if (
    token === "" ||
    token.length !== 85 ||
    !MACHINE_TOKEN_PATTERN.test(token) ||
    token.includes("\0") ||
    containsPrivateKeyMaterial(token)
  ) {
    throw new ControllerConfigError(
      "CONTROLLER_CONFIG_INVALID_TOKEN_FILE",
      "TOKENTIMER_API_TOKEN_FILE",
    );
  }
  return token;
}

function loadControllerConfig(env = process.env, options = {}) {
  if (Object.hasOwn(env, "TOKENTIMER_API_TOKEN")) {
    throw new ControllerConfigError(
      "CONTROLLER_CONFIG_RAW_TOKEN_FORBIDDEN",
      "TOKENTIMER_API_TOKEN",
    );
  }
  if (Object.hasOwn(env, "KUBECONFIG")) {
    throw new ControllerConfigError(
      "CONTROLLER_CONFIG_KUBECONFIG_FORBIDDEN",
      "KUBECONFIG",
    );
  }

  const tokenFile = requiredString(env, "TOKENTIMER_API_TOKEN_FILE");
  // Validate the bounded machine credential at the only permitted source, then
  // discard it. The reporter re-reads this mounted file for each delivery.
  loadApiTokenFromFile(tokenFile, options);

  return Object.freeze({
    apiUrl: parseApiUrl(requiredString(env, "TOKENTIMER_API_URL")),
    apiTokenFile: tokenFile,
    clusterId: parseClusterId(requiredString(env, "TOKENTIMER_CLUSTER_ID")),
    clusterWide: parseBoolean(
      env.CERTOPS_CLUSTER_WIDE,
      "CERTOPS_CLUSTER_WIDE",
    ),
    healthPort: parsePort(
      env.CERTOPS_HEALTH_PORT,
      "CERTOPS_HEALTH_PORT",
      DEFAULT_HEALTH_PORT,
    ),
    mode: parseMode(env.CERTOPS_CONTROLLER_MODE),
    reconcileIntervalMs: parseInterval(
      env.CERTOPS_RECONCILE_INTERVAL,
      "CERTOPS_RECONCILE_INTERVAL",
      DEFAULT_RECONCILE_INTERVAL_MS,
    ),
    secretFallbackEnabled: parseBoolean(
      env.CERTOPS_SECRET_FALLBACK_ENABLED,
      "CERTOPS_SECRET_FALLBACK_ENABLED",
    ),
    shutdownTimeoutMs: parseInterval(
      env.CERTOPS_SHUTDOWN_TIMEOUT,
      "CERTOPS_SHUTDOWN_TIMEOUT",
      DEFAULT_SHUTDOWN_TIMEOUT_MS,
    ),
    watchNamespaces: parseNamespaces(env.CERTOPS_WATCH_NAMESPACES),
    workspaceId: requiredString(env, "TOKENTIMER_WORKSPACE_ID"),
  });
}

module.exports = {
  ControllerConfigError,
  DEFAULT_HEALTH_PORT,
  DEFAULT_RECONCILE_INTERVAL_MS,
  DEFAULT_SHUTDOWN_TIMEOUT_MS,
  RFC1123_LABEL,
  loadApiTokenFromFile,
  loadControllerConfig,
  parseBoolean,
  parseClusterId,
  parseInterval,
  parseMode,
  parseNamespaces,
  parsePort,
  parseApiUrl,
};
