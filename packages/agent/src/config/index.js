"use strict";

/**
 * Agent configuration loading and secure credential storage (M4 bootstrap).
 *
 * Per the CertOps architecture plan section 7.2 ("Agent credential storage"):
 *   - config directory 0700, credential file 0600
 *   - the credential is never printed after registration and is redacted
 *     from agent logs by the same scrub stage that guards key material
 *   - rotation works without downtime (overlap window is a server/Phase 4
 *     concern; this module only swaps the locally stored credential)
 *   - container deployments prefer mounted secrets / orchestrator-native
 *     secrets over baked-in env values; this module's file-based storage is
 *     the default host pattern, not the only supported one
 *
 * Per section 7.7 design lessons ("Memory hygiene"): keys are written 0600
 * in 0700 dirs, and permissions are re-asserted before every write. The same
 * discipline is applied here to the agent's own registration credential,
 * even though it is not customer key material: it is still a bearer secret
 * that would let an attacker impersonate this agent to the control plane.
 *
 * This module is self-contained and does not import from src/index.js or any
 * other sibling module; another engineer wires it into the agent entrypoint.
 */

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const CONFIG_FILE_NAME = "config.json";
const CREDENTIAL_FILE_NAME = "credential";

const AGENT_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
const PROTOCOL_VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+$/;
// Permissive shape check only: the agent never needs to parse the id/secret
// apart, so this is deliberately loose beyond the required prefix.
const CREDENTIAL_SHAPE_PATTERN = /^ttagent_.+$/;

const DEFAULT_PROTOCOL_VERSION = "1.0.0";
const DEFAULT_HEARTBEAT_INTERVAL_MS = 30000;
const DEFAULT_POLL_INTERVAL_MS = 15000;
// Discovery is an inventory scan, not a control loop; hourly by default.
const DEFAULT_DISCOVERY_INTERVAL_MS = 60 * 60 * 1000;

const REDACTED_CREDENTIAL_PLACEHOLDER = "[AGENT_CREDENTIAL_REDACTED]";

/**
 * Resolves the agent config directory.
 * Precedence: explicit arg > TOKENTIMER_AGENT_CONFIG_DIR env var > OS default.
 * @param {string|null|undefined} explicitDir
 * @returns {string}
 */
function resolveConfigDir(explicitDir) {
  if (typeof explicitDir === "string" && explicitDir.length > 0) {
    return explicitDir;
  }
  const envDir = process.env.TOKENTIMER_AGENT_CONFIG_DIR;
  if (typeof envDir === "string" && envDir.length > 0) {
    return envDir;
  }
  if (process.platform === "win32") {
    const appData = process.env.APPDATA || path.join(os.homedir(), "AppData", "Roaming");
    return path.join(appData, "tokentimer-agent");
  }
  return path.join(os.homedir(), ".config", "tokentimer-agent");
}

/**
 * Ensures the config directory exists with 0700 permissions, re-asserting
 * the mode on every call (defense in depth against a prior looser mode).
 * @param {string} configDir
 * @returns {void}
 */
function ensureConfigDir(configDir) {
  fs.mkdirSync(configDir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(configDir, 0o700);
  } catch (_err) {
    // POSIX modes are not meaningful on win32 (no chmod-equivalent ACL model
    // here), so enforcement is best-effort there. This is a defense-in-depth
    // measure for the POSIX hosts the agent primarily runs on per the plan's
    // Linux-host framing; nothing on win32 depends on this call succeeding.
  }
}

function readConfigFile(configDir) {
  const configPath = path.join(configDir, CONFIG_FILE_NAME);
  let raw;
  try {
    raw = fs.readFileSync(configPath, "utf8");
  } catch (err) {
    if (err && err.code === "ENOENT") return {};
    throw err;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `tokentimer-agent: failed to parse ${configPath}: ${err.message}`,
    );
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(
      `tokentimer-agent: ${configPath} must contain a JSON object`,
    );
  }
  return parsed;
}

function parsePositiveIntEnv(envValue, fallback, envName) {
  if (envValue === undefined || envValue === null || envValue === "") {
    return fallback;
  }
  const parsed = Number(envValue);
  if (!Number.isFinite(parsed) || !Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(
      `tokentimer-agent: ${envName} must be a positive integer, got "${envValue}"`,
    );
  }
  return parsed;
}

function validateAgentId(agentId) {
  if (agentId === null || agentId === undefined) return null;
  if (typeof agentId !== "string" || !AGENT_ID_PATTERN.test(agentId)) {
    throw new Error(
      "tokentimer-agent: invalid agentId in config (must match " +
        `${AGENT_ID_PATTERN} and be 1-128 chars), got: ${JSON.stringify(agentId)}`,
    );
  }
  return agentId;
}

function validateProtocolVersion(protocolVersion) {
  if (typeof protocolVersion !== "string" || !PROTOCOL_VERSION_PATTERN.test(protocolVersion)) {
    throw new Error(
      "tokentimer-agent: invalid protocolVersion in config (must be semver " +
        `x.y.z), got: ${JSON.stringify(protocolVersion)}`,
    );
  }
  return protocolVersion;
}

function validateStringArray(value, fieldName) {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error(
      `tokentimer-agent: ${fieldName} must be an array of strings, got: ${JSON.stringify(value)}`,
    );
  }
  return value;
}

function validatePolicyObject(policy) {
  if (policy === undefined || policy === null) return null;
  if (typeof policy !== "object" || Array.isArray(policy)) {
    throw new Error(
      "tokentimer-agent: policy in config.json must be an object " +
        "(allowedCommands/allowedPaths/allowedCaEndpoints/allowedDnsZones/allowedDnsProviders)",
    );
  }
  return policy;
}

function validateDiscoveryObject(discovery) {
  if (discovery === undefined || discovery === null) return null;
  if (typeof discovery !== "object" || Array.isArray(discovery)) {
    throw new Error(
      "tokentimer-agent: discovery in config.json must be an object ({ directories, intervalMs? })",
    );
  }
  const directories = validateStringArray(
    discovery.directories || [],
    "discovery.directories",
  );
  let intervalMs = DEFAULT_DISCOVERY_INTERVAL_MS;
  if (discovery.intervalMs !== undefined) {
    if (
      typeof discovery.intervalMs !== "number" ||
      !Number.isInteger(discovery.intervalMs) ||
      discovery.intervalMs <= 0
    ) {
      throw new Error(
        "tokentimer-agent: discovery.intervalMs must be a positive integer " +
          `(milliseconds), got: ${JSON.stringify(discovery.intervalMs)}`,
      );
    }
    intervalMs = discovery.intervalMs;
  }
  return { directories, intervalMs };
}

/**
 * Loads and returns the agent runtime config as a plain object.
 * Load order: config.json file (non-secret fields) -> env var overrides ->
 * defaults. The credential itself is never part of this object; use
 * readCredential separately.
 * @param {{configDir?: string}} [options]
 * @returns {{
 *   serverUrl: string,
 *   agentId: string|null,
 *   protocolVersion: string,
 *   heartbeatIntervalMs: number,
 *   pollIntervalMs: number,
 *   declaredTargetSelectors: string[],
 *   declaredCommandProfileNames: string[],
 *   policy: object|null,
 *   discovery: {directories: string[], intervalMs: number}|null,
 * }}
 */
function loadAgentConfig({ configDir } = {}) {
  const resolvedDir = resolveConfigDir(configDir);
  const fileConfig = readConfigFile(resolvedDir);

  const serverUrl = process.env.TOKENTIMER_AGENT_SERVER_URL || fileConfig.serverUrl;
  if (typeof serverUrl !== "string" || serverUrl.length === 0) {
    throw new Error(
      "tokentimer-agent: serverUrl is required. Set TOKENTIMER_AGENT_SERVER_URL " +
        `or provide it in ${path.join(resolvedDir, CONFIG_FILE_NAME)}`,
    );
  }

  const agentId = validateAgentId(
    fileConfig.agentId !== undefined && fileConfig.agentId !== null
      ? fileConfig.agentId
      : null,
  );

  const protocolVersion = validateProtocolVersion(
    fileConfig.protocolVersion || DEFAULT_PROTOCOL_VERSION,
  );

  const heartbeatIntervalMs = parsePositiveIntEnv(
    process.env.TOKENTIMER_AGENT_HEARTBEAT_MS,
    typeof fileConfig.heartbeatIntervalMs === "number"
      ? fileConfig.heartbeatIntervalMs
      : DEFAULT_HEARTBEAT_INTERVAL_MS,
    "TOKENTIMER_AGENT_HEARTBEAT_MS",
  );

  const pollIntervalMs = parsePositiveIntEnv(
    process.env.TOKENTIMER_AGENT_POLL_MS,
    typeof fileConfig.pollIntervalMs === "number"
      ? fileConfig.pollIntervalMs
      : DEFAULT_POLL_INTERVAL_MS,
    "TOKENTIMER_AGENT_POLL_MS",
  );

  const declaredTargetSelectors = validateStringArray(
    fileConfig.declaredTargetSelectors || [],
    "declaredTargetSelectors",
  );

  const declaredCommandProfileNames = validateStringArray(
    fileConfig.declaredCommandProfileNames || [],
    "declaredCommandProfileNames",
  );

  // Agent-local policy (ADR-0002): lives in agent-local configuration and is
  // never sourced from the control plane. Kept opaque here; the policy module
  // (loadPolicyConfig) owns deep validation and fails loudly on bad shapes.
  const policy = validatePolicyObject(fileConfig.policy);

  // Filesystem discovery config (M4: observe-only certificate inventory).
  // null means discovery is disabled entirely.
  const discovery = validateDiscoveryObject(fileConfig.discovery);

  return {
    serverUrl,
    agentId,
    protocolVersion,
    heartbeatIntervalMs,
    pollIntervalMs,
    declaredTargetSelectors,
    declaredCommandProfileNames,
    policy,
    discovery,
  };
}

/**
 * Persists the non-secret agentId into config.json, merging with any
 * existing file content rather than clobbering other fields. The credential
 * itself must never be written here; use writeCredential for that.
 * @param {string} configDir
 * @param {{agentId: string}} identity
 * @returns {void}
 */
function writeAgentIdentity(configDir, { agentId }) {
  validateAgentId(agentId);
  ensureConfigDir(configDir);

  const configPath = path.join(configDir, CONFIG_FILE_NAME);
  const existing = readConfigFile(configDir);
  const merged = { ...existing, agentId };
  fs.writeFileSync(configPath, `${JSON.stringify(merged, null, 2)}\n`, "utf8");
}

/**
 * Reads the credential file, returning null if it does not exist.
 * Never logs the raw value; callers must also avoid logging the return
 * value directly (use redactCredentialForLogging for any log call site).
 * @param {string} configDir
 * @returns {string|null}
 */
function readCredential(configDir) {
  const credentialPath = path.join(configDir, CREDENTIAL_FILE_NAME);
  let raw;
  try {
    raw = fs.readFileSync(credentialPath, "utf8");
  } catch (err) {
    if (err && err.code === "ENOENT") return null;
    throw err;
  }
  return raw.trim();
}

function assertValidCredentialShape(rawCredential) {
  if (typeof rawCredential !== "string" || rawCredential.length === 0) {
    throw new Error(
      "tokentimer-agent: credential must be a non-empty string " +
        `(received type ${typeof rawCredential})`,
    );
  }
  if (!CREDENTIAL_SHAPE_PATTERN.test(rawCredential)) {
    throw new Error(
      "tokentimer-agent: credential does not match the expected " +
        `ttagent_<id>_<secret> shape (length ${rawCredential.length})`,
    );
  }
}

/**
 * Writes the credential file with 0600 permissions, re-asserting the mode
 * after write. Validates the credential shape first so garbage is never
 * silently persisted. The raw value is never logged, including in errors.
 * @param {string} configDir
 * @param {string} rawCredential
 * @returns {void}
 */
function writeCredential(configDir, rawCredential) {
  assertValidCredentialShape(rawCredential);
  ensureConfigDir(configDir);

  const credentialPath = path.join(configDir, CREDENTIAL_FILE_NAME);
  fs.writeFileSync(credentialPath, rawCredential, { encoding: "utf8", mode: 0o600 });
  try {
    fs.chmodSync(credentialPath, 0o600);
  } catch (_err) {
    // Best-effort on win32; see the comment in ensureConfigDir for rationale.
  }
}

/**
 * Rotates the agent's stored credential to a new value, once the control
 * plane has confirmed the rotation. This is the same validation/write path
 * as writeCredential, exposed as a distinct named function so intent is
 * clear at rotation call sites (section 7.2). The overlap-window
 * orchestration itself (accepting both old and new credentials for a
 * transition period) is a control-plane/Phase 4 concern, not this module's
 * job: the agent's only responsibility is to swap what it has stored.
 * @param {string} configDir
 * @param {string} newRawCredential
 * @returns {void}
 */
function rotateCredential(configDir, newRawCredential) {
  writeCredential(configDir, newRawCredential);
}

/**
 * Always returns a fixed redaction placeholder regardless of input. This
 * exists so any future logging code that might reference the credential can
 * call this function and be safe by construction, rather than relying on
 * every call site remembering to omit the raw value.
 * @param {*} _value
 * @returns {string}
 */
function redactCredentialForLogging(_value) {
  return REDACTED_CREDENTIAL_PLACEHOLDER;
}

module.exports = {
  resolveConfigDir,
  ensureConfigDir,
  loadAgentConfig,
  writeAgentIdentity,
  readCredential,
  writeCredential,
  rotateCredential,
  redactCredentialForLogging,
};
