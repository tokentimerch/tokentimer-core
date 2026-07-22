"use strict";

/**
 * Agent configuration loading and secure credential storage (agent bootstrap).
 *
 * Agent credential storage requirements:
 *   - config directory 0700, credential file 0600
 *   - the credential is never printed after registration and is redacted
 *     from agent logs by the same scrub stage that guards key material
 *   - rotation works without downtime (overlap window is a server-side
 *     concern; this module only swaps the locally stored credential)
 *   - container deployments prefer mounted secrets / orchestrator-native
 *     secrets over baked-in env values; this module's file-based storage is
 *     the default host pattern, not the only supported one
 *
 * Memory hygiene: keys are written 0600
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
const crypto = require("node:crypto");
const {
  assertNoPrivateKeyMaterial,
} = require("../../../log-scrub/secret-material.js");

const CONFIG_FILE_NAME = "config.json";
const CREDENTIAL_FILE_NAME = "credential";
const PENDING_REGISTRATION_FILE_NAME = "registration.pending.json";
// Pinned control-plane job-signing key (ADR-0003 trust-on-first-use). The
// stored PEM is PUBLIC key material only (never a private key), so this file
// is not a secret; it still gets 0600 in the 0700 config dir purely as an
// integrity measure (only the agent user may swap the pin).
const SIGNING_KEY_PIN_FILE_NAME = "signing-key-pin.json";

const AGENT_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
const PROTOCOL_VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+$/;
const CREDENTIAL_SHAPE_PATTERN =
  /^ttagent_([A-Za-z0-9_.:-]{1,128})_([A-Za-z0-9._~+\/-]{16,1024})$/;
const PEM_CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----/;
const MAX_CA_BUNDLE_BYTES = 1024 * 1024;

const DEFAULT_PROTOCOL_VERSION = "1.0.0";
const DEFAULT_HEARTBEAT_INTERVAL_MS = 30000;
const DEFAULT_POLL_INTERVAL_MS = 15000;
// Discovery is an inventory scan, not a control loop; hourly by default.
const DEFAULT_DISCOVERY_INTERVAL_MS = 60 * 60 * 1000;
// Execution (M5 signed-job dispatch) defaults: disabled and dry-run by
// default so an upgraded agent never starts executing jobs without an
// explicit operator opt-in (ADR-0003).
const DEFAULT_CLOCK_DRIFT_TOLERANCE_MS = 30000;
const KEYS_DIR_NAME = "keys";
const REPLAY_STORE_FILE_NAME = "replay-store.json";

const REDACTED_CREDENTIAL_PLACEHOLDER = "[AGENT_CREDENTIAL_REDACTED]";

function fsyncParentDirectory(filePath) {
  // fsync on a directory is the durable part of an atomic rename on POSIX.
  // Windows does not support opening directories this way, so this remains
  // best effort there while the atomic rename still prevents torn files.
  let directoryFd;
  try {
    directoryFd = fs.openSync(path.dirname(filePath), "r");
    fs.fsyncSync(directoryFd);
  } catch (_err) {
    // Best effort across platforms/filesystems.
  } finally {
    if (directoryFd !== undefined) {
      try {
        fs.closeSync(directoryFd);
      } catch (_err) {
        // Best effort close.
      }
    }
  }
}

function writeFileAtomically(filePath, contents, mode) {
  const temporaryPath = `${filePath}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
  let fd;
  try {
    fd = fs.openSync(temporaryPath, "wx", mode);
    fs.writeFileSync(fd, contents, "utf8");
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(temporaryPath, filePath);
    try {
      fs.chmodSync(filePath, mode);
    } catch (_err) {
      // Best effort on win32; see ensureConfigDir.
    }
    fsyncParentDirectory(filePath);
  } catch (err) {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch (_err) {
        // Best effort close.
      }
    }
    try {
      fs.unlinkSync(temporaryPath);
    } catch (_err) {
      // The file may already have been renamed, or may never have existed.
    }
    throw err;
  }
}

function readBoundedRegularFile(filePath, maxBytes, label) {
  let stats;
  try {
    stats = fs.lstatSync(filePath);
  } catch (err) {
    throw new Error(`tokentimer-agent: failed to inspect ${label}: ${err.message}`);
  }
  if (stats.isSymbolicLink() || !stats.isFile()) {
    throw new Error(`tokentimer-agent: ${label} must be a regular non-symlink file`);
  }
  if (stats.size < 1 || stats.size > maxBytes) {
    throw new Error(`tokentimer-agent: ${label} must be between 1 and ${maxBytes} bytes`);
  }

  let fd;
  try {
    const noFollow = fs.constants.O_NOFOLLOW || 0;
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
    const openedStats = fs.fstatSync(fd);
    if (!openedStats.isFile() || openedStats.size !== stats.size) {
      throw new Error(`${label} changed while being opened`);
    }
    const buffer = Buffer.allocUnsafe(openedStats.size);
    let offset = 0;
    while (offset < buffer.length) {
      const bytesRead = fs.readSync(fd, buffer, offset, buffer.length - offset, offset);
      if (bytesRead === 0) throw new Error(`${label} ended before its declared size`);
      offset += bytesRead;
    }
    return buffer;
  } catch (err) {
    throw new Error(`tokentimer-agent: failed to read ${label}: ${err.message}`);
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch (_err) {
        // Best effort close.
      }
    }
  }
}

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

function validateCaBundlePath(caBundlePath) {
  if (caBundlePath === undefined || caBundlePath === null) return null;
  if (typeof caBundlePath !== "string" || caBundlePath.length === 0) {
    throw new Error(
      "tokentimer-agent: caBundlePath must be a non-empty path to a PEM CA bundle",
    );
  }
  return caBundlePath;
}

/**
 * Reads an operator-provided private-CA bundle through a bounded, regular-file
 * path. A trust bundle is public certificate material only; accepting keys
 * here would violate the control-plane custody invariant before transport is
 * even established.
 * @param {string} caBundlePath
 * @returns {string}
 */
function readCaBundle(caBundlePath) {
  const raw = readBoundedRegularFile(
    caBundlePath,
    MAX_CA_BUNDLE_BYTES,
    `CA bundle at ${caBundlePath}`,
  );
  assertNoPrivateKeyMaterial(raw);
  const pem = raw.toString("utf8");
  if (!PEM_CERTIFICATE_PATTERN.test(pem)) {
    throw new Error(
      `tokentimer-agent: CA bundle at ${caBundlePath} contains no PEM certificate block`,
    );
  }
  return pem;
}

function parseBooleanEnv(value, fallback, envName) {
  if (value === undefined || value === null || value === "") return fallback;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`tokentimer-agent: ${envName} must be "true" or "false"`);
}

/**
 * Validates the optional "execution" config block (M5 signed-job dispatch).
 * Fail-loud like validatePolicyObject/validateDiscoveryObject: a malformed
 * block aborts startup instead of being silently normalized.
 *
 * Returned shape (defaults applied, all fields always present):
 *   {
 *     enabled: boolean            (default false),
 *     dryRun: boolean             (default true),
 *     keysDir: string             (default <configDir>/keys),
 *     replayStorePath: string     (default <configDir>/replay-store.json),
 *     clockDriftToleranceMs: int  (default 30000, must be a positive integer)
 *   }
 *
 * Returns null when the block is absent entirely (execution disabled and
 * not configured; callers treat null like { enabled: false }).
 *
 * @param {*} execution raw config.json "execution" value
 * @param {string} configDir resolved config dir used for path defaults
 * @returns {{
 *   enabled: boolean,
 *   dryRun: boolean,
 *   keysDir: string,
 *   replayStorePath: string,
 *   clockDriftToleranceMs: number,
 * }|null}
 */
function validateExecutionObject(execution, configDir) {
  if (execution === undefined || execution === null) return null;
  if (typeof execution !== "object" || Array.isArray(execution)) {
    throw new Error(
      "tokentimer-agent: execution in config.json must be an object " +
        "({ enabled?, dryRun?, keysDir?, replayStorePath?, clockDriftToleranceMs? })",
    );
  }

  const enabled = execution.enabled === undefined ? false : execution.enabled;
  if (typeof enabled !== "boolean") {
    throw new Error(
      "tokentimer-agent: execution.enabled must be a boolean, got: " +
        JSON.stringify(execution.enabled),
    );
  }

  const dryRun = execution.dryRun === undefined ? true : execution.dryRun;
  if (typeof dryRun !== "boolean") {
    throw new Error(
      "tokentimer-agent: execution.dryRun must be a boolean, got: " +
        JSON.stringify(execution.dryRun),
    );
  }

  let keysDir = path.join(configDir, KEYS_DIR_NAME);
  if (execution.keysDir !== undefined) {
    if (typeof execution.keysDir !== "string" || execution.keysDir.length === 0) {
      throw new Error(
        "tokentimer-agent: execution.keysDir must be a non-empty string, got: " +
          JSON.stringify(execution.keysDir),
      );
    }
    keysDir = execution.keysDir;
  }

  let replayStorePath = path.join(configDir, REPLAY_STORE_FILE_NAME);
  if (execution.replayStorePath !== undefined) {
    if (
      typeof execution.replayStorePath !== "string" ||
      execution.replayStorePath.length === 0
    ) {
      throw new Error(
        "tokentimer-agent: execution.replayStorePath must be a non-empty string, got: " +
          JSON.stringify(execution.replayStorePath),
      );
    }
    replayStorePath = execution.replayStorePath;
  }

  let clockDriftToleranceMs = DEFAULT_CLOCK_DRIFT_TOLERANCE_MS;
  if (execution.clockDriftToleranceMs !== undefined) {
    if (
      typeof execution.clockDriftToleranceMs !== "number" ||
      !Number.isInteger(execution.clockDriftToleranceMs) ||
      execution.clockDriftToleranceMs <= 0
    ) {
      throw new Error(
        "tokentimer-agent: execution.clockDriftToleranceMs must be a positive " +
          `integer (milliseconds), got: ${JSON.stringify(execution.clockDriftToleranceMs)}`,
      );
    }
    clockDriftToleranceMs = execution.clockDriftToleranceMs;
  }

  return { enabled, dryRun, keysDir, replayStorePath, clockDriftToleranceMs };
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
 *   caBundlePath: string|null,
 *   allowInsecureLocalHttp: boolean,
 *   execution: {
 *     enabled: boolean,
 *     dryRun: boolean,
 *     keysDir: string,
 *     replayStorePath: string,
 *     clockDriftToleranceMs: number,
 *   }|null,
 *   pinnedSigningKey: {signingKeyId: string, publicKeyPem: string}|null,
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

  // Filesystem discovery config (observe-only certificate inventory).
  // null means discovery is disabled entirely.
  const discovery = validateDiscoveryObject(fileConfig.discovery);

  const caBundlePath = validateCaBundlePath(
    process.env.TOKENTIMER_AGENT_CA_BUNDLE || fileConfig.caBundlePath,
  );
  if (
    fileConfig.allowInsecureLocalHttp !== undefined &&
    typeof fileConfig.allowInsecureLocalHttp !== "boolean"
  ) {
    throw new Error("tokentimer-agent: allowInsecureLocalHttp in config.json must be a boolean");
  }
  const allowInsecureLocalHttp = parseBooleanEnv(
    process.env.TOKENTIMER_AGENT_ALLOW_INSECURE_LOCAL_HTTP,
    fileConfig.allowInsecureLocalHttp || false,
    "TOKENTIMER_AGENT_ALLOW_INSECURE_LOCAL_HTTP",
  );

  // Signed-job execution config; null means execution not configured
  // (treated everywhere as { enabled: false }).
  const execution = validateExecutionObject(fileConfig.execution, resolvedDir);

  // Pinned control-plane job-signing key, persisted at registration by
  // writeSigningKeyPin. Public key material only.
  const pinnedSigningKey = readSigningKeyPin(resolvedDir);

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
    caBundlePath,
    allowInsecureLocalHttp,
    execution,
    pinnedSigningKey,
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
  writeFileAtomically(configPath, `${JSON.stringify(merged, null, 2)}\n`, 0o600);
}

/**
 * Persists the control-plane job-signing key pin received at registration
 * (ADR-0003 trust-on-first-use). The stored publicKeyPem is PUBLIC key
 * material, not a secret, so storing it on disk is safe; the file still
 * follows the module's 0600-in-0700-dir convention so only the agent user
 * can replace the pin (integrity, not confidentiality).
 * @param {string} configDir
 * @param {{signingKeyId: string, signingPublicKeyPem: string}} pin
 * @returns {void}
 */
function writeSigningKeyPin(configDir, { signingKeyId, signingPublicKeyPem }) {
  if (typeof signingKeyId !== "string" || signingKeyId.length === 0) {
    throw new Error(
      "tokentimer-agent: signingKeyId must be a non-empty string, got: " +
        JSON.stringify(signingKeyId),
    );
  }
  if (
    typeof signingPublicKeyPem !== "string" ||
    !signingPublicKeyPem.includes("BEGIN PUBLIC KEY")
  ) {
    throw new Error(
      "tokentimer-agent: signingPublicKeyPem must be a PEM-encoded PUBLIC key " +
        "(refusing to pin anything that does not look like public key material)",
    );
  }
  if (signingPublicKeyPem.includes("PRIVATE KEY")) {
    throw new Error(
      "tokentimer-agent: refusing to pin signingPublicKeyPem containing " +
        "private key material",
    );
  }
  ensureConfigDir(configDir);

  const pinPath = path.join(configDir, SIGNING_KEY_PIN_FILE_NAME);
  const payload = { signingKeyId, publicKeyPem: signingPublicKeyPem };
  fs.writeFileSync(pinPath, `${JSON.stringify(payload, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  try {
    fs.chmodSync(pinPath, 0o600);
  } catch (_err) {
    // Best-effort on win32; see the comment in ensureConfigDir for rationale.
  }
}

/**
 * Reads the persisted signing-key pin, returning null when none is stored.
 * A present-but-corrupted pin file fails loudly (never silently unpinned).
 * @param {string} configDir
 * @returns {{signingKeyId: string, publicKeyPem: string}|null}
 */
function readSigningKeyPin(configDir) {
  const pinPath = path.join(configDir, SIGNING_KEY_PIN_FILE_NAME);
  let raw;
  try {
    raw = fs.readFileSync(pinPath, "utf8");
  } catch (err) {
    if (err && err.code === "ENOENT") return null;
    throw err;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `tokentimer-agent: failed to parse signing key pin ${pinPath}: ${err.message}`,
    );
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    typeof parsed.signingKeyId !== "string" ||
    parsed.signingKeyId.length === 0 ||
    typeof parsed.publicKeyPem !== "string" ||
    !parsed.publicKeyPem.includes("BEGIN PUBLIC KEY")
  ) {
    throw new Error(
      `tokentimer-agent: ${pinPath} is corrupted (expected ` +
        "{ signingKeyId, publicKeyPem } with a PEM public key); refusing to " +
        "start unsigned. Re-register the agent to re-pin.",
    );
  }
  return { signingKeyId: parsed.signingKeyId, publicKeyPem: parsed.publicKeyPem };
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
  const credential = raw.trim();
  assertValidCredentialShape(credential);
  return credential;
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
  writeFileAtomically(credentialPath, rawCredential, 0o600);
}

function validateRegistrationRecord(record) {
  if (
    record === null ||
    typeof record !== "object" ||
    Array.isArray(record) ||
    Object.keys(record).length !== 2 ||
    !Object.prototype.hasOwnProperty.call(record, "agentId") ||
    !Object.prototype.hasOwnProperty.call(record, "credential")
  ) {
    throw new Error("tokentimer-agent: pending registration record is malformed");
  }
  validateAgentId(record.agentId);
  assertValidCredentialShape(record.credential);
  const credentialAgentId = CREDENTIAL_SHAPE_PATTERN.exec(record.credential)?.[1];
  if (credentialAgentId !== record.agentId) {
    throw new Error("tokentimer-agent: registration credential does not match assigned agentId");
  }
  return { agentId: record.agentId, credential: record.credential };
}

function readPendingRegistration(configDir) {
  const pendingPath = path.join(configDir, PENDING_REGISTRATION_FILE_NAME);
  let raw;
  try {
    raw = fs.readFileSync(pendingPath, "utf8");
  } catch (err) {
    if (err?.code === "ENOENT") return null;
    throw err;
  }
  try {
    return validateRegistrationRecord(JSON.parse(raw));
  } catch (err) {
    throw new Error(`tokentimer-agent: pending registration recovery failed: ${err.message}`);
  }
}

/**
 * Persists a validated registration with a small write-ahead record. A crash
 * after any individual rename leaves registration.pending.json, allowing the
 * next start to replay the same identity/credential pair safely.
 * @param {string} configDir
 * @param {{agentId: string, credential: string}} registration
 */
function persistRegistration(configDir, registration) {
  const validated = validateRegistrationRecord(registration);
  ensureConfigDir(configDir);
  const pendingPath = path.join(configDir, PENDING_REGISTRATION_FILE_NAME);
  writeFileAtomically(pendingPath, `${JSON.stringify(validated)}\n`, 0o600);
  writeAgentIdentity(configDir, validated);
  writeCredential(configDir, validated.credential);
  fs.unlinkSync(pendingPath);
  fsyncParentDirectory(pendingPath);
}

/**
 * Completes a previously interrupted registration transaction, if present.
 * @param {string} configDir
 * @returns {{agentId: string, credential: string}|null}
 */
function recoverPendingRegistration(configDir) {
  const registration = readPendingRegistration(configDir);
  if (registration === null) return null;
  persistRegistration(configDir, registration);
  return registration;
}

/**
 * Rotates the agent's stored credential to a new value, once the control
 * plane has confirmed the rotation. This is the same validation/write path
 * as writeCredential, exposed as a distinct named function so intent is
 * clear at rotation call sites. The overlap-window
 * orchestration itself (accepting both old and new credentials for a
 * transition period) is a control-plane concern, not this module's
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
  readCaBundle,
  validateCaBundlePath,
  writeAgentIdentity,
  writeSigningKeyPin,
  readSigningKeyPin,
  validateExecutionObject,
  readCredential,
  writeCredential,
  rotateCredential,
  persistRegistration,
  recoverPendingRegistration,
  redactCredentialForLogging,
  CREDENTIAL_SHAPE_PATTERN,
  MAX_CA_BUNDLE_BYTES,
};
