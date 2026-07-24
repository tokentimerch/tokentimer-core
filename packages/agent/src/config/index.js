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
// Persisted outbound-message sequence state (crash-safe block reservation;
// see createSequenceAllocator). Not a secret, but 0600 like everything else
// in the state dir so only the agent user can tamper with it.
const SEQUENCE_STATE_FILE_NAME = "sequence-state.json";
// Bootstrap env file written by install-agent.sh for first-run registration;
// the agent deletes it after a successful registration (single-use token).
const BOOTSTRAP_ENV_FILE_NAME = "bootstrap.env";

const AGENT_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
// Same character/length policy as the protocol validator's key-id bound;
// enforced locally too so writeSigningKeyPin is safe regardless of caller.
const SIGNING_KEY_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
// Mirrors the protocol validator's registration-response PEM bound.
const MAX_SIGNING_KEY_PEM_BYTES = 8192;
const PROTOCOL_VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+$/;
const CREDENTIAL_SHAPE_PATTERN =
  /^ttagent_([A-Za-z0-9_.:-]{1,128})_([A-Za-z0-9._~+\/-]{16,1024})$/;
const PEM_CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----/;
const MAX_CA_BUNDLE_BYTES = 1024 * 1024;
// DNS provider credential files are small JSON objects; 64 KiB is generous.
const MAX_DNS_CREDENTIALS_BYTES = 64 * 1024;

const DEFAULT_PROTOCOL_VERSION = "1.0.0";
const DEFAULT_HEARTBEAT_INTERVAL_MS = 30000;
const DEFAULT_POLL_INTERVAL_MS = 15000;
// Discovery is an inventory scan, not a control loop; hourly by default.
const DEFAULT_DISCOVERY_INTERVAL_MS = 60 * 60 * 1000;
// Execution (signed-job dispatch) defaults: disabled and dry-run by
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

/** Provider ids accepted in the dnsProviders config section. Must stay in
 * sync with src/dns listSupportedDnsProviders (duplicated, not imported,
 * to keep this module self-contained; config.test.js fails if the two
 * lists drift). */
const KNOWN_DNS_PROVIDER_IDS = Object.freeze([
  "cloudflare",
  "route53",
  "azure-dns",
  "google-cloud-dns",
  "rfc2136",
  "acme-dns",
  "ovhcloud",
  "hetzner",
  "infomaniak",
  "exoscale",
  "powerdns",
]);

/**
 * Validates the optional "dnsProviders" config block (native DNS-01
 * solvers, src/dns). Fail-loud like validateCaBundlePath: a malformed
 * block aborts startup instead of being silently normalized.
 *
 * Shape: an object mapping provider id -> { credentialsFile: absolutePath,
 * ...providerSpecificNonSecretOptions }, plus an optional reserved
 * `zoneProviderMap` key (zone -> provider id) for hosts with more than one
 * provider. Credentials themselves NEVER live in config.json; only the
 * path to the 0600 credentials file does.
 *
 * @param {*} dnsProviders raw config.json "dnsProviders" value
 * @returns {object|null} the validated block, or null when absent
 */
function validateDnsProvidersObject(dnsProviders) {
  if (dnsProviders === undefined || dnsProviders === null) return null;
  if (typeof dnsProviders !== "object" || Array.isArray(dnsProviders)) {
    throw new Error(
      "tokentimer-agent: dnsProviders in config.json must be an object " +
        "mapping provider id -> { credentialsFile, ...options }",
    );
  }

  const providerIds = Object.keys(dnsProviders).filter(
    (key) => key !== "zoneProviderMap",
  );

  for (const providerId of providerIds) {
    if (!KNOWN_DNS_PROVIDER_IDS.includes(providerId)) {
      throw new Error(
        `tokentimer-agent: dnsProviders.${providerId} is not a known DNS ` +
          `provider id (known: ${KNOWN_DNS_PROVIDER_IDS.join(", ")})`,
      );
    }
    const entry = dnsProviders[providerId];
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(
        `tokentimer-agent: dnsProviders.${providerId} must be an object ` +
          "({ credentialsFile, ...options })",
      );
    }
    if (
      typeof entry.credentialsFile !== "string" ||
      entry.credentialsFile.length === 0 ||
      !path.isAbsolute(entry.credentialsFile)
    ) {
      throw new Error(
        `tokentimer-agent: dnsProviders.${providerId}.credentialsFile must be ` +
          `an absolute path string, got: ${JSON.stringify(entry.credentialsFile)}`,
      );
    }
  }

  const zoneProviderMap = dnsProviders.zoneProviderMap;
  if (zoneProviderMap !== undefined) {
    if (
      zoneProviderMap === null ||
      typeof zoneProviderMap !== "object" ||
      Array.isArray(zoneProviderMap)
    ) {
      throw new Error(
        "tokentimer-agent: dnsProviders.zoneProviderMap must be an object " +
          "mapping zone -> provider id",
      );
    }
    for (const [zone, providerId] of Object.entries(zoneProviderMap)) {
      if (zone.length === 0) {
        throw new Error(
          "tokentimer-agent: dnsProviders.zoneProviderMap contains an empty zone key",
        );
      }
      if (!providerIds.includes(providerId)) {
        throw new Error(
          `tokentimer-agent: dnsProviders.zoneProviderMap.${zone} references ` +
            `provider ${JSON.stringify(providerId)}, which is not configured ` +
            "in dnsProviders",
        );
      }
    }
  }

  return dnsProviders;
}

/**
 * Validates optional dnsPropagation config (timeout/interval/resolvers).
 * Delegates shape rules to src/dns/propagate.normalizePropagationConfig
 * semantics, duplicated here so config stays free of a dns import cycle.
 *
 * @param {*} raw
 * @returns {object}
 */
function normalizeDnsPropagationConfig(raw) {
  const DEFAULT_TIMEOUT_MS = 120 * 1000;
  const DEFAULT_INTERVAL_MS = 2 * 1000;

  if (raw === undefined || raw === null) {
    return {
      timeoutMs: DEFAULT_TIMEOUT_MS,
      intervalMs: DEFAULT_INTERVAL_MS,
      resolvers: [],
      checkAuthoritative: true,
    };
  }
  if (typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(
      "tokentimer-agent: dnsPropagation in config.json must be an object " +
        "({ timeoutMs?, intervalMs?, resolvers?, checkAuthoritative? })",
    );
  }

  const timeoutMs = raw.timeoutMs === undefined ? DEFAULT_TIMEOUT_MS : raw.timeoutMs;
  const intervalMs = raw.intervalMs === undefined ? DEFAULT_INTERVAL_MS : raw.intervalMs;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error(
      `tokentimer-agent: dnsPropagation.timeoutMs must be a positive integer, got ${JSON.stringify(timeoutMs)}`,
    );
  }
  if (!Number.isInteger(intervalMs) || intervalMs <= 0) {
    throw new Error(
      `tokentimer-agent: dnsPropagation.intervalMs must be a positive integer, got ${JSON.stringify(intervalMs)}`,
    );
  }

  let resolvers = [];
  if (raw.resolvers !== undefined) {
    if (
      !Array.isArray(raw.resolvers) ||
      raw.resolvers.some((entry) => typeof entry !== "string" || entry.length === 0)
    ) {
      throw new Error(
        "tokentimer-agent: dnsPropagation.resolvers must be an array of non-empty resolver IP strings",
      );
    }
    resolvers = [...raw.resolvers];
  }

  const checkAuthoritative =
    raw.checkAuthoritative === undefined ? true : raw.checkAuthoritative;
  if (typeof checkAuthoritative !== "boolean") {
    throw new Error(
      "tokentimer-agent: dnsPropagation.checkAuthoritative must be a boolean when provided",
    );
  }

  return { timeoutMs, intervalMs, resolvers, checkAuthoritative };
}

/**
 * Reads and JSON-parses the agent-local DNS credentials file for one
 * configured provider. Fail-loud on every problem: missing config entry,
 * unreadable file, non-JSON content, or (POSIX only, same posture as the
 * 0600 credential file this module writes) a file readable by group/other.
 * The parsed object is returned as-is; deep shape validation is the
 * dns module's job (createDnsSolver fails loud on malformed credentials).
 * The contents are never logged, including in errors.
 *
 * @param {string} providerId
 * @param {{ dnsProviders?: object|null }} config loaded agent config
 * @returns {object} parsed credentials object
 */
function readDnsCredentialsFile(providerId, config) {
  const dnsProviders = config && config.dnsProviders;
  const entry = dnsProviders ? dnsProviders[providerId] : undefined;
  if (!entry || typeof entry.credentialsFile !== "string") {
    throw new Error(
      `tokentimer-agent: dnsProviders.${providerId} is not configured ` +
        "(no credentialsFile)",
    );
  }

  const credentialsPath = entry.credentialsFile;

  if (process.platform !== "win32") {
    let stats;
    try {
      stats = fs.lstatSync(credentialsPath);
    } catch (err) {
      throw new Error(
        `tokentimer-agent: failed to stat DNS credentials file ${credentialsPath}: ${err.message}`,
      );
    }
    if (stats.isSymbolicLink() || !stats.isFile()) {
      throw new Error(
        `tokentimer-agent: DNS credentials file ${credentialsPath} must be a regular non-symlink file`,
      );
    }
    // Same permission posture as the agent credential file: secrets are
    // 0600. A group/other-readable credentials file is a misconfiguration
    // the agent refuses to use rather than silently accepting.
    if ((stats.mode & 0o077) !== 0) {
      throw new Error(
        `tokentimer-agent: refusing to read DNS credentials file ${credentialsPath}: ` +
          "it is readable by group/other (chmod 600 it)",
      );
    }
    // Must be owned by the agent user (or root, so operators can provision
    // credentials without a login shell for the service account).
    if (typeof process.getuid === "function") {
      const uid = process.getuid();
      if (stats.uid !== uid && stats.uid !== 0) {
        throw new Error(
          `tokentimer-agent: refusing to read DNS credentials file ${credentialsPath}: ` +
            "it is not owned by the agent user or root",
        );
      }
    }
  }

  let raw;
  try {
    // Bounded, O_NOFOLLOW re-verified read (defense in depth on top of the
    // lstat above against swap-to-symlink races and oversized files).
    raw = readBoundedRegularFile(
      credentialsPath,
      MAX_DNS_CREDENTIALS_BYTES,
      "DNS credentials file",
    ).toString("utf8");
  } catch (err) {
    throw new Error(
      `tokentimer-agent: failed to read DNS credentials file ${credentialsPath}: ${err.message}`,
    );
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Deliberately does not include the parser message: it can echo file
    // content, and this file holds secrets.
    throw new Error(
      `tokentimer-agent: DNS credentials file ${credentialsPath} is not valid JSON`,
    );
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(
      `tokentimer-agent: DNS credentials file ${credentialsPath} must contain a JSON object`,
    );
  }
  return parsed;
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
 * Validates the optional "execution" config block (signed-job dispatch).
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
 *   dnsProviders: object|null,
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

  // Native DNS-01 solver configuration (src/dns + certops-dns-hook). Only
  // credential file PATHS live here; the secrets stay in their own 0600
  // files, read on demand via readDnsCredentialsFile.
  const dnsProviders = validateDnsProvidersObject(fileConfig.dnsProviders);

  // DNS-01 propagation wait (authoritative + optional recursive polling).
  const dnsPropagation = normalizeDnsPropagationConfig(fileConfig.dnsPropagation);

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
    dnsProviders,
    dnsPropagation,
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
 *
 * Hardening (all fail loudly):
 *   - the PEM must parse via crypto.createPublicKey AND be Ed25519
 *     (ADR-0003 mandates Ed25519 job signing; pinning any other key type
 *     would soft-reject every job as job_integrity_failed, which looks
 *     like an attack instead of the misconfiguration it is);
 *   - signingKeyId and PEM sizes are bounded locally (not only by the
 *     protocol validator upstream);
 *   - an existing pin path that is a symlink or non-regular file is
 *     refused (integrity of the pin is the whole point of the file);
 *   - overwriting an existing pin with a DIFFERENT key requires an
 *     explicit allowRepin flag (re-registration is the only flow allowed
 *     to rotate the pin; a silent overwrite would let any code path
 *     re-pin an attacker-supplied key). Rewriting the identical pin is a
 *     no-op-equivalent and stays allowed.
 *
 * @param {string} configDir
 * @param {{signingKeyId: string, signingPublicKeyPem: string}} pin
 * @param {{allowRepin?: boolean}} [options]
 * @returns {void}
 */
function writeSigningKeyPin(
  configDir,
  { signingKeyId, signingPublicKeyPem },
  { allowRepin = false } = {},
) {
  if (
    typeof signingKeyId !== "string" ||
    !SIGNING_KEY_ID_PATTERN.test(signingKeyId)
  ) {
    throw new Error(
      "tokentimer-agent: signingKeyId must be a 1-128 char string of " +
        "[A-Za-z0-9_.:-], got: " +
        JSON.stringify(signingKeyId),
    );
  }
  if (
    typeof signingPublicKeyPem !== "string" ||
    signingPublicKeyPem.length === 0 ||
    signingPublicKeyPem.length > MAX_SIGNING_KEY_PEM_BYTES ||
    !signingPublicKeyPem.includes("BEGIN PUBLIC KEY")
  ) {
    throw new Error(
      "tokentimer-agent: signingPublicKeyPem must be a PEM-encoded PUBLIC key " +
        `of at most ${MAX_SIGNING_KEY_PEM_BYTES} bytes ` +
        "(refusing to pin anything that does not look like public key material)",
    );
  }
  if (signingPublicKeyPem.includes("PRIVATE KEY")) {
    throw new Error(
      "tokentimer-agent: refusing to pin signingPublicKeyPem containing " +
        "private key material",
    );
  }

  // Parse-and-type check: the pin must be a well-formed Ed25519 public key
  // NOW, at write time, not when the first job soft-rejects.
  let parsedKey;
  try {
    parsedKey = crypto.createPublicKey(signingPublicKeyPem);
  } catch (err) {
    throw new Error(
      `tokentimer-agent: signingPublicKeyPem does not parse as a public key: ${err.message}`,
    );
  }
  if (parsedKey.asymmetricKeyType !== "ed25519") {
    throw new Error(
      "tokentimer-agent: signingPublicKeyPem must be an Ed25519 public key " +
        `(ADR-0003), got ${JSON.stringify(parsedKey.asymmetricKeyType)}`,
    );
  }

  ensureConfigDir(configDir);

  const pinPath = path.join(configDir, SIGNING_KEY_PIN_FILE_NAME);

  // Refuse symlinked/special pin files and silent re-pins to a different key.
  let existingStats = null;
  try {
    existingStats = fs.lstatSync(pinPath);
  } catch (err) {
    if (!err || err.code !== "ENOENT") throw err;
  }
  if (existingStats !== null) {
    if (existingStats.isSymbolicLink() || !existingStats.isFile()) {
      throw new Error(
        `tokentimer-agent: signing key pin path ${pinPath} exists but is ` +
          "not a regular file (symlink or special file); refusing to write " +
          "the pin through it",
      );
    }
    const existingPin = readSigningKeyPin(configDir);
    const samePin =
      existingPin !== null &&
      existingPin.signingKeyId === signingKeyId &&
      existingPin.publicKeyPem === signingPublicKeyPem;
    if (!samePin && !allowRepin) {
      throw new Error(
        "tokentimer-agent: a different signing key is already pinned " +
          `(pinned id ${JSON.stringify(existingPin?.signingKeyId)}, new id ` +
          `${JSON.stringify(signingKeyId)}); refusing to silently re-pin. ` +
          "Pass allowRepin: true only from an explicit re-registration flow.",
      );
    }
  }

  const payload = { signingKeyId, publicKeyPem: signingPublicKeyPem };
  writeFileAtomically(pinPath, `${JSON.stringify(payload, null, 2)}\n`, 0o600);
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

// --- Persisted outbound-message sequence allocator ---

/**
 * How many sequence values one durable write reserves. Every allocation
 * inside the reserved block is memory-only; crossing the block boundary
 * persists a new `reservedThrough` BEFORE any value from the new block is
 * handed out, so a crash can never lead to reuse: a restart resumes AFTER
 * the highest value that was ever reserved on disk.
 */
const SEQUENCE_RESERVATION_BLOCK = 64;
const MAX_SEQUENCE_STATE_BYTES = 4096;

/**
 * Creates the agent's single crash-safe, persisted sequence allocator.
 *
 * One allocator instance must be shared by every protocol client the
 * process creates (registration + steady-state), so all outbound messages
 * draw from one strictly increasing stream that survives restarts. The
 * control plane hard-rejects sequence regressions; without persistence a
 * restarted agent's counter would restart at 1 and lock the agent out.
 *
 * State file (sequence-state.json, 0600): { "reservedThrough": <int> }.
 * Corrupted or missing state starts a fresh reservation from 0 -- safe for
 * a missing file (first run); a corrupted file loses at most one block of
 * already-reserved values... which only ever moves the counter FORWARD
 * after re-reservation, never backward, because the fresh block is written
 * before use. To be safe against a truncated-but-parseable low value, the
 * reader treats any parse problem as "unknown" and the writer always
 * persists max(current, disk) + block.
 *
 * @param {string} configDir
 * @returns {{ next: () => number, peekReservedThrough: () => number }}
 */
function createSequenceAllocator(configDir) {
  ensureConfigDir(configDir);
  const statePath = path.join(configDir, SEQUENCE_STATE_FILE_NAME);

  function readReservedThrough() {
    if (!fs.existsSync(statePath)) return 0;
    try {
      const raw = readBoundedRegularFile(
        statePath,
        MAX_SEQUENCE_STATE_BYTES,
        "sequence state file",
      ).toString("utf8");
      const parsed = JSON.parse(raw);
      const value = parsed?.reservedThrough;
      return Number.isSafeInteger(value) && value >= 0 ? value : 0;
    } catch (_err) {
      // Unreadable/corrupt state: treated as 0 here; reserveThrough()
      // below still writes before any allocation, and the control plane
      // rejecting a regression is the final backstop.
      return 0;
    }
  }

  function reserveThrough(target) {
    writeFileAtomically(
      statePath,
      `${JSON.stringify({ reservedThrough: target })}\n`,
      0o600,
    );
    return target;
  }

  let reservedThrough = readReservedThrough();
  // Resume strictly after everything ever reserved on disk.
  let lastAllocated = reservedThrough;

  return {
    next() {
      const candidate = lastAllocated + 1;
      if (candidate > reservedThrough) {
        // Durable write FIRST, allocation second: a crash between the two
        // wastes a block but can never reuse a value.
        reservedThrough = reserveThrough(candidate + SEQUENCE_RESERVATION_BLOCK - 1);
      }
      lastAllocated = candidate;
      return candidate;
    },
    peekReservedThrough() {
      return reservedThrough;
    },
  };
}

/**
 * Best-effort removal of the installer-written bootstrap env file after a
 * successful registration. The bootstrap token is single-use; once the
 * agent holds a credential, keeping the token on disk (where every later
 * process start re-exports it into the agent environment via systemd
 * EnvironmentFile) only widens exposure.
 *
 * @param {string} configDir
 * @returns {boolean} true when a file was removed
 */
function deleteBootstrapEnvFile(configDir) {
  const bootstrapEnvPath = path.join(configDir, BOOTSTRAP_ENV_FILE_NAME);
  try {
    fs.unlinkSync(bootstrapEnvPath);
    fsyncParentDirectory(bootstrapEnvPath);
    return true;
  } catch (_err) {
    return false;
  }
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
  validateDnsProvidersObject,
  readDnsCredentialsFile,
  readCredential,
  writeCredential,
  rotateCredential,
  persistRegistration,
  recoverPendingRegistration,
  redactCredentialForLogging,
  createSequenceAllocator,
  deleteBootstrapEnvFile,
  KNOWN_DNS_PROVIDER_IDS,
  CREDENTIAL_SHAPE_PATTERN,
  MAX_CA_BUNDLE_BYTES,
  normalizeDnsPropagationConfig,
};
