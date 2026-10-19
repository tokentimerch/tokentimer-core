"use strict";

// Adapter configuration (ADR-0015). The credential is read once, held in a
// closure and never placed on an enumerable property, so serializing,
// logging or inspecting the config object cannot reveal it.

const fs = require("node:fs");
const {
  CredentialStoreError,
  assertPrivateFile,
  defaultCredentialPath,
  parseCredentialFile,
} = require("./credentialStore");

const CREDENTIAL_PATTERN = /^ttopc_[a-f0-9]{16}_[a-f0-9]{64}$/;
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = "ConfigError";
  }
}

function resolveBaseUrl(raw) {
  if (typeof raw !== "string" || raw.trim() === "") {
    throw new ConfigError("TOKENTIMER_API_URL is required");
  }
  let url;
  try {
    url = new URL(raw.trim());
  } catch (_error) {
    throw new ConfigError("TOKENTIMER_API_URL is not a valid URL");
  }
  const local = LOCAL_HOSTS.has(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
    // A bearer credential must never cross the network in clear text.
    throw new ConfigError("TOKENTIMER_API_URL must use https (http is allowed only for localhost)");
  }
  if (url.username || url.password) {
    throw new ConfigError("TOKENTIMER_API_URL must not contain credentials");
  }
  if (url.search || url.hash) {
    throw new ConfigError("TOKENTIMER_API_URL must not contain a query string or fragment");
  }
  const basePath = url.pathname.replace(/\/+$/, "");
  return { origin: url.origin, basePath };
}

// `serverAddress` is where requests will go. A stored credential that records
// the server it was issued by is only ever released to that server: otherwise a
// configuration that merely sets the address could collect it.
function readCredential(env, { readFile, checkFile, defaultFile, exists, serverAddress }) {
  const direct = env.TOKENTIMER_MCP_CREDENTIAL;
  let file = env.TOKENTIMER_MCP_CREDENTIAL_FILE;
  if (file && direct) {
    throw new ConfigError("Set TOKENTIMER_MCP_CREDENTIAL or TOKENTIMER_MCP_CREDENTIAL_FILE, not both");
  }
  // Nothing given explicitly: use the file that `tokentimer-mcp enroll` wrote.
  const automatic = !file && !direct && Boolean(defaultFile) && exists(defaultFile);
  if (automatic) file = defaultFile;
  let value = direct;
  if (file) {
    try {
      // A credential other users can read is refused before it is opened.
      checkFile(file);
      const parsed = parseCredentialFile(readFile(file, "utf8"));
      if (!parsed.valid) throw new ConfigError("The connection credential is not in the expected format");
      if (parsed.binding && parsed.binding !== serverAddress) {
        throw new ConfigError(
          "This credential was issued by a different TokenTimer server than the one configured, so it was not used. " +
            "Check TOKENTIMER_API_URL, or run tokentimer-mcp enroll again for this server.",
        );
      }
      if (automatic && !parsed.binding) {
        throw new ConfigError(
          "The stored credential does not record which server issued it, so it is not used automatically. " +
            "Run tokentimer-mcp enroll --replace, or set TOKENTIMER_MCP_CREDENTIAL_FILE explicitly.",
        );
      }
      value = parsed.credential;
    } catch (error) {
      if (error instanceof ConfigError) throw error;
      if (error instanceof CredentialStoreError && /readable by other users/.test(error.message)) {
        throw new ConfigError(error.message);
      }
      // The path may be sensitive; the message names the setting only.
      throw new ConfigError("The credential file could not be read");
    }
  }
  value = typeof value === "string" ? value.trim() : "";
  if (!value) {
    throw new ConfigError("A connection credential is required (TOKENTIMER_MCP_CREDENTIAL or TOKENTIMER_MCP_CREDENTIAL_FILE)");
  }
  if (!CREDENTIAL_PATTERN.test(value)) {
    // Never echo the value, even partially.
    throw new ConfigError("The connection credential is not in the expected format");
  }
  return value;
}

// The address a credential is bound to: origin plus any path prefix.
function serverAddressOf({ origin, basePath }) {
  return `${origin}${basePath || ""}`;
}

function parsePositiveInt(raw, name, fallback, { min, max }) {
  if (raw === undefined || raw === "") return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || String(parsed) !== String(raw).trim() || parsed < min || parsed > max) {
    throw new ConfigError(`${name} must be an integer from ${min} to ${max}`);
  }
  return parsed;
}

function loadConfig(
  env = process.env,
  {
    readFile = fs.readFileSync,
    checkFile = assertPrivateFile,
    defaultFile = defaultCredentialPath({ env }),
    exists = fs.existsSync,
  } = {},
) {
  const { origin, basePath } = resolveBaseUrl(env.TOKENTIMER_API_URL);
  const credential = readCredential(env, {
    readFile,
    checkFile,
    defaultFile,
    exists,
    serverAddress: serverAddressOf({ origin, basePath }),
  });
  const legacy = (env.TOKENTIMER_MCP_LEGACY || "serve").trim().toLowerCase();
  if (legacy !== "serve" && legacy !== "reject") {
    throw new ConfigError("TOKENTIMER_MCP_LEGACY must be serve or reject");
  }

  const config = {
    origin,
    basePath,
    legacy,
    requestTimeoutMs: parsePositiveInt(env.TOKENTIMER_MCP_TIMEOUT_MS, "TOKENTIMER_MCP_TIMEOUT_MS", 15000, {
      min: 1000,
      max: 120000,
    }),
    maxResponseBytes: parsePositiveInt(env.TOKENTIMER_MCP_MAX_RESPONSE_BYTES, "TOKENTIMER_MCP_MAX_RESPONSE_BYTES", 1048576, {
      min: 4096,
      max: 8388608,
    }),
  };

  // Non-enumerable and accessed only through this function: JSON.stringify,
  // util.inspect and object spread all skip it.
  Object.defineProperty(config, "authorizationHeader", {
    enumerable: false,
    value: () => `Bearer ${credential}`,
  });
  return Object.freeze(config);
}

module.exports = { ConfigError, CREDENTIAL_PATTERN, loadConfig, resolveBaseUrl, serverAddressOf };
