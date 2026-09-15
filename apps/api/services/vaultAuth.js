"use strict";

const { isHttpRedirectStatus } = require("./integrationUtils");
const { logger } = require("../utils/logger");

const VAULT_APPROLE_BAD_ROLE = "VAULT_APPROLE_BAD_ROLE";
const VAULT_APPROLE_BAD_SECRET = "VAULT_APPROLE_BAD_SECRET";
const VAULT_APPROLE_MOUNT_NOT_FOUND = "VAULT_APPROLE_MOUNT_NOT_FOUND";
const VAULT_APPROLE_MISSING_CREDENTIAL = "VAULT_APPROLE_MISSING_CREDENTIAL";
const VAULT_APPROLE_INVALID_RESPONSE = "VAULT_APPROLE_INVALID_RESPONSE";
const VAULT_APPROLE_INVALID_MOUNT = "VAULT_APPROLE_INVALID_MOUNT";

const VAULT_AUTH_USER_MESSAGES = {
  [VAULT_APPROLE_BAD_ROLE]: "Invalid or missing Vault role ID.",
  [VAULT_APPROLE_BAD_SECRET]: "Invalid or missing Vault secret ID.",
  [VAULT_APPROLE_MOUNT_NOT_FOUND]:
    "AppRole auth mount not found. Check the auth mount path.",
  [VAULT_APPROLE_MISSING_CREDENTIAL]:
    "AppRole role ID and secret ID are required.",
  [VAULT_APPROLE_INVALID_RESPONSE]:
    "Vault AppRole login returned an invalid response.",
  [VAULT_APPROLE_INVALID_MOUNT]: "Vault AppRole auth mount path is invalid.",
};

const VAULT_AUTH_HTTP_STATUS = {
  [VAULT_APPROLE_BAD_ROLE]: 401,
  [VAULT_APPROLE_BAD_SECRET]: 401,
  [VAULT_APPROLE_MOUNT_NOT_FOUND]: 404,
  [VAULT_APPROLE_MISSING_CREDENTIAL]: 400,
  [VAULT_APPROLE_INVALID_RESPONSE]: 502,
  [VAULT_APPROLE_INVALID_MOUNT]: 400,
};

class VaultAuthError extends Error {
  constructor(code, message, { status, cause } = {}) {
    super(message || VAULT_AUTH_USER_MESSAGES[code] || code);
    this.name = "VaultAuthError";
    this.code = code;
    this.status = status || VAULT_AUTH_HTTP_STATUS[code] || 502;
    if (cause) this.cause = cause;
  }
}

function isVaultAuthError(err) {
  return Boolean(err) && err.name === "VaultAuthError";
}

function presentString(value) {
  return typeof value === "string" && value.trim() !== "";
}

function maskVaultAddress(address) {
  return String(address || "").replace(/\/\/[^@]+@/, "//***@");
}

function normalizeAuthMount(raw) {
  const value =
    raw == null || String(raw).trim() === "" ? "approle" : String(raw).trim();
  const stripped = value.replace(/^\/+|\/+$/g, "");
  if (!stripped) {
    throw new VaultAuthError(VAULT_APPROLE_INVALID_MOUNT);
  }
  const segments = stripped.split("/");
  for (const segment of segments) {
    if (!segment || segment === "." || segment === "..") {
      throw new VaultAuthError(VAULT_APPROLE_INVALID_MOUNT);
    }
  }
  return segments.map((segment) => encodeURIComponent(segment)).join("/");
}

function namespaceHeaders(namespace) {
  if (!presentString(namespace)) return {};
  return { "X-Vault-Namespace": String(namespace).trim() };
}

function scrubVaultCredentialBody(body) {
  if (!body || typeof body !== "object") return;
  delete body.token;
  delete body.roleId;
  delete body.secretId;
}

function parseVaultAuthFromBody(body) {
  const source = body && typeof body === "object" ? body : {};
  const token = presentString(source.token) ? String(source.token).trim() : "";
  const roleId = presentString(source.roleId)
    ? String(source.roleId).trim()
    : "";
  const secretId = presentString(source.secretId)
    ? String(source.secretId).trim()
    : "";
  const authMount = presentString(source.authMount)
    ? String(source.authMount).trim()
    : "";
  const namespace = presentString(source.namespace)
    ? String(source.namespace).trim()
    : "";

  const hasToken = token.length > 0;
  const hasRole = roleId.length > 0;
  const hasSecret = secretId.length > 0;
  const authMountProvided =
    Object.prototype.hasOwnProperty.call(source, "authMount") &&
    source.authMount != null;

  if (hasToken && (hasRole || hasSecret || authMountProvided)) {
    return {
      error: "provide either token or roleId and secretId, not both",
    };
  }
  if (hasRole !== hasSecret) {
    return {
      error: "roleId and secretId are both required for AppRole",
    };
  }
  if (!hasToken && !hasRole) {
    return {
      error: "address and either token or roleId and secretId are required",
    };
  }

  if (hasToken) {
    return {
      credentials: {
        token,
        namespace: namespace || undefined,
      },
    };
  }

  return {
    credentials: {
      roleId,
      secretId,
      authMount: authMount || undefined,
      namespace: namespace || undefined,
    },
  };
}

function classifyAppRoleLoginFailure(status, bodyText) {
  const lower = String(bodyText || "").toLowerCase();
  if (status === 404) return VAULT_APPROLE_MOUNT_NOT_FOUND;
  if (lower.includes("invalid role") || lower.includes("missing role_id")) {
    return VAULT_APPROLE_BAD_ROLE;
  }
  if (lower.includes("invalid secret") || lower.includes("missing secret_id")) {
    return VAULT_APPROLE_BAD_SECRET;
  }
  return null;
}

async function vaultHttpRequest({
  address,
  path,
  method = "GET",
  body,
  query,
  extraHeaders = {},
}) {
  let url;
  try {
    url = new URL(path.startsWith("/") ? path : `/${path}`, address);
  } catch (e) {
    logger.error("Invalid Vault URL", { address, path, error: e.message });
    throw new Error(`Invalid Vault URL: ${e.message}`, { cause: e });
  }

  if (query && typeof query === "object") {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    }
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 120000);

  try {
    logger.debug("Vault API request", {
      method,
      path: url.pathname,
      address: maskVaultAddress(address),
    });

    const res = await fetch(url, {
      method,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...extraHeaders,
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
      redirect: "manual",
    });

    clearTimeout(timeoutId);

    if (isHttpRedirectStatus(res.status)) {
      const err = new Error(`Vault ${method} ${url.pathname} refused redirect`);
      err.status = 400;
      throw err;
    }

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      logger.warn("Vault API request failed", {
        method,
        path: url.pathname,
        status: res.status,
        statusText: res.statusText,
        address: maskVaultAddress(address),
        responseBody: text.substring(0, 200),
      });
      const err = new Error(`Vault ${method} ${url.pathname} ${res.status}`);
      err.status = res.status;
      err.body = text;
      throw err;
    }
    if (res.status === 204) return null;
    return await res.json();
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === "AbortError") {
      logger.error("Vault API request timeout", {
        method,
        path: url.pathname,
        address: maskVaultAddress(address),
        timeoutMs: 120000,
      });
      const err = new Error(`Vault ${method} ${url.pathname} timeout`);
      err.status = 408;
      err.code = "ETIMEDOUT";
      throw err;
    }
    if (error.message && !error.status) {
      logger.error("Vault network error", {
        method,
        path: url?.pathname,
        address: maskVaultAddress(address),
        error: error.message,
        errorCode: error.code,
        errorType: error.name,
        cause: error.cause?.message,
      });
    }
    throw error;
  }
}

async function vaultAppRoleLogin({
  address,
  roleId,
  secretId,
  authMount,
  namespace,
}) {
  if (!presentString(roleId) || !presentString(secretId)) {
    throw new VaultAuthError(VAULT_APPROLE_MISSING_CREDENTIAL);
  }

  const mount = normalizeAuthMount(authMount);
  const loginPath = `/v1/auth/${mount}/login`;

  let response;
  try {
    response = await vaultHttpRequest({
      address,
      path: loginPath,
      method: "POST",
      body: {
        role_id: String(roleId).trim(),
        secret_id: String(secretId).trim(),
      },
      extraHeaders: namespaceHeaders(namespace),
    });
  } catch (err) {
    const code = classifyAppRoleLoginFailure(err.status, err.body);
    if (code) throw new VaultAuthError(code, undefined, { cause: err });
    throw err;
  }

  const auth = response?.auth;
  if (!auth?.client_token) {
    throw new VaultAuthError(VAULT_APPROLE_INVALID_RESPONSE);
  }
  const ttlSeconds = auth.lease_duration;
  if (
    typeof ttlSeconds !== "number" ||
    !Number.isFinite(ttlSeconds) ||
    ttlSeconds < 0
  ) {
    throw new VaultAuthError(VAULT_APPROLE_INVALID_RESPONSE);
  }

  return {
    clientToken: auth.client_token,
    ttlSeconds,
    renewable: auth.renewable === true,
  };
}

function createVaultAuthSession({
  address,
  token,
  roleId,
  secretId,
  authMount,
  namespace,
  now = () => Date.now(),
}) {
  const ns = presentString(namespace) ? String(namespace).trim() : "";

  if (presentString(token)) {
    const staticToken = String(token).trim();
    return {
      address,
      namespace: ns,
      mode: "token",
      async getToken() {
        return staticToken;
      },
    };
  }

  let clientToken = null;
  let refreshAt = null;
  let refreshPromise = null;

  async function login() {
    const result = await vaultAppRoleLogin({
      address,
      roleId,
      secretId,
      authMount,
      namespace: ns || undefined,
    });
    const issuedAt = now();
    clientToken = result.clientToken;
    if (result.ttlSeconds > 0) {
      refreshAt = issuedAt + result.ttlSeconds * 1000 * 0.8;
    } else {
      refreshAt = null;
    }
    return clientToken;
  }

  return {
    address,
    namespace: ns,
    mode: "approle",
    async getToken() {
      if (clientToken && (refreshAt == null || now() < refreshAt)) {
        return clientToken;
      }
      if (!refreshPromise) {
        refreshPromise = login().finally(() => {
          refreshPromise = null;
        });
      }
      return refreshPromise;
    },
  };
}

async function vaultRequest({
  session,
  address,
  token,
  namespace,
  method = "GET",
  path,
  body,
  query,
}) {
  const auth =
    session ||
    createVaultAuthSession({
      address,
      token,
      namespace,
    });
  const clientToken = await auth.getToken();
  return vaultHttpRequest({
    address: address || auth.address,
    path,
    method,
    body,
    query,
    extraHeaders: {
      "X-Vault-Token": clientToken,
      ...namespaceHeaders(namespace || auth.namespace),
    },
  });
}

module.exports = {
  VAULT_APPROLE_BAD_ROLE,
  VAULT_APPROLE_BAD_SECRET,
  VAULT_APPROLE_MOUNT_NOT_FOUND,
  VAULT_APPROLE_MISSING_CREDENTIAL,
  VAULT_APPROLE_INVALID_RESPONSE,
  VAULT_APPROLE_INVALID_MOUNT,
  VAULT_AUTH_USER_MESSAGES,
  VaultAuthError,
  isVaultAuthError,
  normalizeAuthMount,
  parseVaultAuthFromBody,
  scrubVaultCredentialBody,
  vaultHttpRequest,
  vaultAppRoleLogin,
  createVaultAuthSession,
  vaultRequest,
  maskVaultAddress,
};
