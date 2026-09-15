"use strict";

const LOGIN_BASE_URL = "https://login.microsoftonline.com";
const TOKEN_TIMEOUT_MS = 10000;
const MAX_FIELD_LENGTH = 5000;

const KEY_VAULT_SCOPE = "https://vault.azure.net/.default";
const GRAPH_SCOPE = "https://graph.microsoft.com/.default";
const ALLOWED_AUTH_METHODS = new Set(["token", "client_credentials"]);
const TENANT_GUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

const AUTH_ERROR_MESSAGES = Object.freeze({
  90002: "Tenant not found. Check tenantId.",
  700016: "Application not found in tenant. Check clientId.",
  7000215:
    "Client secret is invalid or expired. Rotate the secret in Entra and update the stored credential.",
  7000222:
    "Client secret is invalid or expired. Rotate the secret in Entra and update the stored credential.",
});

function nonEmptyString(value, field, max = MAX_FIELD_LENGTH) {
  if (typeof value !== "string" || value.trim().length === 0) {
    const err = new Error(`${field} is required`);
    err.status = 400;
    throw err;
  }
  if (value.length > max) {
    const err = new Error(`${field} is too long (max ${max} characters)`);
    err.status = 400;
    throw err;
  }
  return value.trim();
}

function resolveAuthMethod(raw) {
  if (raw === undefined) return "token";
  if (typeof raw !== "string" || !ALLOWED_AUTH_METHODS.has(raw)) {
    const err = new Error(
      'authMethod must be "token" or "client_credentials"',
    );
    err.status = 400;
    throw err;
  }
  return raw;
}

function canonicalTenantGuid(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return TENANT_GUID_RE.test(trimmed) ? trimmed.toLowerCase() : null;
}

function tenantGuidFromLoginUrl(url) {
  if (typeof url !== "string") return null;
  const match = url.match(
    /^https:\/\/login\.microsoftonline\.com\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\/|$)/i,
  );
  return match ? match[1].toLowerCase() : null;
}

function tenantGuidFromOpenIdConfig(body) {
  if (!body || typeof body !== "object") return null;
  return (
    tenantGuidFromLoginUrl(body.issuer) ||
    tenantGuidFromLoginUrl(body.token_endpoint)
  );
}

async function timedJsonFetch(fetchFn, url, init, failedMessage) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TOKEN_TIMEOUT_MS);
  let response;
  try {
    response = await fetchFn(url, {
      ...init,
      signal: controller.signal,
      redirect: "error",
    });
  } catch (_e) {
    const err = new Error(failedMessage);
    err.status = 502;
    throw err;
  } finally {
    clearTimeout(timer);
  }

  let body = {};
  try {
    body = await response.json();
  } catch (_e) {
    body = {};
  }
  return { response, body };
}

async function resolveCanonicalTenantId(tenantId, fetchImpl) {
  const raw = nonEmptyString(tenantId, "tenantId");
  const already = canonicalTenantGuid(raw);
  if (already) return already;

  const fetchFn = fetchImpl || globalThis.fetch;
  if (typeof fetchFn !== "function") {
    const err = new Error("Azure tenant discovery request failed");
    err.status = 502;
    throw err;
  }

  const url = `${LOGIN_BASE_URL}/${encodeURIComponent(raw)}/v2.0/.well-known/openid-configuration`;
  const { response, body } = await timedJsonFetch(
    fetchFn,
    url,
    { method: "GET", headers: { Accept: "application/json" } },
    "Azure tenant discovery request failed",
  );
  if (!response.ok) {
    const err = new Error("Tenant not found. Check tenantId.");
    err.status = 400;
    throw err;
  }
  const guid = tenantGuidFromOpenIdConfig(body);
  if (!guid) {
    const err = new Error("Azure tenant discovery did not return a tenant id");
    err.status = 502;
    throw err;
  }
  return guid;
}

function numericErrorCodes(body) {
  if (!body || !Array.isArray(body.error_codes)) return [];
  return body.error_codes.map((c) => Number(c)).filter(Number.isFinite);
}

function mapAzureAuthError(body) {
  const codes = numericErrorCodes(body);
  for (const code of codes) {
    if (AUTH_ERROR_MESSAGES[code]) {
      return {
        message: AUTH_ERROR_MESSAGES[code],
        status: 401,
        error: typeof body.error === "string" ? body.error : undefined,
        correlationId: body.correlation_id || body.correlationId || undefined,
        errorCode: code,
      };
    }
  }
  const oauthError =
    typeof body?.error === "string" ? body.error : "invalid_client";
  const correlationId = body?.correlation_id || body?.correlationId;
  return {
    message: correlationId
      ? `Azure authentication failed (${oauthError}, correlation_id ${correlationId}).`
      : `Azure authentication failed (${oauthError}).`,
    status: 401,
    error: oauthError,
    correlationId,
  };
}

function createMappedAuthError(body) {
  const mapped = mapAzureAuthError(body || {});
  const err = new Error(mapped.message);
  err.status = mapped.status;
  err.azureError = mapped.error;
  err.correlationId = mapped.correlationId;
  err.azureErrorCode = mapped.errorCode;
  return err;
}

async function mintAccessToken({
  tenantId,
  clientId,
  clientSecret,
  scope,
  fetchImpl,
}) {
  const tid = nonEmptyString(tenantId, "tenantId");
  const cid = nonEmptyString(clientId, "clientId");
  const secret = nonEmptyString(clientSecret, "clientSecret");
  if (typeof scope !== "string" || !scope.trim()) {
    const err = new Error("scope is required");
    err.status = 400;
    throw err;
  }

  const fetchFn = fetchImpl || globalThis.fetch;
  if (typeof fetchFn !== "function") {
    const err = new Error("Azure token endpoint request failed");
    err.status = 502;
    throw err;
  }

  const url = `${LOGIN_BASE_URL}/${encodeURIComponent(tid)}/oauth2/v2.0/token`;
  const { response, body } = await timedJsonFetch(
    fetchFn,
    url,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: cid,
        client_secret: secret,
        scope: scope.trim(),
      }).toString(),
    },
    "Azure token endpoint request failed",
  );

  if (!response.ok) {
    throw createMappedAuthError(body);
  }
  if (!body || typeof body.access_token !== "string" || !body.access_token) {
    const err = new Error("Azure token response carried no access_token");
    err.status = 502;
    throw err;
  }
  return body.access_token;
}

function createBearerTokenProvider(token) {
  return {
    getToken: async () => token,
    refresh: async () => null,
  };
}

function createClientCredentialsTokenProvider({
  tenantId,
  clientId,
  clientSecret,
  scope,
  fetchImpl,
}) {
  let cachedToken = null;
  let inFlight = null;

  async function mint() {
    const token = await mintAccessToken({
      tenantId,
      clientId,
      clientSecret,
      scope,
      fetchImpl,
    });
    cachedToken = token;
    return token;
  }

  function joinMint() {
    if (!inFlight) {
      inFlight = mint().finally(() => {
        inFlight = null;
      });
    }
    return inFlight;
  }

  return {
    getToken: async () => {
      if (cachedToken) return cachedToken;
      return joinMint();
    },
    refresh: async (failedToken) => {
      if (cachedToken && failedToken !== cachedToken) {
        return cachedToken;
      }
      return joinMint();
    },
  };
}

async function withCurrentTokenRetry(authProvider, token, run) {
  const bearer =
    authProvider && typeof authProvider.getToken === "function"
      ? await authProvider.getToken()
      : token;
  try {
    return await run(bearer);
  } catch (error) {
    if (error?.status !== 401 || !authProvider) throw error;
    const next = await authProvider.refresh(bearer);
    if (!next || next === bearer) throw error;
    return await run(next);
  }
}

async function resolveAzureScanAuth({
  authMethod,
  token,
  tenantId,
  clientId,
  clientSecret,
  scope,
  fetchImpl,
}) {
  const method = resolveAuthMethod(authMethod);
  if (method === "token") {
    if (typeof token !== "string" || token.trim().length === 0) {
      const err = new Error("token is required");
      err.status = 400;
      throw err;
    }
    if (token.length > MAX_FIELD_LENGTH) {
      const err = new Error(
        `token is too long (max ${MAX_FIELD_LENGTH} characters)`,
      );
      err.status = 400;
      throw err;
    }
    return { token: token.trim(), authProvider: undefined };
  }

  const canonicalTenantId = await resolveCanonicalTenantId(
    tenantId,
    fetchImpl,
  );
  const authProvider = createClientCredentialsTokenProvider({
    tenantId: canonicalTenantId,
    clientId,
    clientSecret,
    scope,
    fetchImpl,
  });
  const minted = await authProvider.getToken();
  return { token: minted, authProvider, tenantId: canonicalTenantId };
}

function scrubAzureSecretsFromBody(body) {
  if (!body || typeof body !== "object") return;
  delete body.token;
  delete body.clientSecret;
}

module.exports = {
  KEY_VAULT_SCOPE,
  GRAPH_SCOPE,
  MAX_FIELD_LENGTH,
  TENANT_GUID_RE,
  resolveAuthMethod,
  canonicalTenantGuid,
  resolveCanonicalTenantId,
  mapAzureAuthError,
  mintAccessToken,
  createBearerTokenProvider,
  createClientCredentialsTokenProvider,
  withCurrentTokenRetry,
  resolveAzureScanAuth,
  scrubAzureSecretsFromBody,
};
