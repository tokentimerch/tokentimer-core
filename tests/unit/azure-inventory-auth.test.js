"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const Module = require("module");
const path = require("path");
const fs = require("fs");

const azureCreds = require("../../apps/api/services/azureClientCredentials");
const {
  validateAutoSyncCredentials,
  buildAzureAutoSyncScanBody,
} = require("../../apps/api/services/autoSyncCredentials");
const {
  azureKeyVaultUserMessage,
  azureAdUserMessage,
} = require("../../apps/api/services/azureScanUserMessages");
const { redactSensitiveFields } = require("../../apps/api/utils/logger.js");

function resolveAzureIntegration() {
  return path.resolve(
    __dirname,
    "../../apps/api/services/azureIntegration.js",
  );
}

function requireWithMocks(modulePath, mocks) {
  const resolved = require.resolve(modulePath);
  delete require.cache[resolved];
  const originalLoad = Module._load;
  const originalNodeEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = "test";
  Module._load = function patchedLoad(request, parent, isMain) {
    if (Object.prototype.hasOwnProperty.call(mocks, request)) {
      return mocks[request];
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    return require(modulePath);
  } finally {
    Module._load = originalLoad;
    process.env.NODE_ENV = originalNodeEnv;
  }
}

function httpError(status, data = {}) {
  const err = new Error("http");
  err.response = { status, data };
  return err;
}

describe("azure client-credentials mapping", () => {
  it("maps numeric error_codes, not AADSTS strings in error_description", () => {
    const mapped = azureCreds.mapAzureAuthError({
      error: "invalid_client",
      error_codes: [7000215],
      error_description: "AADSTS7000215: secret leaked-value-should-not-appear",
      correlation_id: "corr-1",
    });
    assert.equal(
      mapped.message,
      "Client secret is invalid or expired. Rotate the secret in Entra and update the stored credential.",
    );
    assert.ok(!mapped.message.includes("leaked-value"));
    assert.equal(mapped.errorCode, 7000215);
  });

  it("maps tenant and client id failures", () => {
    assert.match(
      azureCreds.mapAzureAuthError({ error_codes: [90002] }).message,
      /Tenant not found/,
    );
    assert.match(
      azureCreds.mapAzureAuthError({ error_codes: [700016] }).message,
      /Application not found/,
    );
  });

  it("fallback includes only safe fields", () => {
    const mapped = azureCreds.mapAzureAuthError({
      error: "invalid_scope",
      error_description: "secret=super-secret",
      correlation_id: "abc",
    });
    assert.equal(
      mapped.message,
      "Azure authentication failed (invalid_scope, correlation_id abc).",
    );
    assert.ok(!mapped.message.includes("super-secret"));
  });
});

describe("azure token provider", () => {
  it("mints a token and generation-aware refresh shares one mint", async () => {
    let mintCount = 0;
    const fetchImpl = async () => {
      mintCount += 1;
      return {
        ok: true,
        json: async () => ({ access_token: `t${mintCount}` }),
      };
    };
    const provider = azureCreds.createClientCredentialsTokenProvider({
      tenantId: "tenant",
      clientId: "client",
      clientSecret: "secret",
      scope: azureCreds.KEY_VAULT_SCOPE,
      fetchImpl,
    });
    const t1 = await provider.getToken();
    assert.equal(t1, "t1");
    const [a, b] = await Promise.all([
      provider.refresh("t1"),
      provider.refresh("t1"),
    ]);
    assert.equal(a, "t2");
    assert.equal(b, "t2");
    assert.equal(mintCount, 2);
    const later = await provider.refresh("t1");
    assert.equal(later, "t2");
    assert.equal(mintCount, 2);
    const t3 = await provider.refresh("t2");
    assert.equal(t3, "t3");
    assert.equal(mintCount, 3);
  });

  it("bearer refresh cannot retry", async () => {
    const bearer = azureCreds.createBearerTokenProvider("pasted");
    assert.equal(await bearer.refresh("pasted"), null);
  });

  it("maps mint HTTP errors through static messages", async () => {
    const fetchImpl = async () => ({
      ok: false,
      json: async () => ({
        error: "invalid_client",
        error_codes: [7000222],
        error_description: "echo client_secret",
      }),
    });
    await assert.rejects(
      () =>
        azureCreds.mintAccessToken({
          tenantId: "t",
          clientId: "c",
          clientSecret: "s",
          scope: azureCreds.GRAPH_SCOPE,
          fetchImpl,
        }),
      (err) => {
        assert.equal(err.status, 401);
        assert.match(err.message, /Client secret is invalid or expired/);
        assert.ok(!err.message.includes("echo"));
        return true;
      },
    );
  });
});

describe("auto-sync credential validation", () => {
  it("requires vaultUrl for both azure methods", () => {
    assert.match(
      validateAutoSyncCredentials("azure", { token: "t" }),
      /vaultUrl/,
    );
    assert.match(
      validateAutoSyncCredentials("azure", {
        authMethod: "client_credentials",
        tenantId: "t",
        clientId: "c",
        clientSecret: "s",
      }),
      /vaultUrl/,
    );
    assert.equal(
      validateAutoSyncCredentials("azure", {
        vaultUrl: "https://v.vault.azure.net",
        token: "t",
      }),
      null,
    );
    assert.equal(
      validateAutoSyncCredentials("azure", {
        vaultUrl: "https://v.vault.azure.net",
        authMethod: "client_credentials",
        tenantId: "t",
        clientId: "c",
        clientSecret: "s",
      }),
      null,
    );
  });

  it("rejects unknown explicit authMethod and defaults omitted to token", () => {
    assert.match(
      validateAutoSyncCredentials("azure-ad", { authMethod: "foo", token: "t" }),
      /Unknown authMethod/,
    );
    assert.equal(
      validateAutoSyncCredentials("azure-ad", { token: "t" }),
      null,
    );
    assert.match(
      validateAutoSyncCredentials("azure-ad", { authMethod: "", token: "t" }),
      /authMethod must be/,
    );
    assert.match(
      validateAutoSyncCredentials("azure-ad", { authMethod: null, token: "t" }),
      /authMethod must be/,
    );
  });

  it("forwards client credentials, vaultUrl, include, maxItems, and filterRules", () => {
    const body = buildAzureAutoSyncScanBody(
      "azure",
      {
        authMethod: "client_credentials",
        vaultUrl: "https://v.vault.azure.net",
        tenantId: "tid",
        clientId: "cid",
        clientSecret: "csec",
      },
      {
        include: { secrets: true, certificates: false, keys: false },
        maxItems: 25,
        filterRules: [{ type: "include", field: "name", value: "prod" }],
      },
    );
    assert.equal(body.authMethod, "client_credentials");
    assert.equal(body.vaultUrl, "https://v.vault.azure.net");
    assert.equal(body.tenantId, "tid");
    assert.equal(body.clientSecret, "csec");
    assert.equal(body.token, undefined);
    assert.deepEqual(body.include, {
      secrets: true,
      certificates: false,
      keys: false,
    });
    assert.equal(body.maxItems, 25);
    assert.equal(body.filterRules.length, 1);
  });
});

describe("Key Vault inventory from list attributes", () => {
  it("propagates collection 404 instead of returning empty", async () => {
    const azure = requireWithMocks(resolveAzureIntegration(), {
      axios: async () => {
        throw httpError(404);
      },
    });
    await assert.rejects(
      () =>
        azure._test.listSecrets({
          vaultUrl: "https://vault.example.com",
          token: "token",
        }),
      (err) => err.status === 404,
    );
  });

  it("does not call GET /secrets/{name} and still inventories from list attributes", async () => {
    const urls = [];
    const azure = requireWithMocks(resolveAzureIntegration(), {
      axios: async (config) => {
        urls.push(String(config.url));
        if (String(config.url).includes("/secrets?")) {
          return {
            data: {
              value: [
                {
                  id: "https://vault.example.com/secrets/db-password",
                  attributes: {
                    enabled: true,
                    exp: 1893456000,
                    created: 1704067200,
                    updated: 1704153600,
                  },
                },
              ],
            },
          };
        }
        throw httpError(403);
      },
    });
    const result = await azure.scanAzure({
      vaultUrl: "https://vault.example.com",
      token: "token",
      include: { secrets: true, certificates: false, keys: false },
    });
    assert.equal(result.items.length, 1);
    assert.equal(result.items[0].name, "db-password");
    assert.ok(result.items[0].expiration);
    assert.ok(result.items[0].created_at);
    assert.ok(result.items[0].updated_at);
    assert.equal(result.summary[0].complete, true);
    assert.ok(urls.every((u) => !/\/secrets\/db-password(?:\?|$)/.test(u)));
  });

  it("Reader-only detail 403 still inventories certificates from list attributes", async () => {
    const azure = requireWithMocks(resolveAzureIntegration(), {
      axios: async (config) => {
        const url = String(config.url);
        if (url.includes("/certificates?") || /\/certificates\?/.test(url)) {
          return {
            data: {
              value: [
                {
                  id: "https://vault.example.com/certificates/web",
                  attributes: {
                    enabled: true,
                    exp: 1893456000,
                    created: 1704067200,
                    updated: 1704153600,
                  },
                },
              ],
            },
          };
        }
        if (url.includes("/certificates/web")) {
          throw httpError(403);
        }
        return { data: { value: [] } };
      },
    });
    const result = await azure.scanAzure({
      vaultUrl: "https://vault.example.com",
      token: "token",
      include: { secrets: false, certificates: true, keys: false },
    });
    assert.equal(result.items.length, 1);
    assert.equal(result.items[0].name, "web");
    assert.ok(result.items[0].expiration);
    assert.ok(result.items[0].created_at);
    assert.equal(result.summary[0].complete, true);
  });

  it("partial 403 leaves other scopes complete", async () => {
    const azure = requireWithMocks(resolveAzureIntegration(), {
      axios: async (config) => {
        const url = String(config.url);
        if (url.includes("/secrets")) throw httpError(403);
        if (url.includes("/certificates")) {
          return { data: { value: [] } };
        }
        if (url.includes("/keys")) {
          return {
            data: {
              value: [
                {
                  kid: "https://vault.example.com/keys/k1",
                  attributes: { enabled: true, exp: 1893456000 },
                },
              ],
            },
          };
        }
        return { data: { value: [] } };
      },
    });
    const result = await azure.scanAzure({
      vaultUrl: "https://vault.example.com",
      token: "token",
      include: { secrets: true, certificates: true, keys: true },
    });
    const byType = Object.fromEntries(result.summary.map((s) => [s.type, s]));
    assert.equal(byType.secrets.complete, false);
    assert.equal(byType.secrets.status, 403);
    assert.equal(byType.certificates.complete, true);
    assert.equal(byType.keys.complete, true);
    assert.equal(result.items.length, 1);
  });

  it("all collection 403 throws 403, not 401", async () => {
    const azure = requireWithMocks(resolveAzureIntegration(), {
      axios: async () => {
        throw httpError(403);
      },
    });
    await assert.rejects(
      () =>
        azure.scanAzure({
          vaultUrl: "https://vault.example.com",
          token: "token",
        }),
      (err) => err.status === 403 && err.message === "Permission denied",
    );
  });

  it("all collection 404 throws 404", async () => {
    const azure = requireWithMocks(resolveAzureIntegration(), {
      axios: async () => {
        throw httpError(404);
      },
    });
    await assert.rejects(
      () =>
        azure.scanAzure({
          vaultUrl: "https://vault.example.com",
          token: "token",
          include: { secrets: true, certificates: false, keys: false },
        }),
      (err) => err.status === 404,
    );
  });

  it("retries a 401 once per request and never retries 403", async () => {
    const calls = [];
    const azure = requireWithMocks(resolveAzureIntegration(), {
      axios: async (config) => {
        calls.push(String(config.headers.Authorization));
        if (calls.length === 1) throw httpError(401);
        return { data: { value: [] } };
      },
    });
    let mint = 0;
    const authProvider = {
      getToken: async () => "t1",
      refresh: async () => {
        mint += 1;
        return "t2";
      },
    };
    await azure._test.listSecrets({
      vaultUrl: "https://vault.example.com",
      token: "t1",
      authProvider,
    });
    assert.equal(mint, 1);
    assert.deepEqual(calls, ["Bearer t1", "Bearer t2"]);

    const forbiddenCalls = [];
    const azure403 = requireWithMocks(resolveAzureIntegration(), {
      axios: async (config) => {
        forbiddenCalls.push(String(config.headers.Authorization));
        throw httpError(403);
      },
    });
    await assert.rejects(
      () =>
        azure403._test.listSecrets({
          vaultUrl: "https://vault.example.com",
          token: "t1",
          authProvider: { refresh: async () => "t2" },
        }),
      (err) => err.status === 403,
    );
    assert.equal(forbiddenCalls.length, 1);
  });

  it("after a page-1 refresh, page 2's first request uses the cached token", async () => {
    const calls = [];
    let current = "t1";
    const authProvider = {
      getToken: async () => current,
      refresh: async (failed) => {
        if (failed === current) current = "t2";
        return current;
      },
    };
    const azure = requireWithMocks(resolveAzureIntegration(), {
      axios: async (config) => {
        const auth = String(config.headers.Authorization);
        calls.push(auth);
        if (auth === "Bearer t1") throw httpError(401);
        const url = String(config.url);
        if (!url.includes("skiptoken")) {
          return {
            data: {
              value: [
                { id: "https://vault.example.com/secrets/a" },
              ],
              nextLink:
                "https://vault.example.com/secrets?api-version=7.4&$skiptoken=p2",
            },
          };
        }
        return {
          data: {
            value: [{ id: "https://vault.example.com/secrets/b" }],
          },
        };
      },
    });
    const listed = await azure._test.listSecrets({
      vaultUrl: "https://vault.example.com",
      token: "t1",
      authProvider,
    });
    assert.equal(listed.items.length, 2);
    assert.deepEqual(calls, ["Bearer t1", "Bearer t2", "Bearer t2"]);
  });
});

describe("Entra inventory collection failures", () => {
  it("all Graph 403 throws 403, not 401", async () => {
    const azureAd = requireWithMocks(
      path.resolve(__dirname, "../../apps/api/services/azureADIntegration.js"),
      {
        axios: async () => {
          throw httpError(403);
        },
      },
    );
    const payload = Buffer.from(
      JSON.stringify({
        tid: "11111111-1111-1111-1111-111111111111",
        aud: "https://graph.microsoft.com",
      }),
    ).toString("base64");
    const token = `eyJhbGciOiJub25lIn0.${payload}.sig`;
    await assert.rejects(
      () => azureAd.scanAzureAD({ token }),
      (err) => err.status === 403 && err.message === "Permission denied",
    );
  });
});

describe("Azure scan route user messages", () => {
  it("all-403 uses the Reader role message, not authentication failed", () => {
    const msg = azureKeyVaultUserMessage(
      { status: 403, message: "Permission denied" },
      "ref",
      () => "fallback",
    );
    assert.match(msg, /Key Vault Reader/);
    assert.ok(!/authentication failed/i.test(msg));
  });

  it("all-404 uses the not-found message", () => {
    const msg = azureKeyVaultUserMessage(
      { status: 404, message: "Not found" },
      "ref",
      () => "fallback",
    );
    assert.match(msg, /Key Vault not found/);
  });

  it("Graph 403 recommends Application.Read.All over Directory.Read.All", () => {
    const msg = azureAdUserMessage(
      { status: 403, message: "Permission denied" },
      "ref",
      () => "fallback",
    );
    assert.match(msg, /Application\.Read\.All/);
    assert.match(msg, /broader/);
  });

  it("tenant discovery errors keep their own message", () => {
    const discovery = {
      status: 400,
      message: "Tenant not found. Check tenantId.",
      azureTenantDiscovery: true,
    };
    const kv = azureKeyVaultUserMessage(discovery, "ref", () => "fallback");
    assert.equal(kv, "Tenant not found. Check tenantId.");
    assert.ok(!/vault URL/i.test(kv));
    const ad = azureAdUserMessage(discovery, "ref", () => "fallback");
    assert.equal(ad, "Tenant not found. Check tenantId.");
    assert.ok(!/Microsoft Graph/i.test(ad));
  });
});

describe("secret redaction", () => {
  it("redacts clientSecret in logger metadata", () => {
    const out = redactSensitiveFields({
      clientSecret: "super-secret",
      tenantId: "tid",
    });
    assert.equal(out.clientSecret, "[REDACTED]");
    assert.equal(out.tenantId, "tid");
  });

  it("scrubs request bodies including mint failures", () => {
    const body = { token: "t", clientSecret: "s", tenantId: "tid" };
    azureCreds.scrubAzureSecretsFromBody(body);
    assert.equal(body.token, undefined);
    assert.equal(body.clientSecret, undefined);
    assert.equal(body.tenantId, "tid");
  });
});

describe("auto-sync audit rows", () => {
  it("AUTO_SYNC_CREATED metadata is only the provider, never credentials", () => {
    const adminSrc = fs.readFileSync(
      path.resolve(__dirname, "../../apps/api/routes/admin.js"),
      "utf8",
    );
    assert.match(
      adminSrc,
      /action: "AUTO_SYNC_CREATED"[\s\S]{0,500}metadata: \{ provider \}/,
    );
    assert.doesNotMatch(adminSrc, /tokenPrefix/);
    assert.doesNotMatch(
      adminSrc,
      /action: "AUTO_SYNC_CREATED"[\s\S]{0,500}clientSecret/,
    );
  });
});

describe("auto-sync replacement secret lifetime", () => {
  it("clears Azure replacement state after PUT, before the config refresh GET", () => {
    const modalSrc = fs.readFileSync(
      path.resolve(
        __dirname,
        "../../apps/dashboard/src/components/ImportTokensModal.jsx",
      ),
      "utf8",
    );
    const saveMatch = modalSrc.match(
      /const handleSaveAutoSyncChanges = async \(\) => \{([\s\S]*?)\n  \};/,
    );
    assert.ok(saveMatch);
    const body = saveMatch[1];
    const putAt = body.indexOf("apiClient.put");
    const getAt = body.indexOf("apiClient.get");
    const clearAt = body.indexOf("resetReplacement");
    assert.ok(putAt >= 0 && getAt > putAt);
    assert.ok(clearAt > putAt && clearAt < getAt);
  });
});

describe("Azure Key Vault OpenAPI scan request", () => {
  it("bearer and client-credentials variants keep include, maxItems, and filterRules", () => {
    const openapi = fs.readFileSync(
      path.resolve(
        __dirname,
        "../../packages/contracts/openapi/openapi.yaml",
      ),
      "utf8",
    );
    const bearerStart = openapi.indexOf("    AzureKeyVaultBearerScanRequest:");
    const clientStart = openapi.indexOf(
      "    AzureKeyVaultClientCredentialsScanRequest:",
    );
    const adStart = openapi.indexOf("    AzureAdScanRequest:");
    assert.ok(bearerStart > 0 && clientStart > bearerStart && adStart > clientStart);
    const bearer = openapi.slice(bearerStart, clientStart);
    const client = openapi.slice(clientStart, adStart);
    for (const section of [bearer, client]) {
      assert.match(section, /\n        include:\n/);
      assert.match(section, /\n        maxItems:\n/);
      assert.match(section, /\n        filterRules:\n/);
    }
    assert.match(bearer, /required: \[vaultUrl, token\]/);
    assert.match(
      client,
      /required: \[vaultUrl, authMethod, tenantId, clientId, clientSecret\]/,
    );
    assert.match(bearer, /minLength: 1/);
    assert.match(client, /minLength: 1/);
  });
});

describe("authMethod contract", () => {
  it("defaults only omitted authMethod to token and rejects empty or null", async () => {
    assert.equal(azureCreds.resolveAuthMethod(undefined), "token");
    await assert.rejects(
      () => azureCreds.resolveAzureScanAuth({ authMethod: "", token: "t" }),
      (err) => err.status === 400,
    );
    await assert.rejects(
      () => azureCreds.resolveAzureScanAuth({ authMethod: null, token: "t" }),
      (err) => err.status === 400,
    );
  });
});

describe("canonical tenant provenance", () => {
  const TENANT_GUID = "11111111-1111-1111-1111-111111111111";

  it("skips OpenID discovery when tenantId is already a GUID", async () => {
    const urls = [];
    const fetchImpl = async (url) => {
      urls.push(String(url));
      return { ok: true, json: async () => ({ access_token: "minted" }) };
    };
    const resolved = await azureCreds.resolveAzureScanAuth({
      authMethod: "client_credentials",
      tenantId: TENANT_GUID.toUpperCase(),
      clientId: "cid",
      clientSecret: "csec",
      scope: azureCreds.GRAPH_SCOPE,
      fetchImpl,
    });
    assert.equal(resolved.tenantId, TENANT_GUID);
    assert.equal(resolved.token, "minted");
    assert.equal(urls.length, 1);
    assert.match(urls[0], new RegExp(`${TENANT_GUID}/oauth2/v2.0/token`, "i"));
    assert.doesNotMatch(urls[0], /openid-configuration/);
  });

  it("discovers a tenant GUID from OpenID issuer before minting", async () => {
    const urls = [];
    const fetchImpl = async (url) => {
      urls.push(String(url));
      if (String(url).includes("openid-configuration")) {
        return {
          ok: true,
          json: async () => ({
            issuer: `https://login.microsoftonline.com/${TENANT_GUID}/v2.0`,
          }),
        };
      }
      return { ok: true, json: async () => ({ access_token: "minted" }) };
    };
    const resolved = await azureCreds.resolveAzureScanAuth({
      authMethod: "client_credentials",
      tenantId: "contoso.onmicrosoft.com",
      clientId: "cid",
      clientSecret: "csec",
      scope: azureCreds.GRAPH_SCOPE,
      fetchImpl,
    });
    assert.equal(resolved.tenantId, TENANT_GUID);
    assert.match(urls[0], /contoso\.onmicrosoft\.com/);
    assert.match(urls[0], /openid-configuration/);
    assert.match(urls[1], new RegExp(`${TENANT_GUID}/oauth2/v2.0/token`));
  });

  it("Key Vault client credentials mint against the supplied tenant and skip OpenID discovery", async () => {
    const urls = [];
    const fetchImpl = async (url) => {
      urls.push(String(url));
      return { ok: true, json: async () => ({ access_token: "minted-kv" }) };
    };
    const resolved = await azureCreds.resolveAzureScanAuth({
      authMethod: "client_credentials",
      tenantId: "contoso.onmicrosoft.com",
      clientId: "cid",
      clientSecret: "csec",
      scope: azureCreds.KEY_VAULT_SCOPE,
      fetchImpl,
    });
    assert.equal(resolved.token, "minted-kv");
    assert.equal(resolved.tenantId, undefined);
    assert.equal(urls.length, 1);
    assert.match(urls[0], /contoso\.onmicrosoft\.com\/oauth2\/v2\.0\/token/);
    assert.doesNotMatch(urls[0], /openid-configuration/);
  });

  it("maps discovery 429 and 5xx separately from a bad tenant", async () => {
    await assert.rejects(
      () =>
        azureCreds.resolveCanonicalTenantId(
          "contoso.onmicrosoft.com",
          async () => ({ ok: false, status: 429, json: async () => ({}) }),
        ),
      (err) =>
        err.status === 429 &&
        err.azureTenantDiscovery === true &&
        /rate limit/i.test(err.message),
    );
    await assert.rejects(
      () =>
        azureCreds.resolveCanonicalTenantId(
          "contoso.onmicrosoft.com",
          async () => ({ ok: false, status: 503, json: async () => ({}) }),
        ),
      (err) =>
        err.status === 502 &&
        err.azureTenantDiscovery === true &&
        /discovery request failed/i.test(err.message),
    );
    await assert.rejects(
      () =>
        azureCreds.resolveCanonicalTenantId(
          "contoso.onmicrosoft.com",
          async () => ({ ok: false, status: 404, json: async () => ({}) }),
        ),
      (err) =>
        err.status === 400 &&
        err.azureTenantDiscovery === true &&
        err.message === "Tenant not found. Check tenantId.",
    );
  });
});

describe("Entra scan tenant attribution", () => {
  it("uses a provided GUID and does not require a JWT tid claim", async () => {
    const azureAd = requireWithMocks(
      path.resolve(__dirname, "../../apps/api/services/azureADIntegration.js"),
      {
        axios: async () => ({ data: { value: [] } }),
      },
    );
    const result = await azureAd.scanAzureAD({
      token: "opaque-graph-token",
      tenantId: "11111111-1111-1111-1111-111111111111",
      include: { applications: true, servicePrincipals: false },
    });
    assert.equal(result.tenantId, "11111111-1111-1111-1111-111111111111");
  });

  it("rejects an opaque token when no canonical tenant GUID is provided", async () => {
    const azureAd = requireWithMocks(
      path.resolve(__dirname, "../../apps/api/services/azureADIntegration.js"),
      {
        axios: async () => ({ data: { value: [] } }),
      },
    );
    await assert.rejects(
      () => azureAd.scanAzureAD({ token: "opaque-graph-token" }),
      (err) => err.status === 401,
    );
  });

  it("after a Graph page-1 refresh, page 2's first request uses the cached token", async () => {
    const calls = [];
    let current = "t1";
    const authProvider = {
      getToken: async () => current,
      refresh: async (failed) => {
        if (failed === current) current = "t2";
        return current;
      },
    };
    const azureAd = requireWithMocks(
      path.resolve(__dirname, "../../apps/api/services/azureADIntegration.js"),
      {
        axios: async (config) => {
          const auth = String(config.headers.Authorization);
          calls.push(auth);
          if (auth === "Bearer t1") throw httpError(401);
          const url = String(config.url);
          if (!url.includes("skiptoken")) {
            return {
              data: {
                value: [{ id: "app-1", displayName: "A", passwordCredentials: [], keyCredentials: [] }],
                "@odata.nextLink":
                  "https://graph.microsoft.com/v1.0/applications?$skiptoken=p2",
              },
            };
          }
          return {
            data: {
              value: [{ id: "app-2", displayName: "B", passwordCredentials: [], keyCredentials: [] }],
            },
          };
        },
      },
    );
    const listed = await azureAd._test.listApplications({
      token: "t1",
      authProvider,
    });
    assert.equal(listed.items.length, 2);
    assert.deepEqual(calls, ["Bearer t1", "Bearer t2", "Bearer t2"]);
  });
});

describe("Azure scan route wiring", () => {
  const integrationsSrc = fs.readFileSync(
    path.resolve(__dirname, "../../apps/api/routes/integrations.js"),
    "utf8",
  );

  it("Entra scan passes the canonical tenant GUID into scanAzureAD", () => {
    assert.match(
      integrationsSrc,
      /scanAzureAD\(\{[\s\S]*tenantId:\s*resolved\.tenantId/,
    );
  });

  it("scrubs secrets in finally on both Azure scan routes", () => {
    assert.equal(
      (integrationsSrc.match(/scrubAzureSecretsFromBody\(req\.body\)/g) || [])
        .length,
      2,
    );
  });

  it("scrubs the request body after a thrown client-credential mint", async () => {
    const body = {
      authMethod: "client_credentials",
      tenantId: "11111111-1111-1111-1111-111111111111",
      clientId: "cid",
      clientSecret: "leaked-secret",
      token: "pasted-token",
    };
    await assert.rejects(
      () =>
        azureCreds.resolveAzureScanAuth({
          ...body,
          scope: azureCreds.KEY_VAULT_SCOPE,
          fetchImpl: async () => ({
            ok: false,
            json: async () => ({ error_codes: [7000215] }),
          }),
        }),
      (err) => err.status === 401,
    );
    azureCreds.scrubAzureSecretsFromBody(body);
    assert.equal(body.clientSecret, undefined);
    assert.equal(body.token, undefined);
  });

  it("client-credential mint then Key Vault scan uses the minted token", async () => {
    const auths = [];
    const resolved = await azureCreds.resolveAzureScanAuth({
      authMethod: "client_credentials",
      tenantId: "11111111-1111-1111-1111-111111111111",
      clientId: "cid",
      clientSecret: "csec",
      scope: azureCreds.KEY_VAULT_SCOPE,
      fetchImpl: async () => ({
        ok: true,
        json: async () => ({ access_token: "minted-kv" }),
      }),
    });
    const azure = requireWithMocks(resolveAzureIntegration(), {
      axios: async (config) => {
        auths.push(String(config.headers.Authorization));
        return { data: { value: [] } };
      },
    });
    await azure.scanAzure({
      vaultUrl: "https://vault.example.com",
      token: resolved.token,
      authProvider: resolved.authProvider,
      include: { secrets: true, certificates: false, keys: false },
    });
    assert.ok(auths.every((value) => value === "Bearer minted-kv"));
    assert.equal(resolved.token, "minted-kv");
  });
});

