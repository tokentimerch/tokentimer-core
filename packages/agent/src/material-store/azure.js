"use strict";
// Customer-side secret VALUE API. The Certificates API's public certificate
// metadata is not retrievable private-key material; non-exportable/HSM keys
// cannot implement this distribution contract.
const crypto = require("node:crypto");
const fs = require("node:fs");
const { requestJson } = require("./transport");
const { readProtectedFile, validateBundle, failure } = require("./index");
const VERSION = /^[a-f0-9]{32}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const MAX_SECRET_BYTES = 25 * 1024;
const API_VERSION = "7.4";
const CONTENT_TYPE =
  "application/vnd.tokentimer.certificate-bundle+json;version=1";

function credential(config, timeoutMs, requestImpl = requestJson) {
  const auth = config.auth;
  if (
    !auth ||
    !["token-file", "workload-identity", "managed-identity"].includes(auth.type)
  )
    throw failure("material_auth_config_invalid");
  if (
    auth.type === "workload-identity" &&
    (!UUID.test(auth.tenantId || "") || !UUID.test(auth.clientId || ""))
  )
    throw failure("material_auth_config_invalid");
  if (auth.clientId && !UUID.test(auth.clientId))
    throw failure("material_auth_config_invalid");
  let cached;
  return async (refresh = false) => {
    // Read sinks on every request: an externally rotated/revoked token is never
    // hidden behind our cache. Workload assertions are reread at renewal.
    if (
      auth.type !== "token-file" &&
      !refresh &&
      cached?.expires > Date.now() + 120000
    )
      return cached.token;
    try {
      let value;
      if (auth.type === "token-file")
        value = JSON.parse(readProtectedFile(auth.tokenFile, 16384));
      else {
        let response;
        if (auth.type === "workload-identity") {
          const assertion = readProtectedFile(auth.assertionFile, 16384).trim();
          if (!/^[A-Za-z0-9_.-]{20,16384}$/.test(assertion))
            throw failure("material_auth_unavailable");
          response = await requestImpl(
            new URL(
              `https://login.microsoftonline.com/${auth.tenantId}/oauth2/v2.0/token`,
            ),
            {
              method: "POST",
              timeoutMs,
              maxBytes: 32768,
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                client_id: auth.clientId,
                grant_type: "client_credentials",
                scope: "https://vault.azure.net/.default",
                client_assertion: assertion,
                client_assertion_type:
                  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
              }).toString(),
            },
          );
        } else {
          const url = new URL(
            "http://169.254.169.254/metadata/identity/oauth2/token",
          );
          url.search = new URLSearchParams({
            "api-version": "2018-02-01",
            resource: "https://vault.azure.net",
            ...(auth.clientId ? { client_id: auth.clientId } : {}),
          });
          response = await requestImpl(url, {
            timeoutMs,
            maxBytes: 32768,
            headers: { Metadata: "true" },
          });
        }
        if (response.status !== 200) throw failure("material_auth_unavailable");
        value = {
          accessToken: response.json.access_token,
          expiresOn: response.json.expires_on
            ? Number(response.json.expires_on) * 1000
            : Date.now() + Number(response.json.expires_in) * 1000,
        };
      }
      const expires =
        typeof value.expiresOn === "number"
          ? value.expiresOn
          : Date.parse(value.expiresOn);
      if (
        !/^[A-Za-z0-9_.~-]{20,16384}$/.test(value.accessToken || "") ||
        !Number.isFinite(expires) ||
        expires < Date.now() + 30000
      )
        throw failure("material_auth_unavailable");
      cached = { token: value.accessToken, expires };
      return cached.token;
    } catch {
      throw failure("material_auth_unavailable");
    }
  };
}

function createAzureStore(
  { config, scope, address, objectRef, timeoutMs, fixtureHttp },
  intent,
) {
  if (
    (!fixtureHttp &&
      !/^[a-z0-9-]{3,24}\.vault\.azure\.net$/i.test(address.hostname)) ||
    (address.port && address.port !== "443" && !fixtureHttp) ||
    config.namespace ||
    config.mount ||
    config.keyExportable === false ||
    (config.api && config.api !== "secrets")
  )
    throw failure("material_store_config_invalid");
  // A fixed-sized, tenant/group/version-scoped name carries no SANs or PII.
  const name = `tt-${crypto.createHash("sha256").update(`${intent.workspaceId}/${intent.groupId}/${objectRef}`).digest("hex")}`;
  const basePath = `/secrets/${name}`;
  const getToken = credential(config, timeoutMs);
  let ca;
  try {
    ca = config.caFile ? fs.readFileSync(config.caFile) : undefined;
  } catch {
    throw failure("material_store_config_invalid");
  }

  async function request(method, suffix = "", body) {
    const url = new URL(basePath + suffix, address);
    url.searchParams.set("api-version", API_VERSION);
    for (let attempt = 0; attempt < 3; attempt++) {
      const token = await getToken(attempt > 0);
      let response;
      try {
        response = await requestJson(url, {
          method,
          timeoutMs,
          ca,
          body,
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        });
      } catch (error) {
        if (method !== "GET" || attempt === 2) throw error;
        continue;
      }
      if (response.status === 404 && method === "GET") return null;
      if (response.status >= 200 && response.status < 300) return response.json;
      if (response.status === 401 && attempt === 0) continue;
      if (
        method === "GET" &&
        [408, 429, 500, 502, 503, 504].includes(response.status) &&
        attempt < 2
      ) {
        await new Promise((resolve) => setTimeout(resolve, 100 * 2 ** attempt));
        continue;
      }
      const error = failure(
        [401, 403].includes(response.status)
          ? "material_auth_denied"
          : response.status === 400
            ? "material_store_config_invalid"
            : "material_store_unavailable",
      );
      if ([400, 401, 403, 404].includes(response.status))
        error.writeRejected = true;
      throw error;
    }
    throw failure("material_auth_denied");
  }
  function versionFromId(id) {
    let url;
    try {
      url = new URL(id);
    } catch {
      throw failure("material_response_invalid");
    }
    const version = url.pathname.slice(basePath.length + 1);
    if (
      url.origin !== address.origin ||
      url.pathname !== `${basePath}/${version}` ||
      url.search ||
      url.hash ||
      !VERSION.test(version)
    )
      throw failure("material_response_invalid");
    return version;
  }
  async function fetch(providerVersion) {
    if (typeof providerVersion !== "string" || !VERSION.test(providerVersion))
      throw failure("material_provider_version_invalid");
    const result = await request("GET", `/${providerVersion}`);
    if (
      !result ||
      result.attributes?.enabled === false ||
      (result.attributes?.nbf && result.attributes.nbf * 1000 > Date.now()) ||
      (result.attributes?.exp && result.attributes.exp * 1000 <= Date.now())
    )
      throw failure("material_version_unavailable");
    if (
      versionFromId(result.id) !== providerVersion ||
      result.contentType !== CONTENT_TYPE ||
      typeof result.value !== "string" ||
      Buffer.byteLength(result.value) > MAX_SECRET_BYTES
    )
      throw failure("material_response_invalid");
    let bundle;
    try {
      bundle = JSON.parse(result.value);
    } catch {
      throw failure("material_bundle_invalid");
    }
    validateBundle(bundle, intent, scope);
    return bundle;
  }
  async function existingVersion() {
    const result = await request("GET", "/versions?maxresults=2");
    if (!result) return null;
    if (!Array.isArray(result.value))
      throw failure("material_response_invalid");
    // Azure has no CAS on Set Secret. Never adopt an ambiguous name, follow a
    // nextLink, overwrite it or fall back to latest. A single producer owns
    // each UUID object and uncertain PUTs are reconciled before further writes.
    if (result.nextLink || result.value.length > 1)
      throw failure("material_cas_conflict");
    return result.value.length ? versionFromId(result.value[0].id) : null;
  }
  async function recover() {
    const version = await existingVersion();
    if (!version) throw failure("material_version_unavailable");
    return fetch(version);
  }
  async function publish(
    bundle,
    {
      writeAttempted = false,
      beforeWrite = () => {},
      writeRejected = () => {},
    } = {},
  ) {
    const facts = validateBundle(bundle, intent, scope);
    const value = JSON.stringify(bundle);
    if (Buffer.byteLength(value) > MAX_SECRET_BYTES)
      throw failure("material_bundle_too_large");
    let version = await existingVersion();
    if (!version) {
      if (writeAttempted) throw failure("material_publication_uncertain");
      await beforeWrite(); // durable customer-local write-ahead marker
      try {
        const result = await request("PUT", "", {
          value,
          contentType: CONTENT_TYPE,
          attributes: {
            enabled: true,
            exp: Math.floor(Date.parse(facts.validTo) / 1000),
          },
        });
        if (result) version = versionFromId(result.id);
      } catch (error) {
        if (error.writeRejected === true) {
          await writeRejected();
          throw error;
        }
        // A timeout is ambiguous: reconcile, never repeat this PUT.
      }
      let found;
      try {
        found = await existingVersion();
      } catch {
        throw failure("material_publication_uncertain");
      }
      if (!found || (version && found !== version))
        throw failure("material_publication_uncertain");
      version = found;
    }
    let stored;
    try {
      stored = await fetch(version);
    } catch {
      throw failure("material_publication_uncertain");
    }
    if (
      stored.privateKeyPem !== bundle.privateKeyPem ||
      stored.certificatePem !== bundle.certificatePem
    )
      throw failure("material_cas_conflict");
    return {
      schemaVersion: 1,
      workspaceId: intent.workspaceId,
      groupId: intent.groupId,
      materialVersionId: intent.materialVersionId,
      materialStoreRef: intent.materialStoreRef,
      provider: "azure-key-vault",
      providerVersion: version,
      ...facts,
    };
  }
  return Object.freeze({ publish, fetch, recover, scope, objectRef: name });
}
module.exports = {
  createAzureStore,
  credential,
  VERSION,
  MAX_SECRET_BYTES,
  CONTENT_TYPE,
};
