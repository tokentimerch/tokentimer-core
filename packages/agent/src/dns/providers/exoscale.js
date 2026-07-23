"use strict";

/**
 * Exoscale DNS-01 provider.
 *
 * Auth: Exoscale API v2 request signing (EXO2-HMAC-SHA256), implemented
 * here with node:crypto only. Scope the IAM API key to the DNS service
 * only.
 *
 * Credentials shape:
 *   {
 *     apiKey: string,
 *     apiSecret: string,
 *     apiEndpoint?: string,  // default https://api-ch-gva-2.exoscale.com/v2;
 *                            // DNS is global, so any zone endpoint works
 *   }
 *
 * Signing spec (v2): the signed message is
 *   "METHOD /path\n" + body + "\n" + signedQueryArgs + "\n" + signedHeaders
 *   + "\n" + expires
 * with no signed query args and no signed headers (both lines empty --
 * this module never signs query strings), i.e. exactly
 *   `${method} ${path}\n${body}\n\n\n${expires}`
 * where `path` is the full URL pathname (including the /v2 prefix) and
 * `expires` is a unix-seconds expiry (now + 10 minutes here). The
 * signature is base64(HMAC-SHA256(apiSecret, message)), sent as
 *   Authorization: EXO2-HMAC-SHA256 credential=<apiKey>,expires=<unix>,signature=<b64>
 *
 * API surface used:
 *   GET    /dns-domain                          domain id lookup
 *   POST   /dns-domain/<id>/record              create TXT
 *   GET    /dns-domain/<id>/record              record lookup (cleanup)
 *   DELETE /dns-domain/<id>/record/<recordId>   delete TXT
 *
 * Exoscale v2 mutations are ASYNC: they return an operation object that
 * would normally be polled via /operation/<id>. This module deliberately
 * does NOT poll -- an accepted (2xx) response is treated as success, since
 * the ACME tool's propagation wait covers the (short) async apply window.
 *
 * The record name sent to Exoscale is RELATIVE to the zone ("" at the
 * apex). Record listing has no server-side filter, so cleanup matches
 * type + name + content client-side (accepting the content in raw or
 * quoted spelling, as the API returns TXT content quoted).
 */

const crypto = require("node:crypto");

const {
  isNonEmptyString,
  relativeRecordName,
  fetchWithTimeout,
} = require("../internal.js");

const PROVIDER_ID = "exoscale";
const DEFAULT_API_ENDPOINT = "https://api-ch-gva-2.exoscale.com/v2";
const TXT_TTL_SECONDS = 60;
const EXPIRES_WINDOW_SECONDS = 10 * 60;

// --------------------------------------------------------------------------
// EXO2-HMAC-SHA256 signing (exported for the fixed-vector signature test)
// --------------------------------------------------------------------------

/**
 * Computes the Exoscale v2 Authorization header. Deterministic given
 * `expires`, so tests can pin an exact signature for fixed keys.
 *
 * @param {object} options
 * @param {string} options.apiKey
 * @param {string} options.apiSecret
 * @param {string} options.method uppercase HTTP method
 * @param {string} options.path full URL pathname (e.g. "/v2/dns-domain")
 * @param {string} options.body raw request body ("" when none)
 * @param {number} options.expires unix seconds
 * @returns {{ message: string, signature: string, authorizationHeader: string }}
 */
function signExoscaleRequest({ apiKey, apiSecret, method, path, body, expires }) {
  // Empty signed-query-args and signed-headers lines: this module never
  // signs query strings or extra headers.
  const message = `${method} ${path}\n${body}\n\n\n${expires}`;
  const signature = crypto
    .createHmac("sha256", apiSecret)
    .update(message)
    .digest("base64");
  return {
    message,
    signature,
    authorizationHeader: `EXO2-HMAC-SHA256 credential=${apiKey},expires=${expires},signature=${signature}`,
  };
}

// --------------------------------------------------------------------------
// Provider contract
// --------------------------------------------------------------------------

/**
 * @param {object} credentials
 */
function validateCredentials(credentials) {
  if (!isNonEmptyString(credentials.apiKey)) {
    throw new Error("dns: exoscale credentials require a non-empty apiKey string");
  }
  if (!isNonEmptyString(credentials.apiSecret)) {
    throw new Error("dns: exoscale credentials require a non-empty apiSecret string");
  }
  if (credentials.apiEndpoint !== undefined && !isNonEmptyString(credentials.apiEndpoint)) {
    throw new Error("dns: exoscale apiEndpoint must be a non-empty string when provided");
  }
  return {
    apiKey: credentials.apiKey,
    apiSecret: credentials.apiSecret,
    apiEndpoint: (credentials.apiEndpoint || DEFAULT_API_ENDPOINT).replace(/\/+$/, ""),
  };
}

/**
 * @param {ReturnType<typeof validateCredentials>} credentials
 * @returns {string[]} secret strings to redact from any excerpt
 */
function collectSecretStrings(credentials) {
  return [credentials.apiSecret, credentials.apiKey];
}

function createSolverImpl({ credentials, fetchImpl, timeoutMs, excerpt }) {
  /**
   * Signs and sends one request against the configured endpoint.
   * @param {{ method: string, path: string, body?: object|null }} request
   *   `path` is relative to the endpoint (starts with "/", no query).
   */
  function signedFetch({ method, path, body = null }) {
    const url = `${credentials.apiEndpoint}${path}`;
    const bodyText = body === null ? "" : JSON.stringify(body);
    const expires = Math.floor(Date.now() / 1000) + EXPIRES_WINDOW_SECONDS;
    const { authorizationHeader } = signExoscaleRequest({
      apiKey: credentials.apiKey,
      apiSecret: credentials.apiSecret,
      method,
      path: new URL(url).pathname,
      body: bodyText,
      expires,
    });

    const headers = { Authorization: authorizationHeader };
    if (bodyText) {
      headers["Content-Type"] = "application/json";
    }

    return fetchWithTimeout(
      fetchImpl,
      url,
      { method, headers, ...(bodyText ? { body: bodyText } : {}) },
      timeoutMs,
    );
  }

  function httpFailure(operationLabel, response) {
    return {
      ok: false,
      statusCode: response.status,
      detail: excerpt(`exoscale ${operationLabel} failed (HTTP ${response.status}): ${response.bodyText}`),
    };
  }

  function parseJson(bodyText) {
    try {
      const parsed = JSON.parse(bodyText);
      return parsed && typeof parsed === "object" ? parsed : null;
    } catch {
      return null;
    }
  }

  /**
   * Looks the DNS domain id up by zone name (GET /dns-domain lists all
   * domains; there is no server-side name filter). Returns
   * { ok:true, domainId } or an ok:false failure.
   * @param {string} zone
   */
  async function resolveDomainId(zone) {
    const response = await signedFetch({ method: "GET", path: "/dns-domain" });
    if (!response.ok) {
      return httpFailure("domain lookup", response);
    }

    const parsed = parseJson(response.bodyText);
    const domains =
      parsed && Array.isArray(parsed["dns-domains"]) ? parsed["dns-domains"] : [];
    const normalizedZone = zone.toLowerCase();
    const match = domains.find((domain) => {
      const name = domain && (domain["unicode-name"] || domain.name);
      return typeof name === "string" && name.toLowerCase() === normalizedZone;
    });
    if (!match || !isNonEmptyString(match.id)) {
      return {
        ok: false,
        statusCode: response.status,
        detail: excerpt(`exoscale domain lookup returned no domain named ${JSON.stringify(zone)}`),
      };
    }
    return { ok: true, domainId: match.id };
  }

  async function presentChallenge({ zone, recordName, txtValue }) {
    const domainResult = await resolveDomainId(zone);
    if (!domainResult.ok) {
      return domainResult;
    }

    const response = await signedFetch({
      method: "POST",
      path: `/dns-domain/${encodeURIComponent(domainResult.domainId)}/record`,
      body: {
        name: relativeRecordName(recordName, zone),
        type: "TXT",
        content: txtValue,
        ttl: TXT_TTL_SECONDS,
      },
    });
    if (!response.ok) {
      return httpFailure("record create", response);
    }

    // The 2xx response is an async operation object; accepted == success
    // here (no polling), see the module header.
    return { ok: true };
  }

  async function cleanupChallenge({ zone, recordName, txtValue }) {
    const domainResult = await resolveDomainId(zone);
    if (!domainResult.ok) {
      return domainResult;
    }

    const listResponse = await signedFetch({
      method: "GET",
      path: `/dns-domain/${encodeURIComponent(domainResult.domainId)}/record`,
    });
    if (!listResponse.ok) {
      return httpFailure("record lookup", listResponse);
    }

    const relative = relativeRecordName(recordName, zone);
    const parsed = parseJson(listResponse.bodyText);
    const records =
      parsed && Array.isArray(parsed["dns-domain-records"])
        ? parsed["dns-domain-records"]
        : [];
    // Exact type + name + content match (raw or quoted content spelling)
    // so cleanup never deletes an unrelated record sharing the name.
    const matches = records.filter(
      (record) =>
        record &&
        record.type === "TXT" &&
        record.name === relative &&
        (record.content === txtValue || record.content === `"${txtValue}"`) &&
        isNonEmptyString(record.id),
    );
    if (matches.length === 0) {
      // Nothing to delete: cleanup is idempotent, an already-absent record
      // is success, not failure.
      return { ok: true };
    }

    for (const record of matches) {
      const deleteResponse = await signedFetch({
        method: "DELETE",
        path:
          `/dns-domain/${encodeURIComponent(domainResult.domainId)}` +
          `/record/${encodeURIComponent(record.id)}`,
      });
      // 404 means the record is already gone: idempotent success.
      if (!deleteResponse.ok && deleteResponse.status !== 404) {
        return httpFailure("record delete", deleteResponse);
      }
    }

    return { ok: true };
  }

  return { presentChallenge, cleanupChallenge };
}

module.exports = {
  PROVIDER_ID,
  DEFAULT_API_ENDPOINT,
  validateCredentials,
  collectSecretStrings,
  createSolverImpl,
  // Exported for the fixed-vector signature test only.
  signExoscaleRequest,
};
