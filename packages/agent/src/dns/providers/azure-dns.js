"use strict";

/**
 * Azure DNS DNS-01 provider.
 *
 * Auth: OAuth2 client-credentials flow against
 * login.microsoftonline.com/<tenantId>/oauth2/v2.0/token with scope
 * https://management.azure.com/.default, then bearer calls against the
 * Azure Resource Manager API. Scope the service principal to the
 * "DNS Zone Contributor" role on the target zone(s) only.
 *
 * Credentials shape:
 *   {
 *     tenantId: string,
 *     clientId: string,
 *     clientSecret: string,
 *     subscriptionId: string,
 *     resourceGroup: string,
 *   }
 *
 * API surface used (management.azure.com, api-version 2018-05-01):
 *   PUT    .../dnsZones/<zone>/TXT/<relativeRecordName>   create/replace TXT
 *   DELETE .../dnsZones/<zone>/TXT/<relativeRecordName>   delete TXT
 *
 * The record name sent to Azure is RELATIVE to the zone ("@" at the apex).
 * A fresh token is fetched per operation; challenge flows are far shorter
 * than token lifetimes, so no caching layer is warranted here.
 */

const {
  isNonEmptyString,
  relativeRecordName,
  fetchWithTimeout,
} = require("../internal.js");

const PROVIDER_ID = "azure-dns";
const LOGIN_BASE_URL = "https://login.microsoftonline.com";
const MANAGEMENT_BASE_URL = "https://management.azure.com";
const MANAGEMENT_SCOPE = "https://management.azure.com/.default";
const API_VERSION = "2018-05-01";
const TXT_TTL_SECONDS = 60;

const REQUIRED_FIELDS = Object.freeze([
  "tenantId",
  "clientId",
  "clientSecret",
  "subscriptionId",
  "resourceGroup",
]);

/**
 * @param {object} credentials
 */
function validateCredentials(credentials) {
  for (const field of REQUIRED_FIELDS) {
    if (!isNonEmptyString(credentials[field])) {
      throw new Error(`dns: azure-dns credentials require a non-empty ${field} string`);
    }
  }
  return {
    tenantId: credentials.tenantId,
    clientId: credentials.clientId,
    clientSecret: credentials.clientSecret,
    subscriptionId: credentials.subscriptionId,
    resourceGroup: credentials.resourceGroup,
  };
}

/**
 * @param {ReturnType<typeof validateCredentials>} credentials
 * @returns {string[]} secret strings to redact from any excerpt
 */
function collectSecretStrings(credentials) {
  return [credentials.clientSecret, credentials.clientId];
}

function createSolverImpl({ credentials, fetchImpl, timeoutMs, excerpt }) {
  function httpFailure(operationLabel, response) {
    return {
      ok: false,
      statusCode: response.status,
      detail: excerpt(`azure-dns ${operationLabel} failed (HTTP ${response.status}): ${response.bodyText}`),
    };
  }

  /**
   * Client-credentials token request. Returns { ok:true, accessToken } or
   * an ok:false operational failure.
   */
  async function fetchAccessToken() {
    const response = await fetchWithTimeout(
      fetchImpl,
      `${LOGIN_BASE_URL}/${encodeURIComponent(credentials.tenantId)}/oauth2/v2.0/token`,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id: credentials.clientId,
          client_secret: credentials.clientSecret,
          scope: MANAGEMENT_SCOPE,
        }).toString(),
      },
      timeoutMs,
    );
    if (!response.ok) {
      return httpFailure("token request", response);
    }

    let accessToken = null;
    try {
      const parsed = JSON.parse(response.bodyText);
      accessToken = parsed && typeof parsed.access_token === "string" ? parsed.access_token : null;
    } catch {
      // fall through to the failure below
    }
    if (!isNonEmptyString(accessToken)) {
      return {
        ok: false,
        statusCode: response.status,
        detail: excerpt("azure-dns token response carried no access_token"),
      };
    }
    return { ok: true, accessToken };
  }

  function recordSetUrl(zone, recordName) {
    const relative = relativeRecordName(recordName, zone) || "@";
    return (
      `${MANAGEMENT_BASE_URL}/subscriptions/${encodeURIComponent(credentials.subscriptionId)}` +
      `/resourceGroups/${encodeURIComponent(credentials.resourceGroup)}` +
      `/providers/Microsoft.Network/dnsZones/${encodeURIComponent(zone)}` +
      `/TXT/${encodeURIComponent(relative)}` +
      `?api-version=${API_VERSION}`
    );
  }

  async function presentChallenge({ zone, recordName, txtValue }) {
    const tokenResult = await fetchAccessToken();
    if (!tokenResult.ok) {
      return tokenResult;
    }

    const response = await fetchWithTimeout(
      fetchImpl,
      recordSetUrl(zone, recordName),
      {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${tokenResult.accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          properties: {
            TTL: TXT_TTL_SECONDS,
            TXTRecords: [{ value: [txtValue] }],
          },
        }),
      },
      timeoutMs,
    );
    if (!response.ok) {
      return httpFailure("record PUT", response);
    }

    return { ok: true };
  }

  async function cleanupChallenge({ zone, recordName }) {
    const tokenResult = await fetchAccessToken();
    if (!tokenResult.ok) {
      return tokenResult;
    }

    const response = await fetchWithTimeout(
      fetchImpl,
      recordSetUrl(zone, recordName),
      {
        method: "DELETE",
        headers: { Authorization: `Bearer ${tokenResult.accessToken}` },
      },
      timeoutMs,
    );
    // 404 on delete means the record is already gone: cleanup is
    // idempotent, so that is success, not failure.
    if (!response.ok && response.status !== 404) {
      return httpFailure("record DELETE", response);
    }

    return { ok: true };
  }

  return { presentChallenge, cleanupChallenge };
}

module.exports = {
  PROVIDER_ID,
  LOGIN_BASE_URL,
  MANAGEMENT_BASE_URL,
  validateCredentials,
  collectSecretStrings,
  createSolverImpl,
};
