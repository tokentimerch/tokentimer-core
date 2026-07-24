"use strict";

/**
 * Cloudflare DNS-01 provider.
 *
 * Auth: scoped API token (Authorization: Bearer). Create a token with
 * Zone.DNS:Edit on the target zone(s) only; never use a Global API Key.
 *
 * Credentials shape: { apiToken: string, zoneId?: string }
 *   - zoneId is optional; when absent the zone id is looked up by name via
 *     GET /zones?name=<zone> on every operation.
 *
 * API surface used (api.cloudflare.com/client/v4):
 *   GET    /zones?name=<zone>                       zone id lookup
 *   GET    /zones/<zoneId>/dns_records?...          record id lookup (cleanup)
 *   POST   /zones/<zoneId>/dns_records              create TXT
 *   DELETE /zones/<zoneId>/dns_records/<recordId>   delete TXT
 */

const { isNonEmptyString, fetchWithTimeout } = require("../internal.js");

const PROVIDER_ID = "cloudflare";
const API_BASE_URL = "https://api.cloudflare.com/client/v4";
const TXT_TTL_SECONDS = 60;

/**
 * @param {object} credentials
 * @returns {{ apiToken: string, zoneId: string|null }}
 */
function validateCredentials(credentials) {
  if (!isNonEmptyString(credentials.apiToken)) {
    throw new Error("dns: cloudflare credentials require a non-empty apiToken string");
  }
  if (credentials.zoneId !== undefined && !isNonEmptyString(credentials.zoneId)) {
    throw new Error("dns: cloudflare zoneId must be a non-empty string when provided");
  }
  return {
    apiToken: credentials.apiToken,
    zoneId: credentials.zoneId || null,
  };
}

/**
 * @param {ReturnType<typeof validateCredentials>} credentials
 * @returns {string[]} secret strings to redact from any excerpt
 */
function collectSecretStrings(credentials) {
  return [credentials.apiToken];
}

function createSolverImpl({ credentials, fetchImpl, timeoutMs, excerpt }) {
  function authHeaders() {
    return {
      Authorization: `Bearer ${credentials.apiToken}`,
      "Content-Type": "application/json",
    };
  }

  /**
   * Parses a Cloudflare v4 envelope body, returning null on any parse
   * problem (callers treat null as "unexpected response").
   * @param {string} bodyText
   */
  function parseEnvelope(bodyText) {
    try {
      const parsed = JSON.parse(bodyText);
      return parsed && typeof parsed === "object" ? parsed : null;
    } catch {
      return null;
    }
  }

  /** Maps a non-2xx response to the operational-failure result shape. */
  function httpFailure(operationLabel, response) {
    return {
      ok: false,
      statusCode: response.status,
      detail: excerpt(`cloudflare ${operationLabel} failed (HTTP ${response.status}): ${response.bodyText}`),
    };
  }

  /**
   * Resolves the zone id: configured zoneId wins, otherwise looked up by
   * exact zone name. Returns { ok:true, zoneId } or an ok:false failure.
   * @param {string} zone
   */
  async function resolveZoneId(zone) {
    if (credentials.zoneId) {
      return { ok: true, zoneId: credentials.zoneId };
    }

    const response = await fetchWithTimeout(
      fetchImpl,
      `${API_BASE_URL}/zones?name=${encodeURIComponent(zone)}`,
      { method: "GET", headers: authHeaders() },
      timeoutMs,
    );
    if (!response.ok) {
      return httpFailure("zone lookup", response);
    }

    const envelope = parseEnvelope(response.bodyText);
    const zoneId =
      envelope && Array.isArray(envelope.result) && envelope.result[0]
        ? envelope.result[0].id
        : null;
    if (!isNonEmptyString(zoneId)) {
      return {
        ok: false,
        statusCode: response.status,
        detail: excerpt(`cloudflare zone lookup returned no zone named ${JSON.stringify(zone)}`),
      };
    }
    return { ok: true, zoneId };
  }

  async function presentChallenge({ zone, recordName, txtValue }) {
    const zoneResult = await resolveZoneId(zone);
    if (!zoneResult.ok) {
      return zoneResult;
    }

    const response = await fetchWithTimeout(
      fetchImpl,
      `${API_BASE_URL}/zones/${encodeURIComponent(zoneResult.zoneId)}/dns_records`,
      {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          type: "TXT",
          name: recordName,
          content: txtValue,
          ttl: TXT_TTL_SECONDS,
        }),
      },
      timeoutMs,
    );
    if (!response.ok) {
      return httpFailure("record create", response);
    }

    return { ok: true };
  }

  async function cleanupChallenge({ zone, recordName, txtValue }) {
    const zoneResult = await resolveZoneId(zone);
    if (!zoneResult.ok) {
      return zoneResult;
    }

    // Find the exact TXT record (name + content match) so cleanup never
    // deletes an unrelated record that happens to share the name.
    const listUrl =
      `${API_BASE_URL}/zones/${encodeURIComponent(zoneResult.zoneId)}/dns_records` +
      `?type=TXT&name=${encodeURIComponent(recordName)}&content=${encodeURIComponent(txtValue)}`;
    const listResponse = await fetchWithTimeout(
      fetchImpl,
      listUrl,
      { method: "GET", headers: authHeaders() },
      timeoutMs,
    );
    if (!listResponse.ok) {
      return httpFailure("record lookup", listResponse);
    }

    const envelope = parseEnvelope(listResponse.bodyText);
    const records =
      envelope && Array.isArray(envelope.result) ? envelope.result : [];
    if (records.length === 0) {
      // Nothing to delete: cleanup is idempotent, an already-absent record
      // is success, not failure.
      return { ok: true };
    }

    for (const record of records) {
      if (!isNonEmptyString(record.id)) {
        continue;
      }
      const deleteResponse = await fetchWithTimeout(
        fetchImpl,
        `${API_BASE_URL}/zones/${encodeURIComponent(zoneResult.zoneId)}/dns_records/${encodeURIComponent(record.id)}`,
        { method: "DELETE", headers: authHeaders() },
        timeoutMs,
      );
      if (!deleteResponse.ok) {
        return httpFailure("record delete", deleteResponse);
      }
    }

    return { ok: true };
  }

  return { presentChallenge, cleanupChallenge };
}

/**
 * Lists managed zone names (for longest-suffix discovery).
 * @param {object} options
 * @returns {Promise<string[]>}
 */
async function listManagedZones({ credentials, fetchImpl, timeoutMs }) {
  const response = await fetchWithTimeout(
    fetchImpl,
    `${API_BASE_URL}/zones?per_page=50`,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${credentials.apiToken}`,
        "Content-Type": "application/json",
      },
    },
    timeoutMs,
  );
  if (!response.ok) {
    throw new Error(`cloudflare list zones failed (HTTP ${response.status})`);
  }
  let envelope;
  try {
    envelope = JSON.parse(response.bodyText);
  } catch {
    throw new Error("cloudflare list zones returned non-JSON");
  }
  const results = envelope && Array.isArray(envelope.result) ? envelope.result : [];
  return results
    .filter((zone) => zone && isNonEmptyString(zone.name))
    .map((zone) => zone.name.replace(/\.$/, ""));
}

module.exports = {
  PROVIDER_ID,
  API_BASE_URL,
  validateCredentials,
  collectSecretStrings,
  createSolverImpl,
  listManagedZones,
};
