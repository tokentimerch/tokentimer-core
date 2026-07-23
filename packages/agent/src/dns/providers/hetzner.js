"use strict";

/**
 * Hetzner DNS DNS-01 provider.
 *
 * Auth: Hetzner DNS API token sent as the Auth-API-Token header. Create
 * the token in the Hetzner DNS console; it is account-scoped (Hetzner DNS
 * has no per-zone tokens), so prefer a dedicated account for automation.
 *
 * Credentials shape: { apiToken: string, zoneId?: string }
 *   - zoneId is optional; when absent the zone id is looked up by name via
 *     GET /zones?name=<zone> on every operation.
 *
 * API surface used (dns.hetzner.com/api/v1):
 *   GET    /zones?name=<zone>          zone id lookup
 *   POST   /records                    create TXT
 *   GET    /records?zone_id=<zoneId>   record lookup (cleanup)
 *   DELETE /records/<recordId>         delete TXT
 *
 * The record name sent to Hetzner is RELATIVE to the zone ("@" at the
 * apex). The record list endpoint has no name/type filter, so cleanup
 * lists the zone's records and matches type + name + value client-side.
 */

const {
  isNonEmptyString,
  relativeRecordName,
  fetchWithTimeout,
} = require("../internal.js");

const PROVIDER_ID = "hetzner";
const API_BASE_URL = "https://dns.hetzner.com/api/v1";
const TXT_TTL_SECONDS = 60;

/**
 * @param {object} credentials
 * @returns {{ apiToken: string, zoneId: string|null }}
 */
function validateCredentials(credentials) {
  if (!isNonEmptyString(credentials.apiToken)) {
    throw new Error("dns: hetzner credentials require a non-empty apiToken string");
  }
  if (credentials.zoneId !== undefined && !isNonEmptyString(credentials.zoneId)) {
    throw new Error("dns: hetzner zoneId must be a non-empty string when provided");
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
      "Auth-API-Token": credentials.apiToken,
      "Content-Type": "application/json",
    };
  }

  function httpFailure(operationLabel, response) {
    return {
      ok: false,
      statusCode: response.status,
      detail: excerpt(`hetzner ${operationLabel} failed (HTTP ${response.status}): ${response.bodyText}`),
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

    const parsed = parseJson(response.bodyText);
    const zones = parsed && Array.isArray(parsed.zones) ? parsed.zones : [];
    const match = zones.find(
      (candidate) =>
        candidate &&
        typeof candidate.name === "string" &&
        candidate.name.toLowerCase() === zone.toLowerCase(),
    );
    if (!match || !isNonEmptyString(match.id)) {
      return {
        ok: false,
        statusCode: response.status,
        detail: excerpt(`hetzner zone lookup returned no zone named ${JSON.stringify(zone)}`),
      };
    }
    return { ok: true, zoneId: match.id };
  }

  async function presentChallenge({ zone, recordName, txtValue }) {
    const zoneResult = await resolveZoneId(zone);
    if (!zoneResult.ok) {
      return zoneResult;
    }

    const response = await fetchWithTimeout(
      fetchImpl,
      `${API_BASE_URL}/records`,
      {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          zone_id: zoneResult.zoneId,
          type: "TXT",
          name: relativeRecordName(recordName, zone) || "@",
          value: txtValue,
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

    const listResponse = await fetchWithTimeout(
      fetchImpl,
      `${API_BASE_URL}/records?zone_id=${encodeURIComponent(zoneResult.zoneId)}`,
      { method: "GET", headers: authHeaders() },
      timeoutMs,
    );
    if (!listResponse.ok) {
      return httpFailure("record lookup", listResponse);
    }

    const relative = relativeRecordName(recordName, zone) || "@";
    const parsed = parseJson(listResponse.bodyText);
    const records = parsed && Array.isArray(parsed.records) ? parsed.records : [];
    // Exact type + name + value match so cleanup never deletes an
    // unrelated record that happens to share the name.
    const matches = records.filter(
      (record) =>
        record &&
        record.type === "TXT" &&
        record.name === relative &&
        record.value === txtValue &&
        isNonEmptyString(record.id),
    );
    if (matches.length === 0) {
      // Nothing to delete: cleanup is idempotent, an already-absent record
      // is success, not failure.
      return { ok: true };
    }

    for (const record of matches) {
      const deleteResponse = await fetchWithTimeout(
        fetchImpl,
        `${API_BASE_URL}/records/${encodeURIComponent(record.id)}`,
        { method: "DELETE", headers: authHeaders() },
        timeoutMs,
      );
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
  API_BASE_URL,
  validateCredentials,
  collectSecretStrings,
  createSolverImpl,
};
