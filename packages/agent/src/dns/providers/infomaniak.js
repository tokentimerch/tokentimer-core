"use strict";

/**
 * Infomaniak DNS-01 provider.
 *
 * Auth: Infomaniak API token sent as a Bearer header. Create the token in
 * the Infomaniak manager with the "domain" scope only.
 *
 * Credentials shape: { apiToken: string }
 *
 * API surface used (api.infomaniak.com, v2 zone records):
 *   POST   /2/zones/<zone>/records          create TXT
 *   GET    /2/zones/<zone>/records          record lookup (cleanup)
 *   DELETE /2/zones/<zone>/records/<id>     delete TXT
 *
 * Response envelope: every response wraps its payload as
 * { result: "success"|"error", data, error? }. A `result` other than
 * "success" is an operational failure EVEN ON HTTP 200, so both the HTTP
 * status and the envelope are checked on every call.
 *
 * The record `source` sent to Infomaniak is RELATIVE to the zone ("." at
 * the apex, Infomaniak's spelling for the zone root).
 */

const {
  isNonEmptyString,
  relativeRecordName,
  fetchWithTimeout,
} = require("../internal.js");

const PROVIDER_ID = "infomaniak";
const API_BASE_URL = "https://api.infomaniak.com";
const TXT_TTL_SECONDS = 60;

/**
 * @param {object} credentials
 * @returns {{ apiToken: string }}
 */
function validateCredentials(credentials) {
  if (!isNonEmptyString(credentials.apiToken)) {
    throw new Error("dns: infomaniak credentials require a non-empty apiToken string");
  }
  return { apiToken: credentials.apiToken };
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

  function recordsUrl(zone, recordId) {
    const base = `${API_BASE_URL}/2/zones/${encodeURIComponent(zone)}/records`;
    return recordId === undefined ? base : `${base}/${encodeURIComponent(recordId)}`;
  }

  function httpFailure(operationLabel, response) {
    return {
      ok: false,
      statusCode: response.status,
      detail: excerpt(`infomaniak ${operationLabel} failed (HTTP ${response.status}): ${response.bodyText}`),
    };
  }

  /**
   * Parses the { result, data } envelope; returns null on any parse
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

  /**
   * Runs one request and enforces both the HTTP status and the
   * { result: "success" } envelope. Returns { ok:true, data } or an
   * ok:false operational failure.
   * @param {string} operationLabel
   * @param {string} url
   * @param {object} options fetch options
   */
  async function envelopeFetch(operationLabel, url, options) {
    const response = await fetchWithTimeout(fetchImpl, url, options, timeoutMs);
    if (!response.ok) {
      return httpFailure(operationLabel, response);
    }

    const envelope = parseEnvelope(response.bodyText);
    if (!envelope || envelope.result !== "success") {
      // Infomaniak reports application errors as { result: "error" } even
      // on HTTP 200; that is an operational failure, not a success.
      return {
        ok: false,
        statusCode: response.status,
        detail: excerpt(`infomaniak ${operationLabel} returned a non-success envelope: ${response.bodyText}`),
      };
    }
    return { ok: true, data: envelope.data };
  }

  /** Infomaniak spells the zone apex as ".". */
  function sourceName(zone, recordName) {
    return relativeRecordName(recordName, zone) || ".";
  }

  async function presentChallenge({ zone, recordName, txtValue }) {
    const result = await envelopeFetch("record create", recordsUrl(zone), {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        type: "TXT",
        source: sourceName(zone, recordName),
        target: txtValue,
        ttl: TXT_TTL_SECONDS,
      }),
    });
    if (!result.ok) {
      return result;
    }
    return { ok: true };
  }

  async function cleanupChallenge({ zone, recordName, txtValue }) {
    const listResult = await envelopeFetch("record lookup", recordsUrl(zone), {
      method: "GET",
      headers: authHeaders(),
    });
    if (!listResult.ok) {
      return listResult;
    }

    const source = sourceName(zone, recordName);
    const records = Array.isArray(listResult.data) ? listResult.data : [];
    // Exact type + source + target match so cleanup never deletes an
    // unrelated record that happens to share the name. Infomaniak may
    // return the target quoted (RFC 1035 TXT wire representation); accept
    // both spellings so cleanup never silently no-ops and orphans the
    // challenge record.
    const matches = records.filter(
      (record) =>
        record &&
        record.type === "TXT" &&
        record.source === source &&
        (record.target === txtValue || record.target === `"${txtValue}"`) &&
        (isNonEmptyString(record.id) || Number.isInteger(record.id)),
    );
    if (matches.length === 0) {
      // Nothing to delete: cleanup is idempotent, an already-absent record
      // is success, not failure.
      return { ok: true };
    }

    for (const record of matches) {
      const deleteResult = await envelopeFetch(
        "record delete",
        recordsUrl(zone, record.id),
        { method: "DELETE", headers: authHeaders() },
      );
      // A 404 means the record is already gone: idempotent success.
      if (!deleteResult.ok && deleteResult.statusCode !== 404) {
        return deleteResult;
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
