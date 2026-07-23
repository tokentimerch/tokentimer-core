"use strict";

/**
 * OVHcloud DNS-01 provider.
 *
 * Auth: OVH API v1 request signing (application key + application secret +
 * consumer key). Create the consumer key with rights scoped to
 * GET/POST/DELETE on /domain/zone/<zone>/* only.
 *
 * Credentials shape:
 *   {
 *     applicationKey: string,
 *     applicationSecret: string,
 *     consumerKey: string,
 *     endpoint?: string,   // API base URL, default https://eu.api.ovh.com/1.0
 *                          // (other regions: https://ca.api.ovh.com/1.0,
 *                          //  https://us.api.ovhcloud.com/1.0)
 *   }
 *
 * Request signing per the OVH spec: "$1$" + SHA1 hex of
 *   applicationSecret + "+" + consumerKey + "+" + METHOD + "+" + fullUrl
 *   + "+" + body + "+" + timestamp
 * sent as X-Ovh-Signature alongside X-Ovh-Application, X-Ovh-Consumer and
 * X-Ovh-Timestamp. The timestamp is the LOCAL unix time: no /auth/time
 * skew correction is performed (documented simplification; OVH tolerates
 * normal NTP-grade drift and a skewed clock surfaces as a plain HTTP 403
 * operational failure, never a throw).
 *
 * API surface used:
 *   POST   /domain/zone/<zone>/record          create TXT (fieldType,
 *                                              subDomain relative, target)
 *   POST   /domain/zone/<zone>/refresh         apply zone changes
 *   GET    /domain/zone/<zone>/record?...      list record ids (cleanup)
 *   GET    /domain/zone/<zone>/record/<id>     record detail (target match)
 *   DELETE /domain/zone/<zone>/record/<id>     delete TXT
 *
 * The subDomain sent to OVH is RELATIVE to the zone ("" at the apex).
 * OVH's list filter only matches fieldType + subDomain, so cleanup fetches
 * each candidate record and deletes only those whose target matches the
 * challenge value (never an unrelated record sharing the name). A zone
 * refresh is POSTed after every mutation so the change actually serves.
 */

const crypto = require("node:crypto");

const {
  isNonEmptyString,
  relativeRecordName,
  fetchWithTimeout,
} = require("../internal.js");

const PROVIDER_ID = "ovhcloud";
const DEFAULT_ENDPOINT = "https://eu.api.ovh.com/1.0";
const TXT_TTL_SECONDS = 60;

// --------------------------------------------------------------------------
// OVH request signing (exported for the fixed-vector signature test)
// --------------------------------------------------------------------------

/**
 * Computes the OVH v1 request signature. Deterministic given timestamp, so
 * tests can pin an exact signature for fixed keys.
 *
 * @param {object} options
 * @param {string} options.applicationSecret
 * @param {string} options.consumerKey
 * @param {string} options.method uppercase HTTP method
 * @param {string} options.url full request URL (including query string)
 * @param {string} options.body raw request body ("" when none)
 * @param {number} options.timestamp unix seconds
 * @returns {string} "$1$" + SHA1 hex
 */
function signOvhRequest({ applicationSecret, consumerKey, method, url, body, timestamp }) {
  const material = [applicationSecret, consumerKey, method, url, body, String(timestamp)].join("+");
  return `$1$${crypto.createHash("sha1").update(material).digest("hex")}`;
}

// --------------------------------------------------------------------------
// Provider contract
// --------------------------------------------------------------------------

const REQUIRED_FIELDS = Object.freeze([
  "applicationKey",
  "applicationSecret",
  "consumerKey",
]);

/**
 * @param {object} credentials
 */
function validateCredentials(credentials) {
  for (const field of REQUIRED_FIELDS) {
    if (!isNonEmptyString(credentials[field])) {
      throw new Error(`dns: ovhcloud credentials require a non-empty ${field} string`);
    }
  }
  if (credentials.endpoint !== undefined && !isNonEmptyString(credentials.endpoint)) {
    throw new Error("dns: ovhcloud endpoint must be a non-empty string when provided");
  }
  return {
    applicationKey: credentials.applicationKey,
    applicationSecret: credentials.applicationSecret,
    consumerKey: credentials.consumerKey,
    endpoint: (credentials.endpoint || DEFAULT_ENDPOINT).replace(/\/+$/, ""),
  };
}

/**
 * @param {ReturnType<typeof validateCredentials>} credentials
 * @returns {string[]} secret strings to redact from any excerpt
 */
function collectSecretStrings(credentials) {
  return [
    credentials.applicationSecret,
    credentials.consumerKey,
    credentials.applicationKey,
  ];
}

function createSolverImpl({ credentials, fetchImpl, timeoutMs, excerpt }) {
  /**
   * Signs and sends one request against the configured endpoint.
   * @param {{ method: string, path: string, body?: object|null }} request
   *   `path` starts with "/" and may carry a query string; `body` is
   *   JSON-serialized when present, "" otherwise (both are signed as sent).
   */
  function signedFetch({ method, path, body = null }) {
    const url = `${credentials.endpoint}${path}`;
    const bodyText = body === null ? "" : JSON.stringify(body);
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = signOvhRequest({
      applicationSecret: credentials.applicationSecret,
      consumerKey: credentials.consumerKey,
      method,
      url,
      body: bodyText,
      timestamp,
    });

    const headers = {
      "X-Ovh-Application": credentials.applicationKey,
      "X-Ovh-Consumer": credentials.consumerKey,
      "X-Ovh-Timestamp": String(timestamp),
      "X-Ovh-Signature": signature,
    };
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
      detail: excerpt(`ovhcloud ${operationLabel} failed (HTTP ${response.status}): ${response.bodyText}`),
    };
  }

  function parseJson(bodyText) {
    try {
      return JSON.parse(bodyText);
    } catch {
      return null;
    }
  }

  /** POST /domain/zone/<zone>/refresh so the mutation actually serves. */
  async function refreshZone(zone) {
    const response = await signedFetch({
      method: "POST",
      path: `/domain/zone/${encodeURIComponent(zone)}/refresh`,
    });
    if (!response.ok) {
      return httpFailure("zone refresh", response);
    }
    return { ok: true };
  }

  async function presentChallenge({ zone, recordName, txtValue }) {
    const subDomain = relativeRecordName(recordName, zone);

    const response = await signedFetch({
      method: "POST",
      path: `/domain/zone/${encodeURIComponent(zone)}/record`,
      body: {
        fieldType: "TXT",
        subDomain,
        target: txtValue,
        ttl: TXT_TTL_SECONDS,
      },
    });
    if (!response.ok) {
      return httpFailure("record create", response);
    }

    return refreshZone(zone);
  }

  async function cleanupChallenge({ zone, recordName, txtValue }) {
    const subDomain = relativeRecordName(recordName, zone);

    // OVH's list filter matches fieldType + subDomain only; the target is
    // matched below via each record's detail so cleanup never deletes an
    // unrelated record that happens to share the name.
    const listResponse = await signedFetch({
      method: "GET",
      path:
        `/domain/zone/${encodeURIComponent(zone)}/record` +
        `?fieldType=TXT&subDomain=${encodeURIComponent(subDomain)}`,
    });
    if (!listResponse.ok) {
      return httpFailure("record lookup", listResponse);
    }

    const ids = parseJson(listResponse.bodyText);
    const recordIds = Array.isArray(ids) ? ids.filter((id) => Number.isInteger(id) || isNonEmptyString(id)) : [];
    if (recordIds.length === 0) {
      // Nothing to delete: cleanup is idempotent, an already-absent record
      // is success, not failure.
      return { ok: true };
    }

    let deletedAny = false;
    for (const recordId of recordIds) {
      const detailResponse = await signedFetch({
        method: "GET",
        path: `/domain/zone/${encodeURIComponent(zone)}/record/${encodeURIComponent(recordId)}`,
      });
      if (!detailResponse.ok) {
        return httpFailure("record detail", detailResponse);
      }
      const record = parseJson(detailResponse.bodyText);
      const target = record && typeof record.target === "string" ? record.target : null;
      // OVH may store the target quoted; accept both spellings.
      if (target !== txtValue && target !== `"${txtValue}"`) {
        continue;
      }

      const deleteResponse = await signedFetch({
        method: "DELETE",
        path: `/domain/zone/${encodeURIComponent(zone)}/record/${encodeURIComponent(recordId)}`,
      });
      // 404 means the record is already gone: idempotent success.
      if (!deleteResponse.ok && deleteResponse.status !== 404) {
        return httpFailure("record delete", deleteResponse);
      }
      deletedAny = true;
    }

    if (!deletedAny) {
      return { ok: true };
    }
    return refreshZone(zone);
  }

  return { presentChallenge, cleanupChallenge };
}

module.exports = {
  PROVIDER_ID,
  DEFAULT_ENDPOINT,
  validateCredentials,
  collectSecretStrings,
  createSolverImpl,
  // Exported for the fixed-vector signature test only.
  signOvhRequest,
};
