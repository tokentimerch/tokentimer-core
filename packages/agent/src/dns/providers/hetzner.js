"use strict";

/**
 * Hetzner DNS DNS-01 provider (Hetzner Console / Cloud API).
 *
 * ASSUMPTIONS (verify against live Hetzner docs before release):
 *   - Base URL: https://api.hetzner.cloud/v1
 *   - Auth: Authorization: Bearer <project API token> created in the
 *     Hetzner Console (legacy dns.hetzner.com Auth-API-Token tokens do
 *     NOT work against this API).
 *   - Zones: GET /zones?name=<zone>
 *   - Atomic TXT append: POST
 *     /zones/{id_or_name}/rrsets/{rr_name}/TXT/actions/add_records
 *     (auto-creates the RRSet when absent; appends otherwise).
 *   - Value-specific remove: POST
 *     /zones/{id_or_name}/rrsets/{rr_name}/TXT/actions/remove_records
 *   - TXT record values are double-quoted in the API (e.g. "\"token\"").
 *   - RRSet names are relative to the zone, lower case, no trailing dot;
 *     apex uses "@".
 *
 * Credentials shape: { apiToken: string, zoneId?: string }
 *   - zoneId is optional; when absent the zone id is looked up by name.
 *   - apiToken must be a Hetzner Console / Cloud project token with DNS
 *     read+write on the target project.
 *
 * Legacy API (dns.hetzner.com/api/v1, Auth-API-Token) is intentionally
 * NOT used: Hetzner is shutting it down after the Console migration.
 */

const {
  isNonEmptyString,
  relativeRecordName,
  fetchWithTimeout,
} = require("../internal.js");

const PROVIDER_ID = "hetzner";
/** Hetzner Cloud / Console DNS API (not the legacy dns.hetzner.com API). */
const API_BASE_URL = "https://api.hetzner.cloud/v1";
const TXT_TTL_SECONDS = 60;

/** Quote a TXT RDATA value the way the Cloud DNS API expects. */
function quoteTxtValue(txtValue) {
  return `"${txtValue.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

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

/**
 * Lists managed zone names for longest-suffix discovery. Paginates through
 * every page (Hetzner Cloud API caps per_page at 50 and a project can have
 * more zones than that): without this, longest-suffix discovery would
 * silently only ever see the first page and treat any zone past it as
 * "not managed here", causing DNS-01 to spuriously fail.
 * @param {object} options
 * @returns {Promise<string[]>}
 */
async function listManagedZones({ credentials, fetchImpl, timeoutMs }) {
  const names = [];
  let page = 1;
  const perPage = 50;
  // Hard safety cap: never loop forever even if the API's pagination
  // metadata is malformed or inconsistent across pages.
  const MAX_PAGES = 200;
  for (; page <= MAX_PAGES; page += 1) {
    const response = await fetchWithTimeout(
      fetchImpl,
      `${API_BASE_URL}/zones?page=${page}&per_page=${perPage}`,
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${credentials.apiToken}`,
        },
      },
      timeoutMs,
    );
    if (!response.ok) {
      throw new Error(`hetzner list zones failed (HTTP ${response.status})`);
    }
    let parsed;
    try {
      parsed = JSON.parse(response.bodyText);
    } catch {
      throw new Error("hetzner list zones returned non-JSON");
    }
    const zones = parsed && Array.isArray(parsed.zones) ? parsed.zones : [];
    for (const zone of zones) {
      if (zone && isNonEmptyString(zone.name)) {
        names.push(zone.name.replace(/\.$/, ""));
      }
    }
    const nextPage = parsed?.meta?.pagination?.next_page;
    if (!Number.isInteger(nextPage) || nextPage <= page) break;
    page = nextPage - 1; // loop increment adds 1 back
  }
  return names;
}

function createSolverImpl({ credentials, fetchImpl, timeoutMs, excerpt }) {
  function authHeaders() {
    return {
      Authorization: `Bearer ${credentials.apiToken}`,
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

  function rrName(recordName, zone) {
    return relativeRecordName(recordName, zone) || "@";
  }

  function rrsetActionUrl(zoneIdOrName, recordName, zone, action) {
    const name = encodeURIComponent(rrName(recordName, zone));
    const zoneKey = encodeURIComponent(zoneIdOrName);
    return `${API_BASE_URL}/zones/${zoneKey}/rrsets/${name}/TXT/actions/${action}`;
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
        candidate.name.toLowerCase().replace(/\.$/, "") === zone.toLowerCase(),
    );
    if (!match || (!isNonEmptyString(match.id) && !isNonEmptyString(match.name))) {
      return {
        ok: false,
        statusCode: response.status,
        detail: excerpt(`hetzner zone lookup returned no zone named ${JSON.stringify(zone)}`),
      };
    }
    // Prefer numeric/string id when present; the API also accepts zone name
    // as id_or_name on rrset paths.
    return { ok: true, zoneId: isNonEmptyString(match.id) ? String(match.id) : match.name };
  }

  async function presentChallenge({ zone, recordName, txtValue }) {
    const zoneResult = await resolveZoneId(zone);
    if (!zoneResult.ok) {
      return zoneResult;
    }

    // add_records is append-safe: creates the RRSet when missing, otherwise
    // appends distinct values (no read-modify-write clobber).
    const response = await fetchWithTimeout(
      fetchImpl,
      rrsetActionUrl(zoneResult.zoneId, recordName, zone, "add_records"),
      {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          ttl: TXT_TTL_SECONDS,
          records: [{ value: quoteTxtValue(txtValue) }],
        }),
      },
      timeoutMs,
    );
    if (!response.ok) {
      return httpFailure("record add_records", response);
    }

    return { ok: true };
  }

  async function cleanupChallenge({ zone, recordName, txtValue }) {
    const zoneResult = await resolveZoneId(zone);
    if (!zoneResult.ok) {
      return zoneResult;
    }

    // remove_records deletes only the listed values — never the whole set.
    const response = await fetchWithTimeout(
      fetchImpl,
      rrsetActionUrl(zoneResult.zoneId, recordName, zone, "remove_records"),
      {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          records: [{ value: quoteTxtValue(txtValue) }],
        }),
      },
      timeoutMs,
    );
    // 404: RRSet or value already gone — idempotent success.
    if (!response.ok && response.status !== 404) {
      return httpFailure("record remove_records", response);
    }

    return { ok: true };
  }

  return { presentChallenge, cleanupChallenge };
}

module.exports = {
  PROVIDER_ID,
  API_BASE_URL,
  quoteTxtValue,
  validateCredentials,
  collectSecretStrings,
  listManagedZones,
  createSolverImpl,
};
