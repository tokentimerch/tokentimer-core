"use strict";

/**
 * PowerDNS Authoritative Server DNS-01 provider.
 *
 * Auth: the PowerDNS built-in HTTP API key sent as the X-API-Key header
 * (enable with `api=yes` + `api-key=...` in pdns.conf, webserver bound to
 * a trusted interface only).
 *
 * Credentials shape:
 *   {
 *     apiUrl: string,     // e.g. "https://pdns.example:8081" (no trailing
 *                         // /api). Must be https:; set
 *                         // allowInsecureLocalHttp for a loopback-only
 *                         // http endpoint (localhost, *.localhost,
 *                         // 127.x.x.x, ::1). Embedded credentials and
 *                         // hash fragments are always rejected.
 *     apiKey: string,
 *     serverId?: string,  // default "localhost"
 *     allowInsecureLocalHttp?: boolean,  // default false
 *   }
 *
 * API surface used (/api/v1/servers/<serverId>):
 *   GET   /zones/<zone.>   read the zone's rrsets (merge + cleanup basis)
 *   PATCH /zones/<zone.>   REPLACE / DELETE one TXT rrset
 *
 * PowerDNS spellings the caller never sees: zone and record names carry a
 * TRAILING DOT in URLs and rrset names, and TXT record content must be
 * wrapped in double quotes (backslash and quote characters escaped).
 *
 * REPLACE swaps the ENTIRE rrset, so present() first reads the existing
 * TXT rrset at the name and REPLACEs with the union of existing values
 * plus the new one -- parallel challenges at the same name (wildcard +
 * apex orders) never clobber each other. cleanup() REPLACEs with the
 * remaining values, or sends changetype DELETE when none remain.
 */

const {
  isNonEmptyString,
  fetchWithTimeout,
  assertSafeProviderBaseUrl,
} = require("../internal.js");

const PROVIDER_ID = "powerdns";
const DEFAULT_SERVER_ID = "localhost";
const TXT_TTL_SECONDS = 60;

/** PowerDNS TXT content quoting: wrap in double quotes, escape \ and ". */
function quoteTxtValue(txtValue) {
  return `"${txtValue.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** Canonical PowerDNS name: lowercased with exactly one trailing dot. */
function toCanonicalFqdn(name) {
  return `${name.replace(/\.+$/, "").toLowerCase()}.`;
}

/**
 * @param {object} credentials
 * @returns {{ apiUrl: string, apiKey: string, serverId: string }}
 */
function validateCredentials(credentials) {
  if (!isNonEmptyString(credentials.apiUrl)) {
    throw new Error("dns: powerdns credentials require a non-empty apiUrl string");
  }
  if (!isNonEmptyString(credentials.apiKey)) {
    throw new Error("dns: powerdns credentials require a non-empty apiKey string");
  }
  if (credentials.serverId !== undefined && !isNonEmptyString(credentials.serverId)) {
    throw new Error("dns: powerdns serverId must be a non-empty string when provided");
  }
  if (
    credentials.allowInsecureLocalHttp !== undefined &&
    typeof credentials.allowInsecureLocalHttp !== "boolean"
  ) {
    throw new Error("dns: powerdns allowInsecureLocalHttp must be a boolean when provided");
  }

  assertSafeProviderBaseUrl(credentials.apiUrl, {
    allowInsecureLocalHttp: credentials.allowInsecureLocalHttp === true,
  });

  return {
    apiUrl: credentials.apiUrl.replace(/\/+$/, ""),
    apiKey: credentials.apiKey,
    serverId: credentials.serverId || DEFAULT_SERVER_ID,
  };
}

/**
 * @param {ReturnType<typeof validateCredentials>} credentials
 * @returns {string[]} secret strings to redact from any excerpt
 */
function collectSecretStrings(credentials) {
  return [credentials.apiKey];
}

function createSolverImpl({ credentials, fetchImpl, timeoutMs, excerpt }) {
  function authHeaders() {
    return {
      "X-API-Key": credentials.apiKey,
      "Content-Type": "application/json",
    };
  }

  function zoneUrl(zone) {
    return (
      `${credentials.apiUrl}/api/v1/servers/${encodeURIComponent(credentials.serverId)}` +
      `/zones/${encodeURIComponent(toCanonicalFqdn(zone))}`
    );
  }

  function httpFailure(operationLabel, response) {
    return {
      ok: false,
      statusCode: response.status,
      detail: excerpt(`powerdns ${operationLabel} failed (HTTP ${response.status}): ${response.bodyText}`),
    };
  }

  /**
   * Reads the current TXT record contents at `recordFqdn` from the zone.
   * Returns { ok:true, contents: string[] } (empty when the rrset does not
   * exist) or an ok:false operational failure.
   * @param {string} zone
   * @param {string} recordFqdn canonical name with trailing dot
   */
  async function readExistingTxtContents(zone, recordFqdn) {
    const response = await fetchWithTimeout(
      fetchImpl,
      zoneUrl(zone),
      { method: "GET", headers: authHeaders() },
      timeoutMs,
    );
    if (!response.ok) {
      return httpFailure("zone read", response);
    }

    let rrsets = [];
    try {
      const parsed = JSON.parse(response.bodyText);
      rrsets = parsed && Array.isArray(parsed.rrsets) ? parsed.rrsets : [];
    } catch {
      // Treat an unparseable zone body as "no rrsets"; the subsequent
      // PATCH will surface any real API problem.
    }

    const rrset = rrsets.find(
      (candidate) =>
        candidate &&
        candidate.type === "TXT" &&
        typeof candidate.name === "string" &&
        toCanonicalFqdn(candidate.name) === recordFqdn,
    );
    const contents =
      rrset && Array.isArray(rrset.records)
        ? rrset.records
            .map((record) => (record && typeof record.content === "string" ? record.content : null))
            .filter((content) => content !== null)
        : [];
    return { ok: true, contents };
  }

  /**
   * PATCHes one TXT rrset change into the zone.
   * @param {string} zone
   * @param {object} rrset one rrsets[] entry
   * @param {string} operationLabel
   */
  async function patchRrset(zone, rrset, operationLabel) {
    const response = await fetchWithTimeout(
      fetchImpl,
      zoneUrl(zone),
      {
        method: "PATCH",
        headers: authHeaders(),
        body: JSON.stringify({ rrsets: [rrset] }),
      },
      timeoutMs,
    );
    if (!response.ok) {
      return httpFailure(operationLabel, response);
    }
    return { ok: true };
  }

  async function presentChallenge({ zone, recordName, txtValue }) {
    const recordFqdn = toCanonicalFqdn(recordName);
    const existing = await readExistingTxtContents(zone, recordFqdn);
    if (!existing.ok) {
      return existing;
    }

    // Union with whatever is already there so parallel challenges at the
    // same name never clobber each other (REPLACE swaps the whole rrset).
    const quoted = quoteTxtValue(txtValue);
    const contents = existing.contents.includes(quoted)
      ? existing.contents
      : [...existing.contents, quoted];

    return patchRrset(
      zone,
      {
        name: recordFqdn,
        type: "TXT",
        ttl: TXT_TTL_SECONDS,
        changetype: "REPLACE",
        records: contents.map((content) => ({ content, disabled: false })),
      },
      "rrset REPLACE",
    );
  }

  async function cleanupChallenge({ zone, recordName, txtValue }) {
    const recordFqdn = toCanonicalFqdn(recordName);
    const existing = await readExistingTxtContents(zone, recordFqdn);
    if (!existing.ok) {
      return existing;
    }

    const quoted = quoteTxtValue(txtValue);
    if (!existing.contents.includes(quoted)) {
      // Nothing to delete: cleanup is idempotent, an already-absent record
      // is success, not failure.
      return { ok: true };
    }

    const remaining = existing.contents.filter((content) => content !== quoted);
    if (remaining.length === 0) {
      return patchRrset(
        zone,
        { name: recordFqdn, type: "TXT", changetype: "DELETE", records: [] },
        "rrset DELETE",
      );
    }

    return patchRrset(
      zone,
      {
        name: recordFqdn,
        type: "TXT",
        ttl: TXT_TTL_SECONDS,
        changetype: "REPLACE",
        records: remaining.map((content) => ({ content, disabled: false })),
      },
      "rrset REPLACE",
    );
  }

  return { presentChallenge, cleanupChallenge };
}

module.exports = {
  PROVIDER_ID,
  DEFAULT_SERVER_ID,
  validateCredentials,
  collectSecretStrings,
  createSolverImpl,
  // Exported for tests.
  quoteTxtValue,
  toCanonicalFqdn,
};
