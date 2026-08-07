"use strict";

/**
 * pebble-challtestsrv DNS-01 provider
 * (https://github.com/letsencrypt/pebble/tree/main/cmd/pebble-challtestsrv).
 *
 * pebble-challtestsrv is Let's Encrypt's own companion test utility for the
 * Pebble ACME test server: it runs a real authoritative DNS server whose
 * TXT answers are driven entirely by its management HTTP API, so a local
 * Pebble + pebble-challtestsrv pair can run a full, real DNS-01 order
 * without any public DNS zone, registrar, or delegated domain. This is the
 * provider a self-hosted operator (or this project's own CI/E2E harness)
 * points at when validating the DNS-01 path against a local test CA
 * instead of a real one.
 *
 * challtestsrv has no authentication whatsoever ("for TEST USAGE ONLY" per
 * its own README) and is never appropriate as a production DNS-01 target;
 * only ever point it at a loopback/private test instance, and only ever
 * allowlist it in a workspace policy that is itself scoped to test/CI
 * certificates against a test CA endpoint.
 *
 * Credentials shape: { baseUrl: string, allowInsecureLocalHttp?: boolean }
 * baseUrl is the management interface (default port 8055), not the DNS
 * server port. Set allowInsecureLocalHttp: true (default false) to permit
 * a plain-http baseUrl for loopback hosts only, matching every other
 * provider's escape hatch for local test setups.
 *
 * API surface used: POST {baseUrl}/set-txt and POST {baseUrl}/clear-txt,
 * both with body { host, value? } where host carries the trailing dot
 * challtestsrv requires (https://github.com/letsencrypt/pebble/blob/main/
 * cmd/pebble-challtestsrv/README.md).
 *
 * capabilities.cleanupVerifiable is true: unlike acme-dns's fixed two-slot
 * rotation, /clear-txt genuinely removes the record, so the hook's
 * post-cleanup "wait for TXT absence" polling is meaningful here.
 */

const {
  isNonEmptyString,
  fetchWithTimeout,
  assertSafeProviderBaseUrl,
} = require("../internal.js");

const PROVIDER_ID = "pebble-challtestsrv";

/** Provider capability flags consumed by the DNS hook / solver factory. */
const capabilities = Object.freeze({
  cleanupVerifiable: true,
});

/**
 * @param {object} credentials
 * @returns {{ baseUrl: string }}
 */
function validateCredentials(credentials) {
  if (!isNonEmptyString(credentials.baseUrl)) {
    throw new Error("dns: pebble-challtestsrv credentials require a non-empty baseUrl string");
  }
  if (
    credentials.allowInsecureLocalHttp !== undefined &&
    typeof credentials.allowInsecureLocalHttp !== "boolean"
  ) {
    throw new Error(
      "dns: pebble-challtestsrv allowInsecureLocalHttp must be a boolean when provided",
    );
  }

  assertSafeProviderBaseUrl(credentials.baseUrl, {
    allowInsecureLocalHttp: credentials.allowInsecureLocalHttp === true,
  });

  return {
    baseUrl: credentials.baseUrl.endsWith("/")
      ? credentials.baseUrl.slice(0, -1)
      : credentials.baseUrl,
  };
}

/**
 * No secrets: challtestsrv's management API has no authentication.
 * @returns {string[]}
 */
function collectSecretStrings() {
  return [];
}

/**
 * challtestsrv requires the trailing-dot FQDN form for `host`.
 * @param {string} recordName
 * @returns {string}
 */
function toDottedHost(recordName) {
  return recordName.endsWith(".") ? recordName : `${recordName}.`;
}

function createSolverImpl({ credentials, fetchImpl, timeoutMs, excerpt }) {
  async function presentChallenge({ recordName, txtValue }) {
    const response = await fetchWithTimeout(
      fetchImpl,
      `${credentials.baseUrl}/set-txt`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host: toDottedHost(recordName), value: txtValue }),
      },
      timeoutMs,
    );

    if (!response.ok) {
      return {
        ok: false,
        statusCode: response.status,
        detail: excerpt(
          `pebble-challtestsrv set-txt failed (HTTP ${response.status}): ${response.bodyText}`,
        ),
      };
    }

    return { ok: true };
  }

  async function cleanupChallenge({ recordName }) {
    const response = await fetchWithTimeout(
      fetchImpl,
      `${credentials.baseUrl}/clear-txt`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host: toDottedHost(recordName) }),
      },
      timeoutMs,
    );

    if (!response.ok) {
      return {
        ok: false,
        statusCode: response.status,
        detail: excerpt(
          `pebble-challtestsrv clear-txt failed (HTTP ${response.status}): ${response.bodyText}`,
        ),
      };
    }

    return { ok: true };
  }

  return { presentChallenge, cleanupChallenge };
}

module.exports = {
  PROVIDER_ID,
  capabilities,
  validateCredentials,
  collectSecretStrings,
  createSolverImpl,
};
