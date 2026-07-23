"use strict";

/**
 * acme-dns DNS-01 provider (https://github.com/joohoi/acme-dns).
 *
 * acme-dns is a purpose-built minimal DNS server: the operator registers an
 * account once, points a CNAME from _acme-challenge.<domain> at the
 * acme-dns subdomain, and challenges are satisfied by updating that
 * subdomain's TXT value. The blast radius of a leaked credential is one
 * TXT record, not a whole zone -- which is why acme-dns is the recommended
 * wave-1 provider when the authoritative DNS host has no scoped API tokens.
 *
 * Credentials shape:
 *   { baseUrl: string, username: string, password: string, subdomain: string,
 *     allowInsecureLocalHttp?: boolean }
 *   (the fields returned by acme-dns /register; fulldomain is the CNAME
 *   target and is not needed here). baseUrl must be https:; set
 *   allowInsecureLocalHttp: true (default false) to permit a plain-http
 *   baseUrl for loopback hosts only (localhost, *.localhost, 127.x.x.x,
 *   ::1) in local test setups. Embedded credentials and hash fragments are
 *   always rejected.
 *
 * API surface used: POST {baseUrl}/update with X-Api-User / X-Api-Key
 * headers and body { subdomain, txt }.
 *
 * cleanupChallenge is a deliberate no-op success: the acme-dns server keeps
 * exactly two TXT slots per subdomain and rotates the oldest out on every
 * update, so there is nothing to delete and no delete endpoint exists.
 */

const {
  isNonEmptyString,
  fetchWithTimeout,
  assertSafeProviderBaseUrl,
} = require("../internal.js");

const PROVIDER_ID = "acme-dns";

/**
 * @param {object} credentials
 * @returns {{ baseUrl: string, username: string, password: string, subdomain: string }}
 */
function validateCredentials(credentials) {
  for (const field of ["baseUrl", "username", "password", "subdomain"]) {
    if (!isNonEmptyString(credentials[field])) {
      throw new Error(`dns: acme-dns credentials require a non-empty ${field} string`);
    }
  }
  if (
    credentials.allowInsecureLocalHttp !== undefined &&
    typeof credentials.allowInsecureLocalHttp !== "boolean"
  ) {
    throw new Error("dns: acme-dns allowInsecureLocalHttp must be a boolean when provided");
  }

  assertSafeProviderBaseUrl(credentials.baseUrl, {
    allowInsecureLocalHttp: credentials.allowInsecureLocalHttp === true,
  });

  return {
    baseUrl: credentials.baseUrl.endsWith("/")
      ? credentials.baseUrl.slice(0, -1)
      : credentials.baseUrl,
    username: credentials.username,
    password: credentials.password,
    subdomain: credentials.subdomain,
  };
}

/**
 * @param {ReturnType<typeof validateCredentials>} credentials
 * @returns {string[]} secret strings to redact from any excerpt
 */
function collectSecretStrings(credentials) {
  return [credentials.password, credentials.username];
}

function createSolverImpl({ credentials, fetchImpl, timeoutMs, excerpt }) {
  async function presentChallenge({ txtValue }) {
    const response = await fetchWithTimeout(
      fetchImpl,
      `${credentials.baseUrl}/update`,
      {
        method: "POST",
        headers: {
          "X-Api-User": credentials.username,
          "X-Api-Key": credentials.password,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          subdomain: credentials.subdomain,
          txt: txtValue,
        }),
      },
      timeoutMs,
    );

    if (!response.ok) {
      return {
        ok: false,
        statusCode: response.status,
        detail: excerpt(`acme-dns update failed (HTTP ${response.status}): ${response.bodyText}`),
      };
    }

    return { ok: true };
  }

  /**
   * No-op success by design: acme-dns rotates its two TXT slots
   * automatically on each update and exposes no delete endpoint.
   * (Synchronous; the solver layer awaits it either way.)
   */
  function cleanupChallenge() {
    return { ok: true };
  }

  return { presentChallenge, cleanupChallenge };
}

module.exports = {
  PROVIDER_ID,
  validateCredentials,
  collectSecretStrings,
  createSolverImpl,
};
