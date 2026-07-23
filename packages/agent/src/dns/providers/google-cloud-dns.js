"use strict";

/**
 * Google Cloud DNS DNS-01 provider.
 *
 * Auth: service-account JWT bearer flow -- an RS256-signed JWT (built and
 * signed locally with node:crypto against the SA private key) exchanged at
 * oauth2.googleapis.com/token for an access token, then bearer calls
 * against the Cloud DNS v1 API. Grant the service account roles/dns.admin
 * scoped as tightly as the project allows.
 *
 * Custody note: the service-account private key is a DNS PROVIDER
 * credential, not certificate key material. It lives in an agent-local
 * credentials file, is only ever used on this host to sign the OAuth JWT,
 * and never leaves the host (the token endpoint receives the signed JWT,
 * not the key). This is squarely within the agent's credential-locality
 * rules; ADR-0001 zero private-key custody concerns certificate keys.
 *
 * Credentials shape (standard GCP service-account JSON fields, subset):
 *   {
 *     client_email: string,
 *     private_key: string,       // PEM, RS256-capable
 *     project_id: string,
 *     managedZone?: string,      // Cloud DNS managed zone NAME; looked up
 *                                // by dnsName when absent
 *   }
 *
 * API surface used (dns.googleapis.com/dns/v1):
 *   GET  /projects/<p>/managedZones?dnsName=<zone>.      zone lookup
 *   POST /projects/<p>/managedZones/<mz>/changes         additions/deletions
 *
 * Cloud DNS rrset TXT values are quoted strings and names are absolute
 * (trailing dot).
 */

const crypto = require("node:crypto");

const { isNonEmptyString, fetchWithTimeout } = require("../internal.js");

const PROVIDER_ID = "google-cloud-dns";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const API_BASE_URL = "https://dns.googleapis.com/dns/v1";
const OAUTH_SCOPE = "https://www.googleapis.com/auth/ndev.clouddns.readwrite";
const JWT_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const TXT_TTL_SECONDS = 60;

/**
 * @param {object} credentials
 */
function validateCredentials(credentials) {
  for (const field of ["client_email", "private_key", "project_id"]) {
    if (!isNonEmptyString(credentials[field])) {
      throw new Error(`dns: google-cloud-dns credentials require a non-empty ${field} string`);
    }
  }
  if (!credentials.private_key.includes("PRIVATE KEY")) {
    throw new Error(
      "dns: google-cloud-dns private_key does not look like a PEM private key",
    );
  }
  if (credentials.managedZone !== undefined && !isNonEmptyString(credentials.managedZone)) {
    throw new Error("dns: google-cloud-dns managedZone must be a non-empty string when provided");
  }

  return {
    client_email: credentials.client_email,
    private_key: credentials.private_key,
    project_id: credentials.project_id,
    managedZone: credentials.managedZone || null,
  };
}

/**
 * @param {ReturnType<typeof validateCredentials>} credentials
 * @returns {string[]} secret strings to redact from any excerpt (the
 *   PRIVATE KEY marker rule catches the key PEM as well; listing it here
 *   is belt and braces).
 */
function collectSecretStrings(credentials) {
  return [credentials.private_key];
}

function base64UrlEncode(input) {
  return Buffer.from(input).toString("base64url");
}

/**
 * Builds and RS256-signs the service-account assertion JWT locally.
 * @param {{ client_email: string, private_key: string }} credentials
 * @param {number} nowEpochSeconds
 * @returns {string}
 */
function buildServiceAccountJwt(credentials, nowEpochSeconds) {
  const header = base64UrlEncode(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = base64UrlEncode(
    JSON.stringify({
      iss: credentials.client_email,
      scope: OAUTH_SCOPE,
      aud: TOKEN_URL,
      iat: nowEpochSeconds,
      exp: nowEpochSeconds + 300,
    }),
  );
  const signingInput = `${header}.${claims}`;
  const signature = crypto
    .sign("RSA-SHA256", Buffer.from(signingInput), credentials.private_key)
    .toString("base64url");
  return `${signingInput}.${signature}`;
}

function createSolverImpl({ credentials, fetchImpl, timeoutMs, excerpt }) {
  function httpFailure(operationLabel, response) {
    return {
      ok: false,
      statusCode: response.status,
      detail: excerpt(`google-cloud-dns ${operationLabel} failed (HTTP ${response.status}): ${response.bodyText}`),
    };
  }

  async function fetchAccessToken() {
    const assertion = buildServiceAccountJwt(
      credentials,
      Math.floor(Date.now() / 1000),
    );

    const response = await fetchWithTimeout(
      fetchImpl,
      TOKEN_URL,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: JWT_GRANT_TYPE,
          assertion,
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
        detail: excerpt("google-cloud-dns token response carried no access_token"),
      };
    }
    return { ok: true, accessToken };
  }

  /**
   * Resolves the managed zone name: configured name wins, otherwise looked
   * up by dnsName (absolute form with trailing dot).
   * @param {string} accessToken
   * @param {string} zone
   */
  async function resolveManagedZone(accessToken, zone) {
    if (credentials.managedZone) {
      return { ok: true, managedZone: credentials.managedZone };
    }

    const zoneFqdn = zone.endsWith(".") ? zone : `${zone}.`;
    const response = await fetchWithTimeout(
      fetchImpl,
      `${API_BASE_URL}/projects/${encodeURIComponent(credentials.project_id)}/managedZones?dnsName=${encodeURIComponent(zoneFqdn)}`,
      {
        method: "GET",
        headers: { Authorization: `Bearer ${accessToken}` },
      },
      timeoutMs,
    );
    if (!response.ok) {
      return httpFailure("managed zone lookup", response);
    }

    let managedZone = null;
    try {
      const parsed = JSON.parse(response.bodyText);
      const first =
        parsed && Array.isArray(parsed.managedZones) ? parsed.managedZones[0] : null;
      managedZone = first && typeof first.name === "string" ? first.name : null;
    } catch {
      // fall through to the failure below
    }
    if (!isNonEmptyString(managedZone)) {
      return {
        ok: false,
        statusCode: response.status,
        detail: excerpt(`google-cloud-dns managed zone lookup found no zone for ${JSON.stringify(zone)}`),
      };
    }
    return { ok: true, managedZone };
  }

  /**
   * @param {"additions"|"deletions"} changeKind
   * @param {{ zone: string, recordName: string, txtValue: string }} inputs
   */
  async function applyChange(changeKind, { zone, recordName, txtValue }) {
    const tokenResult = await fetchAccessToken();
    if (!tokenResult.ok) {
      return tokenResult;
    }

    const zoneResult = await resolveManagedZone(tokenResult.accessToken, zone);
    if (!zoneResult.ok) {
      return zoneResult;
    }

    const recordFqdn = recordName.endsWith(".") ? recordName : `${recordName}.`;
    const rrset = {
      name: recordFqdn,
      type: "TXT",
      ttl: TXT_TTL_SECONDS,
      rrdatas: [`"${txtValue}"`],
    };

    const response = await fetchWithTimeout(
      fetchImpl,
      `${API_BASE_URL}/projects/${encodeURIComponent(credentials.project_id)}/managedZones/${encodeURIComponent(zoneResult.managedZone)}/changes`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${tokenResult.accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ [changeKind]: [rrset] }),
      },
      timeoutMs,
    );
    if (!response.ok) {
      return httpFailure(`changes ${changeKind}`, response);
    }

    return { ok: true };
  }

  return {
    presentChallenge: (inputs) => applyChange("additions", inputs),
    cleanupChallenge: (inputs) => applyChange("deletions", inputs),
  };
}

module.exports = {
  PROVIDER_ID,
  TOKEN_URL,
  API_BASE_URL,
  validateCredentials,
  collectSecretStrings,
  createSolverImpl,
  // Exported for tests (deterministic given nowEpochSeconds).
  buildServiceAccountJwt,
};
