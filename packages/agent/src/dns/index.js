"use strict";

/**
 * DNS-01 challenge solvers (waves 1 and 2).
 *
 * Native, zero-dependency TXT-record solvers so the agent can satisfy ACME
 * DNS-01 challenges itself instead of relying on certbot/acme.sh DNS
 * plugins. certbot/acme.sh still drive the ACME conversation; they call
 * back into this module through the manual-auth-hook CLI
 * (bin/certops-dns-hook.js -> src/dns/hook.js).
 *
 * Trust and custody model:
 *   - DNS provider credentials are agent-local secrets, loaded from files
 *     on this host by the caller (config.readDnsCredentialsFile) and passed
 *     in as plain data. They are never uploaded to the control plane and
 *     this module never reads files itself. Note the GCP service-account
 *     private key is a DNS credential, not certificate key material: it
 *     stays on this host and is only ever used locally to sign an OAuth
 *     JWT (zero private-key custody, ADR-0001, is about certificate keys;
 *     the same never-leaves-the-host discipline is applied here anyway).
 *   - Policy first: callers (the hook, the dispatch layer) must pass
 *     checkDnsProvider + checkDnsZone against the agent-local policy
 *     engine BEFORE constructing/using a solver. This module trusts that
 *     contract but still enforces the same dot-boundary rule between
 *     recordName and zone as defense in depth.
 *   - Every provider response excerpt that can appear in a returned
 *     `detail` passes through a bounding + redacting helper (max 1024
 *     chars; wholesale [redacted] on any PRIVATE KEY marker or any
 *     occurrence of the credential strings themselves).
 *
 * Error contract (mirrors src/acme): operational failures (HTTP error,
 * timeout, network refusal, DNS server REFUSED) never throw -- they come
 * back as `{ ok: false, provider, statusCode?, detail }`. Throws are
 * reserved for programmer error and malformed credentials, which fail loud
 * at construction/call time.
 *
 * Supported providers (exact ids, matched against the policy engine's
 * allowedDnsProviders exact-match allowlist):
 *   wave 1: cloudflare, route53, azure-dns, google-cloud-dns, rfc2136,
 *           acme-dns
 *   wave 2: ovhcloud, hetzner, infomaniak, exoscale, powerdns
 *
 * This module is self-contained within src/dns: it does not import policy,
 * config, or other sibling src/<name> modules. Wiring policy checks +
 * credential loading + this solver together is the hook's/dispatch
 * layer's job.
 */

const {
  OUTPUT_EXCERPT_MAX_CHARS,
  isNonEmptyString,
  isRecordNameWithinZone,
  makeExcerptRedactor,
} = require("./internal.js");

const cloudflare = require("./providers/cloudflare.js");
const route53 = require("./providers/route53.js");
const azureDns = require("./providers/azure-dns.js");
const googleCloudDns = require("./providers/google-cloud-dns.js");
const rfc2136 = require("./providers/rfc2136.js");
const acmeDns = require("./providers/acme-dns.js");
const ovhcloud = require("./providers/ovhcloud.js");
const hetzner = require("./providers/hetzner.js");
const infomaniak = require("./providers/infomaniak.js");
const exoscale = require("./providers/exoscale.js");
const powerdns = require("./providers/powerdns.js");

/** Default per-request timeout. DNS APIs are fast; propagation waiting is
 * the ACME tool's job, not this module's. */
const DEFAULT_TIMEOUT_MS = 30 * 1000;

const PROVIDER_MODULES = Object.freeze({
  cloudflare,
  route53,
  "azure-dns": azureDns,
  "google-cloud-dns": googleCloudDns,
  rfc2136,
  "acme-dns": acmeDns,
  ovhcloud,
  hetzner,
  infomaniak,
  exoscale,
  powerdns,
});

const SUPPORTED_DNS_PROVIDERS = Object.freeze([
  "cloudflare",
  "route53",
  "azure-dns",
  "google-cloud-dns",
  "rfc2136",
  "acme-dns",
  "ovhcloud",
  "hetzner",
  "infomaniak",
  "exoscale",
  "powerdns",
]);

/**
 * @returns {string[]} provider ids accepted by createDnsSolver (fresh copy).
 */
function listSupportedDnsProviders() {
  return [...SUPPORTED_DNS_PROVIDERS];
}

/**
 * Creates a DNS-01 solver bound to one provider and one credential set.
 *
 * Throws on programmer error / malformed credentials (fail loud at
 * construction); never throws from presentChallenge/cleanupChallenge on
 * operational failure.
 *
 * @param {object} options
 * @param {string} options.provider one of listSupportedDnsProviders().
 * @param {object} options.credentials provider-specific plain-data
 *   credentials (see each providers/<id>.js header for the exact shape).
 *   Loaded from agent-local files by the caller; never read from disk here.
 * @param {Function} [options.fetchImpl] fetch-shaped injection point for
 *   tests; defaults to the global fetch. Unused by rfc2136.
 * @param {Function} [options.dnsUpdateImpl] rfc2136-only injection point:
 *   ({ host, port, message, timeoutMs }) => Promise<Buffer> sending one
 *   length-prefixed DNS message over TCP and resolving with the response
 *   (without the length prefix). Defaults to a node:net implementation.
 *   Tests inject this so they never open sockets.
 * @param {number} [options.timeoutMs] per-request timeout, default 30 s.
 * @returns {{
 *   provider: string,
 *   presentChallenge: (inputs: { zone: string, recordName: string, txtValue: string }) => Promise<object>,
 *   cleanupChallenge: (inputs: { zone: string, recordName: string, txtValue: string }) => Promise<object>,
 * }}
 */
function createDnsSolver({
  provider,
  credentials,
  fetchImpl = globalThis.fetch,
  dnsUpdateImpl,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (!isNonEmptyString(provider)) {
    throw new Error("dns: createDnsSolver requires a non-empty provider string");
  }

  const providerModule = PROVIDER_MODULES[provider];
  if (!providerModule) {
    throw new Error(
      `dns: unsupported provider ${JSON.stringify(provider)}; supported: ${SUPPORTED_DNS_PROVIDERS.join(", ")}`,
    );
  }

  if (credentials === null || typeof credentials !== "object" || Array.isArray(credentials)) {
    throw new Error(`dns: ${provider} credentials must be an object`);
  }

  if (typeof fetchImpl !== "function") {
    throw new Error("dns: fetchImpl must be a function (or global fetch must exist)");
  }

  if (dnsUpdateImpl !== undefined && typeof dnsUpdateImpl !== "function") {
    throw new Error("dns: dnsUpdateImpl must be a function when provided");
  }

  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error(
      `dns: timeoutMs must be a positive integer, got ${JSON.stringify(timeoutMs)}`,
    );
  }

  // Fail loud on malformed credentials at construction, per provider.
  const normalizedCredentials = providerModule.validateCredentials(credentials);

  // Every detail string a caller can see passes through this redactor.
  const excerpt = makeExcerptRedactor(
    providerModule.collectSecretStrings(normalizedCredentials),
  );

  const impl = providerModule.createSolverImpl({
    credentials: normalizedCredentials,
    fetchImpl,
    dnsUpdateImpl,
    timeoutMs,
    excerpt,
  });

  /**
   * Programmer-error validation shared by present and cleanup. Throws.
   * @param {{ zone?: unknown, recordName?: unknown, txtValue?: unknown }} inputs
   */
  function validateChallengeInputs({ zone, recordName, txtValue } = {}) {
    if (!isNonEmptyString(zone)) {
      throw new Error("dns: zone must be a non-empty string");
    }
    if (!isNonEmptyString(recordName)) {
      throw new Error("dns: recordName must be a non-empty string");
    }
    if (!isNonEmptyString(txtValue)) {
      throw new Error("dns: txtValue must be a non-empty string");
    }
    if (!isRecordNameWithinZone(recordName, zone)) {
      throw new Error(
        `dns: recordName ${JSON.stringify(recordName)} is not within zone ` +
          `${JSON.stringify(zone)} (must equal the zone or end with ".${zone}")`,
      );
    }
  }

  /**
   * Runs one provider operation with the never-throw-on-operational-failure
   * contract: anything the impl throws (network error, timeout abort,
   * unexpected response shape) is mapped to { ok: false } with a redacted
   * detail. Input validation throws BEFORE this wrapper engages.
   *
   * @param {"presentChallenge"|"cleanupChallenge"} operation
   * @param {{ zone: string, recordName: string, txtValue: string }} inputs
   */
  async function run(operation, inputs) {
    validateChallengeInputs(inputs);
    try {
      const result = await impl[operation](inputs);
      return { provider, ...result };
    } catch (err) {
      return {
        ok: false,
        provider,
        detail: excerpt(
          `${operation} failed: ${err && err.message ? err.message : String(err)}`,
        ),
      };
    }
  }

  return {
    provider,
    presentChallenge: (inputs) => run("presentChallenge", inputs),
    cleanupChallenge: (inputs) => run("cleanupChallenge", inputs),
  };
}

module.exports = {
  listSupportedDnsProviders,
  createDnsSolver,
  DEFAULT_TIMEOUT_MS,
  OUTPUT_EXCERPT_MAX_CHARS,
};
