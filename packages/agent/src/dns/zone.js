"use strict";

/**
 * Longest-suffix DNS zone discovery for ACME DNS-01 challenges.
 *
 * Never treats the challenge hostname itself as the zone by default: for
 * `www.example.com` the managed zone is usually `example.com`. Resolution
 * order:
 *   1. Explicit `zoneProviderMap` longest-suffix match (caller).
 *   2. Provider zone-list API: walk domain labels longest-first and pick the
 *      first candidate present in the provider's managed zones.
 *   3. DNS NS lookup walk: first parent that answers NS is treated as the
 *      zone cut (used when the provider cannot list zones, e.g. rfc2136).
 */

const dns = require("node:dns");
const { isNonEmptyString } = require("./internal.js");
const { zoneCandidatesForHostname } = require("./propagate.js");

/**
 * Walks suffixes of `hostname` (longest first) and returns the first
 * candidate for which `isManagedZone(candidate)` is true.
 *
 * @param {string} hostname
 * @param {(candidate: string) => Promise<boolean>|boolean} isManagedZone
 * @returns {Promise<string|null>}
 */
async function findLongestManagedZone(hostname, isManagedZone) {
  if (!isNonEmptyString(hostname)) {
    throw new Error("dns: findLongestManagedZone requires a non-empty hostname");
  }
  if (typeof isManagedZone !== "function") {
    throw new Error("dns: findLongestManagedZone requires an isManagedZone callback");
  }

  const candidates = zoneCandidatesForHostname(hostname);
  const normalized = hostname.replace(/\.$/, "").toLowerCase();
  if (normalized.includes(".") && !candidates.includes(normalized)) {
    candidates.unshift(normalized);
  }

  for (const candidate of candidates) {
    const managed = await isManagedZone(candidate);
    if (managed === true) {
      return candidate;
    }
  }
  return null;
}

/**
 * Discovers the zone cut for `hostname` via DNS NS queries (parent walk).
 *
 * @param {string} hostname
 * @param {{ resolveNs?: (name: string) => Promise<string[]> }} [deps]
 * @returns {Promise<string|null>}
 */
async function discoverZoneViaNs(hostname, deps = {}) {
  const resolveNs =
    deps.resolveNs ||
    ((name) =>
      new Promise((resolve, reject) => {
        dns.resolveNs(name, (err, addresses) => (err ? reject(err) : resolve(addresses || [])));
      }));

  const candidates = zoneCandidatesForHostname(hostname);
  const normalized = hostname.replace(/\.$/, "").toLowerCase();
  if (normalized.includes(".") && !candidates.includes(normalized)) {
    candidates.unshift(normalized);
  }

  for (const candidate of candidates) {
    try {
      const ns = await resolveNs(candidate);
      if (Array.isArray(ns) && ns.length > 0) {
        return candidate;
      }
    } catch {
      // try next parent
    }
  }
  return null;
}

/**
 * Resolves the DNS zone for a challenge domain.
 *
 * @param {object} options
 * @param {string} options.domain CERTBOT_DOMAIN / ACME_DOMAIN
 * @param {string|null} options.mappedZone zone from zoneProviderMap, if any
 * @param {(candidate: string) => Promise<boolean>|boolean} [options.isManagedZone]
 *   provider-backed zone membership check
 * @param {{ resolveNs?: Function }} [options.dnsDeps]
 * @returns {Promise<string>}
 */
async function resolveChallengeZone({
  domain,
  mappedZone = null,
  isManagedZone,
  dnsDeps,
} = {}) {
  if (!isNonEmptyString(domain)) {
    throw new Error("dns: resolveChallengeZone requires a non-empty domain");
  }

  if (isNonEmptyString(mappedZone)) {
    return mappedZone.toLowerCase().replace(/\.$/, "");
  }

  if (typeof isManagedZone === "function") {
    const fromProvider = await findLongestManagedZone(domain, isManagedZone);
    if (fromProvider) {
      return fromProvider;
    }
  }

  const fromNs = await discoverZoneViaNs(domain, dnsDeps);
  if (fromNs) {
    return fromNs;
  }

  throw new Error(
    `dns: could not discover a managed DNS zone for ${JSON.stringify(domain)}; ` +
      "configure dnsProviders.zoneProviderMap or ensure the provider can list zones",
  );
}

module.exports = {
  findLongestManagedZone,
  discoverZoneViaNs,
  resolveChallengeZone,
  zoneCandidatesForHostname,
};
