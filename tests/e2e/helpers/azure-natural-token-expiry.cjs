"use strict";

// The caller owns the disposable Azure fixture, exact extracted package and
// cleanup. This helper returns bounded observations, never tokens or responses.
const path = require("node:path");
const assert = require("node:assert/strict");

const MAX_DURATION_MS = 3 * 60 * 60 * 1000;
const MIN_CLEANUP_RESERVE_MS = 10 * 60 * 1000;
const EXPIRY_GRACE_MS = 10 * 60 * 1000;
const POLL_MS = 15000;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function workDeadline({ jobDeadlineMs, resourceDeadlineMs, cleanupReserveMs }, now) {
  if (![jobDeadlineMs, resourceDeadlineMs, cleanupReserveMs, now].every(Number.isSafeInteger) ||
      cleanupReserveMs < MIN_CLEANUP_RESERVE_MS || jobDeadlineMs > now + 90 * 60 * 1000 ||
      resourceDeadlineMs > now + 2 * 60 * 60 * 1000) fail("AZURE_EXPIRY_BUDGET_INVALID");
  const deadline = Math.min(jobDeadlineMs, resourceDeadlineMs) - cleanupReserveMs;
  if (deadline <= now) fail("AZURE_EXPIRY_BUDGET_INVALID");
  return Math.min(deadline, now + MAX_DURATION_MS);
}

function validateScope(config, store, version) {
  let address;
  try { address = new URL(config.address); } catch { fail("AZURE_EXPIRY_SCOPE_DENIED"); }
  if (address.protocol !== "https:" || !/^ttkv[a-f0-9]{20}\.vault\.azure\.net$/.test(address.hostname) ||
      address.port || address.username || address.password || address.pathname !== "/" || address.search || address.hash ||
      config.auth?.type !== "workload-identity" || !/^tt-[a-f0-9]{64}$/.test(store?.objectRef || "") ||
      !/^[a-f0-9]{32}$/.test(version || "") || typeof store.fetch !== "function") fail("AZURE_EXPIRY_SCOPE_DENIED");
  return new URL(`/secrets/${store.objectRef}/${version}?api-version=7.4`, address);
}

// Injected clocks and requests are for offline orchestration tests only.
async function observe({ acquire, read, fetchVersion, renewAssertion, verifyOwned, now, pause, budget }) {
  const started = now(), deadline = workDeadline(budget, started);
  await verifyOwned();
  const first = await acquire();
  if (!Number.isSafeInteger(first.issuedAt) || !Number.isSafeInteger(first.expiresAt) ||
      first.issuedAt < Math.floor(started / 1000) - 30 || first.expiresAt <= first.issuedAt ||
      first.expiresAt * 1000 + EXPIRY_GRACE_MS > deadline || first.expiresAt * 1000 <= now() + 30000)
    fail("AZURE_EXPIRY_OUTSIDE_BUDGET");
  let before;
  try { before = await read(first.token); } catch { fail("AZURE_EXPIRY_NETWORK_BEFORE"); }
  if (before !== 200) fail("AZURE_EXPIRY_INITIAL_ACCESS_DENIED");
  await fetchVersion();
  if (now() >= deadline || first.expiresAt * 1000 + EXPIRY_GRACE_MS > deadline)
    fail("AZURE_EXPIRY_OUTSIDE_BUDGET");
  const delay = first.expiresAt * 1000 - now();
  if (delay > 0) await pause(delay);
  let expiredAt;
  while (now() <= Math.min(deadline, first.expiresAt * 1000 + EXPIRY_GRACE_MS)) {
    let status;
    try { status = await read(first.token); } catch { fail("AZURE_EXPIRY_NETWORK_AFTER"); }
    if (status === 401) { expiredAt = Math.floor(now() / 1000); break; }
    if (status !== 200) fail("AZURE_EXPIRY_UNEXPECTED_STATUS");
    await pause(POLL_MS);
  }
  if (!expiredAt) fail("AZURE_EXPIRY_NOT_OBSERVED");
  await verifyOwned();
  await renewAssertion();
  const renewed = await acquire();
  if (renewed.token === first.token || !Number.isSafeInteger(renewed.issuedAt) ||
      !Number.isSafeInteger(renewed.expiresAt) || renewed.issuedAt < expiredAt ||
      renewed.expiresAt <= renewed.issuedAt || now() > deadline) fail("AZURE_EXPIRY_RENEWAL_INVALID");
  let after;
  try { after = await read(renewed.token); } catch { fail("AZURE_EXPIRY_NETWORK_RENEWED"); }
  if (after !== 200) fail("AZURE_EXPIRY_RENEWED_ACCESS_DENIED");
  await fetchVersion();
  await verifyOwned();
  return { issuedAt: first.issuedAt, expiresAt: first.expiresAt, observedExpiredAt: expiredAt,
    renewedAt: renewed.issuedAt, renewedExpiresAt: renewed.expiresAt,
    azureStatusBefore: 200, azureStatusExpired: 401, azureStatusAfter: 200 };
}

async function runNaturalExpiry({ candidateRoot, config, store, providerVersion, renewAssertion, verifyOwned, budget }) {
  assert.ok(path.isAbsolute(candidateRoot));
  workDeadline(budget || {}, Date.now());
  assert.equal(typeof renewAssertion, "function");
  assert.equal(typeof verifyOwned, "function");
  const url = validateScope(config, store, providerVersion);
  const { credential } = require(path.join(candidateRoot, "src/material-store/azure"));
  const { requestJson } = require(path.join(candidateRoot, "src/material-store/transport"));
  let expiry;
  const getToken = credential(config, 15000, async (target, options) => {
    const response = await requestJson(target, options);
    if (response.status === 200) {
      expiry = Number(response.json?.expires_on);
      if (!Number.isSafeInteger(expiry)) {
        try {
          // A missing/opaque expiry is refused rather than inventing a TTL.
          const parts = response.json.access_token.split(".");
          expiry = parts.length === 3 ? JSON.parse(Buffer.from(parts[1], "base64url")).exp : NaN;
        } catch { expiry = NaN; }
      }
    }
    return response;
  });
  const facts = await observe({
    acquire: async () => {
      expiry = undefined;
      const token = await getToken(true);
      return { token, issuedAt: Math.floor(Date.now() / 1000), expiresAt: expiry };
    },
    read: async token => (await requestJson(url, { timeoutMs: 15000, maxBytes: 100000,
      headers: { Authorization: `Bearer ${token}` } })).status,
    fetchVersion: () => store.fetch(providerVersion),
    renewAssertion, verifyOwned, now: Date.now, pause: sleep, budget,
  });
  return { ...facts, forced401: false, clockOverridden: false, pinnedVersion: providerVersion };
}

module.exports = { runNaturalExpiry, workDeadline, MAX_DURATION_MS, _offline: { observe, validateScope } };
