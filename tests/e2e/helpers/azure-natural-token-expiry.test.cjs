"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { _offline } = require("./azure-natural-token-expiry.cjs");

function fixture() {
  let clock = 1700000000000, acquisitions = 0, reads = 0, fetches = 0, owners = 0, renewals = 0;
  const state = { statuses: [200, 200, 401, 200], networkAt: -1, expiryOffset: 60 };
  const options = {
    now: () => clock, pause: async ms => { clock += ms; },
    budget: { jobDeadlineMs: clock + 80 * 60 * 1000, resourceDeadlineMs: clock + 110 * 60 * 1000,
      cleanupReserveMs: 10 * 60 * 1000 },
    acquire: async () => {
      acquisitions++;
      return { token: `private-token-${acquisitions}`, issuedAt: Math.floor(clock / 1000),
        expiresAt: Math.floor(clock / 1000) + state.expiryOffset };
    },
    read: async () => { reads++; if (reads === state.networkAt) throw new Error("sensitive response"); return state.statuses.shift(); },
    fetchVersion: async () => { fetches++; }, renewAssertion: async () => { renewals++; }, verifyOwned: async () => { owners++; },
  };
  return { state, options, counts: () => ({ acquisitions, reads, fetches, owners, renewals }) };
}

test("offline orchestration observes expiry and renewed access without returning token material", async () => {
  const f = fixture(), result = await _offline.observe(f.options);
  assert.equal(result.azureStatusBefore, 200); assert.equal(result.azureStatusExpired, 401); assert.equal(result.azureStatusAfter, 200);
  assert.ok(result.observedExpiredAt >= result.expiresAt); assert.ok(result.renewedAt >= result.observedExpiredAt);
  assert.equal(JSON.stringify(result).includes("private-token"), false);
  assert.deepEqual(f.counts(), { acquisitions: 2, reads: 4, fetches: 2, owners: 3, renewals: 1 });
});

test("refuses a lifetime outside the bounded run before accessing the vault", async () => {
  const f = fixture(); f.state.expiryOffset = 4 * 60 * 60;
  f.options.prepare = async () => { assert.fail("must not publish with an out-of-budget token"); };
  await assert.rejects(() => _offline.observe(f.options), { code: "AZURE_EXPIRY_OUTSIDE_BUDGET" });
  assert.equal(f.counts().reads, 0);
});

test("checks the observed token before publishing and uses it for the first read", async () => {
  const f = fixture(), acquire = f.options.acquire, read = f.options.read;
  let first;
  f.options.acquire = async () => { const token = await acquire(); first ||= token.token; return token; };
  let prepared = false, checked = false;
  f.options.prepare = async () => { assert.ok(first); prepared = true; };
  f.options.read = async token => {
    if (!checked) { assert.ok(prepared); assert.equal(token, first); checked = true; }
    return read(token);
  };
  assert.equal((await _offline.observe(f.options)).azureStatusExpired, 401);
  assert.ok(checked);
});

test("refuses a real expiry beyond the externally reserved cleanup window before waiting", async () => {
  const f = fixture(); f.state.expiryOffset = 61 * 60;
  f.options.budget.jobDeadlineMs = f.options.now() + 70 * 60 * 1000;
  await assert.rejects(() => _offline.observe(f.options), { code: "AZURE_EXPIRY_OUTSIDE_BUDGET" });
  assert.equal(f.counts().reads, 0);
});

test("reports invalid token times separately from an insufficient observation window", async () => {
  for (const expiryOffset of [NaN, -1, 20]) {
    const f = fixture();
    f.state.expiryOffset = expiryOffset;
    await assert.rejects(() => _offline.observe(f.options), { code: "AZURE_EXPIRY_TOKEN_TIMES_INVALID" });
    assert.equal(f.counts().reads, 0);
  }
});

test("network failure and a 403 never count as expiration", async () => {
  const network = fixture(); network.state.networkAt = 2;
  await assert.rejects(() => _offline.observe(network.options), { code: "AZURE_EXPIRY_NETWORK_AFTER" });
  const forbidden = fixture(); forbidden.state.statuses = [200, 403];
  await assert.rejects(() => _offline.observe(forbidden.options), { code: "AZURE_EXPIRY_UNEXPECTED_STATUS" });
});

test("refuses a renewed token that is still the original", async () => {
  const f = fixture(); f.state.statuses = [200, 401];
  const acquire = f.options.acquire; let first;
  f.options.acquire = async () => { const next = await acquire(); if (!first) first = next.token; return { ...next, token: first }; };
  await assert.rejects(() => _offline.observe(f.options), { code: "AZURE_EXPIRY_RENEWAL_INVALID" });
});

test("accepts only a version-pinned secret on an owned fixture hostname", () => {
  const cfg = { address: `https://ttkv${"a".repeat(20)}.vault.azure.net`, auth: { type: "workload-identity" } };
  const store = { objectRef: `tt-${"b".repeat(64)}`, fetch() {} };
  const version = "c".repeat(32);
  assert.equal(_offline.validateScope(cfg, store, version).pathname, `/secrets/${store.objectRef}/${version}`);
  assert.throws(() => _offline.validateScope({ ...cfg, address: "https://example.com" }, store, version), { code: "AZURE_EXPIRY_SCOPE_DENIED" });
  assert.throws(() => _offline.validateScope(cfg, store, "latest"), { code: "AZURE_EXPIRY_SCOPE_DENIED" });
});
