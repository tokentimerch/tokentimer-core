"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { enrichObservedItems, createScanChecker } = require("./observation");

test("disabled or unavailable local trust never starts a network check", async () => {
  let calls = 0;
  const check = async () => { calls++; return { verdict: "good" }; };
  assert.equal(await createScanChecker({ enabled: false }, { check }), null);
  let loads = 0;
  const noPolicy = await createScanChecker({ enabled: true, allowedOrigins: [] }, { load: async () => { loads++; }, check });
  const entries = [{ certificatePem: "public", item: { fingerprintSha256: "a".repeat(64), metadata: [] } }];
  await enrichObservedItems(entries, noPolicy);
  assert.deepEqual(entries[0].item.metadata, [{ name: "observedRevocationState", value: "not_configured" }]);
  const disabled = await createScanChecker({ enabled: false, explicitlyDisabled: true }, { load: async () => { loads++; }, check });
  const disabledEntries = [{ certificatePem: "public", item: { fingerprintSha256: "b".repeat(64), metadata: [] } }];
  await enrichObservedItems(disabledEntries, disabled);
  assert.deepEqual(disabledEntries[0].item.metadata, [{ name: "observedRevocationState", value: "disabled" }]);
  assert.equal(loads, 0);
  const checker = await createScanChecker({ enabled: true, allowedOrigins: ["http://pki.example"] }, { load: async () => { throw new Error("store inaccessible"); }, check });
  assert.equal((await checker({})).verdict, "unknown");
  assert.equal(calls, 0);
});

test("same fingerprint is checked once and revocation stays separate from location status", async () => {
  const entries = ["store", "binding"].map((name) => ({ certificatePem: "public", item: { fingerprintSha256: "a".repeat(64), metadata: [{ name: "location", value: name }] } }));
  let calls = 0;
  const now = () => Date.parse("2026-01-01T00:30:00Z");
  await enrichObservedItems(entries, async () => { calls++; return { verdict: "revoked", chainStatus: "valid", checkedAt: "2026-01-01T00:00:00Z", validUntil: "2026-01-01T01:00:00Z" }; }, { now });
  assert.equal(calls, 1);
  for (const { item } of entries) assert.equal(item.metadata.find((m) => m.name === "observedRevocationVerdict").value, "revoked");
});

test("scan checker preserves the origin of local trust material", async () => {
  let actual;
  const material = { roots: ["explicit-root"], intermediates: ["explicit-intermediate"], systemRoots: ["system-root"], systemIntermediates: ["system-intermediate"] };
  const checker = await createScanChecker({ enabled: true, allowedOrigins: ["http://pki.example"] }, { load: () => material, check: (value) => { actual = value; return { verdict: "unknown" }; } });
  await checker({ intermediateCertificates: ["observed-intermediate"] });
  assert.deepEqual(actual.roots, ["explicit-root"]);
  assert.deepEqual(actual.systemRoots, ["system-root"]);
  assert.deepEqual(actual.intermediates, ["explicit-intermediate", "observed-intermediate"]);
  assert.deepEqual(actual.systemIntermediates, ["system-intermediate"]);
});

test("failed verification reports unknown with an attempt time, and concurrency is bounded", async () => {
  const entries = Array.from({ length: 10 }, (_, i) => ({ certificatePem: "public", item: { fingerprintSha256: String(i).repeat(64), metadata: [] } }));
  let active = 0, maximum = 0;
  await enrichObservedItems(entries, async () => { active++; maximum = Math.max(maximum, active); await new Promise((resolve) => setTimeout(resolve, 2)); active--; throw new Error("offline"); }, { concurrency: 3 });
  assert.equal(maximum, 3);
  for (const { item } of entries) {
    assert.equal(item.metadata.find((m) => m.name === "observedRevocationVerdict").value, "unknown");
    assert.ok(item.metadata.find((m) => m.name === "observedRevocationCheckedAt").value);
  }
});
