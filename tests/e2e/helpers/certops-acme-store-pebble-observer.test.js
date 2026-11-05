"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createPebbleCaObserver } = require("./certops-acme-store-pebble-observer");
const { verifyCrashRecovery } = require("./certops-acme-store-native-qualification");

test("the Pebble adapter uses the independent proxy and refuses unverified isolation", async () => {
  let isolation = { coverageComplete: true, startedBeforeIssue: true, directCaAccessBlocked: true, proxyAccessAllowed: true, coverageId: "a".repeat(32) };
  let entries = [{ orderId: "b".repeat(64), finalized: true, fingerprintSha256: "c".repeat(64) }];
  const proxy = { snapshot: () => ({ transportFailed: false }), ordersForDns: dns => {
    assert.equal(dns, "run.example.test"); return entries;
  } };
  const observe = createPebbleCaObserver({ proxy, inspectIsolation: async () => isolation });
  const result = await observe({ dnsName: "run.example.test" });
  assert.equal(result.source, "isolated-ca-proxy");
  assert.equal(result.ordersForDns, 1);
  assert.equal(result.finalizedOrdersForDns, 1);
  assert.equal(result.fingerprintSha256, "c".repeat(64));
  entries = [...entries, { orderId: "d".repeat(64), finalized: false }];
  const duplicate = await observe({ dnsName: "run.example.test" });
  assert.equal(duplicate.ordersForDns, 2);
  assert.equal(duplicate.orderId, null);
  isolation = { ...isolation, directCaAccessBlocked: false };
  await assert.rejects(observe({ dnsName: "run.example.test" }));
  assert.throws(() => createPebbleCaObserver({ proxy }));
  assert.throws(() => verifyCrashRecovery({ phase: "foreign" }));
});
