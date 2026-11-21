"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createPebbleCaObserver } = require("./certops-acme-store-pebble-observer");
const { verifyCrashRecovery } = require("./certops-acme-store-native-qualification");

test("the Pebble adapter uses the independent proxy and refuses unverified isolation", async () => {
  let isolation = { coverageComplete: true, startedBeforeIssue: true, directCaAccessBlocked: true, proxyAccessAllowed: true, coverageId: "a".repeat(32) };
  let entries = [{ orderId: "b".repeat(64), finalized: true, fingerprintSha256: "c".repeat(64) }];
  let activeRequests = 0, activeConnections = 0, activeUpstreamRequests = 0;
  const proxy = { snapshot: () => ({ transportFailed: false, activeRequests, activeConnections, activeUpstreamRequests }), ordersForDns: dns => {
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
  activeRequests = 1;
  await assert.rejects(observe({ dnsName: "run.example.test" }), /in flight/);
  activeRequests = undefined;
  await assert.rejects(observe({ dnsName: "run.example.test" }), /permanently invalidated/);
  activeRequests = 0;
  for (const [key, expected] of [["client", /drained client/], ["upstream", /drained upstream/]]) {
    const another = createPebbleCaObserver({ proxy, inspectIsolation: async () => isolation });
    if (key === "client") activeConnections = 1; else activeUpstreamRequests = 1;
    await assert.rejects(another({ dnsName: "run.example.test" }), expected);
    activeConnections = 0; activeUpstreamRequests = 0;
    await assert.rejects(another({ dnsName: "run.example.test" }), /permanently invalidated/);
  }
  isolation = { ...isolation, directCaAccessBlocked: false };
  await assert.rejects(observe({ dnsName: "run.example.test" }));
  assert.throws(() => createPebbleCaObserver({ proxy }));
  assert.throws(() => verifyCrashRecovery({ phase: "foreign" }));
});

test("concurrent observations invalidate even the pending result", async () => {
  let unblock;
  const pending = new Promise(resolve => { unblock = resolve; });
  const observe = createPebbleCaObserver({ proxy: { snapshot: () => ({ transportFailed: false, activeRequests: 0, activeConnections: 0, activeUpstreamRequests: 0 }), ordersForDns: () => [] },
    inspectIsolation: async () => { await pending; return { coverageComplete: true, startedBeforeIssue: true, directCaAccessBlocked: true, proxyAccessAllowed: true, coverageId: "a".repeat(32) }; } });
  const first = observe({ dnsName: "run.example.test" });
  await assert.rejects(observe({ dnsName: "run.example.test" }), /Concurrent/);
  unblock();
  await assert.rejects(first, /permanently invalidated/);
});
