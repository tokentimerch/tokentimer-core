"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { checkPin, createIndependentPebbleObserver } = require("./certops-acme-independent-pebble-observer");

const dnsName = "tt-acme-0123456789abcdef01234567.example.test";
const digest = "a".repeat(64), instance = "b".repeat(32), capture = "c".repeat(32);
const order1 = "d".repeat(64), order2 = "e".repeat(64), leaf = "f".repeat(64);
function setup() {
  let snapshot = { instanceId: instance, orders: [] };
  let guard = { coverageComplete: true, startedBeforeIssue: true, lossFree: true, managementLoopback: true,
    instanceId: instance, binarySha256: digest, processId: 42, captureId: capture };
  return {
    setSnapshot: value => { snapshot = value; }, setGuard: value => { guard = { ...guard, ...value }; },
    create: () => createIndependentPebbleObserver({ origin:"https://127.0.0.1:15000", caPem:"test", tlsSha256:digest,
      binarySha256:digest, dnsName, inspectContinuity:async () => ({ ...guard }),
      readSnapshot:async () => structuredClone(snapshot) }),
  };
}

test("independent CA observer tracks duplicate orders and their public leaf identity", async () => {
  const fixture=setup(), observe=await fixture.create();
  fixture.setSnapshot({ instanceId:instance, orders:[{ orderId:order1, fingerprintSha256:leaf }] });
  const first=await observe();
  assert.equal(first.ordersForDns,1); assert.equal(first.finalizedOrdersForDns,1); assert.equal(first.fingerprintSha256,leaf);
  fixture.setSnapshot({ instanceId:instance, orders:[{ orderId:order1, fingerprintSha256:leaf },{ orderId:order2 }] });
  const after=await observe(); assert.equal(after.ordersForDns,2); assert.equal(after.orderId,null);
});

test("restarts, lost monitoring, altered binaries and disappearing orders fail closed", async () => {
  for (const change of [{coverageComplete:false},{lossFree:false},{managementLoopback:false},
    {startedBeforeIssue:false},{instanceId:"1".repeat(32)},{binarySha256:"1".repeat(64)},
    {captureId:"1".repeat(32)},{processId:43}]) {
    const fixture=setup(), observe=await fixture.create(); fixture.setGuard(change);
    await assert.rejects(observe());
  }
  const fixture=setup(), observe=await fixture.create();
  fixture.setSnapshot({instanceId:instance,orders:[{orderId:order1,fingerprintSha256:leaf}]}); await observe();
  fixture.setSnapshot({instanceId:instance,orders:[]}); await assert.rejects(observe());
  fixture.setSnapshot({instanceId:"1".repeat(32),orders:[{orderId:order1}]}); await assert.rejects(observe());
  fixture.setSnapshot({instanceId:instance,orders:[{orderId:order1},{orderId:order1}]}); await assert.rejects(observe());
});

test("CA TLS must pass hostname verification and the exact leaf pin", () => {
  const cert={subjectaltname:"IP Address:127.0.0.1",raw:Buffer.from("public certificate")};
  const correct=createHash("sha256").update(cert.raw).digest("hex");
  assert.equal(checkPin("127.0.0.1",cert,correct),undefined);
  assert.ok(checkPin("127.0.0.1",cert,"0".repeat(64)) instanceof Error);
  assert.ok(checkPin("127.0.0.2",cert,correct) instanceof Error);
});

test("lost continuity and failed reads permanently invalidate the observation", async () => {
  const fixture = setup(), observe = await fixture.create();
  fixture.setGuard({ lossFree: false });
  await assert.rejects(observe());
  fixture.setGuard({ lossFree: true });
  await assert.rejects(observe(), /permanently invalidated/);
  const other = setup(), read = await other.create();
  other.setSnapshot(null);
  await assert.rejects(read());
  other.setSnapshot({ instanceId: instance, orders: [] });
  await assert.rejects(read(), /permanently invalidated/);
});

test("concurrent observations invalidate even the pending CA result", async () => {
  let unblock, block = false;
  const pending = new Promise(resolve => { unblock = resolve; });
  const guard = { coverageComplete: true, startedBeforeIssue: true, lossFree: true, managementLoopback: true,
    instanceId: instance, binarySha256: digest, processId: 42, captureId: capture };
  const observe = await createIndependentPebbleObserver({ origin: "https://127.0.0.1:15000", caPem: "test", tlsSha256: digest,
    binarySha256: digest, dnsName, inspectContinuity: async () => { if (block) await pending; return guard; },
    readSnapshot: async () => ({ instanceId: instance, orders: [] }) });
  block = true;
  const first = observe();
  await assert.rejects(observe(), /Concurrent/);
  unblock();
  await assert.rejects(first, /permanently invalidated/);
});
