"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { deployStoreConsumers } = require("./store-consumers");
const binding = { address: "*", port: 443, store: "My", site: "Default Web Site" };
const common = { authorizeImpl: async () => true, predecessorThumbprint: "ab".repeat(20), certificatePem: "public cert", onBeforeMutation() {} };

test("updates only the supplied authorized bindings once using the predecessor", async () => {
  const calls = [];
  const consumers = [{ consumerId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", authorizationRevision: 1, binding },
    { consumerId: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", authorizationRevision: 1, binding: { ...binding, port: 8443 } }];
  const result = await deployStoreConsumers({ ...common, consumers, deployImpl: async (opts) => {
    calls.push(opts); return calls.length === 1 ? { ok: true } : { ok: false, code: "EXPECTED_BINDING_MISSING" };
  } });
  assert.equal(calls.length, 2);
  assert.equal(calls[0].expectedExistingThumbprint, "AB".repeat(20));
  assert.deepEqual(result, { allAttempted: true, outcomes: [{ id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", ok: true, code: null },
    { id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", ok: false, code: "EXPECTED_BINDING_MISSING" }] });
});

test("rejects duplicate physical selectors and unapproved consumers before any mutation", async () => {
  let calls = 0; const deployImpl = async () => { calls++; return { ok: true }; };
  const sameSelector = [{ consumerId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", authorizationRevision: 1, binding },
    { consumerId: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", authorizationRevision: 1, binding: { ...binding, site: "Other Site" } }];
  await assert.rejects(deployStoreConsumers({ ...common, consumers: sameSelector, deployImpl }), /duplicate/);
  await assert.rejects(deployStoreConsumers({ ...common, consumers: [{ consumerId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", authorizationRevision: 0, binding }], deployImpl }), /authorization/);
  assert.equal(calls, 0);
});

test("stops after cancellation without touching subsequent bindings", async () => {
  const controller = new AbortController();
  const consumers = [{ consumerId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", authorizationRevision: 1, binding }, { consumerId: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", authorizationRevision: 1, binding: { ...binding, port: 8443 } }];
  const result = await deployStoreConsumers({ ...common, consumers, signal: controller.signal, deployImpl: async () => {
    controller.abort(); return { ok: false, code: "ABORTED" };
  } });
  assert.deepEqual(result, { allAttempted: false, outcomes: [{ id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", ok: false, code: "ABORTED" }] });
});

test("does not dispatch a binding when authorization is lost at the mutation gate", async () => {
  const controller = new AbortController(); let calls = 0;
  const result = await deployStoreConsumers({ ...common, consumers: [{ consumerId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", authorizationRevision: 1, binding }],
    signal: controller.signal, onBeforeMutation() { controller.abort(); },
    deployImpl: async () => { calls++; return { ok: true }; } });
  assert.equal(calls, 0);
  assert.deepEqual(result, { allAttempted: false, outcomes: [] });
});

test("does not change a binding when live authorization is denied or unavailable", async () => {
  let mutations = 0;
  const result = await deployStoreConsumers({ ...common, consumers: [{ consumerId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", authorizationRevision: 1, binding }],
    authorizeImpl: async () => false, deployImpl: async () => { mutations++; return { ok: true }; } });
  assert.equal(mutations, 0);
  assert.deepEqual(result, { allAttempted: true, outcomes: [{ id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", ok: false, code: "CONSENT_UNAVAILABLE" }] });
});
