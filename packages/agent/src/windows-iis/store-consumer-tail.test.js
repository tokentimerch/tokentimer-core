"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { runStoreConsumerTail } = require("./store-consumer-tail");
const consumer = { consumerId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", authorizationRevision: 1,
  binding: { address: "*", store: "My", site: "Default Web Site", port: 443 } };
function scenario(overrides = {}) {
  const calls = [];
  return { calls, options: { snapshot: { predecessorFingerprintSha256: "ab".repeat(32), iisConsumers: [consumer] },
    certificatePem: "verified certificate", jobId: "job", claimId: "claim",
    client: { authorizeIisConsumer: async (request) => { calls.push(["authorize", request]); return true; } },
    acquireLock: async () => ({ assertHeld() {}, run: async (fn) => fn(), release() { calls.push(["released"]); } }),
    ensureLease: async () => {}, onBeforeMutation: () => calls.push(["mutation"]),
    observeImpl: async () => ({ existingThumbprintSha1: "cd".repeat(20) }),
    deployImpl: async (options) => { calls.push(["deploy", options]); return { ok: true }; },
    reportOutcome: async (outcome) => calls.push(["outcome", outcome]), ...overrides } };
}
test("Store consumer tail uses the frozen predecessor and the current claim, then reports each result", async () => {
  const { options, calls } = scenario();
  assert.equal((await runStoreConsumerTail(options)).allAttempted, true);
  assert.deepEqual(calls[0], ["authorize", { jobId: "job", claimId: "claim", consumerId: consumer.consumerId, authorizationRevision: 1 }]);
  assert.equal(calls[2][1].expectedExistingThumbprint, "CD".repeat(20));
  assert.equal(calls[3][0], "outcome");
  assert.equal(calls.at(-1)[0], "released");
});
test("an unavailable authorization reports a skipped consumer without changing IIS", async () => {
  const { options, calls } = scenario({ client: { authorizeIisConsumer: async () => { throw new Error("offline"); } } });
  const result = await runStoreConsumerTail(options);
  assert.equal(result.outcomes[0].code, "CONSENT_UNAVAILABLE");
  assert.equal(calls.some(([name]) => name === "deploy"), false);
});
test("a missing predecessor or a lost lease never changes IIS and always releases the lock", async () => {
  for (const overrides of [{ observeImpl: async () => ({ error: "missing" }) }, { ensureLease: async () => { throw new Error("lease lost"); } }]) {
    const { options, calls } = scenario(overrides);
    await assert.rejects(runStoreConsumerTail(options));
    assert.equal(calls.some(([name]) => name === "deploy"), false);
    assert.equal(calls.at(-1)[0], "released");
  }
});
test("Store-only renewal has no IIS side effects without opt-in", async () => {
  assert.deepEqual(await runStoreConsumerTail({ snapshot: {}, acquireLock() { throw new Error("unexpected"); } }), { allAttempted: true, outcomes: [] });
});
