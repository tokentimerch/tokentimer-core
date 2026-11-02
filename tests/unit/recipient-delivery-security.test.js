"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const verification = require("../../packages/recipient-verification");
const shared = require("../../packages/alert-eligibility/deliveryLedger");

const dangerous = ["__proto__", "constructor", "prototype"];
const hostile = JSON.parse('{"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}},"prototype":{"polluted":true}}');

function cleanTree(value) {
  if (!value || typeof value !== "object") return;
  assert.ok([Object.prototype, Array.prototype, null].includes(Object.getPrototypeOf(value)));
  for (const key of Object.keys(value)) {
    assert.ok(!dangerous.includes(key), `unsafe key ${key}`);
    cleanTree(value[key]);
  }
  assert.equal(Object.prototype.polluted, undefined);
  assert.equal(Object.prototype.state, undefined);
}

for (const [name, module] of [["recipient", verification], ["shared", shared]]) {
  test(`${name} ledger sanitizes channel, recipient, endpoint and nested JSON keys`, () => {
    const prior = {
      version: 1, retry: ["email", ...dangerous], required: ["email", "webhooks", ...dangerous],
      outcomes: {
        ...hostile,
        email: { state: "failed", recipients: { ...hostile, "person@example.com": { state: "failed", ...hostile } } },
        webhooks: { state: "failed", endpoints: { ...hostile, abc: "failed" } },
      },
    };
    for (const input of [prior, JSON.stringify(prior)]) {
      const parsed = module.parseDeliveryLedger(input);
      assert.deepEqual(parsed.required, ["email", "webhooks"]);
      assert.deepEqual(parsed.retry, ["email"]);
      cleanTree(parsed);
      assert.equal(parsed.outcomes.email.recipients["person@example.com"].state, "failed");
      const merged = module.mergeDeliveryAttempt({
        prior: input,
        liveChannels: ["email", "webhooks", ...dangerous],
        attempted: [...dangerous.map((channel) => ({ channel, success: true })), {
          channel: "webhooks", success: false, endpoints: { ...hostile, abc: "failed" },
        }],
      });
      cleanTree(merged);
      assert.deepEqual(merged.ledger.required, ["email", "webhooks"]);
      assert.equal(merged.outcome.retry, true);
    }
    assert.equal(Object.hasOwn(prior.outcomes, "__proto__"), true, "caller input is unchanged");
  });

  test(`${name} ledger keeps legacy arrays, serialized arrays and ordinary extension channels`, () => {
    for (const prior of [["email", "whatsapp", "webhooks", "custom"], '["email","whatsapp","webhooks","custom"]']) {
      assert.deepEqual(module.parseDeliveryLedger(prior).retry, ["email", "whatsapp", "webhooks", "custom"]);
      const merged = module.mergeDeliveryAttempt({ prior, attempted: [{ channel: "email", success: true }], liveChannels: ["email", "whatsapp"] });
      assert.deepEqual(merged.ledger.retry, ["whatsapp"]);
      assert.equal(merged.ledger.outcomes.email.state, "sent");
      cleanTree(merged);
    }
  });
}

test("hostile log channels cannot mutate prototypes or manufacture a successful delivery", () => {
  const merged = verification.mergeDeliveryAttempt({
    prior: ["email", "webhooks"], liveChannels: ["email", "webhooks"],
    logRows: [
      ...dangerous.map((channel) => ({ channel, status: "success" })),
      ...dangerous.map((recipient) => ({ channel: "email", status: "success", metadata: { recipient } })),
      ...dangerous.map((urlHash) => ({ channel: "webhooks", status: "success", metadata: { urlHash } })),
      { channel: "email", status: "failed", metadata: { recipient: "person@example.com" } },
      { channel: "webhooks", status: "failed", metadata: { urlHash: "safe-hash" } },
    ],
  });
  cleanTree(merged);
  assert.deepEqual(merged.ledger.retry, ["email", "webhooks"]);
  assert.equal(merged.ledger.outcomes.email.recipients["person@example.com"].state, "failed");
  assert.equal(merged.ledger.outcomes.webhooks.endpoints["safe-hash"], "failed");
});

test("nested attempts retain unresolved recipients while dropping reserved keys", () => {
  const pending = verification.mergeDeliveryAttempt({
    prior: ["email"], liveChannels: ["email"], attempted: [{ channel: "email", recipients: {
      ...hostile, "one@example.com": { state: "sent" }, "two@example.com": { state: "unavailable" },
    } }],
  });
  const retry = verification.planManualRetry(pending.ledger, "email");
  assert.equal(retry.ok, true);
  const reconciled = verification.reconcileDeliveryChannels(retry.channels, ["email", ...dangerous]);
  cleanTree(reconciled.channels);
  assert.deepEqual(reconciled.channels.retry, ["email"]);
  for (const key of dangerous) assert.equal(verification.planManualRetry(pending.ledger, key).ok, false);
  const settled = verification.mergeDeliveryAttempt({ prior: reconciled.channels, attempted: [{
    channel: "email", recipients: { "two@example.com": { state: "sent" }, ...hostile },
  }] });
  assert.equal(settled.outcome.status, "sent");
  assert.equal(settled.ledger.outcomes.email.recipients["one@example.com"].state, "sent");
  cleanTree(settled);
});

test("parsing discards inherited outcomes and inherited recipient state", () => {
  const inherited = Object.create({ state: "sent", terminal: true });
  const prior = { version: 1, retry: ["email"], required: ["email"], outcomes: Object.create({ email: inherited }) };
  const merged = verification.mergeDeliveryAttempt({ prior });
  assert.deepEqual(merged.ledger.retry, []);
  const configured = verification.mergeDeliveryAttempt({ prior, liveChannels: ["email"] });
  assert.deepEqual(configured.ledger.retry, ["email"]);
  assert.equal(configured.outcome.status, "failed");
  assert.equal(verification.recipientChannelOutcome({ "person@example.com": inherited }).state, "blocked");
  cleanTree(configured);
});
