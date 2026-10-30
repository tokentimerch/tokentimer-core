"use strict";
const { before, it } = require("node:test");
const assert = require("node:assert/strict");
const ledger = require("../../packages/alert-eligibility/deliveryLedger");
let create;
before(async () => {
  ({ createNotificationDeliveryState: create } =
    await import("../../apps/worker/src/shared/notificationDeliveryState.js"));
});
it("parses legitimate arrays and versioned JSON without accepting unknown formats", () => {
  assert.deepEqual(ledger.parseDeliveryLedger('["webhooks"]')?.retry, [
    "webhooks",
  ]);
  assert.equal(
    ledger.parseDeliveryLedger({
      version: 1,
      retry: [],
      required: [],
      outcomes: {},
    })?.legacy,
    false,
  );
  for (const value of [
    null,
    {},
    { version: 2, retry: [] },
    "garbage",
    [{ channel: "email" }],
  ])
    assert.equal(ledger.parseDeliveryLedger(value), null);
});
it("settles proven channels while preserving existing receipts and retry generation", () => {
  const state = create(null);
  const prior = {
    version: 1,
    required: ["email", "webhooks"],
    retry: ["webhooks"],
    evidenceRevision: "keep",
    outcomes: {
      email: { state: "sent", terminal: true, receipt: "preserve" },
      webhooks: {
        state: "failed",
        terminal: false,
        retryGeneration: 3,
        endpoints: { old: "sent" },
      },
    },
  };
  const snapshot = JSON.stringify(prior);
  const result = state.settle({
    prior,
    attempted: [{ channel: "webhooks", success: true }],
    liveChannels: prior.required,
  });
  assert.equal(result.outcome.status, "sent");
  assert.deepEqual(result.ledger.retry, []);
  assert.equal(result.ledger.outcomes.email.receipt, "preserve");
  assert.equal(result.ledger.outcomes.webhooks.retryGeneration, 3);
  assert.deepEqual(result.ledger.outcomes.webhooks.endpoints, { old: "sent" });
  assert.equal(result.ledger.evidenceRevision, "keep");
  assert.equal(JSON.stringify(prior), snapshot);
});
it("preserves unrelated terminal eligibility and provider failures", () => {
  const state = create(null);
  for (const reason of ["eligibility", "provider"]) {
    const prior = {
      version: 1,
      required: ["email", "webhooks"],
      retry: ["webhooks"],
      outcomes: {
        email: {
          state: "blocked",
          terminal: true,
          reason,
          code:
            reason === "eligibility"
              ? "NO_VERIFIED_RECIPIENTS"
              : "PERMANENT_DELIVERY_FAILURE",
        },
      },
    };
    const result = state.settle({
      prior,
      attempted: [{ channel: "webhooks", success: true }],
      liveChannels: prior.required,
    });
    assert.equal(result.outcome.status, "partial");
    assert.deepEqual(result.ledger.outcomes.email, prior.outcomes.email);
    assert.deepEqual(result.ledger.retry, []);
  }
});
it("fails closed when verification is required but its companion is absent", async () => {
  const old = process.env.RECIPIENT_VERIFICATION_MODE;
  const deployment = process.env.TT_DEPLOYMENT;
  try {
    process.env.TT_DEPLOYMENT = "self-hosted";
    process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
    const result = await create(null).recipients({}, "workspace", "email", [
      { contactId: "contact", destination: "a@example.test" },
    ]);
    assert.equal(result.unavailable, true);
    assert.deepEqual(result.allowed, []);
  } finally {
    if (old === undefined) delete process.env.RECIPIENT_VERIFICATION_MODE;
    else process.env.RECIPIENT_VERIFICATION_MODE = old;
    if (deployment === undefined) delete process.env.TT_DEPLOYMENT;
    else process.env.TT_DEPLOYMENT = deployment;
  }
});
