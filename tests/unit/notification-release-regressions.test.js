"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const verification = require("../../packages/recipient-verification");

for (const [channel, accepted, obsolete, replacement] of [
  ["email", "accepted@example.test", "old@example.test", "new@example.test"],
  ["whatsapp", "+14155550101", "+14155550102", "+14155550103"],
]) {
  for (const mode of ["corrected", "removed"]) {
    test(`${channel} settles against ${mode} current recipients and retains history`, () => {
      const current = mode === "corrected" ? [accepted, replacement] : [accepted];
      const prior = {
        version: 1, retry: [channel], required: [channel],
        outcomes: { [channel]: { state: "failed", terminal: false, recipients: {
          [accepted]: { state: "sent" }, [obsolete]: { state: "failed", code: "SMTP_FAILURE" },
        } } },
      };
      const recipients = Object.fromEntries(current.map((key) => [key, { state: "sent" }]));
      const result = verification.mergeDeliveryAttempt({
        prior, liveChannels: [channel],
        attempted: [{ channel, success: true, recipients, currentRecipients: current }],
      });
      assert.equal(result.outcome.status, "sent");
      assert.equal(result.outcome.retry, false);
      assert.equal(result.ledger.outcomes[channel].recipients[obsolete].state, "failed");
      const replay = verification.mergeDeliveryAttempt({
        prior: result.ledger, liveChannels: [channel], attempted: [],
        logRows: [{ channel, status: "failed", metadata: { recipient: obsolete } }],
      });
      assert.equal(replay.outcome.status, "sent");
      const summary = verification.mergeDeliveryAttempt({
        prior: result.ledger, liveChannels: [channel],
        attempted: [{ channel, success: true }],
      });
      assert.equal(summary.outcome.status, "sent");
      assert.equal(summary.ledger.outcomes[channel].recipients[obsolete].state, "failed");
      assert.deepEqual(summary.ledger.outcomes[channel].currentRecipients, current);
    });
  }
}

test("unattempted current recipients remain retryable when the routing lookup succeeds", () => {
  const prior = {
    version: 1, retry: ["email"], required: ["email"],
    outcomes: { email: { state: "failed", terminal: false, recipients: {
      "removed@example.test": { state: "failed" },
      "delivered@example.test": { state: "sent" },
    } } },
  };
  const result = verification.mergeDeliveryAttempt({
    prior,
    liveChannels: ["email"],
    attempted: [{
      channel: "email", success: false, recipients: {},
      currentRecipients: ["delivered@example.test", "pending@example.test"],
    }],
  });
  assert.equal(result.outcome.status, "failed");
  assert.equal(result.ledger.outcomes.email.recipients["delivered@example.test"].state, "sent");
  assert.equal(result.ledger.outcomes.email.recipients["removed@example.test"].state, "failed");
  assert.equal(result.ledger.outcomes.email.recipients["pending@example.test"].state, "failed");
});

for (const action of ["trigger", "acknowledge", "resolve"]) {
  for (const reverse of [false, true]) {
    test(`PagerDuty ${action} and mixed webhook history preserve failed destination (reverse=${reverse})`, () => {
      const generic = { channel: "webhooks", status: "failed", metadata: { urlHash: "generic", terminal: true } };
      const trigger = { channel: "webhooks", status: "success", metadata: { kind: "pagerduty", event_action: "trigger", destination_id: "pagerduty" } };
      const lifecycle = { channel: "webhooks", status: "success", metadata: { kind: "pagerduty", event_action: action, destination_id: "pagerduty" } };
      const logRows = reverse ? [trigger, lifecycle, generic] : [generic, trigger, lifecycle];
      const result = verification.mergeDeliveryAttempt({
        prior: { version: 1, retry: ["email"], required: ["email", "webhooks"], outcomes: {} },
        logRows, attempted: [{ channel: "email", success: true }], liveChannels: ["email", "webhooks"],
      });
      assert.equal(result.outcome.status, "partial");
      assert.equal(result.outcome.notifyProviderTerminal, true);
      assert.equal(result.ledger.outcomes.webhooks.endpoints.generic, "permanent");
      assert.equal(result.ledger.outcomes.webhooks.endpoints.pagerduty, "sent");
    });
  }
}

test("ambiguous legacy PagerDuty events cannot settle another webhook", () => {
  const result = verification.mergeDeliveryAttempt({
    prior: { version: 1, retry: ["email"], required: ["email", "webhooks"], outcomes: {} },
    logRows: [
      { channel: "webhooks", status: "failed", metadata: { urlHash: "generic", terminal: true } },
      { channel: "webhooks", status: "success", metadata: { kind: "pagerduty", event_action: "trigger", urlHash: "generic" } },
    ],
    attempted: [{ channel: "email", success: true }], liveChannels: ["email", "webhooks"],
  });
  assert.equal(result.ledger.outcomes.webhooks.endpoints.generic, "permanent");
  assert.equal(result.outcome.status, "partial");
});
