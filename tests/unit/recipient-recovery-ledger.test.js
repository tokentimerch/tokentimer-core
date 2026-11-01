"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const verification = require("../../packages/recipient-verification");

for (const channel of ["email", "whatsapp"]) {
  const destination = channel === "email" ? "recipient@example.com" : "+14155550100";
  test(`${channel} recovery clears an earlier channel-level verification outage`, () => {
    const pending = verification.mergeDeliveryAttempt({
      prior: [channel],
      attempted: [{ channel, success: false, recipients: {
        [destination]: { state: "unavailable", code: "RECIPIENT_VERIFICATION_UNAVAILABLE" },
      } }],
      liveChannels: [channel],
    });
    const recovered = verification.mergeDeliveryAttempt({
      prior: pending.ledger,
      logRows: [{ channel, status: "failed", error_message: "RECIPIENT_VERIFICATION_UNAVAILABLE",
        metadata: { group_id: "default", code: "RECIPIENT_VERIFICATION_UNAVAILABLE" } }],
      attempted: [{ channel, success: true, recipients: { [destination]: { state: "sent" } } }],
      liveChannels: [channel],
    });
    assert.equal(recovered.outcome.status, "sent");
    assert.equal(recovered.outcome.retry, false);
    assert.deepEqual(Object.keys(recovered.ledger.outcomes[channel].recipients), [destination]);
  });
}

test("partial delivery logs preserve another recipient awaiting verification infrastructure", () => {
  const pending = verification.mergeDeliveryAttempt({
    prior: ["email", "webhooks"],
    attempted: [{ channel: "email", success: false, recipients: {
      "a@example.com": { state: "sent" },
      "b@example.com": { state: "unavailable", code: "RECIPIENT_VERIFICATION_UNAVAILABLE" },
    } }],
    liveChannels: ["email", "webhooks"],
  });
  const webhookOnly = verification.mergeDeliveryAttempt({
    prior: pending.ledger,
    logRows: [{ channel: "email", status: "success", metadata: { recipient: "a@example.com" } }],
    attempted: [{ channel: "webhooks", success: true }],
    liveChannels: ["email", "webhooks"],
  });
  assert.equal(webhookOnly.outcome.status, "partial");
  assert.deepEqual(webhookOnly.ledger.retry, ["email"]);
  assert.equal(webhookOnly.ledger.outcomes.email.recipients["b@example.com"].state, "unavailable");
});
