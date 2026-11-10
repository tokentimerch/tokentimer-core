"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const verification = require("../../packages/recipient-verification");

const unverified = {
  state: "blocked", terminal: true, reason: "eligibility", code: "NO_VERIFIED_RECIPIENTS",
};

test("manual recipient retry reopens an old unverified result and preserves delivered channels", () => {
  const settled = {
    version: 1, retry: [], required: ["email", "webhooks"],
    outcomes: { email: unverified, webhooks: { state: "sent", terminal: true } },
  };
  const retry = verification.planManualRetry(settled);
  assert.equal(retry.ok, true);
  assert.deepEqual(retry.channels.retry, ["email"]);
  assert.equal(retry.channels.outcomes.email, undefined);
  assert.equal(retry.channels.outcomes.webhooks.state, "sent");
  const stillUnverified = verification.mergeDeliveryAttempt({
    prior: retry.channels, liveChannels: ["email", "webhooks"],
    attempted: [{ channel: "email", eligibilityTerminal: true, errorCode: "NO_VERIFIED_RECIPIENTS" }],
  });
  assert.equal(stillUnverified.outcome.status, "partial");
  assert.deepEqual(stillUnverified.ledger.retry, []);
  const confirmed = verification.mergeDeliveryAttempt({
    prior: retry.channels, liveChannels: ["email", "webhooks"],
    attempted: [{ channel: "email", success: true }],
  });
  assert.equal(confirmed.outcome.status, "sent");
});

test("manual recipient retry retains an explicit opt-out, revocation, or suppression", () => {
  for (const code of ["RECIPIENT_OPTED_OUT", "RECIPIENT_REVOKED", "RECIPIENT_SUPPRESSED"]) {
    const settled = { version: 1, retry: [], required: ["email"], outcomes: { email: { ...unverified, code } } };
    assert.equal(verification.planManualRetry(settled, "email").code, code);
  }
});

test("the worker gate reads fresh consent for each retry and honours a later opt-out", async (t) => {
  const envKeys = ["TT_DEPLOYMENT", "RECIPIENT_VERIFICATION_MODE", "RECIPIENT_FINGERPRINT_SECRET"];
  const previous = envKeys.map((key) => process.env[key]);
  t.after(() => envKeys.forEach((key, index) => {
    if (previous[index] === undefined) delete process.env[key];
    else process.env[key] = previous[index];
  }));
  process.env.TT_DEPLOYMENT = "cloud";
  process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
  process.env.RECIPIENT_FINGERPRINT_SECRET = "recipient-manual-recheck-fixture";

  const { gateDestinations, recheckDestination } = await import("../../apps/worker/src/shared/recipientDeliveryGate.js");
  for (const [channel, destination] of [["email", "pending@example.com"], ["whatsapp", "+14155550101"]]) {
    const recipient = { contactId: "contact", destination };
    let current = { status: "pending", consent_at: null };
    const client = {
      async query(sql) {
        if (sql.includes("RV_SUPPRESSION_LOOKUP")) return { rows: [] };
        if (sql.includes("RV_VERIFIED_MEMBER_EMAILS")) return { rows: [] };
        assert.match(sql, /RV_DELIVERY_LOOKUP/);
        return { rows: [current] };
      },
    };
    const first = await gateDestinations(client, "workspace", channel, [recipient]);
    assert.equal(first.code, "NO_VERIFIED_RECIPIENTS");
    const settled = { version: 1, retry: [], required: [channel], outcomes: { [channel]: unverified } };
    const retry = verification.planManualRetry(settled, channel);
    assert.deepEqual(retry.channels.retry, [channel]);
    current = { status: "verified", consent_at: new Date() };
    assert.deepEqual((await gateDestinations(client, "workspace", channel, [recipient])).allowed, [recipient]);
    current = { status: "opted_out", consent_at: null };
    assert.equal((await recheckDestination(client, "workspace", channel, recipient)).code, "RECIPIENT_OPTED_OUT");
  }
});
