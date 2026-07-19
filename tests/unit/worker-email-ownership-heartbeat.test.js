"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const emailModuleUrl = pathToFileURL(
  path.resolve(__dirname, "../../apps/worker/src/notify/email.js"),
).href;

describe("worker email SMTP ownership heartbeat helpers", () => {
  it("caps SMTP account attempts below the delivery lease budget", async () => {
    const { resolveSmtpAccountAttemptLimit } = await import(emailModuleUrl);
    assert.equal(resolveSmtpAccountAttemptLimit(1), 1);
    assert.equal(resolveSmtpAccountAttemptLimit(10), 10);
    assert.equal(resolveSmtpAccountAttemptLimit(25), 10);
    assert.equal(resolveSmtpAccountAttemptLimit(25, "3"), 3);
    assert.equal(resolveSmtpAccountAttemptLimit(25, "0"), 10);
    assert.equal(resolveSmtpAccountAttemptLimit(25, "nope"), 10);
  });

  it("invokes onBeforeAttempt in test short-circuit and propagates ownership loss", async () => {
    const prev = process.env.NODE_ENV;
    process.env.NODE_ENV = "test";
    try {
      const { sendEmailNotification } = await import(
        `${emailModuleUrl}?heartbeat=${Date.now()}`
      );
      const calls = [];
      const ok = await sendEmailNotification({
        to: "a@example.com",
        subject: "s",
        text: "t",
        onBeforeAttempt: async (meta) => {
          calls.push(meta);
        },
      });
      assert.equal(ok.success, true);
      assert.equal(calls.length, 1);
      assert.equal(calls[0].attempt, "test-short-circuit");

      const lost = new Error("ownership lost");
      lost.name = "DeliveryOwnershipLostError";
      await assert.rejects(
        () =>
          sendEmailNotification({
            to: "a@example.com",
            subject: "s",
            text: "t",
            onBeforeAttempt: async () => {
              throw lost;
            },
          }),
        (err) => err?.name === "DeliveryOwnershipLostError",
      );
    } finally {
      process.env.NODE_ENV = prev;
    }
  });
});
