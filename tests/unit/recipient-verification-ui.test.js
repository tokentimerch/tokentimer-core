"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.resolve(__dirname, "../../apps/dashboard/src/pages/AlertPreferences.jsx"), "utf8");

// Evaluate the actual page handlers with API, toast and clipboard boundaries
// recorded. This catches false success messages when the server withheld delivery.
function handler(channel, data, { viewer = false, pageSource = source } = {}) {
  const name = channel === "email" ? "handleInviteEmail" : "handleShareWhatsApp";
  const match = pageSource.match(new RegExp(`^  async function ${name}\\(contact\\) \\{[\\s\\S]*?(?=^  (?:async )?function )`, "m"));
  assert.ok(match, `Missing actual page handler ${name}`);
  const calls = { success: [], errors: [], posts: [], clipboard: [], busy: [], refreshes: 0 };
  const run = vm.runInNewContext(`${match[0]}\n${name}`, {
    workspaceId: "workspace-a", isViewer: viewer,
    apiClient: { post: async url => { calls.posts.push(url); return { data }; } },
    showSuccess: message => calls.success.push(message),
    showError: message => calls.errors.push(message),
    setVerificationBusy: value => calls.busy.push(value),
    refreshContacts: async () => { calls.refreshes++; },
    verificationErrorMessage: error => error.message,
    navigator: { clipboard: { writeText: async value => calls.clipboard.push(value) } },
    window: { prompt() { throw Error("Unexpected browser prompt"); } },
  });
  return { run, calls };
}

for (const channel of ["email", "whatsapp"]) {
  for (const data of [{ status: "opted_out" }, { code: "RECIPIENT_OPTED_OUT" }]) {
    test(`${channel} opted-out ${Object.keys(data)[0]} reports withheld delivery without a false success`, async () => {
      const { run, calls } = handler(channel, {
        ...data,
        share_url: "https://example.test/verify/recipient/withheld-link",
      });
      await run({ id: "contact-b" });
      assert.deepEqual(calls.success, []);
      assert.equal(calls.errors.length, 1);
      assert.match(calls.errors[0], channel === "email" ? /did not email them/ : /did not create a confirmation link/);
      if (channel === "whatsapp") {
        assert.match(calls.errors[0], /re-subscription is not currently available/);
        assert.doesNotMatch(calls.errors[0], /can subscribe again/);
      }
      assert.deepEqual(calls.clipboard, []);
      assert.equal(calls.refreshes, 1);
      assert.equal(calls.busy.at(-1), "");
      assert.deepEqual(calls.posts, [`/api/v1/workspaces/workspace-a/contacts/contact-b/verifications/${channel}`]);
    });
  }
  test(`${channel} verification actions remain blocked for viewers`, async () => {
    const { run, calls } = handler(channel, {}, { viewer: true });
    await run({ id: "contact-b" });
    assert.deepEqual(calls.posts, []);
    assert.deepEqual(calls.busy, []);
  });
}

test("email sent acknowledgement still reports an actual invitation", async () => {
  const { run, calls } = handler("email", { status: "sent" });
  await run({ id: "contact-b" });
  assert.equal(calls.success.length, 1);
  assert.deepEqual(calls.errors, []);
  assert.equal(calls.refreshes, 1);
});

test("pending WhatsApp invitation still copies the returned confirmation link", async () => {
  const url = "https://example.test/verify/recipient/test-token";
  const { run, calls } = handler("whatsapp", { status: "pending", share_url: url });
  await run({ id: "contact-b" });
  assert.deepEqual(calls.clipboard, [url]);
  assert.equal(calls.success.length, 1);
  assert.deepEqual(calls.errors, []);
});
