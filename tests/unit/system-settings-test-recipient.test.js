"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const recipientVerification = require("../../packages/recipient-verification");

const source = fs.readFileSync(path.resolve(__dirname, "../../apps/api/routes/alerts.js"), "utf8");
const block = source.slice(source.indexOf("// GET /api/admin/system-settings"), source.indexOf("// PUT /api/admin/system-settings"));
const start = block.indexOf("async (req, res) => {");
const end = block.lastIndexOf("\n  },");
assert.ok(start >= 0 && end > start, "Actual system-settings handler must exist");

for (const [deployment, mode, locked] of [
  ["self-hosted", "off", false],
  ["self-hosted", "shadow", false],
  ["self-hosted", "enforce", true],
  ["cloud", "off", true],
]) {
  test(`system settings exposes the effective SMTP test destination for ${deployment}/${mode}`, async () => {
    const names = ["TT_DEPLOYMENT", "RECIPIENT_VERIFICATION_MODE", "RECIPIENT_VERIFICATION_CLOUD_SHADOW"];
    const before = Object.fromEntries(names.map(name => [name, process.env[name]]));
    try {
      process.env.TT_DEPLOYMENT = deployment;
      process.env.RECIPIENT_VERIFICATION_MODE = mode;
      delete process.env.RECIPIENT_VERIFICATION_CLOUD_SHADOW;
      const handler = vm.runInNewContext(`(${block.slice(start, end)}\n})`, {
        recipientVerification,
        pool: {},
        systemSettings: {
          getAllSettings: async () => ({}),
          isSmtpConfigured: async () => true,
          isWhatsAppAvailable: async () => false,
          listRegisteredJsonColumns: () => [],
        },
        logger: { error: () => assert.fail("System-settings handler failed") },
      });
      let response;
      await handler({ user: { email: "administrator@example.test" } }, {
        json: value => { response = value; },
        status: () => assert.fail("System-settings handler returned an error"),
      });
      assert.equal(response.smtp.test_recipient, locked ? "administrator@example.test" : null);
    } finally {
      for (const name of names) {
        if (before[name] === undefined) delete process.env[name];
        else process.env[name] = before[name];
      }
    }
  });
}

function providerTestHandler(providerError) {
  const page = fs.readFileSync(path.resolve(__dirname, "../../apps/dashboard/src/pages/SystemSettings.jsx"), "utf8");
  const start = page.indexOf("  async function handleTestWhatsapp()");
  const end = page.indexOf("  function renderField(", start);
  assert.ok(start >= 0 && end > start, "Actual administrator provider-test handler must exist");
  const calls = { successes: [], warnings: [], busy: [], posts: 0 };
  const run = vm.runInNewContext(page.slice(start, end) + "\nhandleTestWhatsapp", {
    testPhone: "+12025550123",
    setTestingWhatsapp: value => calls.busy.push(value),
    apiClient: { post: async () => {
      calls.posts++;
      if (providerError) throw providerError;
      return { data: { message: "Test message sent" } };
    } },
    showSuccess: value => calls.successes.push(value),
    showWarning: value => calls.warnings.push(value),
  });
  return { run, calls };
}

test("administrator WhatsApp tests distinguish submission from confirmed delivery", async () => {
  const { run, calls } = providerTestHandler();
  await run();
  assert.equal(calls.posts, 1);
  assert.equal(calls.successes.length, 1);
  assert.match(calls.successes[0], /submitted.*phone.*confirm delivery/i);
  assert.deepEqual(calls.warnings, []);
  assert.deepEqual(calls.busy, [true, false]);
});

test("administrator WhatsApp tests explain an unavailable provider account without a false success", async () => {
  const { run, calls } = providerTestHandler({ response: { data: { code: 63112 } } });
  await run();
  assert.deepEqual(calls.successes, []);
  assert.match(calls.warnings[0], /Meta business verification and account status/);
  assert.deepEqual(calls.busy, [true, false]);
});
