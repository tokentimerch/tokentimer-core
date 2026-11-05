"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.resolve(__dirname, "../../apps/dashboard/src/pages/AlertPreferences.jsx"), "utf8");

// Evaluate the actual page handlers with API, toast and clipboard boundaries
// recorded. This catches false success messages when the server withheld delivery.
function handler(channel, data, { viewer = false, pageSource = source, clipboardFailure = false, clipboardAvailable = true } = {}) {
  const name = channel === "email" ? "handleInviteEmail" : "handleShareWhatsApp";
  const match = pageSource.match(new RegExp(`^  async function ${name}\\(contact\\) \\{[\\s\\S]*?(?=^  (?:async )?function )`, "m"));
  assert.ok(match, `Missing actual page handler ${name}`);
  const calls = { success: [], errors: [], posts: [], clipboard: [], busy: [], refreshes: 0, shares: {} };
  const run = vm.runInNewContext(`${match[0]}\n${name}`, {
    workspaceId: "workspace-a", isViewer: viewer,
    apiClient: { post: async url => { calls.posts.push(url); return { data }; } },
    showSuccess: message => calls.success.push(message),
    showError: message => calls.errors.push(message),
    setVerificationBusy: value => calls.busy.push(value),
    setWhatsappShareLinks: next => { calls.shares = next(calls.shares); },
    refreshContacts: async () => { calls.refreshes++; },
    verificationErrorMessage: error => error.message,
    navigator: { clipboard: clipboardAvailable ? { writeText: async value => { calls.clipboard.push(value); if (clipboardFailure) throw Error("Clipboard permission denied"); } } : undefined },
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

test("contact refresh preserves the last list on failure and clears the error after recovery", async () => {
  const start=source.indexOf("  async function refreshContacts()");
  const end=source.indexOf("  function verificationErrorMessage(", start);
  assert.ok(start>=0 && end>start);
  const calls={ items:[{ id:"existing" }], error:false, busy:[], fail:true };
  const refresh=vm.runInNewContext(source.slice(start,end)+"\nrefreshContacts", {
    workspaceId:"workspace-a", setRefreshingContacts:v=>calls.busy.push(v),
    setContactsLoadError:v=>{calls.error=v;}, setContacts:v=>{calls.items=v;},
    setRecipientVerificationMode:()=>{},
    apiClient:{get:async()=>{if(calls.fail)throw Error("temporary outage");return {data:{items:[{id:"confirmed",verifications:{email:{status:"verified"}}}],verification_summary:{mode:"enforce"}}};}}
  });
  await refresh();
  assert.equal(calls.error,true);assert.equal(calls.items[0].id,"existing");
  assert.deepEqual(calls.busy,[true,false]);
  calls.fail=false;await refresh();
  assert.equal(calls.error,false);assert.equal(calls.items[0].id,"confirmed");
  assert.equal(calls.items[0].verifications.email.status,"verified");
});
test("public re-subscription does not promise delivery when sending is limited", () => {
  const policy=require("../../packages/recipient-verification");
  const html=policy.renderResubscribeAccepted();
  assert.doesNotMatch(html,/is on its way/);
  assert.match(html,/Daily and weekly limits/);
  assert.match(html,/email delivery failure/);
  assert.match(html,/24 hours/);
  assert.match(html,/Nothing is confirmed until you accept/);
});

for (const options of [{ clipboardFailure: true }, { clipboardAvailable: false }]) {
  test('WhatsApp invitation remains available when the clipboard is ' + (options.clipboardFailure ? 'denied' : 'unavailable'), async () => {
    const url = 'https://example.test/verify/recipient/visible-link';
    const expires = new Date(Date.now() + 3600000).toISOString();
    const { run, calls } = handler('whatsapp', { status: 'pending', share_url: url, expires_at: expires }, options);
    await run({ id: 'contact-b', phone_e164: '+12025550123' });
    assert.deepEqual(calls.errors, []);
    assert.equal(calls.shares['workspace-a:contact-b:+12025550123'].url, url);
    assert.equal(calls.shares['workspace-a:contact-b:+12025550123'].expiresAt, expires);
    assert.equal(calls.success.length, 1);
    assert.match(calls.success[0], /Confirmation link ready below/);
    assert.doesNotMatch(calls.success[0], /link copied/);
    assert.equal(calls.posts.length, 1);
    assert.equal(calls.refreshes, 1);
  });
}

function phoneTestHandler(providerError) {
  const start = source.indexOf('  async function handleTestWhatsappPhone(');
  const end = source.indexOf('  function renderMobileContactCard', start);
  const match = start >= 0 && end > start ? [source.slice(start, end)] : null;
  assert.ok(match, 'Missing actual saved-contact WhatsApp test handler');
  const calls = { success: [], errors: [], posts: [], cooldowns: {}, testing: [] };
  const run = vm.runInNewContext(match[0] + '\nhandleTestWhatsappPhone', {
    workspaceId: 'workspace-a', waContactCooldowns: {},
    setTestingContact: value => calls.testing.push(value),
    setWaContactCooldowns: next => { calls.cooldowns = next(calls.cooldowns); },
    apiClient: { post: async (url, data) => {
      calls.posts.push({ url, data });
      if (providerError) throw providerError;
      return { data: { success: true, status: 'queued' } };
    } },
    showSuccess: message => calls.success.push(message),
    showError: message => calls.errors.push(message),
  });
  return { run, calls };
}

test('a queued WhatsApp test reports submission and requires phone delivery confirmation', async () => {
  const { run, calls } = phoneTestHandler();
  await run('+12025550123', 'contact-b', 'contact-b');
  assert.equal(calls.success.length, 1);
  assert.match(calls.success[0], /submitted.*phone.*confirm delivery/i);
  assert.doesNotMatch(calls.success[0], /\b(?:sent|delivered)\b/i);
  assert.deepEqual(calls.errors, []);
  assert.equal(calls.posts.length, 1);
  assert.ok(calls.cooldowns['contact-b'] > Date.now());
  assert.equal(calls.testing.at(-1), null);
});

for (const code of [63112, '63112']) test('WhatsApp provider-account failure ' + typeof code + ' is actionable without a false success', async () => {
  const { run, calls } = phoneTestHandler({ response: { data: { code, error: 'Provider rejected the request' } } });
  await run('+12025550123', 'contact-b', 'contact-b');
  assert.deepEqual(calls.success, []);
  assert.match(calls.errors[0], /WhatsApp provider account unavailable/);
  assert.deepEqual(calls.cooldowns, {});
  assert.equal(calls.testing.at(-1), null);
});
