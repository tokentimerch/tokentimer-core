"use strict";

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");
const fs = require("node:fs");
const { chromium } = require("playwright");
const { Pool } = require("pg");

const enabled = process.env.RV_BROWSER_TEST === "1";
const mode = process.env.RV_BROWSER_MODE || "enforce";
const enforced = mode !== "off";
const api = "http://localhost:44061";
const app = "http://localhost:5173";
const mail = "http://127.0.0.1:18025";
const password = "BrowserTest123!";
const run = `${mode}-${Date.now()}`;
const output = process.env.RV_BROWSER_OUTPUT || path.resolve("test-results/recipient-verification");
let browser, context, page, pool, workspace, contact;
let groupId;
let requestsToTwilio = 0;
const pageErrors = [];

async function until(fn, message = "condition did not become true") {
  const end = Date.now() + 15000;
  let last;
  while (Date.now() < end) {
    try { const result = await fn(); if (result) return result; } catch (error) { last = error; }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw last || new Error(message);
}

async function apiCall(method, route, data, target = context) {
  const csrf = await target.request.get(`${api}/api/csrf-token`);
  assert.equal(csrf.status(), 200);
  const token = (await csrf.json()).csrfToken;
  return target.request.fetch(`${api}${route}`, { method, data, headers: { "X-CSRF-Token": token, Origin: app } });
}

const contactsPath = () => `/api/v1/workspaces/${workspace}/contacts`;
const invitePath = (id, channel = "email") => `${contactsPath()}/${id}/verifications/${channel}`;
const row = () => page.getByRole("row").filter({ hasText: `Browser ${run}` });

async function preferences(target = page) {
  await target.goto(`${app}/workspace-preferences?workspace_id=${workspace}`);
  await target.locator("#contacts").waitFor();
  await until(async () => (await target.locator("#contacts").innerText()).includes("Browser") || (await target.getByRole("button", { name: "Add contact", exact: true }).count()) > 0);
}

async function confirmation(fixture = contact, target = page) {
  const dialog = target.getByRole("dialog");
  if (!await dialog.isVisible()) {
    await target.getByRole("button", { name: "Review confirmations", exact: true }).click();
  }
  await dialog.getByRole("combobox").selectOption(fixture.id);
  return dialog;
}

async function closeConfirmation(target = page) {
  await target.getByRole("dialog").getByRole("button", { name: "Close", exact: true }).last().click();
  await target.getByRole("dialog").waitFor({ state: "hidden" });
}

async function login(target, email) {
  await target.goto(`${app}/login`);
  await target.getByPlaceholder("Enter your email").fill(email);
  await target.getByPlaceholder("Enter your password").fill(password);
  await target.getByRole("button", { name: "Sign In", exact: true }).click();
  await target.waitForURL((url) => !url.pathname.startsWith("/login"));
}

async function newContact(label, { phone = null, target = context } = {}) {
  const email = `${label}-${run}@example.com`;
  const response = await apiCall("POST", contactsPath(), { first_name: label, last_name: run, details: { email }, phone_e164: phone }, target);
  assert.equal(response.status(), 201, await response.text());
  return response.json();
}

async function verifiedMemberContact(label) {
  const fixture = await newContact(label);
  const email = fixture.details.email;
  const user = await pool.query(
    "INSERT INTO users(email,email_original,display_name,password_hash,auth_method,email_verified) VALUES($1,$4,$2,$3,'local',true) RETURNING id",
    [email, label, await require("bcryptjs").hash(password, 10), email]);
  const userId = user.rows[0].id;
  await pool.query("INSERT INTO workspace_memberships(user_id,workspace_id,role,invited_by) VALUES($1,$2,'viewer',$1)", [userId, workspace]);
  return { ...fixture, userId };
}

async function emailVerification(fixture) {
  const response = await apiCall("GET", contactsPath());
  assert.equal(response.status(), 200, await response.text());
  return (await response.json()).items.find((entry) => entry.id === fixture.id).verification.email;
}

async function assertInheritedMember(fixture) {
  assert.deepEqual(await emailVerification(fixture), {
    status: "verified", delivery_basis: "verified_member",
    verified_at: null, consent_at: null, invitation: null,
  });
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM contact_channel_verifications WHERE contact_id=$1", [fixture.id])).rows[0].n, 0);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM contact_verification_challenges WHERE contact_id=$1", [fixture.id])).rows[0].n, 0);
}

async function emailLink(email) {
  return until(async () => {
    const listing = await (await fetch(`${mail}/api/v1/messages`)).json();
    const item = listing.messages?.find((message) => message.To?.some((to) => to.Address === email));
    if (!item) return null;
    const message = await (await fetch(`${mail}/api/v1/message/${item.ID}`)).json();
    return message.Text?.match(/http:\/\/localhost:44061\/verify\/recipient\/[A-Za-z0-9_-]+/)?.[0];
  }, `SMTP sink did not receive invitation for ${email}`);
}

async function screenshot(name, target = page) {
  await target.screenshot({ path: path.join(output, `${mode}-${name}.png`), fullPage: true });
}

describe(`recipient verification in Chromium: ${mode}`, { skip: !enabled, timeout: 300000 }, () => {
  before(async () => {
    assert.equal(process.env.DB_HOST, "127.0.0.1");
    assert.equal(process.env.DB_PORT, "54339");
    assert.equal(process.env.DB_NAME, "recipient_browser_test");
    fs.mkdirSync(output, { recursive: true });
    pool = new Pool({ host: process.env.DB_HOST, port: Number(process.env.DB_PORT), database: process.env.DB_NAME, user: process.env.DB_USER, password: process.env.DB_PASSWORD });
    workspace = (await pool.query("SELECT w.id FROM workspaces w JOIN users u ON u.id = w.created_by WHERE u.email = $1 ORDER BY w.created_at LIMIT 1", ["admin@recipient.test"])).rows[0].id;
    browser = await chromium.launch({ headless: true });
    context = await browser.newContext({ viewport: { width: 1440, height: 1080 }, permissions: ["clipboard-read", "clipboard-write"] });
    context.setDefaultTimeout(10000);
    await context.addInitScript(() => localStorage.setItem("tt_tour_dashboard", "true"));
    await context.tracing.start({ screenshots: true, snapshots: true, sources: true });
    page = await context.newPage();
    page.on("pageerror", (error) => pageErrors.push(error.message));
    // Abort any accidental browser request to Twilio. Server sends are disabled
    // by WHATSAPP_DRY_RUN; SMTP traffic goes only to the local Mailpit sink.
    await context.route("https://*.twilio.com/**", async (route) => { requestsToTwilio += 1; await route.abort(); });
    await login(page, "admin@recipient.test");
    await preferences();
  });

  after(async () => {
    if (context) {
      await screenshot("final").catch(() => {});
      await context.tracing.stop({ path: path.join(output, `${mode}-trace.zip`) });
    }
    await browser?.close();
    await pool?.end();
  });

  it("creates a workspace contact through the real UI and persists it on reload", async () => {
    await page.locator("#contacts").getByRole("button", { name: "Add contact", exact: true }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByPlaceholder("First name").fill("Browser");
    await dialog.getByPlaceholder("Last name").fill(run);
    await dialog.getByPlaceholder("name@example.com").fill(`browser-${run}@example.com`);
    await dialog.getByPlaceholder("+14155550100").fill(`+1415555${String(Date.now()).slice(-4)}`);
    const created = page.waitForResponse((r) => r.url().endsWith(contactsPath()) && r.request().method() === "POST");
    await dialog.getByRole("button", { name: "Add contact", exact: true }).click();
    const response = await created;
    assert.equal(response.status(), 201);
    contact = await response.json();
    await dialog.waitFor({ state: "hidden" });
    await row().waitFor();
    await page.reload();
    await row().waitFor();
    const list = await (await apiCall("GET", contactsPath())).json();
    assert.equal(list.verification_summary.mode, enforced ? "enforce" : "off");
    assert.equal(list.items.find((entry) => entry.id === contact.id).verification.email.status, "pending");
    if (enforced) {
      const controls = await confirmation();
      assert.equal(await controls.getByText("Pending", { exact: true }).count(), 2);
    }
    else {
      assert.equal(await row().getByRole("button", { name: "Send invitation" }).count(), 0);
      await page.getByText("Recipient confirmation is off for this deployment.", { exact: false }).waitFor();
    }
    await screenshot("contact-pending");
    if (enforced) await closeConfirmation();
  });

  it("inherits exact verified local member proof without email or consent, and honors authenticated revocation", { skip: mode !== "enforce" }, async () => {
    const messagesBefore = (await (await fetch(`${mail}/api/v1/messages`)).json()).total;
    const fixture = await verifiedMemberContact("verified-member");
    await preferences();
    const controls = await confirmation(fixture);
    await controls.getByText("Verified member", { exact: true }).waitFor();
    await page.reload();
    await confirmation(fixture);
    await controls.getByText("Verified member", { exact: true }).waitFor();
    await assertInheritedMember(fixture);
    assert.equal(await controls.getByRole("button", { name: "Send invitation", exact: true }).count(), 0);
    for (let attempt = 0; attempt < 2; attempt++) {
      const response = await apiCall("POST", invitePath(fixture.id));
      assert.equal(response.status(), 200, await response.text());
      assert.deepEqual(await response.json(), {
        status: "verified", channel: "email", delivery_basis: "verified_member",
      });
    }
    await assertInheritedMember(fixture);
    assert.equal((await (await fetch(`${mail}/api/v1/messages`)).json()).total, messagesBefore);
    const revoked = page.waitForResponse((response) => response.url().endsWith(`${invitePath(fixture.id)}/revoke`) && response.request().method() === "POST");
    await controls.getByRole("button", { name: "Stop notifications", exact: true }).click();
    const response = await revoked;
    assert.equal(response.status(), 200, await response.text());
    assert.deepEqual(await response.json(), { status: "revoked", channel: "email" });
    await page.reload();
    await confirmation(fixture);
    await controls.getByText("Revoked", { exact: true }).waitFor();
    assert.equal(await controls.getByText("Verified member", { exact: true }).count(), 0);
    const state = await emailVerification(fixture);
    assert.equal(state.status, "revoked");
    assert.notEqual(state.delivery_basis, "verified_member");
    assert.equal(state.consent_at, null);
    assert.equal((await pool.query("SELECT u.email_verified FROM users u JOIN workspace_memberships wm ON wm.user_id=u.id WHERE u.id=$1 AND wm.workspace_id=$2", [fixture.userId, workspace])).rows[0].email_verified, true);
    await screenshot("member-revoked");
    await closeConfirmation();
  });

  it("drops inherited member eligibility after removal through the authenticated membership endpoint", { skip: mode !== "enforce" }, async () => {
    // A separate destination isolates membership loss from the revocation above.
    const fixture = await verifiedMemberContact("removed-member");
    await preferences();
    const controls = await confirmation(fixture);
    await controls.getByText("Verified member", { exact: true }).waitFor();
    await assertInheritedMember(fixture);
    const removed = await apiCall("DELETE", `/api/v1/workspaces/${workspace}/members/${fixture.userId}`);
    assert.equal(removed.status(), 204, await removed.text());
    const state = await emailVerification(fixture);
    assert.equal(state.status, "pending");
    assert.notEqual(state.delivery_basis, "verified_member");
    assert.equal(state.consent_at ?? null, null);
    assert.equal(state.invitation, null);
    await page.reload();
    await confirmation(fixture);
    await controls.getByText("Pending", { exact: true }).waitFor();
    assert.equal(await controls.getByText("Verified member", { exact: true }).count(), 0);
    await controls.getByRole("button", { name: "Send invitation", exact: true }).waitFor();
    assert.equal((await pool.query("SELECT email_verified FROM users WHERE id=$1", [fixture.userId])).rows[0].email_verified, true);
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM contact_channel_verifications WHERE contact_id=$1", [fixture.id])).rows[0].n, 0);
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM contact_verification_challenges WHERE contact_id=$1", [fixture.id])).rows[0].n, 0);
    await screenshot("member-removed");
    await closeConfirmation();
  });

  it("keeps Vite-denied files private when query suffixes are supplied", async () => {
    const fixture = path.resolve("apps/dashboard/.env.recipient-browser-security-probe");
    const canary = `recipient-browser-deny-${crypto.randomUUID()}`;
    fs.writeFileSync(fixture, canary, { flag: "wx" });
    try {
      for (const query of ["?raw", "?import&raw", "?import&url&inline"]) {
        const response = await context.request.get(`${app}/@fs/${fixture.replaceAll("\\", "/")}${query}`);
        assert.equal(response.status(), 403);
        assert.equal((await response.text()).includes(canary), false);
      }
    } finally {
      fs.unlinkSync(fixture);
    }
  });

  it("keeps existing alerts and contact groups usable with pending contacts", async () => {
    const settingsPath = `/api/v1/workspaces/${workspace}/alert-settings`;
    const settings = await (await apiCall("GET", settingsPath)).json();
    groupId = crypto.randomUUID();
    const group = { id: groupId, name: `Browser group ${run}`, email_contact_ids: [contact.id], whatsapp_contact_ids: [contact.id], webhook_names: [], channels: ["email", "whatsapp"] };
    const saved = await apiCall("PUT", settingsPath, { contact_groups: [...(settings.contact_groups || []), group] });
    assert.equal(saved.status(), 200, await saved.text());
    const loaded = await (await apiCall("GET", settingsPath)).json();
    assert.deepEqual(loaded.contact_groups.find((entry) => entry.id === groupId).email_contact_ids, [contact.id]);
    const alerts = await apiCall("GET", `/api/alert-queue?workspace_id=${workspace}`);
    assert.equal(alerts.status(), 200, await alerts.text());
    await preferences();
    await page.locator("option").filter({ hasText: group.name }).waitFor({ state: "attached" });
    const select = page.locator("select").filter({ has: page.locator("option", { hasText: group.name }) });
    await select.selectOption(groupId);
    await page.getByRole("dialog").getByText("Edit contact group", { exact: true }).waitFor();
    await page.getByRole("dialog").getByText(`Browser ${run}`, { exact: true }).first().waitFor();
    await screenshot("contact-group");
    await page.getByRole("dialog").getByRole("button", { name: "Cancel", exact: true }).click();
  });

  it("enforces unverified WhatsApp tests; OFF permits a saved-contact dry run", async () => {
    const response = await apiCall("POST", `/api/test-whatsapp?workspace_id=${workspace}`, { contact_id: contact.id, phone_e164: contact.phone_e164 });
    assert.equal(response.status(), enforced ? 403 : 200, await response.text());
    if (enforced) assert.equal((await response.json()).code, "RECIPIENT_NOT_VERIFIED");
  });

  it("recovers from a contacts load failure with the Retry contacts control", async () => {
    assert.equal(await page.getByRole("button", { name: "Refresh contacts", exact: true }).count(), 0);
    const controls = enforced ? await confirmation() : null;
    // Block the real SQL query, rather than replacing a browser API response.
    const blocker = await pool.connect();
    await blocker.query("BEGIN");
    await blocker.query("LOCK TABLE workspace_contacts IN ACCESS EXCLUSIVE MODE");
    try {
      const failed = page.waitForResponse((response) => response.url().endsWith(contactsPath()) && response.request().method() === "GET");
      if (enforced) {
        await controls.getByRole("button", { name: "Refresh confirmation status", exact: true }).click();
      } else {
        await page.reload();
      }
      await until(async () => {
        const blocked = await pool.query("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%FROM workspace_contacts%' AND pid <> pg_backend_pid()");
        if (!blocked.rows.length) return false;
        for (const entry of blocked.rows) await pool.query("SELECT pg_cancel_backend($1)", [entry.pid]);
        return true;
      });
      assert.equal((await failed).status(), 500);
      await screenshot("contacts-error-response");
      if (enforced) {
        await controls.getByText("Could not refresh confirmation status. Try again.", { exact: true }).waitFor();
        await closeConfirmation();
        assert.equal(await row().isVisible(), true);
      }
      await page.getByText("Contacts and confirmation status could not be loaded.", { exact: true }).waitFor();
      await screenshot("contacts-load-error");
      await page.getByRole("button", { name: "Retry contacts", exact: true }).click();
      await until(async () => await page.locator("#contacts button[disabled]").count() > 0);
      await screenshot("contacts-retry-loading");
    } finally {
      await blocker.query("ROLLBACK");
      blocker.release();
    }
    await row().waitFor();
    await page.getByText("Contacts and confirmation status could not be loaded.", { exact: true }).waitFor({ state: "hidden" });
  });

  it("sends an email invitation over SMTP, remains pending until explicit confirmation, and reloads verified", { skip: !enforced }, async () => {
    const controls = await confirmation();
    const responsePromise = page.waitForResponse((response) => response.url().endsWith(invitePath(contact.id)) && response.request().method() === "POST");
    await controls.getByRole("button", { name: "Send invitation", exact: true }).click();
    const response = await responsePromise;
    assert.equal(response.status(), 202, await response.text());
    await until(async () => (await controls.innerText()).includes("Invitation open until"));
    assert.equal(await controls.getByText("Pending", { exact: true }).count(), 2);
    const link = await emailLink(contact.details.email);
    const recipient = await context.newPage();
    const publicResponse = await recipient.goto(link);
    assert.equal(publicResponse.headers()["cache-control"], "no-store");
    assert.equal(publicResponse.headers()["referrer-policy"], "no-referrer");
    await recipient.getByRole("button", { name: "Yes, send me these notifications", exact: true }).waitFor();
    assert.equal((await pool.query("SELECT status FROM contact_channel_verifications WHERE contact_id=$1 AND channel='email'", [contact.id])).rows[0]?.status || "pending", "pending");
    await recipient.getByRole("button", { name: "Yes, send me these notifications", exact: true }).click();
    await recipient.getByRole("heading", { name: "Confirmed", exact: true }).waitFor();
    assert.match(recipient.url(), /\/done\?result=accepted$/);
    await page.reload();
    await confirmation();
    await controls.getByText("Verified", { exact: true }).waitFor();
    await screenshot("email-verified");
    await closeConfirmation();
    await recipient.goto(link);
    assert.equal(await recipient.locator("form").count(), 0);
    const replay = await context.request.post(`${link}/accept`);
    assert.match(replay.url(), /result=invalid$/);
    await recipient.close();
  });

  it("refuses expired, rejected and forged links in the real confirmation UI", { skip: !enforced }, async () => {
    for (const scenario of ["expired", "declined"]) {
      const fixture = await newContact(scenario);
      const invited = await apiCall("POST", invitePath(fixture.id));
      assert.equal(invited.status(), 202, await invited.text());
      const link = await emailLink(fixture.details.email);
      if (scenario === "expired") await pool.query("UPDATE contact_verification_challenges SET expires_at=NOW()-INTERVAL '1 second' WHERE contact_id=$1", [fixture.id]);
      const recipient = await context.newPage();
      await recipient.goto(link);
      if (scenario === "declined") {
        await recipient.getByRole("button", { name: "Do not notify me", exact: true }).click();
        await recipient.getByRole("heading", { name: "Declined", exact: true }).waitFor();
        const replay = await context.request.post(`${link}/accept`);
        assert.match(replay.url(), /result=invalid$/);
        const retry = await apiCall("POST", invitePath(fixture.id));
        assert.equal((await retry.json()).code, "RECIPIENT_OPTED_OUT");
      } else {
        await recipient.getByRole("heading", { name: "This invitation is unavailable", exact: true }).waitFor();
        assert.equal(await recipient.locator("form").count(), 0);
      }
      await screenshot(scenario, recipient);
      await recipient.close();
    }
    const recipient = await context.newPage();
    await recipient.goto(`${api}/verify/recipient/forged-token`);
    await recipient.getByRole("heading", { name: "This invitation is unavailable" }).waitFor();
    await recipient.close();
  });

  it("generates and copies WhatsApp links without sending, verifies signed inbound, and rejects wrong senders/signatures", { skip: !enforced }, async () => {
    await preferences();
    const messagesBefore = (await (await fetch(`${mail}/api/v1/messages`)).json()).total;
    const controls = await confirmation();
    await controls.getByRole("button", { name: "Confirm WhatsApp", exact: true }).click();
    const generated = page.waitForResponse((response) => response.url().endsWith(invitePath(contact.id, "whatsapp")) && response.request().method() === "POST");
    await controls.getByRole("button", { name: "Create confirmation link", exact: true }).click();
    const response = await generated;
    assert.equal(response.status(), 201, await response.text());
    const invitation = await response.json();
    await until(async () => (await page.evaluate(() => navigator.clipboard.readText())) === invitation.share_url);
    assert.equal((await (await fetch(`${mail}/api/v1/messages`)).json()).total, messagesBefore);
    const recipient = await context.newPage();
    await recipient.goto(invitation.share_url);
    const deepLink = new URL(await recipient.getByRole("link", { name: "Open WhatsApp and send confirmation" }).getAttribute("href"));
    assert.equal(deepLink.hostname, "wa.me");
    assert.equal(deepLink.pathname, "/14155550999");
    const body = deepLink.searchParams.get("text");
    assert.match(body, /^CONFIRM [A-HJ-NP-Z2-9]{10}$/);
    await screenshot("whatsapp-confirmation", recipient);
    const inbound = `${api}/webhooks/twilio/whatsapp/inbound`;
    const send = async (from, validSignature = true, sid = crypto.randomUUID()) => {
      const params = { From: `whatsapp:${from}`, Body: body, MessageSid: sid };
      const signed = inbound + Object.keys(params).sort().map((key) => key + params[key]).join("");
      const signature = crypto.createHmac("sha1", "browser-test-signature-secret").update(signed).digest("base64");
      return context.request.post(inbound, { form: params, headers: { "X-Twilio-Signature": validSignature ? signature : "invalid" } });
    };
    assert.equal((await send(contact.phone_e164, false)).status(), 403);
    assert.equal((await send("+14155550001")).status(), 200);
    const state = async () => (await pool.query("SELECT status FROM contact_channel_verifications WHERE contact_id=$1 AND channel='whatsapp'", [contact.id])).rows[0]?.status || "pending";
    assert.equal(await state(), "pending");
    const sid = crypto.randomUUID();
    assert.equal((await send(contact.phone_e164, true, sid)).status(), 200);
    assert.equal(await state(), "verified");
    assert.equal((await send(contact.phone_e164, true, sid)).status(), 200);
    assert.equal(await state(), "verified");
    await page.reload();
    await confirmation();
    await until(async () => await controls.getByText("Verified", { exact: true }).count() === 2);
    await screenshot("both-verified");
    await closeConfirmation();
    await recipient.close();
  });

  it("revokes email confirmation and invalidates WhatsApp after editing the saved number", { skip: !enforced }, async () => {
    const controls = await confirmation();
    await controls.getByRole("button", { name: "Stop notifications", exact: true }).first().click();
    await controls.getByText("Revoked", { exact: true }).waitFor();
    await closeConfirmation();
    await row().getByRole("button", { name: "Edit", exact: true }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByPlaceholder("+14155550100").fill(`+1415556${String(Date.now()).slice(-4)}`);
    await dialog.getByPlaceholder("name@example.com").fill(`updated-${run}@example.com`);
    await dialog.getByRole("button", { name: "Save changes", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });
    await page.reload();
    await confirmation();
    await until(async () => await controls.getByText("Pending", { exact: true }).count() === 2);
    const settings = await (await apiCall("GET", `/api/v1/workspaces/${workspace}/alert-settings`)).json();
    assert.deepEqual(settings.contact_groups.find((entry) => entry.id === groupId).email_contact_ids, [contact.id]);
    await screenshot("edited-contact");
    await closeConfirmation();
  });

  it("shows loading and provider errors, then recovers through a real invitation and reload", { skip: !enforced }, async () => {
    // Fault injection is only at SMTP: the browser still calls the actual API,
    // which creates a transaction, attempts delivery and records the failure.
    const fixture = await newContact("errors");
    await preferences();
    const controls = await confirmation(fixture);
    const { spawnSync } = require("node:child_process");
    const compose = ["compose", "-p", "tt-recipient-browser", "-f", "tests/e2e/recipient-verification.compose.yml"];
    assert.equal(spawnSync("docker", [...compose, "stop", "mailpit"], { env: process.env, windowsHide: true }).status, 0);
    try {
      const response = page.waitForResponse((r) => r.url().endsWith(invitePath(fixture.id)) && r.request().method() === "POST");
      await controls.getByRole("button", { name: "Send invitation", exact: true }).click();
      await until(async () => await controls.locator("button[disabled]").count() > 0);
      const failed = await response;
      assert.equal(failed.status(), 502, await failed.text());
      await page.getByText(/Verification email could not be sent|Failed to send verification email/).first().waitFor();
      await screenshot("smtp-error");
    } finally {
      assert.equal(spawnSync("docker", [...compose, "start", "mailpit"], { env: process.env, windowsHide: true }).status, 0);
      await until(async () => (await fetch(`${mail}/api/v1/messages`)).ok);
    }
    const response = page.waitForResponse((r) => r.url().endsWith(invitePath(fixture.id)) && r.request().method() === "POST");
    await controls.getByRole("button", { name: /Send invitation|Resend invitation/ }).click();
    assert.equal((await response).status(), 202);
    await emailLink(fixture.details.email);
    await page.reload();
    await confirmation(fixture);
    await controls.getByRole("button", { name: "Resend invitation" }).waitFor();
    await closeConfirmation();
  });

  it("enforces viewer restrictions and allows workspace managers through actual sessions and UI", async () => {
    const bcrypt = require("bcryptjs");
    for (const role of ["viewer", "workspace_manager"]) {
      const email = `${role}-${run}@example.com`;
      const user = await pool.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method,email_verified) VALUES($1,$4,$2,$3,'local',true) RETURNING id", [email, role, await bcrypt.hash(password, 10), email]);
      await pool.query("INSERT INTO workspace_memberships(user_id,workspace_id,role,invited_by) VALUES($1,$2,$3,$1)", [user.rows[0].id, workspace, role]);
      const ctx = await browser.newContext({ viewport: { width: 1440, height: 1080 } });
      const target = await ctx.newPage();
      await login(target, email);
      const response = await apiCall("POST", invitePath(contact.id, "whatsapp"), {}, ctx);
      if (role === "viewer") {
        assert.equal(response.status(), 403);
        const update = await apiCall("PUT", `${contactsPath()}/${contact.id}`, { first_name: "Unauthorized", last_name: "Change" }, ctx);
        assert.equal(update.status(), 403);
        const revoke = await apiCall("POST", `${invitePath(contact.id)}/revoke`, {}, ctx);
        assert.equal(revoke.status(), 403);
        await target.goto(`${app}/workspace-preferences?workspace_id=${workspace}`);
        await until(async () => !new URL(target.url()).pathname.includes("workspace-preferences"));
        assert.equal(await target.getByRole("button", { name: "Send invitation", exact: true }).count(), 0);
      } else {
        // A manager can invite a fresh contact without admin privileges.
        const fresh = await newContact("manager", { phone: `+1415557${String(Date.now()).slice(-4)}`, target: ctx });
        const invited = await apiCall("POST", invitePath(fresh.id, "whatsapp"), {}, ctx);
        assert.equal(invited.status(), 201, await invited.text());
        await preferences(target);
        const managerRow = target.getByRole("row").filter({ hasText: `manager ${run}` });
        await managerRow.waitFor();
        assert.equal(await managerRow.getByRole("button", { name: "Edit", exact: true }).isEnabled(), true);
        if (enforced) {
          const controls = await confirmation(fresh, target);
          assert.equal(await controls.getByRole("button", { name: "Send invitation", exact: true }).isEnabled(), true);
          await closeConfirmation(target);
        }
      }
      await screenshot(role, target);
      await ctx.close();
    }
  });

  it("does not raise browser runtime errors or contact a Twilio provider", () => {
    assert.deepEqual(pageErrors, []);
    assert.equal(requestsToTwilio, 0);
  });
});
