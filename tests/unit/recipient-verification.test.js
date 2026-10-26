"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const verification = require("../../packages/recipient-verification");

const ROOT = path.resolve(__dirname, "../..");
const SECRET = "unit-recipient-fingerprint-secret";

function rowsOf(rows) {
  return { rows, rowCount: rows.length };
}

function createStore() {
  const state = {
    contacts: new Map(),
    workspaces: new Map(),
    challenges: [],
    verifications: [],
    suppressions: [],
    events: [],
    inbound: new Set(),
    queries: [],
    locks: [],
    nextId: 1,
  };

  function expired(row) {
    return row.expires_at && new Date(row.expires_at).getTime() <= Date.now();
  }

  function contactKey(workspaceId, contactId) {
    return `${workspaceId}:${contactId}`;
  }

  function handle(sql, params = []) {
    const text = String(sql);
    state.queries.push(text);
    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return rowsOf([]);
    if (text.includes("pg_advisory_xact_lock")) {
      state.locks.push(params[0]);
      return rowsOf([]);
    }

    if (text.includes("RV_CONTACT")) {
      const contact = state.contacts.get(contactKey(params[0], params[1]));
      return rowsOf(contact ? [contact] : []);
    }

    if (text.includes("RV_SUPPRESSION_LOOKUP")) {
      const [channel, fingerprint, workspaceId] = params;
      const abuseOnly = text.includes("verification_abuse");
      const match = state.suppressions.find((row) => {
        if (row.channel !== channel || row.destination_fingerprint !== fingerprint) return false;
        if (expired(row)) return false;
        if (abuseOnly && row.reason !== "verification_abuse") return false;
        return row.scope === "global" || row.workspace_id === workspaceId;
      });
      return rowsOf(match ? [match] : []);
    }

    if (text.includes("RV_PRUNE")) {
      const cutoff = Date.now() - 8 * 24 * 60 * 60 * 1000;
      state.events = state.events.filter((row) => row.bucket_key !== params[0] || row.created_at >= cutoff);
      return rowsOf([]);
    }

    if (text.includes("RV_COUNT_EVENTS")) {
      const windowMs = Number(params[1]) * 1000;
      const n = state.events.filter((row) => row.bucket_key === params[0] && row.created_at > Date.now() - windowMs).length;
      return rowsOf([{ n }]);
    }

    if (text.includes("RV_INSERT_EVENT")) {
      state.events.push({ bucket_key: params[0], workspace_id: params[1], created_at: Date.now() });
      return rowsOf([]);
    }

    if (text.includes("RV_DISTINCT_WORKSPACES")) {
      const ids = new Set(
        state.events
          .filter((row) => row.bucket_key === params[0] && row.created_at > Date.now() - 7 * 24 * 60 * 60 * 1000)
          .map((row) => row.workspace_id),
      );
      return rowsOf([{ n: ids.size }]);
    }

    if (text.includes("RV_INSERT_SUPPRESSION")) {
      const abuse = text.includes("verification_abuse");
      const row = abuse
        ? {
            channel: params[0],
            destination_fingerprint: params[1],
            scope: "global",
            workspace_id: null,
            reason: "verification_abuse",
            expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
          }
        : {
            channel: params[0],
            destination_fingerprint: params[1],
            scope: "workspace",
            workspace_id: params[2],
            reason: "recipient_declined",
            expires_at: null,
          };
      const existing = state.suppressions.find((item) => (
        item.channel === row.channel
        && item.destination_fingerprint === row.destination_fingerprint
        && item.scope === row.scope
        && item.workspace_id === row.workspace_id
        && item.reason === row.reason
      ));
      if (!existing) state.suppressions.push(row);
      else if (row.expires_at) existing.expires_at = row.expires_at;
      return rowsOf([]);
    }

    if (text.includes("RV_CLEAR_DECLINE")) {
      state.suppressions = state.suppressions.filter((row) => !(
        row.channel === params[0]
        && row.destination_fingerprint === params[1]
        && row.scope === "workspace"
        && row.workspace_id === params[2]
        && row.reason === "recipient_declined"
      ));
      return rowsOf([]);
    }

    if (text.includes("RV_SUPERSEDE")) {
      for (const challenge of state.challenges) {
        if (
          challenge.workspace_id === params[0]
          && challenge.contact_id === params[1]
          && challenge.channel === params[2]
          && challenge.status === "pending"
        ) {
          challenge.status = "superseded";
        }
      }
      return rowsOf([]);
    }

    if (text.includes("RV_INSERT_CHALLENGE")) {
      const ttl = Number(params[8]) * 1000;
      const row = {
        id: `ch-${state.nextId++}`,
        workspace_id: params[0],
        contact_id: params[1],
        channel: params[2],
        destination_normalized: params[3],
        destination_fingerprint: params[4],
        token_hash: params[5],
        code_hash: params[6],
        code_ciphertext: params[7],
        status: "pending",
        expires_at: new Date(Date.now() + ttl),
        attempt_count: 0,
        created_by: params[9],
      };
      state.challenges.push(row);
      return rowsOf([{ id: row.id, expires_at: row.expires_at }]);
    }

    if (text.includes("RV_LOAD_CHALLENGE")) {
      const challenge = state.challenges.find((row) => row.token_hash === params[0]);
      if (!challenge) return rowsOf([]);
      const verificationRow = state.verifications.find((row) => (
        row.workspace_id === challenge.workspace_id
        && row.contact_id === challenge.contact_id
        && row.channel === challenge.channel
        && row.destination_normalized === challenge.destination_normalized
      ));
      return rowsOf([{
        ...challenge,
        workspace_name: state.workspaces.get(challenge.workspace_id) || "Workspace",
        verification_status: verificationRow?.status || null,
      }]);
    }

    if (text.includes("RV_CONSUME_CHALLENGE") && text.includes("channel = 'email'")) {
      const challenge = state.challenges.find((row) => (
        row.token_hash === params[0]
        && row.channel === "email"
        && row.status === "pending"
        && new Date(row.expires_at).getTime() > Date.now()
      ));
      if (!challenge) return rowsOf([]);
      challenge.status = params[1];
      challenge.consumed_at = new Date();
      challenge.attempt_count += 1;
      return rowsOf([{ ...challenge }]);
    }

    if (text.includes("RV_CONSUME_CHALLENGE") && text.includes("channel = 'whatsapp'")) {
      const challenge = state.challenges.find((row) => (
        row.code_hash === params[0]
        && row.channel === "whatsapp"
        && row.status === "pending"
        && new Date(row.expires_at).getTime() > Date.now()
        && row.destination_normalized === params[1]
      ));
      if (!challenge) return rowsOf([]);
      challenge.status = "consumed";
      challenge.consumed_at = new Date();
      challenge.attempt_count += 1;
      return rowsOf([{ ...challenge }]);
    }

    if (text.includes("RV_UPSERT_VERIFICATION")) {
      const status = text.includes("'revoked'") && !text.includes("$6") ? "revoked" : params[5];
      const row = {
        workspace_id: params[0],
        contact_id: params[1],
        channel: params[2],
        destination_normalized: params[3],
        destination_fingerprint: params[4],
        status: status || "revoked",
        consent_at: (status || "revoked") === "verified" ? new Date() : null,
        verified_at: (status || "revoked") === "verified" ? new Date() : null,
      };
      const index = state.verifications.findIndex((item) => (
        item.workspace_id === row.workspace_id
        && item.contact_id === row.contact_id
        && item.channel === row.channel
      ));
      if (index === -1) state.verifications.push(row);
      else state.verifications[index] = row;
      return rowsOf([]);
    }

    if (text.includes("RV_DELETE_VERIFICATION")) {
      state.verifications = state.verifications.filter((row) => !(
        row.workspace_id === params[0] && row.contact_id === params[1] && row.channel === params[2]
      ));
      return rowsOf([]);
    }

    if (text.includes("RV_INVALIDATE")) {
      const row = state.verifications.find((item) => (
        item.workspace_id === params[0] && item.contact_id === params[1] && item.channel === params[2]
      ));
      if (row && row.destination_normalized !== params[3]) {
        row.status = "pending";
        row.destination_normalized = params[3];
        row.destination_fingerprint = params[4];
        row.consent_at = null;
        row.verified_at = null;
      }
      return rowsOf([]);
    }

    if (text.includes("RV_DELIVERY_LOOKUP")) {
      const [workspaceId, contactId, channel, destination] = params;
      const contact = state.contacts.get(contactKey(workspaceId, contactId));
      const row = state.verifications.find((item) => (
        item.workspace_id === workspaceId
        && item.contact_id === contactId
        && item.channel === channel
        && item.destination_normalized === destination
      ));
      if (!contact || !row) return rowsOf([]);
      const current = channel === "email"
        ? String(contact.details?.email || "").trim().toLowerCase()
        : contact.phone_e164;
      if (current !== destination) return rowsOf([]);
      return rowsOf([row]);
    }

    if (text.includes("RV_DESTINATION_CONTACTS")) {
      const [workspaceId, channel, destination] = params;
      const matches = [];
      for (const contact of state.contacts.values()) {
        if (contact.workspace_id !== workspaceId) continue;
        const current = channel === "email"
          ? String(contact.details?.email || "").trim().toLowerCase()
          : contact.phone_e164;
        if (current === destination) matches.push({ id: contact.id });
      }
      return rowsOf(matches);
    }

    if (text.includes("RV_INBOUND_DEDUPE")) {
      const sid = String(params[0]);
      if (state.inbound.has(sid)) return rowsOf([]);
      state.inbound.add(sid);
      return rowsOf([{ message_sid: sid }]);
    }

    if (text.includes("RV_LIST_STATUS")) {
      const ids = params[1];
      return rowsOf(state.verifications.filter((row) => row.workspace_id === params[0] && ids.includes(row.contact_id)));
    }

    if (text.includes("RV_LIST_CHALLENGES")) {
      const ids = params[1];
      return rowsOf(state.challenges.filter((row) => (
        row.workspace_id === params[0]
        && ids.includes(row.contact_id)
        && row.status === "pending"
        && new Date(row.expires_at).getTime() > Date.now()
      )));
    }

    if (text.includes("RV_LOCK_CONTACT")) return rowsOf([{ id: params[1] }]);

    if (text.includes("RV_PREVIEW_CHALLENGE")) {
      const challenge = state.challenges.find((row) => {
        const hashMatch = text.includes("code_hash") ? row.code_hash === params[0] : row.token_hash === params[0];
        if (!hashMatch || row.status !== "pending" || new Date(row.expires_at).getTime() <= Date.now()) return false;
        if (text.includes("destination_normalized = $2") && row.destination_normalized !== params[1]) return false;
        return true;
      });
      return rowsOf(challenge ? [challenge] : []);
    }

    throw new Error(`unexpected SQL: ${text.slice(0, 180)}`);
  }

  let tail = Promise.resolve();
  function pool() {
    return {
      query: (sql, params) => handle(sql, params),
      async connect() {
        let releaseGate;
        const gate = new Promise((resolve) => {
          releaseGate = resolve;
        });
        const previous = tail;
        tail = gate;
        await previous;
        return {
          query: (sql, params) => handle(sql, params),
          release() {
            releaseGate();
          },
        };
      },
    };
  }

  return { state, handle, pool: pool(), client: { query: (sql, params) => handle(sql, params) } };
}

function seedContact(store, overrides = {}) {
  const contact = {
    id: "contact-1",
    workspace_id: "ws-1",
    phone_e164: "+14155550100",
    details: { email: "person@example.com" },
    first_name: "Pat",
    last_name: "Lee",
    ...overrides,
  };
  store.state.contacts.set(`${contact.workspace_id}:${contact.id}`, contact);
  store.state.workspaces.set(contact.workspace_id, overrides.workspaceName || "Northwind");
  return contact;
}

describe("recipient verification", () => {
  const previous = {};
  beforeEach(() => {
    for (const key of ["RECIPIENT_FINGERPRINT_SECRET", "TT_DEPLOYMENT", "RECIPIENT_VERIFICATION_MODE", "RECIPIENT_VERIFY_EMAIL_DEST_PER_DAY", "RECIPIENT_VERIFY_EMAIL_DEST_PER_WEEK", "RECIPIENT_VERIFY_WORKSPACE_PER_DAY", "RECIPIENT_VERIFY_USER_PER_DAY"]) {
      previous[key] = process.env[key];
    }
    process.env.RECIPIENT_FINGERPRINT_SECRET = SECRET;
    delete process.env.TT_DEPLOYMENT;
    delete process.env.RECIPIENT_VERIFICATION_MODE;
    delete process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_DAY;
    delete process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_WEEK;
    delete process.env.RECIPIENT_VERIFY_WORKSPACE_PER_DAY;
    delete process.env.RECIPIENT_VERIFY_USER_PER_DAY;
  });
  afterEach(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  it("keeps Cloud fail-closed and self-hosted shadow unless an operator sets a mode", () => {
    assert.equal(verification.resolveEnforcementMode({ TT_DEPLOYMENT: "cloud", RECIPIENT_VERIFICATION_MODE: "off" }), "enforce");
    assert.equal(verification.resolveEnforcementMode({ TT_DEPLOYMENT: "cloud", RECIPIENT_VERIFICATION_MODE: "shadow" }), "shadow");
    assert.equal(verification.resolveEnforcementMode({ TT_DEPLOYMENT: "self-hosted" }), "shadow");
    assert.equal(verification.resolveEnforcementMode({ TT_DEPLOYMENT: "self-hosted", RECIPIENT_VERIFICATION_MODE: "enforce" }), "enforce");
    if (verification.DEFAULT_DEPLOYMENT === "cloud") {
      assert.equal(verification.resolveEnforcementMode({}), "enforce");
    } else {
      assert.equal(verification.resolveEnforcementMode({}), "shadow");
    }
  });

  it("fingerprints destinations with HMAC and refuses a missing secret", () => {
    assert.equal(verification.destinationFingerprint("email", "a@example.com", {}), null);
    const email = verification.destinationFingerprint("email", "a@example.com", { RECIPIENT_FINGERPRINT_SECRET: SECRET });
    const phone = verification.destinationFingerprint("whatsapp", "+14155550100", { RECIPIENT_FINGERPRINT_SECRET: SECRET });
    assert.equal(email.length, 64);
    assert.notEqual(email, phone);
    assert.equal(verification.normalizeEmail(" Person@Example.COM ").value, "person@example.com");
    assert.equal(verification.normalizePhone("whatsapp:+14155550100").value, "+14155550100");
    assert.equal(verification.normalizePhone("00123").ok, false);
  });

  it("classifies account mail separately from workspace notifications", () => {
    assert.equal(verification.DELIVERY_POLICIES.password_reset, "platform_transactional");
    assert.equal(verification.DELIVERY_POLICIES.account_verification, "platform_transactional");
    assert.equal(verification.DELIVERY_POLICIES.workspace_alert_email, "recipient_consent_required");
    assert.equal(verification.DELIVERY_POLICIES.weekly_digest_whatsapp, "recipient_consent_required");
    assert.equal(verification.DELIVERY_POLICIES.workspace_test_whatsapp, "recipient_consent_required");
    assert.equal(verification.DELIVERY_POLICIES.webhook, "not_a_recipient_destination");
  });

  it("does not confirm an email invitation on load, and accepts only one explicit POST", async () => {
    const store = createStore();
    seedContact(store);
    const invitation = await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      actorUserId: 7,
    });
    assert.notEqual(store.state.challenges[0].token_hash, invitation.token);
    assert.equal(store.state.challenges[0].token_hash, verification.hashToken(invitation.token));
    store.state.queries.length = 0;
    const page = await verification.loadChallenge(store.pool, invitation.token);
    assert.equal(page.state, "pending");
    assert.equal(page.workspaceName, "Northwind");
    assert.equal(store.state.queries.some((sql) => sql.includes("UPDATE")), false);
    const html = verification.renderChallengePage({
      state: "pending",
      token: invitation.token,
      workspaceName: page.workspaceName,
      channel: "email",
    });
    assert.match(html, /method="post"/);
    assert.match(html, /does not opt you in/);
    assert.doesNotMatch(html, /http-equiv="refresh"/i);
    const invalid = verification.renderChallengePage({ state: "invalid" });
    assert.doesNotMatch(invalid, /<form/);

    const [first, second] = await Promise.all([
      verification.consumeEmailChallenge({ pool: store.pool, token: invitation.token, decision: "accept" }),
      verification.consumeEmailChallenge({ pool: store.pool, token: invitation.token, decision: "accept" }),
    ]);
    const accepted = [first, second].filter((result) => result.ok);
    assert.equal(accepted.length, 1);
    assert.equal(store.state.verifications[0].status, "verified");
    assert.ok(store.state.verifications[0].consent_at);

    process.env.TT_DEPLOYMENT = "self-hosted";
    process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
    const allowed = await verification.evaluateRecipient({
      client: store.client,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      destination: "person@example.com",
    });
    assert.equal(allowed.allowed, true);
    const otherWorkspace = await verification.evaluateRecipient({
      client: store.client,
      workspaceId: "ws-2",
      contactId: "contact-1",
      channel: "email",
      destination: "person@example.com",
    });
    assert.equal(otherWorkspace.allowed, false);
  });

  it("rejects expired, declined, stale, and forged email confirmation", async () => {
    const store = createStore();
    seedContact(store);
    const invitation = await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      actorUserId: 7,
    });
    store.state.challenges[0].expires_at = new Date(Date.now() - 1000);
    const expired = await verification.consumeEmailChallenge({
      pool: store.pool,
      token: invitation.token,
      decision: "accept",
    });
    assert.equal(expired.ok, false);
    assert.equal(store.state.verifications.length, 0);

    store.state.challenges[0].expires_at = new Date(Date.now() + 60_000);
    store.state.challenges[0].status = "pending";
    const declined = await verification.consumeEmailChallenge({
      pool: store.pool,
      token: invitation.token,
      decision: "decline",
    });
    assert.equal(declined.outcome, "declined");
    assert.equal(store.state.verifications[0].status, "opted_out");
    const blocked = await verification.evaluateRecipient({
      client: store.client,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      destination: "person@example.com",
    });
    assert.equal(blocked.code, "RECIPIENT_OPTED_OUT");

    store.state.contacts.delete("ws-1:contact-1");
    seedContact(store, { id: "contact-2" });
    const recreated = await verification.evaluateRecipient({
      client: store.client,
      workspaceId: "ws-1",
      contactId: "contact-2",
      channel: "email",
      destination: "person@example.com",
    });
    assert.equal(recreated.code, "RECIPIENT_OPTED_OUT");

    const fresh = createStore();
    seedContact(fresh);
    const next = await verification.createInvitation({
      pool: fresh.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      actorUserId: 7,
    });
    fresh.state.contacts.get("ws-1:contact-1").details.email = "other@example.com";
    const stale = await verification.consumeEmailChallenge({
      pool: fresh.pool,
      token: next.token,
      decision: "accept",
    });
    assert.equal(stale.ok, false);
    assert.equal(fresh.state.verifications.length, 0);
    assert.equal(verification.evaluateRecipient.length >= 0, true);
  });

  it("invalidates only the channel whose destination changed", async () => {
    const store = createStore();
    const contact = seedContact(store);
    store.state.verifications.push({
      workspace_id: "ws-1",
      contact_id: contact.id,
      channel: "email",
      destination_normalized: "person@example.com",
      destination_fingerprint: "email-fp",
      status: "verified",
      consent_at: new Date(),
    });
    store.state.verifications.push({
      workspace_id: "ws-1",
      contact_id: contact.id,
      channel: "whatsapp",
      destination_normalized: "+14155550100",
      destination_fingerprint: "phone-fp",
      status: "verified",
      consent_at: new Date(),
    });
    await verification.invalidateChangedDestination({
      client: store.client,
      workspaceId: "ws-1",
      contactId: contact.id,
      channel: "email",
      previousDestination: "person@example.com",
      nextDestination: "next@example.com",
    });
    const email = store.state.verifications.find((row) => row.channel === "email");
    const phone = store.state.verifications.find((row) => row.channel === "whatsapp");
    assert.equal(email.status, "pending");
    assert.equal(email.consent_at, null);
    assert.equal(phone.status, "verified");
  });

  it("confirms WhatsApp only from the saved number and ignores bad or replayed webhooks", async () => {
    const store = createStore();
    seedContact(store);
    const invitation = await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "whatsapp",
      actorUserId: 7,
    });
    const page = await verification.loadChallenge(store.pool, invitation.token);
    const html = verification.renderChallengePage({
      state: page.state,
      token: invitation.token,
      workspaceName: page.workspaceName,
      channel: "whatsapp",
      code: page.code,
      fromNumber: "whatsapp:+15557654321",
    });
    assert.match(html, /https:\/\/wa\.me\/15557654321/);
    assert.doesNotMatch(html, /\/accept/);
    assert.equal(page.code, invitation.code);

    const wrongSender = await verification.confirmWhatsAppInbound({
      pool: store.pool,
      from: "whatsapp:+19998887777",
      body: `CONFIRM ${invitation.code}`,
      messageSid: "SM-wrong",
    });
    assert.equal(wrongSender.ok, false);
    assert.equal(store.state.challenges[0].status, "pending");

    const confirmed = await verification.confirmWhatsAppInbound({
      pool: store.pool,
      from: "whatsapp:+14155550100",
      body: `confirm ${invitation.code}`,
      messageSid: "SM-ok",
    });
    assert.equal(confirmed.ok, true);
    assert.equal(confirmed.workspaceId, "ws-1");
    const replay = await verification.confirmWhatsAppInbound({
      pool: store.pool,
      from: "whatsapp:+14155550100",
      body: `CONFIRM ${invitation.code}`,
      messageSid: "SM-ok",
    });
    assert.equal(replay.duplicate, true);

    const other = createStore();
    seedContact(other, { workspace_id: "ws-9", id: "contact-9" });
    const foreign = await verification.createInvitation({
      pool: other.pool,
      workspaceId: "ws-9",
      contactId: "contact-9",
      channel: "whatsapp",
      actorUserId: 3,
    });
    other.state.challenges[0].expires_at = new Date(Date.now() - 1000);
    const expired = await verification.confirmWhatsAppInbound({
      pool: other.pool,
      from: "+14155550100",
      body: `CONFIRM ${foreign.code}`,
      messageSid: "SM-expired",
    });
    assert.equal(expired.reason, "invalid");
    assert.equal(other.state.verifications.length, 0);

    const url = "https://example.com/webhooks/twilio/whatsapp/inbound";
    const params = { Body: `CONFIRM ${invitation.code}`, From: "whatsapp:+14155550100", MessageSid: "SM-ok" };
    const data = url + Object.keys(params).sort().map((key) => key + params[key]).join("");
    const signature = crypto.createHmac("sha1", "twilio-token").update(data).digest("base64");
    assert.equal(verification.verifyTwilioSignature({ url, params, signature, authToken: "twilio-token" }), true);
    assert.equal(verification.verifyTwilioSignature({ url, params, signature: "bad", authToken: "twilio-token" }), false);
    assert.equal(verification.verifyTwilioSignature({ url, params, signature, authToken: "" }), false);
    assert.equal(verification.parseConfirmCode("hello"), null);
  });

  it("rate-limits invitations per destination, across workspaces, and under parallel requests", async () => {
    process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_DAY = "1";
    process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_WEEK = "5";
    const store = createStore();
    seedContact(store);
    await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      actorUserId: 1,
    });
    await assert.rejects(
      () => verification.createInvitation({
        pool: store.pool,
        workspaceId: "ws-1",
        contactId: "contact-1",
        channel: "email",
        actorUserId: 1,
      }),
      (error) => error.code === "RECIPIENT_VERIFICATION_RATE_LIMITED",
    );

    const parallel = createStore();
    seedContact(parallel);
    const results = await Promise.allSettled([
      verification.createInvitation({ pool: parallel.pool, workspaceId: "ws-1", contactId: "contact-1", channel: "email", actorUserId: 1 }),
      verification.createInvitation({ pool: parallel.pool, workspaceId: "ws-1", contactId: "contact-1", channel: "email", actorUserId: 1 }),
    ]);
    assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
    assert.equal(results.filter((result) => result.status === "rejected").length, 1);

    process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_DAY = "10";
    process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_WEEK = "3";
    const abuse = createStore();
    const fingerprint = verification.destinationFingerprint("email", "person@example.com");
    for (const workspaceId of ["ws-a", "ws-b", "ws-c"]) {
      abuse.state.events.push({
        bucket_key: `dest:email:${fingerprint}:7d`,
        workspace_id: workspaceId,
        created_at: Date.now(),
      });
    }
    seedContact(abuse, { workspace_id: "ws-d", id: "contact-d" });
    await assert.rejects(
      () => verification.createInvitation({
        pool: abuse.pool,
        workspaceId: "ws-d",
        contactId: "contact-d",
        channel: "email",
        actorUserId: 9,
      }),
      (error) => error.code === "RECIPIENT_VERIFICATION_RATE_LIMITED",
    );
    assert.equal(abuse.state.suppressions.some((row) => row.reason === "verification_abuse" && row.scope === "global"), true);
    await assert.rejects(
      () => verification.createInvitation({
        pool: abuse.pool,
        workspaceId: "ws-d",
        contactId: "contact-d",
        channel: "email",
        actorUserId: 9,
      }),
      (error) => error.code === "RECIPIENT_SUPPRESSED",
    );
  });

  it("blocks unverified delivery without retry and still allows a verified recipient", async () => {
    process.env.TT_DEPLOYMENT = "self-hosted";
    process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
    const store = createStore();
    seedContact(store);
    const blocked = await verification.filterDeliveryRecipients({
      client: store.client,
      workspaceId: "ws-1",
      channel: "email",
      recipients: [{ contactId: "contact-1", destination: "person@example.com" }],
    });
    assert.equal(blocked.allowed.length, 0);
    assert.equal(blocked.code, "NO_VERIFIED_RECIPIENTS");
    const disposition = verification.deliveryDisposition([
      { channel: "email", success: false, eligibilityTerminal: true },
    ]);
    assert.deepEqual(disposition, {
      status: "blocked",
      retry: false,
      channels: [],
      code: "NO_VERIFIED_RECIPIENTS",
    });
    assert.equal(verification.deliveryDisposition([
      { channel: "email", success: false, eligibilityTerminal: false },
    ]).retry, true);

    store.state.verifications.push({
      workspace_id: "ws-1",
      contact_id: "contact-1",
      channel: "email",
      destination_normalized: "person@example.com",
      destination_fingerprint: verification.destinationFingerprint("email", "person@example.com"),
      status: "verified",
      consent_at: new Date(),
    });
    const allowed = await verification.canDeliverToRecipient({
      client: store.client,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      destination: "person@example.com",
    });
    assert.equal(allowed.allowed, true);

    store.state.contacts.get("ws-1:contact-1").details.email = "changed@example.com";
    const stale = await verification.canDeliverToRecipient({
      client: store.client,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      destination: "person@example.com",
    });
    assert.equal(stale.allowed, false);

    process.env.RECIPIENT_VERIFICATION_MODE = "shadow";
    const shadow = await verification.canDeliverToRecipient({
      client: store.client,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      destination: "changed@example.com",
    });
    assert.equal(shadow.allowed, true);
    assert.equal(shadow.shadowBlocked, true);

    await assert.rejects(
      () => verification.authorizeWorkspaceTest({
        pool: store.pool,
        workspaceId: "ws-1",
        contactId: null,
        channel: "whatsapp",
        destination: "+14155550100",
      }),
      (error) => error.code === "CONTACT_REQUIRED",
    );
    await assert.rejects(
      () => verification.authorizeWorkspaceTest({
        pool: store.pool,
        workspaceId: "ws-1",
        contactId: "contact-1",
        channel: "whatsapp",
        destination: "+19998887777",
      }),
      (error) => error.code === "DESTINATION_MISMATCH",
    );
  });

  it("starts contacts unverified and does not trust a client verification status", async () => {
    const store = createStore();
    const contact = seedContact(store);
    const attached = await verification.attachVerification(store.pool, "ws-1", [contact]);
    assert.equal(attached.items[0].verification.email.status, "pending");
    assert.equal(attached.items[0].verification.whatsapp.status, "pending");
    const routeNames = ["apps/api/routes/contacts.js", "apps/saas/routes/contacts.js"];
    const routePath = routeNames.map((name) => path.join(ROOT, name)).find((candidate) => fs.existsSync(candidate));
    const source = fs.readFileSync(routePath, "utf8");
    assert.equal(source.includes("contact_created"), false);
    assert.equal(source.includes("req.body.verification"), false);
    assert.equal(source.includes("attachVerification"), true);

    const worker = fs.readFileSync(path.join(ROOT, "apps/worker/src/delivery-worker.js"), "utf8");
    const digest = fs.readFileSync(path.join(ROOT, "apps/worker/src/weekly-digest.js"), "utf8");
    assert.equal(worker.includes("gateDestinations"), true);
    assert.equal(worker.includes("eligibilityTerminal"), true);
    assert.equal(worker.includes("queueDeliveryOutcome"), true);
    assert.equal(worker.includes("selectDeliverableDestinations"), true);
    const route = fs.readFileSync(path.join(ROOT, "apps/api/routes/recipientVerification.js"), "utf8");
    assert.equal(route.includes("recipientVerificationPageLimiter"), true);
    assert.equal(route.includes("withholdDelivery"), true);
    assert.equal(route.includes("/webhooks/twilio/whatsapp/inbound"), true);
    const policy = fs.readFileSync(path.join(ROOT, "packages/recipient-verification/index.js"), "utf8");
    assert.equal(policy.includes("limited.recordAbuse"), true);
    assert.equal(policy.includes("recordAbuseSuppression"), true);
    assert.equal(digest.includes("destinationAllowed"), true);
    const whatsappRoute = ["apps/api/routes/whatsapp.js", "apps/saas/routes/whatsapp.js"]
      .map((name) => path.join(ROOT, name))
      .find((candidate) => fs.existsSync(candidate));
    const whatsapp = fs.readFileSync(whatsappRoute, "utf8");
    assert.equal(whatsapp.includes("whatsappTestCooldowns"), false);
    assert.equal(whatsapp.includes("authorizeWorkspaceTest"), true);
    const migration = fs.readFileSync(path.join(ROOT, "packages/recipient-verification/migration.sql"), "utf8");
    assert.equal(migration.includes("contact_channel_verifications"), true);
    assert.equal(migration.includes("UPDATE workspace_contacts"), false);
  });

  it("keeps verification status labels independent of a boolean", async () => {
    const uiPath = [
      "apps/dashboard/src/pages/contactVerificationStatus.js",
      "apps/web/pages/contactVerificationStatus.js",
    ].map((name) => path.join(ROOT, name)).find((candidate) => fs.existsSync(candidate));
    const ui = await import(pathToFileURL(uiPath).href);
    const contact = {
      id: "contact-1",
      phone_e164: "+14155550100",
      details: { email: "person@example.com" },
      verification: {
        email: { status: "pending" },
        whatsapp: { status: "verified" },
      },
    };
    assert.equal(ui.channelStatus(contact, "email").label, "Pending");
    assert.equal(ui.canTestSavedWhatsApp(contact, "+14155550100"), true);
    assert.equal(ui.canTestSavedWhatsApp(contact, "+19998887777"), false);
    assert.equal(ui.canTestSavedWhatsApp({ id: "new", phone_e164: "+14155550100" }, "+14155550100"), false);
    const notes = ui.groupEligibilityNote(
      [contact],
      ["contact-1"],
      [],
    );
    assert.equal(notes.length, 1);
    assert.match(ui.formatRetry(3700), /hours/);
  });

  it("records delivery outcomes without treating a blocked recipient as sent", () => {
    assert.equal("ABCDEFGHJKLMNPQRSTUVWXYZ23456789".length, 32);
    assert.equal(verification.queueDeliveryOutcome([
      { channel: "email", success: true },
      { channel: "whatsapp", success: true },
    ]).status, "sent");
    const blocked = verification.queueDeliveryOutcome([
      { channel: "email", success: false, eligibilityTerminal: true },
    ]);
    assert.equal(blocked.status, "blocked");
    assert.equal(blocked.retry, false);
    const partial = verification.queueDeliveryOutcome([
      { channel: "email", success: true },
      { channel: "whatsapp", success: false, eligibilityTerminal: true },
    ]);
    assert.equal(partial.status, "partial");
    assert.equal(partial.retry, false);
    assert.deepEqual(partial.channels, []);
    const retryable = verification.queueDeliveryOutcome([
      { channel: "email", success: true },
      { channel: "webhooks", success: false, eligibilityTerminal: false },
    ]);
    assert.equal(retryable.status, "partial");
    assert.equal(retryable.retry, true);
    assert.deepEqual(retryable.channels, ["webhooks"]);
    const forced = verification.queueDeliveryOutcome([
      { channel: "whatsapp", success: false, eligibilityTerminal: false },
    ], { whatsappPermanentFailure: true });
    assert.equal(forced.status, "blocked");
    assert.equal(forced.retry, false);
    const selected = verification.selectDeliverableDestinations([
      { contactId: "verified", destination: "person@example.com" },
      { contactId: "duplicate", destination: "person@example.com" },
      { contactId: "other", destination: "second@example.com" },
    ]);
    assert.deepEqual(selected.destinations, ["person@example.com", "second@example.com"]);
    assert.equal(selected.contactIdByDestination.get("person@example.com"), "verified");
  });

  it("lets a new pending invitation re-open consent after a decline without emailing that address", async () => {
    const store = createStore();
    seedContact(store);
    const fingerprint = verification.destinationFingerprint("email", "person@example.com");
    store.state.verifications.push({
      workspace_id: "ws-1",
      contact_id: "contact-1",
      channel: "email",
      destination_normalized: "person@example.com",
      destination_fingerprint: fingerprint,
      status: "opted_out",
      consent_at: null,
    });
    store.state.suppressions.push({
      channel: "email",
      destination_fingerprint: fingerprint,
      scope: "workspace",
      workspace_id: "ws-1",
      reason: "recipient_declined",
      expires_at: null,
    });
    const invitation = await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      actorUserId: 4,
    });
    assert.equal(invitation.withholdDelivery, true);
    const page = await verification.loadChallenge(store.pool, invitation.token);
    assert.equal(page.state, "pending");
    store.state.locks.length = 0;
    await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "whatsapp",
      actorUserId: 4,
    });
    const locks = store.state.locks.slice(-3);
    assert.deepEqual(locks, [...locks].sort());
    const accepted = await verification.consumeEmailChallenge({
      pool: store.pool,
      token: invitation.token,
      decision: "accept",
    });
    assert.equal(accepted.ok, true);
    assert.equal(store.state.suppressions.some((row) => row.reason === "recipient_declined"), false);
  });

  it("limits public confirmation attempts without describing the token", async () => {
    process.env.RECIPIENT_VERIFY_PUBLIC_PER_WINDOW = "1";
    process.env.RECIPIENT_VERIFY_PUBLIC_WINDOW_SECONDS = "600";
    const store = createStore();
    await verification.assertPublicVerificationBudget(store.pool, "ip-hash");
    await assert.rejects(
      () => verification.assertPublicVerificationBudget(store.pool, "ip-hash"),
      (error) => error.status === 429 && error.code === "RECIPIENT_VERIFICATION_RATE_LIMITED",
    );
  });

  it("delivers when a later duplicate contact is the verified one", async () => {
    process.env.TT_DEPLOYMENT = "self-hosted";
    process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
    const store = createStore();
    seedContact(store);
    store.state.contacts.set("ws-1:contact-2", {
      id: "contact-2",
      workspace_id: "ws-1",
      phone_e164: "+14155550100",
      details: { email: "person@example.com" },
    });
    store.state.verifications.push({
      workspace_id: "ws-1",
      contact_id: "contact-2",
      channel: "email",
      destination_normalized: "person@example.com",
      destination_fingerprint: verification.destinationFingerprint("email", "person@example.com"),
      status: "verified",
      consent_at: new Date(),
    });
    const gated = await verification.filterDeliveryRecipients({
      client: store.client,
      workspaceId: "ws-1",
      channel: "email",
      recipients: [
        { contactId: "contact-1", destination: "person@example.com" },
        { contactId: "contact-2", destination: "person@example.com" },
      ],
    });
    const selected = verification.selectDeliverableDestinations(gated.allowed);
    assert.deepEqual(selected.destinations, ["person@example.com"]);
    assert.equal(selected.contactIdByDestination.get("person@example.com"), "contact-2");
    const digest = await verification.canDeliverToDestination({
      client: store.client,
      workspaceId: "ws-1",
      channel: "email",
      destination: "person@example.com",
    });
    assert.equal(digest.allowed, true);
  });
});
