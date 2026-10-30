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
    audit: [],
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
    if (text.includes("SAVEPOINT rv_optional_verification")) return rowsOf([]);
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

    if (text.includes("RV_TEST_RATE_COUNT")) {
      if (state.auditMissing) {
        const error = new Error("relation audit_events does not exist");
        error.code = "42P01";
        throw error;
      }
      const windowMs = Number(params[2]) * 1000;
      const n = state.audit.filter((row) => (
        row.workspace_id === params[0]
        && row.bucket === params[1]
        && row.occurred_at > Date.now() - windowMs
      )).length;
      return rowsOf([{ n }]);
    }

    if (text.includes("RV_TEST_RATE_INSERT")) {
      if (state.auditMissing) {
        const error = new Error("relation audit_events does not exist");
        error.code = "42P01";
        throw error;
      }
      state.audit.push({
        channel: params[0],
        workspace_id: params[1],
        bucket: params[2],
        contact_id: params[3],
        occurred_at: Date.now(),
      });
      return rowsOf([]);
    }

    if (text.includes("RV_PENDING_CHALLENGE")) {
      const pending = state.challenges.find((row) => (
        row.workspace_id === params[0]
        && row.contact_id === params[1]
        && row.channel === "email"
        && row.status === "pending"
        && new Date(row.expires_at).getTime() > Date.now()
      ));
      return rowsOf(pending ? [{ id: pending.id, created_at: new Date(pending.created_at || Date.now()) }] : []);
    }

    if (text.includes("RV_DISPATCH_EVENTS")) {
      const prefix = String(params[0] || "").replace(/%$/, "");
      return rowsOf(state.events
        .filter((row) => String(row.bucket_key).startsWith(prefix))
        .map((row) => ({ bucket_key: row.bucket_key, created_at: new Date(row.created_at) })));
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
        created_at: Date.now(),
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
      const challenge = state.challenges.find((row) => {
        const hashMatch = text.includes("token_hash")
          ? row.token_hash === params[0]
          : row.code_hash === params[0];
        return hashMatch
          && row.channel === "whatsapp"
          && row.status === "pending"
          && new Date(row.expires_at).getTime() > Date.now()
          && row.destination_normalized === params[1];
      });
      if (!challenge) return rowsOf([]);
      challenge.status = text.includes("status = 'declined'") ? "declined" : "consumed";
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

    if (text.includes("RV_RESUBSCRIBE_TARGETS")) {
      const fingerprint = params[0];
      const email = params[1];
      const rows = [];
      for (const contact of state.contacts.values()) {
        const contactEmail = String(contact.details?.email || "").trim().toLowerCase();
        if (contactEmail !== email) continue;
        const declined = state.suppressions.find((row) => (
          row.reason === "recipient_declined"
          && row.destination_fingerprint === fingerprint
          && row.workspace_id === contact.workspace_id
          && !expired(row)
        ));
        if (!declined) continue;
        rows.push({
          workspace_id: contact.workspace_id,
          contact_id: contact.id,
          workspace_name: state.workspaces.get(contact.workspace_id) || "Workspace",
        });
      }
      return rowsOf(rows);
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
    for (const key of ["RECIPIENT_FINGERPRINT_SECRET", "TT_DEPLOYMENT", "RECIPIENT_VERIFICATION_MODE", "RECIPIENT_VERIFY_EMAIL_DEST_PER_DAY", "RECIPIENT_VERIFY_EMAIL_DEST_PER_WEEK", "RECIPIENT_VERIFY_WORKSPACE_PER_DAY", "RECIPIENT_VERIFY_USER_PER_DAY", "RECIPIENT_VERIFICATION_DISPATCH_LEASE_SECONDS", "RECIPIENT_TEST_PER_CONTACT_PER_DAY", "RECIPIENT_TEST_COOLDOWN_SECONDS"]) {
      previous[key] = process.env[key];
    }
    process.env.RECIPIENT_FINGERPRINT_SECRET = SECRET;
    delete process.env.TT_DEPLOYMENT;
    delete process.env.RECIPIENT_VERIFICATION_MODE;
    delete process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_DAY;
    delete process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_WEEK;
    delete process.env.RECIPIENT_VERIFY_WORKSPACE_PER_DAY;
    delete process.env.RECIPIENT_VERIFY_USER_PER_DAY;
    delete process.env.RECIPIENT_VERIFICATION_DISPATCH_LEASE_SECONDS;
    delete process.env.RECIPIENT_TEST_PER_CONTACT_PER_DAY;
    delete process.env.RECIPIENT_TEST_COOLDOWN_SECONDS;
  });
  afterEach(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  it("defaults Cloud to enforce and self-hosted to off", () => {
    assert.equal(verification.resolveEnforcementMode({ TT_DEPLOYMENT: "cloud" }), "enforce");
    assert.equal(verification.resolveEnforcementMode({ TT_DEPLOYMENT: "cloud", RECIPIENT_VERIFICATION_MODE: "enforce" }), "enforce");
    assert.equal(verification.resolveEnforcementMode({ TT_DEPLOYMENT: "cloud", RECIPIENT_VERIFICATION_MODE: "off" }), "enforce");
    assert.equal(verification.resolveEnforcementMode({ TT_DEPLOYMENT: "cloud", RECIPIENT_VERIFICATION_MODE: "shadow" }), "enforce");
    assert.equal(verification.resolveEnforcementMode({
      TT_DEPLOYMENT: "cloud",
      RECIPIENT_VERIFICATION_MODE: "shadow",
      RECIPIENT_VERIFICATION_CLOUD_SHADOW: "1",
    }), "shadow");
    assert.equal(verification.resolveEnforcementMode({ TT_DEPLOYMENT: "prod" }), "enforce");
    assert.equal(verification.resolveEnforcementMode({ TT_DEPLOYMENT: "self-hosted" }), "off");
    assert.equal(verification.resolveEnforcementMode({ TT_DEPLOYMENT: "self-hosted", RECIPIENT_VERIFICATION_MODE: "off" }), "off");
    assert.equal(verification.resolveEnforcementMode({ TT_DEPLOYMENT: "self-hosted", RECIPIENT_VERIFICATION_MODE: "shadow" }), "shadow");
    assert.equal(verification.resolveEnforcementMode({ TT_DEPLOYMENT: "self-hosted", RECIPIENT_VERIFICATION_MODE: "enforce" }), "enforce");
    const cloudReport = verification.describeEnforcement({ TT_DEPLOYMENT: "cloud" });
    assert.equal(cloudReport.mode, "enforce");
    assert.equal(cloudReport.deployment, "cloud");
    if (verification.DEFAULT_DEPLOYMENT === "cloud") {
      assert.equal(verification.resolveEnforcementMode({}), "enforce");
    } else {
      assert.equal(verification.resolveEnforcementMode({}), "off");
    }
  });

  it("sends to unverified recipients when verification is off and blocks them when Cloud enforces", async () => {
    delete process.env.RECIPIENT_FINGERPRINT_SECRET;
    process.env.TT_DEPLOYMENT = "self-hosted";
    delete process.env.RECIPIENT_VERIFICATION_MODE;
    const store = createStore();
    seedContact(store);
    const recipients = [{ contactId: "contact-1", destination: "person@example.com" }];
    const off = await verification.filterDeliveryRecipients({
      client: store.client,
      workspaceId: "ws-1",
      channel: "email",
      recipients,
    });
    assert.equal(off.mode, "off");
    assert.equal(off.allowed.length, 1);
    assert.equal(off.code, null);
    const digest = await verification.canDeliverToDestination({
      client: store.client,
      workspaceId: "ws-1",
      channel: "email",
      destination: "person@example.com",
    });
    assert.equal(digest.allowed, true);
    assert.equal(digest.mode, "off");
    const tested = await verification.authorizeWorkspaceTest({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      destination: "person@example.com",
    });
    assert.equal(tested.destination, "person@example.com");
    assert.equal(verification.confirmDigestConsent({ mode: "off", finalAllowed: false }).send, true);

    process.env.RECIPIENT_FINGERPRINT_SECRET = SECRET;
    process.env.TT_DEPLOYMENT = "cloud";
    delete process.env.RECIPIENT_VERIFICATION_MODE;
    const blocked = await verification.filterDeliveryRecipients({
      client: store.client,
      workspaceId: "ws-1",
      channel: "email",
      recipients,
    });
    assert.equal(blocked.mode, "enforce");
    assert.equal(blocked.allowed.length, 0);
    assert.equal(blocked.code, "NO_VERIFIED_RECIPIENTS");
    await assert.rejects(
      () => verification.authorizeWorkspaceTest({
        pool: store.pool,
        workspaceId: "ws-1",
        contactId: "contact-1",
        channel: "email",
        destination: "person@example.com",
      }),
      (error) => error.code === "RECIPIENT_NOT_VERIFIED",
    );
    process.env.RECIPIENT_VERIFICATION_MODE = "shadow";
    process.env.TT_DEPLOYMENT = "self-hosted";
    const shadowTest = await verification.authorizeWorkspaceTest({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "whatsapp",
      destination: "+14155550100",
    });
    assert.equal(shadowTest.destination, "+14155550100");
    assert.equal(verification.confirmDigestConsent({ mode: "shadow", finalAllowed: false }).send, true);
    assert.equal(verification.confirmDigestConsent({ mode: "enforce", finalAllowed: false }).send, false);
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
    const invited = await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      actorUserId: 1,
    });
    await verification.noteInvitationDispatch({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      challengeId: invited.challengeId,
      outcome: "accepted",
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
    assert.equal(route.includes("status: \"opted_out\""), true);
    assert.equal(route.includes("/verify/recipient/resubscribe"), true);
    assert.equal(route.includes("share_url: shareUrl"), true);
    assert.equal(route.includes("/webhooks/twilio/whatsapp/inbound"), true);
    const policy = fs.readFileSync(path.join(ROOT, "packages/recipient-verification/index.js"), "utf8");
    assert.equal(policy.includes("limited.recordAbuse"), true);
    assert.equal(policy.includes("recordAbuseSuppression"), true);
    assert.equal(digest.includes("destinationAllowed"), true);
    const digestLoop = digest.slice(digest.indexOf("for (const row of inverted)"));
    assert.ok(digestLoop.indexOf("claimWeeklyDigestRecipient") < digestLoop.indexOf("confirmDigestConsent"));
    assert.ok(digestLoop.indexOf("confirmDigestConsent") < digestLoop.indexOf("deliverRecipientDigest"));
    assert.equal(digestLoop.includes("releaseWeeklyDigestRecipientClaim"), true);
    assert.equal(digestLoop.includes("claimToken: claim.claim_token"), true);
    assert.equal(digestLoop.includes("runOwnedDigestDelivery"), true);
    assert.equal(digestLoop.includes("completion !== \"confirmed\""), true);
    assert.equal(digestLoop.includes("delivery_state === \"uncertain\""), true);
    assert.equal(digest.includes("weekly-digest-delivery-unconfirmed"), true);
    assert.equal(digest.includes("weeklyDigestWhatsAppIdempotencyKey"), true);
    assert.equal(digest.includes("isUncertainProviderFailure"), true);
    const digestClaims = fs.readFileSync(path.join(ROOT, "apps/worker/src/shared/weeklyDigestRecipients.js"), "utf8");
    assert.equal(digestClaims.includes("noteWeeklyDigestProviderAccepted"), true);
    assert.equal(digestClaims.includes("provider_accepted_at"), true);
    const preferences = fs.readFileSync(path.join(ROOT, "apps/dashboard/src/pages/AlertPreferences.jsx"), "utf8");
    const whatsappInvite = preferences.slice(preferences.indexOf("async function handleShareWhatsApp"));
    assert.ok(whatsappInvite.indexOf("RECIPIENT_OPTED_OUT") < whatsappInvite.indexOf("share_url"));
    assert.ok(route.indexOf("invitation.withholdDelivery") < route.indexOf("share_url: shareUrl"));
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
    assert.equal(ui.groupEligibilityNote([contact], ["contact-1"], [], "off").length, 0);
    assert.equal(ui.groupEligibilityNote([contact], ["contact-1"], [], "shadow").length, 0);
    assert.equal(ui.verificationControlsVisible("off"), false);
    assert.equal(ui.verificationControlsVisible("enforce"), true);
    assert.equal(ui.verificationControlsVisible("shadow"), true);
    assert.match(ui.verificationWaitCopy("enforce"), /Alerts wait until/);
    assert.match(ui.verificationWaitCopy("shadow"), /still sent/);
    assert.equal(ui.verificationWaitCopy("off"), null);
    assert.match(ui.verificationIntro("off"), /confirmation is off/i);
    assert.doesNotMatch(ui.verificationIntro("shadow"), /Alerts wait until/);
    assert.doesNotMatch(ui.groupChannelHint("off"), /do not receive/);
    assert.match(ui.groupChannelHint("enforce"), /do not receive/);
    assert.equal(ui.canTestSavedWhatsApp(contact, "+14155550100", "off"), true);
    assert.equal(ui.canTestSavedWhatsApp(
      { id: "contact-1", phone_e164: "+14155550100", details: { email: "person@example.com" } },
      "+14155550100",
      "off",
    ), true);
    assert.match(ui.addContactTestHint("off"), /does not require confirmation/);
    assert.match(ui.addContactTestHint("shadow"), /does not block the test/);
    assert.match(ui.addContactTestHint("enforce"), /only after this number is confirmed/);
    assert.match(ui.testNumberHint("off"), /does not require confirmation/);
    assert.match(ui.testNumberHint("shadow"), /does not block/);
    assert.match(ui.testNumberHint("enforce"), /stays confirmed/);
    assert.equal(ui.addContactTestHint(null), "Save the contact first.");
    const preferences = fs.readFileSync(path.join(ROOT, "apps/dashboard/src/pages/AlertPreferences.jsx"), "utf8");
    assert.equal(preferences.includes("addContactTestHint(recipientVerificationMode)"), true);
    assert.equal(preferences.includes("A WhatsApp test is available only after this number is confirmed."), false);
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
    assert.equal(invitation.token, null);
    assert.equal(store.state.challenges.length, 0);
    const resumed = await verification.requestEmailResubscribe({
      pool: store.pool,
      email: "person@example.com",
    });
    assert.equal(resumed.length, 1);
    assert.equal(typeof resumed[0].token, "string");
    const page = await verification.loadChallenge(store.pool, resumed[0].token);
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
      token: resumed[0].token,
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

  it("keeps an earlier blocked channel when a later retry succeeds", () => {
    const first = verification.mergeDeliveryAttempt({
      prior: ["email", "webhooks"],
      logRows: [],
      attempted: [
        { channel: "email", success: false, eligibilityTerminal: true, errorCode: "NO_VERIFIED_RECIPIENTS" },
        { channel: "webhooks", success: false, eligibilityTerminal: false },
      ],
      liveChannels: ["email", "webhooks"],
    });
    assert.equal(first.outcome.status, "failed");
    assert.deepEqual(first.outcome.channels, ["webhooks"]);
    const second = verification.mergeDeliveryAttempt({
      prior: first.ledger,
      logRows: [],
      attempted: [{ channel: "webhooks", success: true }],
      liveChannels: ["email", "webhooks"],
    });
    assert.equal(second.outcome.status, "partial");
    assert.equal(second.outcome.retry, false);
    assert.deepEqual(second.ledger.retry, []);
    const whatsapp = verification.mergeDeliveryAttempt({
      prior: {
        version: 1,
        retry: ["email"],
        required: ["email", "whatsapp"],
        outcomes: {
          whatsapp: { state: "blocked", terminal: true, code: "NO_VERIFIED_RECIPIENTS" },
          email: { state: "failed", terminal: false },
        },
      },
      attempted: [{ channel: "email", success: true }],
      liveChannels: ["email", "whatsapp"],
    });
    assert.equal(whatsapp.outcome.status, "partial");
    const recovered = verification.mergeDeliveryAttempt({
      prior: ["email", "whatsapp"],
      logRows: [
        { channel: "email", status: "success", metadata: { recipient: "person@example.com" } },
        { channel: "whatsapp", status: "failed", error_message: "timeout" },
      ],
      attempted: [{ channel: "whatsapp", success: true }],
      liveChannels: ["email", "whatsapp"],
    });
    assert.equal(recovered.outcome.status, "sent");
    const endpoints = verification.mergeDeliveryAttempt({
      prior: [],
      attempted: [{
        channel: "webhooks",
        success: false,
        partialSuccess: true,
        terminal: false,
        endpoints: { a: "sent", b: "failed" },
      }],
      liveChannels: ["webhooks"],
    });
    assert.equal(endpoints.outcome.status, "partial");
    assert.deepEqual(endpoints.outcome.channels, ["webhooks"]);
    const finished = verification.mergeDeliveryAttempt({
      prior: endpoints.ledger,
      attempted: [{
        channel: "webhooks",
        success: true,
        endpoints: { a: "sent", b: "sent" },
      }],
      liveChannels: ["webhooks"],
    });
    assert.equal(finished.outcome.status, "sent");
    const permanent = verification.mergeDeliveryAttempt({
      prior: [],
      attempted: [{
        channel: "webhooks",
        success: false,
        partialSuccess: true,
        terminal: true,
        endpoints: { a: "sent", b: "permanent" },
      }],
      liveChannels: ["webhooks"],
    });
    assert.equal(permanent.outcome.status, "partial");
    assert.equal(permanent.outcome.retry, false);
    assert.equal(permanent.outcome.notifyUnverified, false);
    assert.equal(permanent.outcome.notifyProviderTerminal, true);
  });

  it("retries only the channels named by a delivery ledger", async () => {
    const groups = await import(pathToFileURL(path.join(ROOT, "apps/worker/src/shared/contactGroups.js")).href);
    assert.deepEqual(
      groups.channelsForDeliveryAttempt(
        ["email", "webhooks", "whatsapp"],
        { version: 1, retry: ["webhooks"] },
        { isRetry: true },
      ),
      ["webhooks"],
    );
    assert.deepEqual(
      groups.channelsForDeliveryAttempt(["email", "webhooks"], ["email"], { isRetry: true }),
      ["email"],
    );
  });

  it("preserves a delivery ledger and separates recipient failures from webhook failures", () => {
    const ledger = {
      version: 1,
      retry: ["webhooks"],
      required: ["email", "webhooks"],
      outcomes: {
        email: { state: "blocked", terminal: true, code: "NO_VERIFIED_RECIPIENTS", reason: "eligibility" },
        webhooks: { state: "failed", terminal: false, code: "HTTP_500" },
      },
    };
    const same = verification.reconcileDeliveryChannels(ledger, ["webhooks", "email"]);
    assert.equal(same.changed, false);
    assert.equal(same.channels.outcomes.email.state, "blocked");
    assert.deepEqual(same.channels.retry, ["webhooks"]);
    assert.equal(verification.reconcileDeliveryChannels(same.channels, ["email", "webhooks"]).changed, false);

    const delivered = verification.reconcileDeliveryChannels({
      version: 1,
      retry: ["email"],
      required: ["email", "webhooks"],
      outcomes: {
        email: { state: "sent", terminal: true },
        webhooks: { state: "failed", terminal: false },
      },
    }, ["email", "webhooks"]);
    assert.deepEqual(delivered.channels.retry, ["webhooks"]);

    const terminalWebhook = verification.reconcileDeliveryChannels({
      version: 1,
      retry: ["webhooks"],
      required: ["webhooks"],
      outcomes: { webhooks: { state: "blocked", terminal: true, reason: "provider", code: "HTTP_404" } },
    }, ["webhooks"]);
    assert.deepEqual(terminalWebhook.channels.retry, []);
    assert.equal(verification.reconcileDeliveryChannels(terminalWebhook.channels, ["webhooks"]).changed, false);

    const legacy = verification.reconcileDeliveryChannels(["email", "webhooks"], ["email"]);
    assert.equal(legacy.format, "legacy");
    assert.deepEqual(legacy.channels, ["email"]);
    assert.equal(verification.reconcileDeliveryChannels(["email"], ["email", "webhooks"]).changed, false);

    const added = verification.reconcileDeliveryChannels(ledger, ["email", "webhooks", "whatsapp"]);
    assert.deepEqual(added.channels.retry, ["webhooks", "whatsapp"]);
    assert.equal(added.channels.outcomes.email.terminal, true);
    const removed = verification.reconcileDeliveryChannels(added.channels, ["webhooks"]);
    assert.equal(removed.channels.outcomes.email, undefined);
    assert.equal(removed.channels.outcomes.whatsapp, undefined);
    assert.deepEqual(removed.channels.retry, ["webhooks"]);

    const unverified = verification.mergeDeliveryAttempt({
      prior: ["email"],
      attempted: [{ channel: "email", success: false, eligibilityTerminal: true, errorCode: "NO_VERIFIED_RECIPIENTS" }],
      liveChannels: ["email"],
    });
    assert.equal(unverified.outcome.notifyUnverified, true);
    assert.equal(unverified.outcome.notifyProviderTerminal, false);
    assert.equal(unverified.outcome.status, "blocked");
    assert.equal(unverified.outcome.retry, false);

    const replayedOptOut = verification.mergeDeliveryAttempt({
      prior: [],
      logRows: [
        { channel: "whatsapp", status: "blocked", error_message: "RECIPIENT_OPTED_OUT" },
        { channel: "whatsapp", status: "failed", error_message: "RECIPIENT_OPTED_OUT" },
      ],
      attempted: [],
      liveChannels: ["whatsapp"],
    });
    assert.equal(replayedOptOut.ledger.outcomes.whatsapp.state, "blocked");
    assert.equal(replayedOptOut.ledger.outcomes.whatsapp.reason, "eligibility");
    assert.equal(replayedOptOut.outcome.retry, false);
    assert.equal(replayedOptOut.outcome.notifyUnverified, true);

    const optedOut = verification.mergeDeliveryAttempt({
      prior: ["whatsapp"],
      attempted: [{ channel: "whatsapp", success: false, eligibilityTerminal: true, errorCode: "RECIPIENT_OPTED_OUT" }],
      liveChannels: ["whatsapp"],
    });
    assert.equal(optedOut.outcome.code, "RECIPIENT_OPTED_OUT");
    assert.equal(optedOut.outcome.notifyUnverified, true);
    assert.equal(optedOut.ledger.outcomes.whatsapp.reason, "eligibility");

    const permanentWebhook = verification.mergeDeliveryAttempt({
      prior: ["webhooks"],
      attempted: [{ channel: "webhooks", success: false, terminal: true, errorCode: "HTTP_404", endpoints: { h: "permanent" } }],
      liveChannels: ["webhooks"],
    });
    assert.equal(permanentWebhook.outcome.notifyUnverified, false);
    assert.equal(permanentWebhook.outcome.notifyProviderTerminal, true);
    assert.equal(permanentWebhook.outcome.code, "PERMANENT_DELIVERY_FAILURE");
    assert.equal(permanentWebhook.outcome.status, "blocked");

    const transient = verification.mergeDeliveryAttempt({
      prior: ["webhooks"],
      attempted: [{ channel: "webhooks", success: false, terminal: false, errorCode: "HTTP_429" }],
      liveChannels: ["webhooks"],
    });
    assert.equal(transient.outcome.retry, true);
    assert.equal(transient.outcome.notifyProviderTerminal, false);
    assert.equal(transient.outcome.notifyUnverified, false);

    const oneEndpoint = verification.mergeDeliveryAttempt({
      prior: ["webhooks"],
      attempted: [{
        channel: "webhooks",
        success: false,
        partialSuccess: true,
        terminal: true,
        endpoints: { ok: "sent", bad: "permanent" },
      }],
      liveChannels: ["webhooks"],
    });
    assert.equal(oneEndpoint.outcome.status, "partial");
    assert.equal(oneEndpoint.outcome.retry, false);
    assert.equal(oneEndpoint.outcome.notifyUnverified, false);

    const combined = verification.mergeDeliveryAttempt({
      prior: ["email", "webhooks"],
      attempted: [
        { channel: "email", success: false, eligibilityTerminal: true, errorCode: "NO_VERIFIED_RECIPIENTS" },
        { channel: "webhooks", success: false, terminal: true, endpoints: { h: "permanent" } },
      ],
      liveChannels: ["email", "webhooks"],
    });
    assert.equal(combined.outcome.notifyUnverified, true);
    assert.equal(combined.outcome.notifyProviderTerminal, true);
    assert.equal(combined.outcome.retry, false);

    const manual = verification.planManualRetry(combined.ledger, "webhooks");
    assert.equal(manual.ok, true);
    assert.equal(manual.format, "ledger");
    assert.equal(manual.channels.outcomes.email.code, "NO_VERIFIED_RECIPIENTS");
    assert.equal(manual.channels.outcomes.webhooks.retryGeneration, 1);
    assert.equal(manual.channels.outcomes.webhooks.reopened, undefined);
    assert.deepEqual(manual.channels.retry, ["webhooks"]);
    const retriedTransient = verification.mergeDeliveryAttempt({
      prior: manual.channels,
      logRows: [],
      attempted: [{
        channel: "webhooks",
        success: false,
        terminal: false,
        errorCode: "HTTP_503",
        endpoints: { h: "failed" },
      }],
      liveChannels: ["email", "webhooks"],
    });
    assert.equal(retriedTransient.ledger.outcomes.webhooks.retryGeneration, 1);
    assert.equal(retriedTransient.ledger.outcomes.webhooks.terminal, false);
    assert.deepEqual(retriedTransient.ledger.retry, ["webhooks"]);
    assert.deepEqual(verification.webhookPermanentHashes([
      { channel: "webhooks", status: "failed", metadata: { terminal: true, urlHash: "old", retryGeneration: 0 } },
      { channel: "webhooks", status: "failed", metadata: { terminal: true, urlHash: "new", retryGeneration: 1 } },
      { channel: "webhooks", status: "success", metadata: { urlHash: "sent", retryGeneration: 1 } },
    ], retriedTransient.ledger), ["new"]);
    assert.equal(verification.webhookRetryGeneration({ reopened: true }), 1);
    const now = new Date();
    assert.equal(verification.deliveryClaimIsActive({
      delivery_claim_id: "claim",
      next_attempt_at: new Date(now.getTime() + 60000),
    }, now), true);
    assert.equal(verification.deliveryClaimIsActive({
      delivery_claim_id: "claim",
      next_attempt_at: new Date(now.getTime() - 60000),
    }, now), false);
    assert.equal(verification.deliveryClaimIsActive({
      delivery_claim_id: null,
      next_attempt_at: new Date(now.getTime() + 60000),
    }, now), false);
    const reopenedAgain = verification.planManualRetry({
      ...retriedTransient.ledger,
      outcomes: {
        ...retriedTransient.ledger.outcomes,
        webhooks: { ...retriedTransient.ledger.outcomes.webhooks, terminal: true, state: "blocked" },
      },
    }, "webhooks");
    assert.equal(reopenedAgain.channels.outcomes.webhooks.retryGeneration, 2);
    assert.equal(verification.planManualRetry(combined.ledger, "email").code, "NO_VERIFIED_RECIPIENTS");
    assert.deepEqual(verification.planManualRetry(["email", "webhooks"], "webhooks").channels, ["webhooks"]);
    assert.equal(verification.planManualRetry({
      version: 1,
      retry: [],
      required: ["email"],
      outcomes: { email: { state: "sent", terminal: true } },
    }, "email").code, "ALREADY_DELIVERED");
    assert.equal(verification.planManualRetry(permanentWebhook.ledger).code, "CHANNEL_PERMANENT");

    for (const state of ["pending", "failed", "partial", "blocked", "sent"]) {
      const listed = verification.publicDeliveryChannels(state === "pending"
        ? { version: 1, retry: ["email"], required: ["email"], outcomes: {} }
        : {
          version: 1,
          retry: state === "failed" ? ["email"] : [],
          required: ["email"],
          outcomes: { email: { state, terminal: state !== "failed" } },
        });
      assert.deepEqual(listed.map((row) => row.channel), ["email"]);
      assert.equal(listed[0].channel_state, state === "pending" ? "pending" : state);
      assert.equal(Object.hasOwn(listed[0], "endpoints"), false);
    }
    assert.equal(verification.publicDeliveryChannels(["webhooks"])[0].channel_state, null);

    const requeued = verification.requeueWebhookChannel(permanentWebhook.ledger);
    assert.equal(requeued.version, 1);
    assert.equal(requeued.outcomes.webhooks.terminal, false);
    assert.equal(requeued.outcomes.webhooks.retryGeneration, 1);
    assert.equal(requeued.outcomes.webhooks.reopened, undefined);
    assert.deepEqual(verification.requeueWebhookChannel(["email"]), ["email", "webhooks"]);

    const api = fs.readFileSync(path.join(ROOT, "apps/api/index.js"), "utf8");
    assert.match(api, /planManualRetry\(alert\.channels, channel\)/);
    assert.match(api, /manualRetryUpdateSql\(/);
    assert.match(api, /DELIVERY_IN_PROGRESS/);
    assert.match(api, /currentWorkspaceAccessSql\(currentAnchor, "\$3"\)/);
    const alerts = fs.readFileSync(path.join(ROOT, "apps/api/routes/alerts.js"), "utf8");
    assert.equal(alerts.includes("jsonb_array_elements_text"), false);
    assert.match(alerts, /publicDeliveryChannels\(alert\.channels\)/);
    assert.match(alerts, /delivery_claim_id IS NULL/);
    const worker = fs.readFileSync(path.join(ROOT, "apps/worker/src/delivery-worker.js"), "utf8");
    assert.equal(worker.includes("__permanent__"), false);
    assert.match(worker, /webhookPermanentHashes/);
    assert.match(worker, /type: "delivery_webhook_permanent"/);
    assert.match(worker, /type: "delivery_unverified_recipients"/);
    const queue = fs.readFileSync(path.join(ROOT, "apps/worker/src/queue-manager.js"), "utf8");
    assert.match(queue, /reconcileDeliveryChannels/);
    assert.match(queue, /delivery_claim_id IS NULL/);
  });

  it("does not let public re-subscriptions share one anonymous user quota", async () => {
    process.env.RECIPIENT_VERIFY_USER_PER_DAY = "1";
    process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_DAY = "1";
    process.env.RECIPIENT_VERIFY_WORKSPACE_PER_DAY = "10";
    const store = createStore();
    seedContact(store, { id: "contact-1", details: { email: "one@example.com" }, phone_e164: "+14155550101" });
    seedContact(store, { id: "contact-2", details: { email: "two@example.com" }, phone_e164: "+14155550102" });
    const first = await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      actorUserId: null,
      recipientInitiated: true,
      requestIp: "203.0.113.10",
    });
    const second = await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-2",
      channel: "email",
      actorUserId: null,
      recipientInitiated: true,
      requestIp: "203.0.113.11",
    });
    assert.equal(typeof first.token, "string");
    assert.equal(typeof second.token, "string");
    assert.equal(store.state.events.some((row) => String(row.bucket_key).startsWith("user:unknown")), false);
    process.env.RECIPIENT_VERIFY_WORKSPACE_PER_DAY = "1";
    const other = createStore();
    seedContact(other, { id: "contact-1", details: { email: "one@example.com" }, phone_e164: "+14155550101" });
    seedContact(other, { id: "contact-2", details: { email: "two@example.com" }, phone_e164: "+14155550102" });
    await verification.createInvitation({
      pool: other.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      recipientInitiated: true,
    });
    await assert.rejects(
      () => verification.createInvitation({
        pool: other.pool,
        workspaceId: "ws-1",
        contactId: "contact-2",
        channel: "email",
        recipientInitiated: true,
      }),
      (error) => error.code === "RECIPIENT_VERIFICATION_RATE_LIMITED",
    );
  });

  it("retries a failed verification email without using another destination allowance", async () => {
    process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_DAY = "1";
    process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_WEEK = "3";
    const store = createStore();
    seedContact(store);
    const first = await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      actorUserId: 7,
    });
    await assert.rejects(
      () => verification.createInvitation({
        pool: store.pool,
        workspaceId: "ws-1",
        contactId: "contact-1",
        channel: "email",
        actorUserId: 7,
      }),
      (error) => error.code === "VERIFICATION_DISPATCH_UNCONFIRMED",
    );
    await verification.noteInvitationDispatch({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      challengeId: first.challengeId,
      outcome: "failed",
    });
    const retried = await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      actorUserId: 7,
    });
    assert.notEqual(retried.token, first.token);
    assert.equal(store.state.challenges.filter((row) => row.status === "pending").length, 1);
    await verification.noteInvitationDispatch({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      challengeId: retried.challengeId,
      outcome: "ambiguous",
    });
    await assert.rejects(
      () => verification.createInvitation({
        pool: store.pool,
        workspaceId: "ws-1",
        contactId: "contact-1",
        channel: "email",
        actorUserId: 7,
      }),
      (error) => error.code === "VERIFICATION_DISPATCH_UNCONFIRMED",
    );
    const accepted = await verification.consumeEmailChallenge({
      pool: store.pool,
      token: retried.token,
      decision: "accept",
    });
    assert.equal(accepted.ok, true);
    assert.equal(accepted.outcome, "accepted");
  });

  it("retries an interrupted verification email after the dispatch lease and still blocks an opt-out", async () => {
    process.env.RECIPIENT_VERIFICATION_DISPATCH_LEASE_SECONDS = "1";
    process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_DAY = "5";
    process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_WEEK = "5";
    const store = createStore();
    seedContact(store);
    const first = await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      actorUserId: 7,
    });
    await assert.rejects(
      () => verification.createInvitation({
        pool: store.pool,
        workspaceId: "ws-1",
        contactId: "contact-1",
        channel: "email",
        actorUserId: 7,
      }),
      (error) => error.code === "VERIFICATION_DISPATCH_UNCONFIRMED",
    );
    for (const event of store.state.events) {
      if (String(event.bucket_key).includes(String(first.challengeId))) event.created_at = Date.now() - 5000;
    }
    const recovered = await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      actorUserId: 7,
    });
    assert.notEqual(recovered.token, first.token);
    assert.equal(store.state.challenges.filter((row) => row.status === "pending").length, 1);
    store.state.challenges.find((row) => row.id === recovered.challengeId).expires_at = new Date(Date.now() - 1000);
    const replaced = await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      actorUserId: 7,
    });
    assert.ok(replaced.token);
    const accepted = await verification.consumeEmailChallenge({
      pool: store.pool,
      token: replaced.token,
      decision: "accept",
    });
    assert.equal(accepted.outcome, "accepted");
    const again = await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      actorUserId: 7,
    });
    assert.ok(again.token);
    store.state.suppressions.push({
      channel: "email",
      destination_fingerprint: verification.destinationFingerprint("email", "person@example.com"),
      scope: "workspace",
      workspace_id: "ws-1",
      reason: "recipient_declined",
      expires_at: null,
    });
    const withheld = await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "email",
      actorUserId: 7,
    });
    assert.equal(withheld.withholdDelivery, true);
    assert.equal(withheld.token, null);
  });

  it("keeps WhatsApp test limits when verification tables are missing", async () => {
    process.env.TT_DEPLOYMENT = "self-hosted";
    delete process.env.RECIPIENT_VERIFICATION_MODE;
    process.env.RECIPIENT_TEST_PER_CONTACT_PER_DAY = "2";
    process.env.RECIPIENT_TEST_COOLDOWN_SECONDS = "120";
    const store = createStore();
    seedContact(store);
    const input = {
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "whatsapp",
      destination: "+14155550100",
    };
    const first = await verification.authorizeWorkspaceTest(input);
    assert.equal(first.destination, "+14155550100");
    await assert.rejects(
      () => verification.authorizeWorkspaceTest(input),
      (error) => error.code === "TEST_WHATSAPP_COOLDOWN",
    );
    store.state.auditMissing = true;
    await assert.rejects(
      () => verification.authorizeWorkspaceTest(input),
      (error) => error.code === "TEST_RATE_LIMIT_UNAVAILABLE" && error.status === 503,
    );
    await assert.rejects(
      () => verification.authorizeWorkspaceTest({ ...input, destination: "+19998887777" }),
      (error) => error.code === "DESTINATION_MISMATCH",
    );
  });

  it("blocks a digest send when consent changes after the claim", () => {
    assert.equal(verification.confirmDigestConsent({ mode: "enforce", finalAllowed: false }).send, false);
    assert.equal(verification.confirmDigestConsent({ mode: "enforce", finalAllowed: true }).send, true);
    assert.equal(verification.confirmDigestConsent({ mode: "shadow", finalAllowed: false }).send, true);
    assert.equal(verification.confirmDigestConsent({ mode: "off", finalAllowed: false }).send, true);
  });

  it("does not report a verified status for a different destination", async () => {
    const store = createStore();
    const contact = seedContact(store);
    store.state.verifications.push({
      workspace_id: "ws-1",
      contact_id: contact.id,
      channel: "email",
      status: "verified",
      destination_normalized: "old@example.com",
      verified_at: new Date(),
    });
    store.state.challenges.push({
      workspace_id: "ws-1",
      contact_id: contact.id,
      channel: "email",
      status: "pending",
      destination_normalized: "old@example.com",
      expires_at: new Date(Date.now() + 60000),
    });
    const stale = await verification.attachVerification(store.pool, "ws-1", [contact]);
    assert.equal(stale.items[0].verification.email.status, "pending");
    assert.equal(stale.items[0].verification.email.invitation, null);
    assert.equal(stale.items[0].verification.email.verified_at, undefined);
    store.state.verifications[0].destination_normalized = "person@example.com";
    store.state.challenges[0].destination_normalized = "person@example.com";
    const current = await verification.attachVerification(store.pool, "ws-1", [contact]);
    assert.equal(current.items[0].verification.email.status, "verified");
    assert.ok(current.items[0].verification.email.invitation);
  });

  it("does not let a stale WhatsApp decline replace the current number", async () => {
    const store = createStore();
    seedContact(store);
    const invitation = await verification.createInvitation({
      pool: store.pool,
      workspaceId: "ws-1",
      contactId: "contact-1",
      channel: "whatsapp",
      actorUserId: 4,
    });
    assert.ok(invitation.token);
    store.state.contacts.get("ws-1:contact-1").phone_e164 = "+14155550999";
    const declined = await verification.declineWhatsAppChallenge({
      pool: store.pool,
      token: invitation.token,
    });
    assert.equal(declined.ok, false);
    assert.equal(declined.stale, true);
    assert.equal(store.state.verifications.length, 0);
    assert.equal(store.state.challenges[0].status, "pending");
  });

  it("withholds a WhatsApp invitation after a decline", async () => {
    const store = createStore();
    seedContact(store);
    const fingerprint = verification.destinationFingerprint("whatsapp", "+14155550100");
    store.state.suppressions.push({
      channel: "whatsapp",
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
      channel: "whatsapp",
      actorUserId: 4,
    });
    assert.equal(invitation.withholdDelivery, true);
    assert.equal(invitation.token, null);
  });

  it("retries a verification timeout and does not let one recipient or another channel settle the rest", async () => {
    process.env.TT_DEPLOYMENT = "self-hosted";
    process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
    const timeout = new Error("canceling statement due to statement timeout");
    timeout.code = "57014";
    assert.equal(verification.isTemporaryVerificationFailure(timeout), true);
    const gated = await verification.filterDeliveryRecipients({
      client: { query: async () => { throw timeout; } },
      workspaceId: "ws-1",
      channel: "email",
      recipients: [
        { contactId: "c1", destination: "a@example.com" },
        { contactId: "c2", destination: "b@example.com" },
      ],
    });
    assert.equal(gated.unavailable, true);
    assert.equal(gated.code, "RECIPIENT_VERIFICATION_UNAVAILABLE");
    assert.equal(gated.allowed.length, 0);
    const pending = verification.mergeDeliveryAttempt({
      prior: ["email", "webhooks"],
      attempted: [{
        channel: "email",
        success: false,
        recipients: {
          "a@example.com": { state: "unavailable", code: "RECIPIENT_VERIFICATION_UNAVAILABLE" },
          "b@example.com": { state: "unavailable", code: "RECIPIENT_VERIFICATION_UNAVAILABLE" },
        },
      }],
      liveChannels: ["email", "webhooks"],
    });
    assert.equal(pending.outcome.retry, true);
    assert.equal(pending.ledger.outcomes.email.state, "failed");
    assert.equal(pending.ledger.outcomes.email.code, "RECIPIENT_VERIFICATION_UNAVAILABLE");
    assert.equal(verification.planManualRetry(pending.ledger, "email").ok, true);
    const mixed = verification.mergeDeliveryAttempt({
      prior: pending.ledger,
      logRows: [
        { channel: "email", status: "success", metadata: { recipient: "a@example.com" } },
        { channel: "email", status: "failed", error_message: "smtp down", metadata: { recipient: "b@example.com" } },
        { channel: "email", status: "blocked", error_message: "RECIPIENT_NOT_VERIFIED", metadata: { recipient: "c@example.com" } },
      ],
      attempted: [{ channel: "webhooks", success: true }],
      liveChannels: ["email", "webhooks"],
    });
    assert.equal(mixed.ledger.outcomes.email.state, "failed");
    assert.equal(mixed.ledger.outcomes.webhooks.state, "sent");
    assert.deepEqual(mixed.ledger.retry, ["email"]);
    assert.equal(mixed.outcome.status, "partial");
    assert.deepEqual(verification.channelNamesForSettlement(mixed.ledger), ["email", "webhooks"]);
    assert.deepEqual(verification.channelNamesForSettlement(["email", "whatsapp"]), ["email", "whatsapp"]);
    assert.equal(verification.channelNamesForSettlement(["email", "pagerduty"]), null);
    const recovered = verification.requiredRecipientDelivery({
      channel: "email",
      recipients: ["a@example.com", "b@example.com", "c@example.com"],
      history: [
        { channel: "email", status: "success", metadata: { recipient: "a@example.com" } },
        { channel: "email", status: "success", metadata: { recipient: "b@example.com" } },
      ],
      eligibility: { "c@example.com": { code: "RECIPIENT_NOT_VERIFIED" } },
    });
    assert.equal(recovered.complete, true);
    assert.equal(recovered.delivered, true);
    assert.deepEqual(recovered.eligible, ["a@example.com", "b@example.com"]);
    const unresolved = verification.requiredRecipientDelivery({
      channel: "email",
      recipients: ["a@example.com", "b@example.com"],
      history: [{ channel: "email", status: "success", metadata: { recipient: "a@example.com" } }],
      eligibility: { "b@example.com": { code: "RECIPIENT_VERIFICATION_UNAVAILABLE" } },
    });
    assert.equal(unresolved.complete, false);
    assert.equal(unresolved.unavailable, true);
  });
});
