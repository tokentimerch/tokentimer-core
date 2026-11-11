"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { Pool } = require("pg");
const verification = require("../../packages/recipient-verification");

const ROOT = path.join(__dirname, "..", "..");
const MIGRATION = fs.readFileSync(
  path.join(ROOT, "packages/recipient-verification/migration.sql"),
  "utf8",
);

const pool = new Pool({
  host: process.env.RV_TEST_DB_HOST || "127.0.0.1",
  port: Number(process.env.RV_TEST_DB_PORT || 54329),
  database: process.env.RV_TEST_DB_NAME || "contact_verification_atomicity",
  user: process.env.RV_TEST_DB_USER || "tokentimer",
  password: process.env.RV_TEST_DB_PASSWORD || "password",
  max: 8,
});

async function applySchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE
    );
    CREATE TABLE IF NOT EXISTS workspaces (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS workspace_contacts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
      first_name TEXT NULL,
      last_name TEXT NULL,
      phone_e164 TEXT NULL,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS tt_test_flags (
      name TEXT PRIMARY KEY,
      enabled BOOLEAN NOT NULL DEFAULT FALSE
    );
  `);
  await pool.query(MIGRATION);
  await pool.query(`
    CREATE OR REPLACE FUNCTION tt_reject_verification() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      IF EXISTS (SELECT 1 FROM tt_test_flags WHERE name = 'reject_verification' AND enabled) THEN
        RAISE EXCEPTION 'verification invalidation failed';
      END IF;
      IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
      RETURN NEW;
    END;
    $$;
    DROP TRIGGER IF EXISTS trg_tt_reject_verification ON contact_channel_verifications;
    CREATE TRIGGER trg_tt_reject_verification
      BEFORE UPDATE OR DELETE ON contact_channel_verifications
      FOR EACH ROW EXECUTE FUNCTION tt_reject_verification();
  `);
}

async function seed({ email = "person@example.com", phone = "+14155550100", first = "Pat", last = "Lee" } = {}) {
  const user = await pool.query(
    "INSERT INTO users (email) VALUES ($1) RETURNING id",
    [`user-${Date.now()}-${Math.random()}@example.com`],
  );
  const workspace = await pool.query("INSERT INTO workspaces (name) VALUES ('Workspace') RETURNING id");
  const contact = await pool.query(
    `INSERT INTO workspace_contacts (workspace_id, first_name, last_name, phone_e164, details)
     VALUES ($1, $2, $3, $4, $5::jsonb) RETURNING id, phone_e164, details`,
    [workspace.rows[0].id, first, last, phone, JSON.stringify({ email })],
  );
  return {
    userId: user.rows[0].id,
    workspaceId: workspace.rows[0].id,
    contactId: contact.rows[0].id,
  };
}

async function markVerified(ids, channel, destination) {
  const fingerprint = verification.destinationFingerprint(channel, destination);
  await pool.query(
    `INSERT INTO contact_channel_verifications
       (workspace_id, contact_id, channel, destination_normalized, destination_fingerprint, status, verified_at, consent_at)
     VALUES ($1, $2, $3, $4, $5, 'verified', NOW(), NOW())`,
    [ids.workspaceId, ids.contactId, channel, destination, fingerprint],
  );
}

async function verificationRow(ids, channel) {
  const result = await pool.query(
    `SELECT status, destination_normalized FROM contact_channel_verifications
      WHERE workspace_id = $1 AND contact_id = $2 AND channel = $3`,
    [ids.workspaceId, ids.contactId, channel],
  );
  return result.rows[0] || null;
}

async function contactRow(ids) {
  const result = await pool.query(
    "SELECT first_name, last_name, phone_e164, details FROM workspace_contacts WHERE id = $1",
    [ids.contactId],
  );
  return result.rows[0];
}

async function hideVerificationTables() {
  await pool.query(`
    ALTER TABLE contact_channel_verifications RENAME TO hidden_contact_channel_verifications;
    ALTER TABLE contact_verification_challenges RENAME TO hidden_contact_verification_challenges;
    ALTER TABLE notification_suppressions RENAME TO hidden_notification_suppressions;
    ALTER TABLE recipient_verification_events RENAME TO hidden_recipient_verification_events;
    ALTER TABLE twilio_inbound_messages RENAME TO hidden_twilio_inbound_messages;
  `);
}

async function restoreVerificationTables() {
  await pool.query(`
    ALTER TABLE hidden_contact_channel_verifications RENAME TO contact_channel_verifications;
    ALTER TABLE hidden_contact_verification_challenges RENAME TO contact_verification_challenges;
    ALTER TABLE hidden_notification_suppressions RENAME TO notification_suppressions;
    ALTER TABLE hidden_recipient_verification_events RENAME TO recipient_verification_events;
    ALTER TABLE hidden_twilio_inbound_messages RENAME TO twilio_inbound_messages;
  `);
}

test.before(async () => {
  process.env.RECIPIENT_FINGERPRINT_SECRET = "postgres-recipient-verification-secret";
  process.env.TT_DEPLOYMENT = "self-hosted";
  process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
  await applySchema();
});

test.after(async () => {
  await pool.end();
});

test("contact changes and verification stay in one transaction", async () => {
  await pool.query("DELETE FROM twilio_inbound_messages");
  await pool.query("DELETE FROM recipient_verification_events");
  await pool.query("DELETE FROM notification_suppressions");
  await pool.query("DELETE FROM contact_verification_challenges");
  await pool.query("DELETE FROM contact_channel_verifications");
  await pool.query("DELETE FROM workspace_contacts");
  await pool.query("DELETE FROM workspaces");
  await pool.query("DELETE FROM users");
  await pool.query("UPDATE tt_test_flags SET enabled = FALSE WHERE name = 'reject_verification'");
  process.env.TT_DEPLOYMENT = "self-hosted";
  process.env.RECIPIENT_VERIFICATION_MODE = "enforce";

  const emailChange = await seed();
  await markVerified(emailChange, "email", "person@example.com");
  const changedEmail = await verification.updateContactWithVerification({
    pool,
    workspaceId: emailChange.workspaceId,
    contactId: emailChange.contactId,
    hasPhoneField: false,
    hasDetails: true,
    details: { email: "next@example.com" },
  });
  assert.equal(changedEmail.details.email, "next@example.com");
  assert.equal((await verificationRow(emailChange, "email")).status, "pending");
  assert.equal((await verificationRow(emailChange, "email")).destination_normalized, "next@example.com");
  const attachedEmail = await verification.attachVerification(pool, emailChange.workspaceId, [changedEmail]);
  assert.equal(attachedEmail.items[0].verification.email.status, "pending");

  const phoneChange = await seed({ email: "phone@example.com", phone: "+14155550110" });
  await markVerified(phoneChange, "whatsapp", "+14155550110");
  const changedPhone = await verification.updateContactWithVerification({
    pool,
    workspaceId: phoneChange.workspaceId,
    contactId: phoneChange.contactId,
    hasPhoneField: true,
    phoneE164: "+14155550111",
    hasDetails: false,
  });
  assert.equal(changedPhone.phone_e164, "+14155550111");
  assert.equal((await verificationRow(phoneChange, "whatsapp")).status, "pending");
  assert.equal((await verificationRow(phoneChange, "whatsapp")).destination_normalized, "+14155550111");

  const both = await seed({ email: "both@example.com", phone: "+14155550120" });
  await markVerified(both, "email", "both@example.com");
  await markVerified(both, "whatsapp", "+14155550120");
  await verification.updateContactWithVerification({
    pool,
    workspaceId: both.workspaceId,
    contactId: both.contactId,
    hasPhoneField: true,
    phoneE164: "+14155550121",
    hasDetails: true,
    details: { email: "both-next@example.com" },
  });
  assert.equal((await verificationRow(both, "email")).status, "pending");
  assert.equal((await verificationRow(both, "whatsapp")).status, "pending");

  const renamed = await seed({ email: "name@example.com", phone: "+14155550130" });
  await markVerified(renamed, "email", "name@example.com");
  await verification.updateContactWithVerification({
    pool,
    workspaceId: renamed.workspaceId,
    contactId: renamed.contactId,
    firstName: "Nora",
    hasPhoneField: false,
    hasDetails: false,
  });
  assert.equal((await contactRow(renamed)).first_name, "Nora");
  assert.equal((await verificationRow(renamed, "email")).status, "verified");

  const same = await seed({ email: "same@example.com", phone: "+14155550140" });
  await markVerified(same, "email", "same@example.com");
  await verification.updateContactWithVerification({
    pool,
    workspaceId: same.workspaceId,
    contactId: same.contactId,
    hasPhoneField: false,
    hasDetails: true,
    details: { email: "Same@Example.com" },
  });
  assert.equal((await verificationRow(same, "email")).status, "verified");
  assert.equal((await verificationRow(same, "email")).destination_normalized, "same@example.com");

  const failing = await seed({ email: "fail@example.com", phone: "+14155550150" });
  await markVerified(failing, "email", "fail@example.com");
  await pool.query(
    `INSERT INTO tt_test_flags (name, enabled) VALUES ('reject_verification', TRUE)
     ON CONFLICT (name) DO UPDATE SET enabled = TRUE`,
  );
  await assert.rejects(
    () => verification.updateContactWithVerification({
      pool,
      workspaceId: failing.workspaceId,
      contactId: failing.contactId,
      hasPhoneField: false,
      hasDetails: true,
      details: { email: "fail-next@example.com" },
    }),
    (error) => /verification invalidation failed/.test(error.message),
  );
  await pool.query("UPDATE tt_test_flags SET enabled = FALSE WHERE name = 'reject_verification'");
  assert.equal((await contactRow(failing)).details.email, "fail@example.com");
  assert.equal((await verificationRow(failing, "email")).status, "verified");

  const pending = await seed({ email: "pending@example.com", phone: "+14155550160" });
  const invitation = await verification.createInvitation({
    pool,
    workspaceId: pending.workspaceId,
    contactId: pending.contactId,
    channel: "email",
    actorUserId: pending.userId,
  });
  await verification.updateContactWithVerification({
    pool,
    workspaceId: pending.workspaceId,
    contactId: pending.contactId,
    hasPhoneField: false,
    hasDetails: true,
    details: { email: "pending-next@example.com" },
  });
  const challenge = await pool.query(
    "SELECT status FROM contact_verification_challenges WHERE token_hash = $1",
    [verification.hashToken(invitation.token)],
  );
  assert.equal(challenge.rows[0].status, "superseded");
  const consumed = await verification.consumeEmailChallenge({
    pool,
    token: invitation.token,
    decision: "accept",
  });
  assert.equal(consumed.ok, false);

  const racedEmail = await seed({ email: "race@example.com", phone: "+14155550170" });
  const emailInvite = await verification.createInvitation({
    pool,
    workspaceId: racedEmail.workspaceId,
    contactId: racedEmail.contactId,
    channel: "email",
    actorUserId: racedEmail.userId,
  });
  await Promise.all([
    verification.updateContactWithVerification({
      pool,
      workspaceId: racedEmail.workspaceId,
      contactId: racedEmail.contactId,
      hasPhoneField: false,
      hasDetails: true,
      details: { email: "race-next@example.com" },
    }),
    verification.consumeEmailChallenge({ pool, token: emailInvite.token, decision: "accept" }),
  ]);
  const racedEmailRow = await contactRow(racedEmail);
  assert.equal(racedEmailRow.details.email, "race-next@example.com");
  const racedEmailStatus = await verificationRow(racedEmail, "email");
  assert.notEqual(racedEmailStatus && racedEmailStatus.status, "verified");

  const racedPhone = await seed({ email: "race-phone@example.com", phone: "+14155550180" });
  const phoneInvite = await verification.createInvitation({
    pool,
    workspaceId: racedPhone.workspaceId,
    contactId: racedPhone.contactId,
    channel: "whatsapp",
    actorUserId: racedPhone.userId,
  });
  await Promise.all([
    verification.updateContactWithVerification({
      pool,
      workspaceId: racedPhone.workspaceId,
      contactId: racedPhone.contactId,
      hasPhoneField: true,
      phoneE164: "+14155550181",
      hasDetails: false,
    }),
    verification.confirmWhatsAppInbound({
      pool,
      from: "whatsapp:+14155550180",
      body: `CONFIRM ${phoneInvite.code}`,
      messageSid: `SM-race-${racedPhone.contactId}`,
    }),
  ]);
  const racedPhoneRow = await contactRow(racedPhone);
  assert.equal(racedPhoneRow.phone_e164, "+14155550181");
  const racedPhoneStatus = await verificationRow(racedPhone, "whatsapp");
  assert.notEqual(racedPhoneStatus && racedPhoneStatus.status, "verified");
  assert.notEqual(racedPhoneStatus && racedPhoneStatus.destination_normalized, "+14155550180");

  process.env.TT_DEPLOYMENT = "self-hosted";
  process.env.RECIPIENT_VERIFICATION_MODE = "off";
  const offPresent = await seed({ email: "off-present@example.com", phone: "+14155550192" });
  await markVerified(offPresent, "email", "off-present@example.com");
  await verification.updateContactWithVerification({
    pool,
    workspaceId: offPresent.workspaceId,
    contactId: offPresent.contactId,
    hasPhoneField: false,
    hasDetails: true,
    details: { email: "off-present-next@example.com" },
  });
  const persistedOffPresent = await contactRow(offPresent);
  assert.equal(persistedOffPresent.details.email, "off-present-next@example.com");
  assert.equal((await verificationRow(offPresent, "email")).status, "pending");
  assert.equal((await verificationRow(offPresent, "email")).destination_normalized, "off-present-next@example.com");

  process.env.RECIPIENT_VERIFICATION_MODE = "shadow";
  const shadowPresent = await seed({ email: "shadow-present@example.com", phone: "+14155550193" });
  await markVerified(shadowPresent, "email", "shadow-present@example.com");
  await verification.updateContactWithVerification({
    pool,
    workspaceId: shadowPresent.workspaceId,
    contactId: shadowPresent.contactId,
    hasPhoneField: false,
    hasDetails: true,
    details: { email: "shadow-present-next@example.com" },
  });
  assert.equal((await contactRow(shadowPresent)).details.email, "shadow-present-next@example.com");
  assert.equal((await verificationRow(shadowPresent, "email")).status, "pending");

  const offContact = await seed({ email: "off@example.com", phone: "+14155550190" });
  await hideVerificationTables();
  try {
    process.env.TT_DEPLOYMENT = "self-hosted";
    process.env.RECIPIENT_VERIFICATION_MODE = "off";
    const offUpdated = await verification.updateContactWithVerification({
      pool,
      workspaceId: offContact.workspaceId,
      contactId: offContact.contactId,
      hasPhoneField: false,
      hasDetails: true,
      details: { email: "off-next@example.com" },
    });
    assert.equal(offUpdated.details.email, "off-next@example.com");
    const persistedOffEmail = await pool.query(
      "SELECT details, phone_e164 FROM workspace_contacts WHERE id = $1",
      [offContact.contactId],
    );
    assert.equal(persistedOffEmail.rows[0].details.email, "off-next@example.com");
    const offPhone = await verification.updateContactWithVerification({
      pool,
      workspaceId: offContact.workspaceId,
      contactId: offContact.contactId,
      hasPhoneField: true,
      phoneE164: "+14155550194",
      hasDetails: false,
    });
    assert.equal(offPhone.phone_e164, "+14155550194");
    const persistedOffPhone = await pool.query(
      "SELECT details, phone_e164 FROM workspace_contacts WHERE id = $1",
      [offContact.contactId],
    );
    assert.equal(persistedOffPhone.rows[0].phone_e164, "+14155550194");
    assert.equal(persistedOffPhone.rows[0].details.email, "off-next@example.com");
    const sessionOk = await pool.query("SELECT 1 AS ok");
    assert.equal(sessionOk.rows[0].ok, 1);

    process.env.TT_DEPLOYMENT = "cloud";
    delete process.env.RECIPIENT_VERIFICATION_MODE;
    const enforceContact = await pool.query(
      `INSERT INTO workspace_contacts (workspace_id, first_name, phone_e164, details)
       VALUES ($1, 'Cloud', '+14155550191', $2::jsonb) RETURNING id`,
      [offContact.workspaceId, JSON.stringify({ email: "cloud@example.com" })],
    );
    await assert.rejects(
      () => verification.updateContactWithVerification({
        pool,
        workspaceId: offContact.workspaceId,
        contactId: enforceContact.rows[0].id,
        hasPhoneField: false,
        hasDetails: true,
        details: { email: "cloud-next@example.com" },
      }),
      (error) => error.status === 503 && error.code === "RECIPIENT_VERIFICATION_UNAVAILABLE",
    );
    const unchanged = await pool.query(
      "SELECT details FROM workspace_contacts WHERE id = $1",
      [enforceContact.rows[0].id],
    );
    assert.equal(unchanged.rows[0].details.email, "cloud@example.com");

    process.env.TT_DEPLOYMENT = "self-hosted";
    process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
    const selfHostedEnforce = await pool.query(
      `INSERT INTO workspace_contacts (workspace_id, first_name, phone_e164, details)
       VALUES ($1, 'Hosted', '+14155550195', $2::jsonb) RETURNING id`,
      [offContact.workspaceId, JSON.stringify({ email: "hosted@example.com" })],
    );
    await assert.rejects(
      () => verification.updateContactWithVerification({
        pool,
        workspaceId: offContact.workspaceId,
        contactId: selfHostedEnforce.rows[0].id,
        hasPhoneField: false,
        hasDetails: true,
        details: { email: "hosted-next@example.com" },
      }),
      (error) => error.status === 503 && error.code === "RECIPIENT_VERIFICATION_UNAVAILABLE",
    );
    const hostedUnchanged = await pool.query(
      "SELECT details FROM workspace_contacts WHERE id = $1",
      [selfHostedEnforce.rows[0].id],
    );
    assert.equal(hostedUnchanged.rows[0].details.email, "hosted@example.com");
    const afterFailure = await pool.query("SELECT 1 AS ok");
    assert.equal(afterFailure.rows[0].ok, 1);
  } finally {
    await restoreVerificationTables();
    process.env.TT_DEPLOYMENT = "self-hosted";
    process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
  }

  await whatsAppDeclineCases();
});

async function whatsAppDeclineCases() {
  await pool.query("DELETE FROM twilio_inbound_messages");
  await pool.query("DELETE FROM recipient_verification_events");
  await pool.query("DELETE FROM notification_suppressions");
  await pool.query("DELETE FROM contact_verification_challenges");
  await pool.query("DELETE FROM contact_channel_verifications");
  await pool.query("DELETE FROM workspace_contacts");
  await pool.query("DELETE FROM workspaces");
  await pool.query("DELETE FROM users");
  process.env.TT_DEPLOYMENT = "self-hosted";
  process.env.RECIPIENT_VERIFICATION_MODE = "enforce";

  const valid = await seed({ email: "decline@example.com", phone: "+14155550200" });
  const invitation = await verification.createInvitation({
    pool,
    workspaceId: valid.workspaceId,
    contactId: valid.contactId,
    channel: "whatsapp",
    actorUserId: valid.userId,
  });
  const declined = await verification.declineWhatsAppChallenge({ pool, token: invitation.token });
  assert.equal(declined.ok, true);
  assert.equal((await verificationRow(valid, "whatsapp")).status, "opted_out");
  const repeated = await verification.declineWhatsAppChallenge({ pool, token: invitation.token });
  assert.equal(repeated.ok, false);
  assert.equal((await verificationRow(valid, "whatsapp")).status, "opted_out");
  const suppressions = await pool.query(
    "SELECT COUNT(*)::int AS n FROM notification_suppressions WHERE workspace_id = $1 AND reason = 'recipient_declined'",
    [valid.workspaceId],
  );
  assert.equal(suppressions.rows[0].n, 1);

  const expired = await seed({ email: "expired@example.com", phone: "+14155550210" });
  const expiredInvite = await verification.createInvitation({
    pool,
    workspaceId: expired.workspaceId,
    contactId: expired.contactId,
    channel: "whatsapp",
    actorUserId: expired.userId,
  });
  await pool.query(
    "UPDATE contact_verification_challenges SET expires_at = NOW() - INTERVAL '1 minute' WHERE token_hash = $1",
    [verification.hashToken(expiredInvite.token)],
  );
  const expiredDecline = await verification.declineWhatsAppChallenge({ pool, token: expiredInvite.token });
  assert.equal(expiredDecline.ok, false);
  assert.equal(await verificationRow(expired, "whatsapp"), null);

  const stale = await seed({ email: "stale@example.com", phone: "+14155550220" });
  const staleInvite = await verification.createInvitation({
    pool,
    workspaceId: stale.workspaceId,
    contactId: stale.contactId,
    channel: "whatsapp",
    actorUserId: stale.userId,
  });
  await pool.query(
    "UPDATE workspace_contacts SET phone_e164 = $2 WHERE id = $1",
    [stale.contactId, "+14155550221"],
  );
  const staleDecline = await verification.declineWhatsAppChallenge({ pool, token: staleInvite.token });
  assert.equal(staleDecline.ok, false);
  assert.equal(staleDecline.stale, true);
  const staleStatus = await verificationRow(stale, "whatsapp");
  assert.notEqual(staleStatus && staleStatus.status, "opted_out");
  const replacement = await verification.createInvitation({
    pool,
    workspaceId: stale.workspaceId,
    contactId: stale.contactId,
    channel: "whatsapp",
    actorUserId: stale.userId,
  });
  assert.ok(replacement.token);
  const confirmed = await verification.confirmWhatsAppInbound({
    pool,
    from: "whatsapp:+14155550221",
    body: `CONFIRM ${replacement.code}`,
    messageSid: `SM-replacement-${stale.contactId}`,
  });
  assert.equal(confirmed.ok, true);
  assert.equal((await verificationRow(stale, "whatsapp")).status, "verified");
  assert.equal((await verificationRow(stale, "whatsapp")).destination_normalized, "+14155550221");

  const raced = await seed({ email: "race-decline@example.com", phone: "+14155550230" });
  const racedInvite = await verification.createInvitation({
    pool,
    workspaceId: raced.workspaceId,
    contactId: raced.contactId,
    channel: "whatsapp",
    actorUserId: raced.userId,
  });
  await Promise.all([
    verification.updateContactWithVerification({
      pool,
      workspaceId: raced.workspaceId,
      contactId: raced.contactId,
      hasPhoneField: true,
      phoneE164: "+14155550231",
      hasDetails: false,
    }),
    verification.declineWhatsAppChallenge({ pool, token: racedInvite.token }),
  ]);
  const racedStatus = await verificationRow(raced, "whatsapp");
  assert.notEqual(racedStatus && racedStatus.destination_normalized === "+14155550231" && racedStatus.status, "opted_out");

  const contested = await seed({ email: "contest@example.com", phone: "+14155550240" });
  const contestedInvite = await verification.createInvitation({
    pool,
    workspaceId: contested.workspaceId,
    contactId: contested.contactId,
    channel: "whatsapp",
    actorUserId: contested.userId,
  });
  const [confirmResult, declineResult] = await Promise.all([
    verification.confirmWhatsAppInbound({
      pool,
      from: "whatsapp:+14155550240",
      body: `CONFIRM ${contestedInvite.code}`,
      messageSid: `SM-contest-${contested.contactId}`,
    }),
    verification.declineWhatsAppChallenge({ pool, token: contestedInvite.token }),
  ]);
  const winners = [confirmResult.ok, declineResult.ok].filter(Boolean);
  assert.equal(winners.length, 1);
  const contestedStatus = await verificationRow(contested, "whatsapp");
  assert.ok(contestedStatus.status === "verified" || contestedStatus.status === "opted_out");
  const pendingLeft = await pool.query(
    "SELECT COUNT(*)::int AS n FROM contact_verification_challenges WHERE contact_id = $1 AND status = 'pending'",
    [contested.contactId],
  );
  assert.equal(pendingLeft.rows[0].n, 0);

  await pool.query("DELETE FROM workspace_contacts WHERE id = $1", [valid.contactId]);
  const recreated = await pool.query(
    `INSERT INTO workspace_contacts (workspace_id, phone_e164, details)
     VALUES ($1, '+14155550200', $2::jsonb) RETURNING id`,
    [valid.workspaceId, JSON.stringify({ email: "decline@example.com" })],
  );
  const withheld = await verification.createInvitation({
    pool,
    workspaceId: valid.workspaceId,
    contactId: recreated.rows[0].id,
    channel: "whatsapp",
    actorUserId: valid.userId,
  });
  assert.equal(withheld.withholdDelivery, true);
  assert.equal(withheld.token, null);
}
