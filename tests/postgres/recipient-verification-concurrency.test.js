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
  database: process.env.RV_TEST_DB_NAME || "recipient_verification_test",
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
      phone_e164 TEXT NULL,
      details JSONB NOT NULL DEFAULT '{}'::jsonb
    );
  `);
  await pool.query(MIGRATION);
  await pool.query(MIGRATION);
}

async function resetRows() {
  await pool.query("DELETE FROM twilio_inbound_messages");
  await pool.query("DELETE FROM recipient_verification_events");
  await pool.query("DELETE FROM notification_suppressions");
  await pool.query("DELETE FROM contact_verification_challenges");
  await pool.query("DELETE FROM contact_channel_verifications");
  await pool.query("DELETE FROM workspace_contacts");
  await pool.query("DELETE FROM workspaces");
  await pool.query("DELETE FROM users");
}

async function seed({ email = "person@example.com", phone = "+14155550100", workspaceName = "Workspace" } = {}) {
  const user = await pool.query(
    "INSERT INTO users (email) VALUES ($1) RETURNING id",
    [`user-${Date.now()}-${Math.random()}@example.com`],
  );
  const workspace = await pool.query(
    "INSERT INTO workspaces (name) VALUES ($1) RETURNING id",
    [workspaceName],
  );
  const contact = await pool.query(
    `INSERT INTO workspace_contacts (workspace_id, phone_e164, details)
     VALUES ($1, $2, $3::jsonb) RETURNING id`,
    [workspace.rows[0].id, phone, JSON.stringify({ email })],
  );
  return {
    userId: user.rows[0].id,
    workspaceId: workspace.rows[0].id,
    contactId: contact.rows[0].id,
  };
}

test.before(async () => {
  process.env.RECIPIENT_FINGERPRINT_SECRET = "postgres-recipient-verification-secret";
  process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
  process.env.TT_DEPLOYMENT = "self-hosted";
  await applySchema();
});

test.after(async () => {
  await pool.end();
});

test.beforeEach(async () => {
  await resetRows();
  delete process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_DAY;
  delete process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_WEEK;
  delete process.env.RECIPIENT_VERIFY_WORKSPACE_PER_DAY;
  delete process.env.RECIPIENT_VERIFY_USER_PER_DAY;
  delete process.env.RECIPIENT_VERIFY_PUBLIC_PER_WINDOW;
  delete process.env.RECIPIENT_VERIFY_PUBLIC_WINDOW_SECONDS;
});

test("migration 78 is idempotent and creates the verification indexes", async () => {
  const indexes = await pool.query(
    `SELECT indexname FROM pg_indexes
      WHERE indexname IN (
        'uq_contact_verification_one_pending',
        'uq_notification_suppressions_global',
        'uq_notification_suppressions_workspace',
        'idx_recipient_verification_events_bucket'
      )`,
  );
  assert.equal(indexes.rows.length, 4);
});

test("parallel invitations to different destinations share one workspace limit", async () => {
  process.env.RECIPIENT_VERIFY_WORKSPACE_PER_DAY = "1";
  process.env.RECIPIENT_VERIFY_USER_PER_DAY = "20";
  const first = await seed({ email: "one@example.com", phone: "+14155550101" });
  const secondContact = await pool.query(
    `INSERT INTO workspace_contacts (workspace_id, phone_e164, details)
     VALUES ($1, $2, $3::jsonb) RETURNING id`,
    [first.workspaceId, "+14155550102", JSON.stringify({ email: "two@example.com" })],
  );
  const attempts = await Promise.allSettled([
    verification.createInvitation({
      pool,
      workspaceId: first.workspaceId,
      contactId: first.contactId,
      channel: "email",
      actorUserId: first.userId,
    }),
    verification.createInvitation({
      pool,
      workspaceId: first.workspaceId,
      contactId: secondContact.rows[0].id,
      channel: "email",
      actorUserId: first.userId,
    }),
  ]);
  const fulfilled = attempts.filter((row) => row.status === "fulfilled");
  const rejected = attempts.filter((row) => row.status === "rejected");
  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].reason.status, 429);
  const challenges = await pool.query(
    "SELECT id FROM contact_verification_challenges WHERE workspace_id = $1",
    [first.workspaceId],
  );
  assert.equal(challenges.rows.length, 1);
  const workspaceEvents = await pool.query(
    "SELECT COUNT(*)::int AS n FROM recipient_verification_events WHERE bucket_key = $1",
    [`ws:${first.workspaceId}:24h`],
  );
  assert.equal(workspaceEvents.rows[0].n, 1);
});

test("parallel invitations to different destinations share one user limit", async () => {
  process.env.RECIPIENT_VERIFY_USER_PER_DAY = "1";
  process.env.RECIPIENT_VERIFY_WORKSPACE_PER_DAY = "50";
  const first = await seed({ email: "user-a@example.com", phone: "+14155550111" });
  const secondContact = await pool.query(
    `INSERT INTO workspace_contacts (workspace_id, phone_e164, details)
     VALUES ($1, $2, $3::jsonb) RETURNING id`,
    [first.workspaceId, "+14155550112", JSON.stringify({ email: "user-b@example.com" })],
  );
  for (let i = 0; i < 5; i += 1) {
    await pool.query("DELETE FROM contact_verification_challenges");
    await pool.query("DELETE FROM recipient_verification_events");
    const attempts = await Promise.allSettled([
      verification.createInvitation({
        pool,
        workspaceId: first.workspaceId,
        contactId: first.contactId,
        channel: "email",
        actorUserId: first.userId,
      }),
      verification.createInvitation({
        pool,
        workspaceId: first.workspaceId,
        contactId: secondContact.rows[0].id,
        channel: "email",
        actorUserId: first.userId,
      }),
    ]);
    assert.equal(attempts.filter((row) => row.status === "fulfilled").length, 1);
  }
});

test("abuse suppression commits when the invitation transaction rolls back", async () => {
  process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_WEEK = "3";
  const row = await seed({ email: "abused@example.com" });
  const fingerprint = verification.destinationFingerprint("email", "abused@example.com");
  const bucket = `dest:email:${fingerprint}:7d`;
  for (const workspaceId of [row.workspaceId, row.workspaceId, row.workspaceId]) {
    await pool.query(
      "INSERT INTO recipient_verification_events (bucket_key, workspace_id) VALUES ($1, $2)",
      [bucket, workspaceId],
    );
  }
  const otherA = await pool.query("INSERT INTO workspaces (name) VALUES ('A') RETURNING id");
  const otherB = await pool.query("INSERT INTO workspaces (name) VALUES ('B') RETURNING id");
  await pool.query("DELETE FROM recipient_verification_events WHERE bucket_key = $1", [bucket]);
  for (const workspaceId of [row.workspaceId, otherA.rows[0].id, otherB.rows[0].id]) {
    await pool.query(
      "INSERT INTO recipient_verification_events (bucket_key, workspace_id) VALUES ($1, $2)",
      [bucket, workspaceId],
    );
  }
  await assert.rejects(
    () => verification.createInvitation({
      pool,
      workspaceId: row.workspaceId,
      contactId: row.contactId,
      channel: "email",
      actorUserId: row.userId,
    }),
    (error) => error.status === 429 && error.code === "RECIPIENT_VERIFICATION_RATE_LIMITED",
  );
  const challenges = await pool.query(
    "SELECT id FROM contact_verification_challenges WHERE contact_id = $1",
    [row.contactId],
  );
  assert.equal(challenges.rows.length, 0);
  const suppression = await pool.query(
    `SELECT reason, expires_at FROM notification_suppressions
      WHERE channel = 'email' AND destination_fingerprint = $1 AND reason = 'verification_abuse'`,
    [fingerprint],
  );
  assert.equal(suppression.rows.length, 1);
  assert.ok(new Date(suppression.rows[0].expires_at).getTime() > Date.now());
  await assert.rejects(
    () => verification.createInvitation({
      pool,
      workspaceId: row.workspaceId,
      contactId: row.contactId,
      channel: "email",
      actorUserId: row.userId,
    }),
    (error) => error.code === "RECIPIENT_SUPPRESSED",
  );
  await pool.query("DELETE FROM recipient_verification_events WHERE bucket_key = $1", [bucket]);
  await pool.query(
    "UPDATE notification_suppressions SET expires_at = NOW() - INTERVAL '1 minute' WHERE reason = 'verification_abuse'",
  );
  const expired = await verification.createInvitation({
    pool,
    workspaceId: row.workspaceId,
    contactId: row.contactId,
    channel: "email",
    actorUserId: row.userId,
  });
  assert.equal(expired.withholdDelivery, false);
});

test("a decline blocks delivery after recreate and a new acceptance restores it", async () => {
  process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_DAY = "5";
  process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_WEEK = "5";
  const row = await seed({ email: "declined@example.com" });
  const invitation = await verification.createInvitation({
    pool,
    workspaceId: row.workspaceId,
    contactId: row.contactId,
    channel: "email",
    actorUserId: row.userId,
  });
  const declined = await verification.consumeEmailChallenge({
    pool,
    token: invitation.token,
    decision: "decline",
  });
  assert.equal(declined.ok, true);
  await pool.query("DELETE FROM workspace_contacts WHERE id = $1", [row.contactId]);
  const recreated = await pool.query(
    `INSERT INTO workspace_contacts (workspace_id, phone_e164, details)
     VALUES ($1, $2, $3::jsonb) RETURNING id`,
    [row.workspaceId, "+14155550100", JSON.stringify({ email: "declined@example.com" })],
  );
  const blocked = await verification.evaluateRecipient({
    client: pool,
    workspaceId: row.workspaceId,
    contactId: recreated.rows[0].id,
    channel: "email",
    destination: "declined@example.com",
  });
  assert.equal(blocked.code, "RECIPIENT_OPTED_OUT");
  const again = await verification.createInvitation({
    pool,
    workspaceId: row.workspaceId,
    contactId: recreated.rows[0].id,
    channel: "email",
    actorUserId: row.userId,
  });
  assert.equal(again.withholdDelivery, true);
  const oldPage = await verification.loadChallenge(pool, invitation.token);
  assert.equal(oldPage.state, "invalid");
  const accepted = await verification.consumeEmailChallenge({
    pool,
    token: again.token,
    decision: "accept",
  });
  assert.equal(accepted.ok, true);
  const allowed = await verification.evaluateRecipient({
    client: pool,
    workspaceId: row.workspaceId,
    contactId: recreated.rows[0].id,
    channel: "email",
    destination: "declined@example.com",
  });
  assert.equal(allowed.allowed, true);
  await pool.query(
    "UPDATE contact_verification_challenges SET expires_at = NOW() - INTERVAL '1 minute', status = 'pending' WHERE id = $1",
    [again.challengeId],
  );
  const replay = await verification.consumeEmailChallenge({
    pool,
    token: again.token,
    decision: "decline",
  });
  assert.equal(replay.ok, false);
  const stillAllowed = await verification.evaluateRecipient({
    client: pool,
    workspaceId: row.workspaceId,
    contactId: recreated.rows[0].id,
    channel: "email",
    destination: "declined@example.com",
  });
  assert.equal(stillAllowed.allowed, true);
});

test("only one concurrent confirmation consumes a challenge", async () => {
  const row = await seed();
  const invitation = await verification.createInvitation({
    pool,
    workspaceId: row.workspaceId,
    contactId: row.contactId,
    channel: "email",
    actorUserId: row.userId,
  });
  const results = await Promise.all([
    verification.consumeEmailChallenge({ pool, token: invitation.token, decision: "accept" }),
    verification.consumeEmailChallenge({ pool, token: invitation.token, decision: "accept" }),
  ]);
  assert.equal(results.filter((item) => item.ok).length, 1);
  const status = await pool.query(
    "SELECT status FROM contact_channel_verifications WHERE contact_id = $1",
    [row.contactId],
  );
  assert.equal(status.rows[0].status, "verified");
});

test("a destination change during confirmation does not verify the old address", async () => {
  const row = await seed({ email: "before@example.com" });
  const invitation = await verification.createInvitation({
    pool,
    workspaceId: row.workspaceId,
    contactId: row.contactId,
    channel: "email",
    actorUserId: row.userId,
  });
  const locker = await pool.connect();
  try {
    await locker.query("BEGIN");
    await locker.query("SELECT id FROM workspace_contacts WHERE id = $1 FOR UPDATE", [row.contactId]);
    const pending = verification.consumeEmailChallenge({
      pool,
      token: invitation.token,
      decision: "accept",
    });
    await new Promise((resolve) => setTimeout(resolve, 200));
    await locker.query(
      "UPDATE workspace_contacts SET details = $2::jsonb WHERE id = $1",
      [row.contactId, JSON.stringify({ email: "after@example.com" })],
    );
    await locker.query("COMMIT");
    const result = await pending;
    assert.equal(result.ok, false);
  } finally {
    await locker.query("ROLLBACK").catch(() => {});
    locker.release();
  }
  const decision = await verification.evaluateRecipient({
    client: pool,
    workspaceId: row.workspaceId,
    contactId: row.contactId,
    channel: "email",
    destination: "after@example.com",
  });
  assert.equal(decision.allowed, false);
  const oldDecision = await verification.evaluateRecipient({
    client: pool,
    workspaceId: row.workspaceId,
    contactId: row.contactId,
    channel: "email",
    destination: "before@example.com",
  });
  assert.equal(oldDecision.allowed, false);
});

test("public confirmation budget is shared across concurrent requests", async () => {
  process.env.RECIPIENT_VERIFY_PUBLIC_PER_WINDOW = "1";
  process.env.RECIPIENT_VERIFY_PUBLIC_WINDOW_SECONDS = "600";
  const attempts = await Promise.allSettled([
    verification.assertPublicVerificationBudget(pool, "client-a"),
    verification.assertPublicVerificationBudget(pool, "client-a"),
  ]);
  assert.equal(attempts.filter((row) => row.status === "fulfilled").length, 1);
  assert.equal(attempts.filter((row) => row.status === "rejected").length, 1);
  const events = await pool.query(
    "SELECT COUNT(*)::int AS n FROM recipient_verification_events WHERE bucket_key = $1",
    ["public:client-a"],
  );
  assert.equal(events.rows[0].n, 1);
});

test("an expired challenge cannot clear an opt-out", async () => {
  const row = await seed({ email: "expired@example.com" });
  const invitation = await verification.createInvitation({
    pool,
    workspaceId: row.workspaceId,
    contactId: row.contactId,
    channel: "email",
    actorUserId: row.userId,
  });
  await verification.consumeEmailChallenge({
    pool,
    token: invitation.token,
    decision: "decline",
  });
  await pool.query(
    "UPDATE contact_verification_challenges SET status = 'pending', expires_at = NOW() - INTERVAL '1 hour' WHERE id = $1",
    [invitation.challengeId],
  );
  const page = await verification.loadChallenge(pool, invitation.token);
  assert.equal(page.state, "declined");
  const consumed = await verification.consumeEmailChallenge({
    pool,
    token: invitation.token,
    decision: "accept",
  });
  assert.equal(consumed.ok, false);
  const decision = await verification.evaluateRecipient({
    client: pool,
    workspaceId: row.workspaceId,
    contactId: row.contactId,
    channel: "email",
    destination: "expired@example.com",
  });
  assert.equal(decision.code, "RECIPIENT_OPTED_OUT");
});
