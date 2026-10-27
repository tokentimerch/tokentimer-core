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

test("migration 79 is idempotent and creates the verification indexes", async () => {
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
  assert.equal(again.token, null);
  const oldPage = await verification.loadChallenge(pool, invitation.token);
  assert.equal(oldPage.state, "invalid");
  const resumed = await verification.requestEmailResubscribe({
    pool,
    email: "declined@example.com",
  });
  assert.equal(resumed.length, 1);
  const accepted = await verification.consumeEmailChallenge({
    pool,
    token: resumed[0].token,
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
  const other = await seed({ email: "other@example.com", phone: "+14155550123", workspaceName: "Other" });
  const otherDecision = await verification.evaluateRecipient({
    client: pool,
    workspaceId: other.workspaceId,
    contactId: other.contactId,
    channel: "email",
    destination: "declined@example.com",
  });
  assert.equal(otherDecision.allowed, false);
  await pool.query(
    "UPDATE contact_verification_challenges SET expires_at = NOW() - INTERVAL '1 minute', status = 'pending' WHERE id = $1",
    [resumed[0].challengeId],
  );
  const replay = await verification.consumeEmailChallenge({
    pool,
    token: resumed[0].token,
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

test("partial delivery rows with an empty retry set are not claimed again", async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS alert_queue (
      id SERIAL PRIMARY KEY,
      channels JSONB NOT NULL DEFAULT '[]'::jsonb,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      due_date DATE NOT NULL DEFAULT CURRENT_DATE,
      next_attempt_at TIMESTAMP NULL,
      delivery_claim_id UUID NULL,
      error_message TEXT NULL
    )
  `);
  await pool.query("DELETE FROM alert_queue");
  await pool.query(
    `INSERT INTO alert_queue (channels, status) VALUES
      ('[]'::jsonb, 'partial'),
      ('["webhooks"]'::jsonb, 'partial'),
      ($1::jsonb, 'partial'),
      ($2::jsonb, 'failed')`,
    [
      JSON.stringify({ version: 1, retry: [], required: ["email", "webhooks"], outcomes: {} }),
      JSON.stringify({ version: 1, retry: ["email"], required: ["email", "whatsapp"], outcomes: {} }),
    ],
  );
  const claimed = await pool.query(
    `SELECT id, status, channels FROM alert_queue aq
      WHERE aq.status IN ('pending', 'failed', 'partial')
        AND aq.due_date <= CURRENT_DATE
        ${verification.DELIVERY_CLAIM_EXCLUSION_SQL}
      ORDER BY id`,
  );
  assert.equal(claimed.rows.length, 2);
  const retryValues = claimed.rows.map((row) => (
    Array.isArray(row.channels) ? row.channels : row.channels.retry
  ));
  assert.deepEqual(retryValues, [["webhooks"], ["email"]]);
});

test("two workers cannot both commit a delivery result for one claim", async () => {
  await pool.query("DELETE FROM alert_queue");
  const inserted = await pool.query(
    "INSERT INTO alert_queue (channels, status, delivery_claim_id) VALUES ('[]'::jsonb, 'pending', $1) RETURNING id",
    ["11111111-1111-1111-1111-111111111111"],
  );
  const id = inserted.rows[0].id;
  const first = pool.connect();
  const second = pool.connect();
  const a = await first;
  const b = await second;
  try {
    const winner = await a.query(
      `UPDATE alert_queue SET status = 'partial', channels = $2, delivery_claim_id = NULL
        WHERE id = $1 AND delivery_claim_id = $3 RETURNING id`,
      [id, JSON.stringify({ version: 1, retry: ["webhooks"], required: ["email", "webhooks"], outcomes: { email: { state: "blocked", terminal: true } } }), "11111111-1111-1111-1111-111111111111"],
    );
    const loser = await b.query(
      `UPDATE alert_queue SET status = 'sent', delivery_claim_id = NULL
        WHERE id = $1 AND delivery_claim_id = $2 RETURNING id`,
      [id, "11111111-1111-1111-1111-111111111111"],
    );
    assert.equal(winner.rowCount, 1);
    assert.equal(loser.rowCount, 0);
    const stored = await pool.query("SELECT status, channels FROM alert_queue WHERE id = $1", [id]);
    assert.equal(stored.rows[0].status, "partial");
    assert.deepEqual(stored.rows[0].channels.retry, ["webhooks"]);
  } finally {
    a.release();
    b.release();
  }
});

test("reconciliation, listing, and webhook requeue keep ledger history", async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS alert_queue (
      id SERIAL PRIMARY KEY,
      channels JSONB NOT NULL DEFAULT '[]'::jsonb,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      due_date DATE NOT NULL DEFAULT CURRENT_DATE,
      next_attempt_at TIMESTAMP NULL,
      delivery_claim_id UUID NULL,
      error_message TEXT NULL
    )
  `);
  await pool.query("ALTER TABLE alert_queue ADD COLUMN IF NOT EXISTS user_id INTEGER");
  await pool.query("ALTER TABLE alert_queue ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP");
  await pool.query("DELETE FROM alert_queue");

  const ledger = {
    version: 1,
    retry: ["webhooks"],
    required: ["email", "webhooks"],
    outcomes: {
      email: { state: "blocked", terminal: true, code: "NO_VERIFIED_RECIPIENTS", reason: "eligibility" },
      webhooks: { state: "failed", terminal: false, code: "HTTP_500" },
    },
  };
  const inserted = await pool.query(
    `INSERT INTO alert_queue (channels, status, user_id, error_message)
     VALUES ($1::jsonb, 'failed', 7, 'webhooks: HTTP 500')
     RETURNING id, channels`,
    [JSON.stringify(ledger)],
  );
  const id = inserted.rows[0].id;
  const first = verification.reconcileDeliveryChannels(inserted.rows[0].channels, ["email", "webhooks"]);
  assert.equal(first.changed, false);
  assert.equal(first.channels.outcomes.email.state, "blocked");
  assert.equal(verification.reconcileDeliveryChannels(first.channels, ["email", "webhooks"]).changed, false);

  const claim = "33333333-3333-3333-3333-333333333333";
  await pool.query("UPDATE alert_queue SET delivery_claim_id = $2 WHERE id = $1", [id, claim]);
  const held = await pool.query(
    `UPDATE alert_queue
        SET channels = $1, updated_at = NOW()
      WHERE id = $2
        AND status = ANY($3::text[])
        AND delivery_claim_id IS NULL
        AND channels = $4`,
    [JSON.stringify(["email"]), id, ["pending", "failed", "partial"], JSON.stringify(ledger)],
  );
  assert.equal(held.rowCount, 0);
  const settled = {
    version: 1,
    retry: [],
    required: ["email", "webhooks"],
    outcomes: {
      email: { state: "blocked", terminal: true, code: "NO_VERIFIED_RECIPIENTS", reason: "eligibility" },
      webhooks: { state: "sent", terminal: true },
    },
  };
  const owner = await pool.connect();
  const reconciler = await pool.connect();
  try {
    const [delivered, raced] = await Promise.all([
      owner.query(
        `UPDATE alert_queue
            SET channels = $2, status = 'partial', delivery_claim_id = NULL
          WHERE id = $1 AND delivery_claim_id = $3
          RETURNING channels`,
        [id, JSON.stringify(settled), claim],
      ),
      reconciler.query(
        `UPDATE alert_queue
            SET channels = $1, updated_at = NOW()
          WHERE id = $2
            AND status = ANY($3::text[])
            AND delivery_claim_id IS NULL
            AND channels = $4`,
        [JSON.stringify(["email"]), id, ["pending", "failed", "partial"], JSON.stringify(ledger)],
      ),
    ]);
    assert.equal(delivered.rowCount, 1);
    assert.equal(raced.rowCount, 0);
  } finally {
    owner.release();
    reconciler.release();
  }
  const afterRace = await pool.query("SELECT channels, status FROM alert_queue WHERE id = $1", [id]);
  assert.equal(afterRace.rows[0].status, "partial");
  assert.equal(afterRace.rows[0].channels.outcomes.webhooks.state, "sent");
  const stale = await pool.query(
    `UPDATE alert_queue
        SET channels = $1, updated_at = NOW()
      WHERE id = $2
        AND delivery_claim_id IS NULL
        AND channels = $3`,
    [JSON.stringify(["email"]), id, JSON.stringify(ledger)],
  );
  assert.equal(stale.rowCount, 0);
  const settledReconcile = verification.reconcileDeliveryChannels(afterRace.rows[0].channels, ["email", "webhooks"]);
  assert.deepEqual(settledReconcile.channels.retry, []);
  assert.equal(settledReconcile.channels.outcomes.webhooks.state, "sent");

  const narrowed = verification.reconcileDeliveryChannels(ledger, ["webhooks"]);
  const wrote = await pool.query(
    `UPDATE alert_queue
        SET channels = $1, updated_at = NOW()
      WHERE id = $2 AND delivery_claim_id IS NULL
      RETURNING channels`,
    [JSON.stringify(narrowed.channels), id],
  );
  assert.equal(wrote.rows[0].channels.outcomes.email, undefined);
  assert.deepEqual(wrote.rows[0].channels.retry, ["webhooks"]);
  assert.equal(verification.reconcileDeliveryChannels(wrote.rows[0].channels, ["webhooks"]).changed, false);

  const permanent = {
    version: 1,
    retry: [],
    required: ["email", "webhooks"],
    outcomes: {
      email: { state: "sent", terminal: true },
      webhooks: { state: "blocked", terminal: true, reason: "provider", code: "HTTP_404", endpoints: { h: "permanent" } },
    },
  };
  await pool.query(
    `UPDATE alert_queue
        SET channels = $1::jsonb, status = 'failed', error_message = 'webhooks: HTTP 404', user_id = 7
      WHERE id = $2`,
    [JSON.stringify(permanent), id],
  );
  const storedPermanent = await pool.query("SELECT channels FROM alert_queue WHERE id = $1", [id]);
  const next = verification.requeueWebhookChannel(storedPermanent.rows[0].channels);
  assert.equal(Array.isArray(next), false);
  assert.equal(next.outcomes.email.state, "sent");
  const requeued = await pool.query(
    `UPDATE alert_queue
        SET channels = $1, status = 'pending', next_attempt_at = NOW(), updated_at = NOW()
      WHERE id = $2 AND user_id = $3 AND status = 'failed' AND delivery_claim_id IS NULL
      RETURNING channels, status`,
    [JSON.stringify(next), id, 7],
  );
  assert.equal(requeued.rows[0].status, "pending");
  assert.equal(requeued.rows[0].channels.version, 1);
  assert.equal(requeued.rows[0].channels.outcomes.webhooks.retryGeneration, 1);
  assert.equal(requeued.rows[0].channels.outcomes.email.state, "sent");
  const kind = await pool.query("SELECT jsonb_typeof(channels) AS kind FROM alert_queue WHERE id = $1", [id]);
  assert.equal(kind.rows[0].kind, "object");

  const otherUser = await pool.query(
    `UPDATE alert_queue SET status = 'pending' WHERE id = $1 AND user_id = $2 RETURNING id`,
    [id, 8],
  );
  assert.equal(otherUser.rowCount, 0);

  const refused = verification.planManualRetry(requeued.rows[0].channels, "email");
  assert.equal(refused.code, "ALREADY_DELIVERED");
  const allowed = verification.planManualRetry(requeued.rows[0].channels, "webhooks");
  const retried = await pool.query(
    `UPDATE alert_queue SET channels = $1, status = 'pending' WHERE id = $2 AND user_id = $3 RETURNING channels`,
    [JSON.stringify(allowed.channels), id, 7],
  );
  assert.equal(retried.rows[0].channels.outcomes.email.state, "sent");
  assert.deepEqual(retried.rows[0].channels.retry, ["webhooks"]);

  const legacyInserted = await pool.query(
    `INSERT INTO alert_queue (channels, status, user_id)
     VALUES ('["email"]'::jsonb, 'failed', 7)
     RETURNING id, channels`,
  );
  const legacyWrite = await pool.query(
    `UPDATE alert_queue SET channels = $1 WHERE id = $2 RETURNING channels`,
    [JSON.stringify(verification.requeueWebhookChannel(legacyInserted.rows[0].channels)), legacyInserted.rows[0].id],
  );
  assert.deepEqual(legacyWrite.rows[0].channels, ["email", "webhooks"]);
  const legacyKind = await pool.query(
    "SELECT jsonb_typeof(channels) AS kind FROM alert_queue WHERE id = $1",
    [legacyInserted.rows[0].id],
  );
  assert.equal(legacyKind.rows[0].kind, "array");

  await pool.query("DELETE FROM alert_queue WHERE user_id = 11");
  for (const status of ["pending", "failed", "partial", "blocked", "sent"]) {
    const channels = status === "pending"
      ? { version: 1, retry: ["email"], required: ["email"], outcomes: {} }
      : {
        version: 1,
        retry: status === "failed" ? ["email"] : [],
        required: ["email"],
        outcomes: { email: { state: status, terminal: status !== "failed" } },
      };
    await pool.query(
      "INSERT INTO alert_queue (channels, status, user_id) VALUES ($1::jsonb, $2, 11)",
      [JSON.stringify(channels), status],
    );
  }
  const listed = await pool.query(
    "SELECT status, channels FROM alert_queue WHERE user_id = 11 ORDER BY id",
  );
  assert.deepEqual(listed.rows.map((row) => row.status), ["pending", "failed", "partial", "blocked", "sent"]);
  for (const row of listed.rows) {
    const expanded = verification.publicDeliveryChannels(row.channels);
    assert.deepEqual(expanded.map((item) => item.channel), ["email"]);
    assert.equal(expanded[0].channel_state, row.status === "pending" ? "pending" : row.status);
  }
});

test("an interrupted verification email recovers after the dispatch lease without a duplicate send", async () => {
  process.env.RECIPIENT_VERIFICATION_DISPATCH_LEASE_SECONDS = "1";
  process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_DAY = "5";
  process.env.RECIPIENT_VERIFY_EMAIL_DEST_PER_WEEK = "8";
  process.env.TT_DEPLOYMENT = "self-hosted";
  const seeded = await seed();
  const invite = {
    pool,
    workspaceId: seeded.workspaceId,
    contactId: seeded.contactId,
    channel: "email",
    actorUserId: seeded.userId,
  };
  const first = await verification.createInvitation(invite);
  await assert.rejects(
    () => verification.createInvitation(invite),
    (error) => error.code === "VERIFICATION_DISPATCH_UNCONFIRMED",
  );
  await pool.query(
    `UPDATE recipient_verification_events
        SET created_at = NOW() - INTERVAL '5 minutes'
      WHERE bucket_key LIKE $1`,
    [`dispatch:${seeded.workspaceId}:${seeded.contactId}:email:${first.challengeId}:%`],
  );
  const recovered = await verification.createInvitation(invite);
  assert.notEqual(recovered.token, first.token);
  const pending = await pool.query(
    `SELECT id FROM contact_verification_challenges
      WHERE contact_id = $1 AND status = 'pending'`,
    [seeded.contactId],
  );
  assert.equal(pending.rows.length, 1);
  assert.equal(String(pending.rows[0].id), String(recovered.challengeId));

  await pool.query(
    `UPDATE recipient_verification_events
        SET created_at = NOW() - INTERVAL '5 minutes'
      WHERE bucket_key LIKE $1`,
    [`dispatch:${seeded.workspaceId}:${seeded.contactId}:email:${recovered.challengeId}:%`],
  );
  const raced = await Promise.allSettled([
    verification.createInvitation(invite),
    verification.createInvitation(invite),
  ]);
  assert.equal(raced.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(raced.filter((result) => result.status === "rejected").length, 1);
  const stillPending = await pool.query(
    `SELECT COUNT(*)::int AS n FROM contact_verification_challenges
      WHERE contact_id = $1 AND status = 'pending'`,
    [seeded.contactId],
  );
  assert.equal(stillPending.rows[0].n, 1);

  const current = raced.find((result) => result.status === "fulfilled").value;
  await verification.noteInvitationDispatch({
    pool,
    workspaceId: seeded.workspaceId,
    contactId: seeded.contactId,
    channel: "email",
    challengeId: current.challengeId,
    outcome: "ambiguous",
  });
  await assert.rejects(
    () => verification.createInvitation(invite),
    (error) => error.code === "VERIFICATION_DISPATCH_UNCONFIRMED",
  );
  await pool.query(
    "UPDATE contact_verification_challenges SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1",
    [current.challengeId],
  );
  const replaced = await verification.createInvitation(invite);
  assert.ok(replaced.token);
  const accepted = await verification.consumeEmailChallenge({
    pool,
    token: replaced.token,
    decision: "accept",
  });
  assert.equal(accepted.ok, true);
  const afterVerified = await verification.createInvitation(invite);
  assert.ok(afterVerified.token);
  const fingerprint = verification.destinationFingerprint("email", "person@example.com");
  await pool.query(
    `INSERT INTO notification_suppressions
       (channel, destination_fingerprint, scope, workspace_id, reason)
     VALUES ('email', $1, 'workspace', $2, 'recipient_declined')`,
    [fingerprint, seeded.workspaceId],
  );
  const withheld = await verification.createInvitation(invite);
  assert.equal(withheld.withholdDelivery, true);
  assert.equal(withheld.token, null);
});
