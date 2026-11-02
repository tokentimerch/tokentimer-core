"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { Pool } = require("pg");
const verification = require("../../packages/recipient-verification");

const pool = new Pool({
  host: process.env.RV_TEST_DB_HOST || "127.0.0.1",
  port: Number(process.env.RV_TEST_DB_PORT || 54329),
  database: process.env.RV_TEST_DB_NAME || "recipient_delivery_retry",
  user: process.env.RV_TEST_DB_USER || "tokentimer",
  password: process.env.RV_TEST_DB_PASSWORD || "password",
  max: 4,
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
    CREATE TABLE IF NOT EXISTS delivery_retry_probe (
      id INTEGER PRIMARY KEY,
      channels JSONB NOT NULL
    );
  `);
  await pool.query(fs.readFileSync(
    path.join(__dirname, "../../packages/recipient-verification/migration.sql"),
    "utf8",
  ));
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

test("a statement timeout stays retryable and a later consent read can send", async () => {
  const user = await pool.query(
    "INSERT INTO users (email) VALUES ($1) RETURNING id",
    [`retry-${Date.now()}@example.com`],
  );
  const workspace = await pool.query("INSERT INTO workspaces (name) VALUES ('Retry') RETURNING id");
  const workspaceId = workspace.rows[0].id;
  const contact = await pool.query(
    `INSERT INTO workspace_contacts (workspace_id, details) VALUES ($1, $2::jsonb) RETURNING id`,
    [workspaceId, JSON.stringify({ email: "retry@example.com" })],
  );
  const contactId = contact.rows[0].id;
  const destination = "retry@example.com";
  await pool.query(
    `INSERT INTO contact_channel_verifications
       (workspace_id, contact_id, channel, destination_normalized, destination_fingerprint, status, verified_at, consent_at)
     VALUES ($1, $2, 'email', $3, $4, 'verified', NOW(), NOW())`,
    [workspaceId, contactId, destination, verification.destinationFingerprint("email", destination)],
  );

  const probe = await pool.connect();
  try {
    await probe.query("SET statement_timeout = '50ms'");
    await assert.rejects(
      () => probe.query("SELECT pg_sleep(0.2)"),
      (error) => error.code === "57014",
    );
    await probe.query("SET statement_timeout = 0");
  } finally {
    probe.release();
  }

  const holder = await pool.connect();
  const reader = await pool.connect();
  try {
    await holder.query("BEGIN");
    await holder.query("LOCK TABLE contact_channel_verifications IN ACCESS EXCLUSIVE MODE");
    await reader.query("SET statement_timeout = '200ms'");
    const timedOut = await verification.canDeliverToRecipient({
      client: reader,
      workspaceId,
      contactId,
      channel: "email",
      destination,
    });
    assert.equal(timedOut.allowed, false);
    assert.equal(timedOut.code, "RECIPIENT_VERIFICATION_UNAVAILABLE");
    const gated = await verification.filterDeliveryRecipients({
      client: reader,
      workspaceId,
      channel: "email",
      recipients: [{ contactId, destination }],
    });
    assert.equal(gated.unavailable, true);
    assert.equal(gated.code, "RECIPIENT_VERIFICATION_UNAVAILABLE");
    const pending = verification.mergeDeliveryAttempt({
      prior: ["email"],
      attempted: [{
        channel: "email",
        success: false,
        errorCode: "RECIPIENT_VERIFICATION_UNAVAILABLE",
        recipients: {
          [destination]: { state: "unavailable", code: "RECIPIENT_VERIFICATION_UNAVAILABLE" },
        },
      }],
      liveChannels: ["email"],
    });
    assert.equal(pending.outcome.status, "failed");
    assert.equal(pending.outcome.retry, true);
    assert.equal(verification.planManualRetry(pending.ledger, "email").ok, true);
    await pool.query(
      `INSERT INTO delivery_retry_probe (id, channels) VALUES (1, $1::jsonb)
       ON CONFLICT (id) DO UPDATE SET channels = EXCLUDED.channels`,
      [JSON.stringify(pending.ledger)],
    );
    await holder.query("ROLLBACK");
    await reader.query("SET statement_timeout = 0");
    const recovered = await verification.canDeliverToRecipient({
      client: reader,
      workspaceId,
      contactId,
      channel: "email",
      destination,
    });
    assert.equal(recovered.allowed, true);
    const settled = verification.mergeDeliveryAttempt({
      prior: (await pool.query("SELECT channels FROM delivery_retry_probe WHERE id = 1")).rows[0].channels,
      attempted: [{
        channel: "email",
        success: true,
        recipients: { [destination]: { state: "sent" } },
      }],
      liveChannels: ["email"],
    });
    await pool.query("UPDATE delivery_retry_probe SET channels = $1::jsonb WHERE id = 1", [
      JSON.stringify(settled.ledger),
    ]);
    const stored = await pool.query("SELECT channels FROM delivery_retry_probe WHERE id = 1");
    assert.equal(stored.rows[0].channels.outcomes.email.state, "sent");
    assert.equal(settled.outcome.status, "sent");
    const completion = verification.requiredRecipientDelivery({
      channel: "email",
      recipients: [destination, "other@example.com"],
      history: [{ channel: "email", status: "success", metadata: { recipient: destination } }],
      eligibility: { "other@example.com": { code: "RECIPIENT_NOT_VERIFIED" } },
    });
    assert.equal(completion.complete, true);
    assert.equal(completion.delivered, true);
  } finally {
    await holder.query("ROLLBACK").catch(() => {});
    await reader.query("SET statement_timeout = 0").catch(() => {});
    reader.release();
    holder.release();
  }
});
