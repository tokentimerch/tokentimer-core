"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");
const { pathToFileURL } = require("node:url");
const { Pool } = require("pg");

const pool = new Pool({
  host: process.env.RV_TEST_DB_HOST || "127.0.0.1",
  port: Number(process.env.RV_TEST_DB_PORT || 54329),
  database: process.env.RV_TEST_DB_NAME || "weekly_digest_claim_test",
  user: process.env.RV_TEST_DB_USER || "tokentimer",
  password: process.env.RV_TEST_DB_PASSWORD || "password",
  max: 8,
});

const digestHref = pathToFileURL(
  path.resolve(__dirname, "../../apps/worker/src/shared/weeklyDigestRecipients.js"),
).href;

async function applySchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS workspaces (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS weekly_digest_recipient_log (
      id BIGSERIAL PRIMARY KEY,
      workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
      week_start_date DATE NOT NULL,
      channel TEXT NOT NULL,
      recipient_key TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      attempt_count INTEGER NOT NULL DEFAULT 0,
      lease_expires_at TIMESTAMPTZ NULL,
      tokens_count INTEGER NOT NULL DEFAULT 0,
      claim_token TEXT,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS uq_weekly_digest_recipient_week_channel
      ON weekly_digest_recipient_log(workspace_id, week_start_date, channel, recipient_key);
  `);
}

test.before(async () => {
  process.env.WEEKLY_DIGEST_RECIPIENT_KEY = "postgres-digest-recipient-key";
  await applySchema();
});

test.after(async () => {
  await pool.end();
});

test.beforeEach(async () => {
  await pool.query("DELETE FROM weekly_digest_recipient_log");
  await pool.query("DELETE FROM workspaces");
});

test("a stale digest worker cannot release or complete another worker's claim", async () => {
  const digest = await import(digestHref);
  const workspace = await pool.query("INSERT INTO workspaces (name) VALUES ('Workspace') RETURNING id");
  const workspaceId = workspace.rows[0].id;
  const claimInput = {
    workspaceId,
    weekStartDate: "2026-10-26",
    channel: "email",
    recipientKey: "person@example.com",
    tokensCount: 2,
    leaseMs: 60000,
  };
  const client = await pool.connect();
  try {
    const first = await digest.claimWeeklyDigestRecipient(client, claimInput);
    assert.ok(first.claim_token);
    const completed = await digest.markWeeklyDigestRecipientSent(client, {
      ...claimInput,
      claimToken: first.claim_token,
    });
    assert.equal(completed.status, "sent");
    const secondComplete = await digest.markWeeklyDigestRecipientSent(client, {
      ...claimInput,
      claimToken: first.claim_token,
    });
    assert.equal(secondComplete, null);
    await pool.query("DELETE FROM weekly_digest_recipient_log");

    const owner = await digest.claimWeeklyDigestRecipient(client, claimInput);
    const released = await digest.releaseWeeklyDigestRecipientClaim(client, {
      ...claimInput,
      claimToken: owner.claim_token,
    });
    assert.equal(released, true);
    const afterRelease = await digest.claimWeeklyDigestRecipient(client, claimInput);
    assert.ok(afterRelease.claim_token);
    assert.notEqual(afterRelease.claim_token, owner.claim_token);

    await pool.query(
      "UPDATE weekly_digest_recipient_log SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE claim_token = $1",
      [afterRelease.claim_token],
    );
    const reclaimed = await digest.claimWeeklyDigestRecipient(client, claimInput);
    assert.notEqual(reclaimed.claim_token, afterRelease.claim_token);
    const staleRelease = await digest.releaseWeeklyDigestRecipientClaim(client, {
      ...claimInput,
      claimToken: afterRelease.claim_token,
    });
    assert.equal(staleRelease, false);
    const staleComplete = await digest.markWeeklyDigestRecipientSent(client, {
      ...claimInput,
      claimToken: afterRelease.claim_token,
    });
    assert.equal(staleComplete, null);
    const stillOwned = await pool.query(
      "SELECT claim_token, status FROM weekly_digest_recipient_log WHERE workspace_id = $1",
      [workspaceId],
    );
    assert.equal(stillOwned.rows.length, 1);
    assert.equal(stillOwned.rows[0].claim_token, reclaimed.claim_token);
    assert.equal(stillOwned.rows[0].status, "pending");
    const finished = await digest.markWeeklyDigestRecipientSent(client, {
      ...claimInput,
      claimToken: reclaimed.claim_token,
    });
    assert.equal(finished.status, "sent");
    const raced = await Promise.all([
      digest.markWeeklyDigestRecipientSent(client, { ...claimInput, claimToken: reclaimed.claim_token }),
      digest.claimWeeklyDigestRecipient(client, claimInput),
    ]);
    assert.equal(raced[0], null);
    assert.equal(raced[1], null);

    await pool.query("DELETE FROM weekly_digest_recipient_log");
    const abandoned = await digest.claimWeeklyDigestRecipient(client, { ...claimInput, leaseMs: 1 });
    await pool.query(
      "UPDATE weekly_digest_recipient_log SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE claim_token = $1",
      [abandoned.claim_token],
    );
    const retry = await digest.claimWeeklyDigestRecipient(client, claimInput);
    assert.ok(retry.claim_token);
    assert.notEqual(retry.claim_token, abandoned.claim_token);
    const sent = await digest.markWeeklyDigestRecipientSent(client, {
      ...claimInput,
      claimToken: retry.claim_token,
    });
    assert.equal(sent.status, "sent");
  } finally {
    client.release();
  }
});
