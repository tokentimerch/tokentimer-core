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
      provider_accepted_at TIMESTAMPTZ NULL,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS uq_weekly_digest_recipient_week_channel
      ON weekly_digest_recipient_log(workspace_id, week_start_date, channel, recipient_key);
    ALTER TABLE weekly_digest_recipient_log
      ADD COLUMN IF NOT EXISTS provider_accepted_at TIMESTAMPTZ;
    CREATE TABLE IF NOT EXISTS weekly_digest_log (
      workspace_id UUID NOT NULL,
      contact_group_id UUID NOT NULL,
      week_start_date DATE NOT NULL,
      tokens_count INTEGER NOT NULL DEFAULT 0,
      channels JSONB NOT NULL DEFAULT '[]'::jsonb,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      PRIMARY KEY (workspace_id, contact_group_id, week_start_date)
    );
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
  await pool.query("DELETE FROM weekly_digest_log");
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

test("a lost digest claim is not counted and a recorded acceptance is not sent again", async () => {
  const digest = await import(digestHref);
  const workspace = await pool.query("INSERT INTO workspaces (name) VALUES ('Workspace') RETURNING id");
  const workspaceId = workspace.rows[0].id;
  const groupId = "11111111-1111-4111-8111-111111111111";
  const claimInput = {
    workspaceId,
    weekStartDate: "2026-10-26",
    channel: "email",
    recipientKey: "person@example.com",
    tokensCount: 2,
    leaseMs: 60000,
  };
  const sends = [];
  const recordGroup = async () => {
    await pool.query(
      `INSERT INTO weekly_digest_log (workspace_id, contact_group_id, week_start_date, tokens_count, channels, metadata)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb)`,
      [workspaceId, groupId, claimInput.weekStartDate, 2, JSON.stringify(["email"]), JSON.stringify({ sent_to_count: 1 })],
    );
  };
  const client = await pool.connect();
  try {
    const owner = await digest.claimWeeklyDigestRecipient(client, claimInput);
    sends.push("owner");
    await pool.query(
      "UPDATE weekly_digest_recipient_log SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE claim_token = $1",
      [owner.claim_token],
    );
    const reclaimed = await digest.claimWeeklyDigestRecipient(client, claimInput);
    const lost = await digest.finalizeWeeklyDigestDelivery(client, {
      ...claimInput,
      claimToken: owner.claim_token,
    });
    assert.equal(lost.completion, "delivered-ownership-lost");
    assert.equal(lost.row, null);
    const groups = await pool.query("SELECT COUNT(*)::int AS n FROM weekly_digest_log");
    assert.equal(groups.rows[0].n, 0);
    assert.equal(reclaimed.provider_accepted_at, null);
    sends.push("reclaimed");
    const reclaimedDone = await digest.markWeeklyDigestRecipientSent(client, {
      ...claimInput,
      claimToken: reclaimed.claim_token,
    });
    assert.equal(reclaimedDone.status, "sent");
    assert.deepEqual(sends, ["owner", "reclaimed"]);

    await pool.query("DELETE FROM weekly_digest_recipient_log");
    sends.length = 0;
    const acceptedOwner = await digest.claimWeeklyDigestRecipient(client, claimInput);
    sends.push("owner");
    const noted = await digest.noteWeeklyDigestProviderAccepted(client, {
      ...claimInput,
      claimToken: acceptedOwner.claim_token,
    });
    assert.ok(noted.provider_accepted_at);
    await pool.query(
      "UPDATE weekly_digest_recipient_log SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE claim_token = $1",
      [acceptedOwner.claim_token],
    );
    const nextOwner = await digest.claimWeeklyDigestRecipient(client, claimInput);
    assert.ok(nextOwner.provider_accepted_at);
    const staleFinish = await digest.finalizeWeeklyDigestDelivery(client, {
      ...claimInput,
      claimToken: acceptedOwner.claim_token,
    });
    assert.equal(staleFinish.completion, "delivered-ownership-lost");
    if (!nextOwner.provider_accepted_at) sends.push("reclaimed");
    const finished = await digest.markWeeklyDigestRecipientSent(client, {
      ...claimInput,
      claimToken: nextOwner.claim_token,
    });
    assert.equal(finished.status, "sent");
    await recordGroup();
    assert.deepEqual(sends, ["owner"]);
    const logged = await pool.query("SELECT COUNT(*)::int AS n FROM weekly_digest_log");
    assert.equal(logged.rows[0].n, 1);
  } finally {
    client.release();
  }
});
