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
      delivery_state TEXT,
      retry_after TIMESTAMPTZ,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS uq_weekly_digest_recipient_week_channel
      ON weekly_digest_recipient_log(workspace_id, week_start_date, channel, recipient_key);
    ALTER TABLE weekly_digest_recipient_log
      ADD COLUMN IF NOT EXISTS provider_accepted_at TIMESTAMPTZ;
    ALTER TABLE weekly_digest_recipient_log
      ADD COLUMN IF NOT EXISTS delivery_state TEXT;
    ALTER TABLE weekly_digest_recipient_log
      ADD COLUMN IF NOT EXISTS retry_after TIMESTAMPTZ;
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

test.describe("weekly digest claims", { concurrency: 1 }, () => {
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

test("owned digest delivery holds the lease and recovers without a second immediate send", async () => {
  const digest = await import(digestHref);
  const workspace = await pool.query("INSERT INTO workspaces (name) VALUES ('Delivery') RETURNING id");
  const workspaceId = workspace.rows[0].id;
  const groupId = "22222222-2222-4222-8222-222222222222";
  const baseInput = {
    workspaceId,
    channel: "email",
    recipientKey: "digest@example.com",
    tokensCount: 1,
    leaseMs: 60000,
    uncertainRetrySeconds: 900,
  };
  const client = await pool.connect();

  async function reset(weekStartDate) {
    await pool.query("DELETE FROM weekly_digest_log WHERE workspace_id = $1", [workspaceId]);
    await pool.query(
      "DELETE FROM weekly_digest_recipient_log WHERE workspace_id = $1 AND week_start_date = $2",
      [workspaceId, weekStartDate],
    );
  }

  async function stored(weekStartDate) {
    const result = await pool.query(
      `SELECT status, claim_token, delivery_state, provider_accepted_at, retry_after, lease_expires_at
         FROM weekly_digest_recipient_log
        WHERE workspace_id = $1 AND week_start_date = $2`,
      [workspaceId, weekStartDate],
    );
    assert.equal(result.rows.length, 1);
    return result.rows[0];
  }

  async function expire(token) {
    await pool.query(
      "UPDATE weekly_digest_recipient_log SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE claim_token = $1",
      [token],
    );
  }

  async function historyCount() {
    const result = await pool.query(
      "SELECT COUNT(*)::int AS n FROM weekly_digest_log WHERE workspace_id = $1",
      [workspaceId],
    );
    return result.rows[0].n;
  }

  async function recordIfConfirmed(weekStartDate, completion) {
    if (completion !== "confirmed") return;
    await pool.query(
      `INSERT INTO weekly_digest_log (workspace_id, contact_group_id, week_start_date, tokens_count, channels, metadata)
       VALUES ($1, $2, $3, 1, '["email"]'::jsonb, '{"sent_to_count":1}'::jsonb)`,
      [workspaceId, groupId, weekStartDate],
    );
  }

  try {
    const week1 = "2026-11-02";
    const input = { ...baseInput, weekStartDate: week1 };
    const claimed = await digest.claimWeeklyDigestRecipient(client, input);
    const completed = await digest.runOwnedDigestDelivery(client, {
      ...input,
      claimToken: claimed.claim_token,
    }, async () => ({ success: true }));
    assert.equal(completed.completion, "confirmed");
    assert.equal(completed.sentExternal, true);
    const completedRow = await stored(week1);
    assert.equal(completedRow.status, "sent");
    assert.ok(completedRow.provider_accepted_at);
    await recordIfConfirmed(week1, completed.completion);
    assert.equal(await historyCount(), 1);

    const week2 = "2026-11-09";
    const renewInput = { ...baseInput, weekStartDate: week2 };
    const renewClaim = await digest.claimWeeklyDigestRecipient(client, renewInput);
    const started = await digest.beginWeeklyDigestDelivery(client, {
      ...renewInput,
      claimToken: renewClaim.claim_token,
    });
    assert.equal(started.delivery_state, "in_progress");
    const blockedWhileLive = await digest.claimWeeklyDigestRecipient(client, renewInput);
    assert.equal(blockedWhileLive, null);
    const renewed = await digest.renewWeeklyDigestClaimLease(client, {
      ...renewInput,
      claimToken: renewClaim.claim_token,
    });
    assert.ok(renewed);
    assert.ok(new Date(renewed.lease_expires_at).getTime() > Date.now());
    const staleRenew = await digest.renewWeeklyDigestClaimLease(client, {
      ...renewInput,
      claimToken: "stale-token",
    });
    assert.equal(staleRenew, null);
    const renewRow = await stored(week2);
    assert.equal(renewRow.claim_token, renewClaim.claim_token);
    assert.equal(renewRow.delivery_state, "in_progress");
    assert.equal(renewRow.status, "pending");

    const week3 = "2026-11-16";
    const longInput = { ...baseInput, weekStartDate: week3, leaseMs: 1000 };
    const longClaim = await digest.claimWeeklyDigestRecipient(client, longInput);
    let rivalDuringCall = "pending";
    const longOutcome = await digest.runOwnedDigestDelivery(client, {
      ...longInput,
      claimToken: longClaim.claim_token,
    }, async ({ renew }) => {
      await expire(longClaim.claim_token);
      const extended = await renew();
      assert.ok(extended);
      rivalDuringCall = await digest.claimWeeklyDigestRecipient(client, longInput);
      return { success: true };
    });
    assert.equal(rivalDuringCall, null);
    assert.equal(longOutcome.completion, "confirmed");
    assert.equal(longOutcome.sentExternal, true);
    assert.equal((await stored(week3)).status, "sent");
    await recordIfConfirmed(week3, longOutcome.completion);

    const week4 = "2026-11-23";
    const beforeInput = { ...baseInput, weekStartDate: week4 };
    const beforeClaim = await digest.claimWeeklyDigestRecipient(client, beforeInput);
    await expire(beforeClaim.claim_token);
    const beforeNext = await digest.claimWeeklyDigestRecipient(client, beforeInput);
    assert.notEqual(beforeNext.claim_token, beforeClaim.claim_token);
    assert.equal(beforeNext.delivery_state, null);
    assert.equal(beforeNext.provider_accepted_at, null);
    const beforeOutcome = await digest.runOwnedDigestDelivery(client, {
      ...beforeInput,
      claimToken: beforeNext.claim_token,
    }, async () => ({ success: true }));
    assert.equal(beforeOutcome.sentExternal, true);
    assert.equal((await stored(week4)).status, "sent");

    const week5 = "2026-11-30";
    const crashInput = { ...baseInput, weekStartDate: week5 };
    const crashClaim = await digest.claimWeeklyDigestRecipient(client, crashInput);
    await digest.beginWeeklyDigestDelivery(client, {
      ...crashInput,
      claimToken: crashClaim.claim_token,
    });
    await expire(crashClaim.claim_token);
    const crashNext = await digest.claimWeeklyDigestRecipient(client, crashInput);
    assert.equal(crashNext.delivery_state, "uncertain");
    assert.equal(crashNext.provider_accepted_at, null);
    assert.ok(new Date(crashNext.retry_after).getTime() > Date.now());
    assert.equal(await digest.claimWeeklyDigestRecipient(client, crashInput), null);
    const premature = await digest.runOwnedDigestDelivery(client, {
      ...crashInput,
      claimToken: crashNext.claim_token,
    }, async () => ({ success: true }));
    assert.equal(premature.completion, "ownership-lost");
    assert.equal(premature.sentExternal, false);
    assert.equal((await stored(week5)).status, "pending");
    await recordIfConfirmed(week5, premature.completion);
    assert.equal(await historyCount(), 2);

    const week6 = "2026-12-07";
    const acceptedInput = { ...baseInput, weekStartDate: week6 };
    const acceptedClaim = await digest.claimWeeklyDigestRecipient(client, acceptedInput);
    await digest.beginWeeklyDigestDelivery(client, {
      ...acceptedInput,
      claimToken: acceptedClaim.claim_token,
    });
    const noted = await digest.noteWeeklyDigestProviderAccepted(client, {
      ...acceptedInput,
      claimToken: acceptedClaim.claim_token,
    });
    assert.ok(noted.provider_accepted_at);
    await expire(acceptedClaim.claim_token);
    const acceptedNext = await digest.claimWeeklyDigestRecipient(client, acceptedInput);
    assert.ok(acceptedNext.provider_accepted_at);
    assert.equal(acceptedNext.delivery_state, "accepted");
    const resent = [];
    const recoveredAccepted = await digest.runOwnedDigestDelivery(client, {
      ...acceptedInput,
      claimToken: acceptedNext.claim_token,
      providerAcceptedAt: acceptedNext.provider_accepted_at,
    }, async () => {
      resent.push("resent");
      return { success: true };
    });
    assert.deepEqual(resent, []);
    assert.equal(recoveredAccepted.completion, "confirmed");
    assert.equal(recoveredAccepted.sentExternal, false);
    assert.equal((await stored(week6)).status, "sent");
    assert.ok((await stored(week6)).provider_accepted_at);
    const staleAccepted = await digest.finalizeWeeklyDigestDelivery(client, {
      ...acceptedInput,
      claimToken: acceptedClaim.claim_token,
    });
    assert.equal(staleAccepted.completion, "delivered-ownership-lost");
    assert.equal((await stored(week6)).status, "sent");
    await recordIfConfirmed(week6, recoveredAccepted.completion);

    const week7 = "2026-12-14";
    const ambiguousInput = { ...baseInput, weekStartDate: week7 };
    const ambiguousClaim = await digest.claimWeeklyDigestRecipient(client, ambiguousInput);
    const ambiguous = await digest.runOwnedDigestDelivery(client, {
      ...ambiguousInput,
      claimToken: ambiguousClaim.claim_token,
    }, async () => ({ success: false, uncertain: true }));
    assert.equal(ambiguous.completion, "uncertain");
    assert.equal(ambiguous.sentExternal, false);
    const ambiguousRow = await stored(week7);
    assert.equal(ambiguousRow.status, "pending");
    assert.equal(ambiguousRow.delivery_state, "uncertain");
    assert.equal(ambiguousRow.provider_accepted_at, null);
    assert.equal(await digest.claimWeeklyDigestRecipient(client, ambiguousInput), null);
    await pool.query(
      `UPDATE weekly_digest_recipient_log
          SET retry_after = NOW() - INTERVAL '1 second',
              lease_expires_at = NOW() - INTERVAL '1 second'
        WHERE workspace_id = $1 AND week_start_date = $2`,
      [workspaceId, week7],
    );
    const ambiguousRetry = await digest.claimWeeklyDigestRecipient(client, ambiguousInput);
    assert.equal(ambiguousRetry.delivery_state, null);
    const ambiguousDone = await digest.runOwnedDigestDelivery(client, {
      ...ambiguousInput,
      claimToken: ambiguousRetry.claim_token,
    }, async () => ({ success: true }));
    assert.equal(ambiguousDone.completion, "confirmed");
    assert.equal(ambiguousDone.sentExternal, true);
    assert.equal((await stored(week7)).status, "sent");

    const week8 = "2026-12-21";
    const thrownInput = { ...baseInput, weekStartDate: week8 };
    const thrownClaim = await digest.claimWeeklyDigestRecipient(client, thrownInput);
    const thrownOutcome = await digest.runOwnedDigestDelivery(client, {
      ...thrownInput,
      claimToken: thrownClaim.claim_token,
    }, async () => {
      const error = new Error("socket hang up");
      error.code = "ECONNRESET";
      throw error;
    });
    assert.equal(thrownOutcome.completion, "uncertain");
    assert.equal((await stored(week8)).delivery_state, "uncertain");
    assert.equal((await stored(week8)).status, "pending");

    const week9 = "2026-12-28";
    const rejectedInput = { ...baseInput, weekStartDate: week9 };
    const rejectedClaim = await digest.claimWeeklyDigestRecipient(client, rejectedInput);
    const rejected = await digest.runOwnedDigestDelivery(client, {
      ...rejectedInput,
      claimToken: rejectedClaim.claim_token,
    }, async () => ({ success: false }));
    assert.equal(rejected.completion, "rejected");
    assert.equal(rejected.sentExternal, false);
    assert.equal((await stored(week9)).delivery_state, "rejected");
    assert.equal((await stored(week9)).status, "pending");
    assert.equal(await digest.claimWeeklyDigestRecipient(client, rejectedInput), null);
    await expire((await stored(week9)).claim_token);
    const rejectedRetry = await digest.claimWeeklyDigestRecipient(client, rejectedInput);
    assert.equal(rejectedRetry.delivery_state, null);
    const rejectedDone = await digest.runOwnedDigestDelivery(client, {
      ...rejectedInput,
      claimToken: rejectedRetry.claim_token,
    }, async () => ({ success: true }));
    assert.equal(rejectedDone.completion, "confirmed");
    assert.equal((await stored(week9)).status, "sent");

    const week10 = "2027-01-04";
    const raceInput = { ...baseInput, weekStartDate: week10 };
    const raceClaim = await digest.claimWeeklyDigestRecipient(client, raceInput);
    let rival = null;
    const lostDuringSend = await digest.runOwnedDigestDelivery(client, {
      ...raceInput,
      claimToken: raceClaim.claim_token,
    }, async () => {
      await expire(raceClaim.claim_token);
      rival = await digest.claimWeeklyDigestRecipient(client, raceInput);
      return { success: true };
    });
    assert.equal(rival.delivery_state, "uncertain");
    assert.equal(lostDuringSend.completion, "ownership-lost");
    assert.equal(lostDuringSend.sentExternal, true);
    const lostRow = await stored(week10);
    assert.equal(lostRow.status, "pending");
    assert.equal(lostRow.claim_token, rival.claim_token);
    assert.equal(lostRow.provider_accepted_at, null);
    assert.equal(lostRow.delivery_state, "uncertain");
    const staleFinish = await digest.finalizeWeeklyDigestDelivery(client, {
      ...raceInput,
      claimToken: raceClaim.claim_token,
    });
    assert.equal(staleFinish.completion, "delivered-ownership-lost");
    assert.equal((await stored(week10)).status, "pending");
    assert.equal((await stored(week10)).claim_token, rival.claim_token);
    await recordIfConfirmed(week10, lostDuringSend.completion);
    const historyBeforeRecovery = await historyCount();
    await pool.query(
      `UPDATE weekly_digest_recipient_log
          SET retry_after = NOW() - INTERVAL '1 second',
              lease_expires_at = NOW() - INTERVAL '1 second'
        WHERE claim_token = $1`,
      [rival.claim_token],
    );
    const recovered = await digest.claimWeeklyDigestRecipient(client, raceInput);
    assert.equal(recovered.delivery_state, null);
    const recoveredOutcome = await digest.runOwnedDigestDelivery(client, {
      ...raceInput,
      claimToken: recovered.claim_token,
    }, async () => ({ success: true }));
    assert.equal(recoveredOutcome.completion, "confirmed");
    assert.equal(recoveredOutcome.sentExternal, true);
    assert.equal((await stored(week10)).status, "sent");
    await recordIfConfirmed(week10, recoveredOutcome.completion);
    assert.equal(await historyCount(), historyBeforeRecovery + 1);
    await reset(week10);
  } finally {
    client.release();
  }
});
});
