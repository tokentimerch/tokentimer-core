"use strict";

// Concurrent manual retry against a migrated database.
// docker run --name tt-rv-worker-pg -e POSTGRES_USER=tokentimer -e POSTGRES_PASSWORD=password -e POSTGRES_DB=tokentimer_delivery_worker -p 54330:5432 -d postgres:16

process.env.NODE_ENV = "test";
process.env.DB_HOST = process.env.DELIVERY_WORKER_DB_HOST || "127.0.0.1";
process.env.DB_PORT = process.env.DELIVERY_WORKER_DB_PORT || "54330";
process.env.DB_NAME = process.env.DELIVERY_WORKER_DB_NAME || "tokentimer_delivery_worker";
process.env.DB_USER = process.env.DELIVERY_WORKER_DB_USER || "tokentimer";
process.env.DB_PASSWORD = process.env.DELIVERY_WORKER_DB_PASSWORD || "password";
process.env.TT_DEPLOYMENT = "self-hosted";
process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
process.env.RECIPIENT_FINGERPRINT_SECRET = "manual-retry-claim-test-secret";
delete process.env.DB_SSL;
delete process.env.ENABLE_METRICS;

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const test = require("node:test");
const { Pool } = require("pg");
const verification = require("../../packages/recipient-verification");
const { currentWorkspaceAccessSql } = require("../../apps/api/services/rbac");

const ROOT = path.join(__dirname, "..", "..");
const pool = new Pool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  max: 6,
});

function migrate() {
  const result = spawnSync(process.execPath, ["apps/api/migrations/migrate.js"], {
    cwd: ROOT,
    env: process.env,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout || `migrate exited ${result.status}`);
  }
}

function retrySql() {
  const access = `${currentWorkspaceAccessSql(`COALESCE(
        (SELECT t.workspace_id FROM tokens t WHERE t.id = aq.token_id),
        (SELECT ca.workspace_id FROM certops_agents ca WHERE ca.id = aq.certops_agent_id)
      )`, "$3")} OR (aq.token_id IS NULL AND aq.certops_agent_id IS NULL)`;
  return verification.manualRetryUpdateSql(access, "aq.id, aq.status, aq.channels, aq.delivery_claim_id");
}

function applyRetry(alert, channels, userId = alert.user_id) {
  return pool.query(retrySql(), [
    JSON.stringify(channels),
    alert.id,
    userId,
    alert.status,
    JSON.stringify(alert.channels),
    alert.delivery_claim_id,
  ]);
}

async function loadAlert(id) {
  const result = await pool.query(
    `SELECT id, user_id, status, channels, delivery_claim_id, next_attempt_at
       FROM alert_queue WHERE id = $1`,
    [id],
  );
  return result.rows[0];
}

async function seedAlert(channels, status = "failed") {
  const user = await pool.query(
    `INSERT INTO users (email, display_name, auth_method, password_hash, email_verified)
     VALUES ($1, 'Owner', 'local', 'hash', true) RETURNING id`,
    [`manual-retry-${crypto.randomUUID()}@example.com`],
  );
  const userId = user.rows[0].id;
  const workspaceId = crypto.randomUUID();
  await pool.query(
    `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1, 'Retry', 'oss', $2)`,
    [workspaceId, userId],
  );
  await pool.query(
    `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
     VALUES ($1, $2, 'admin', $1)`,
    [userId, workspaceId],
  );
  const token = await pool.query(
    `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
     VALUES ($1, $2, $1, 'Retry', CURRENT_DATE + INTERVAL '7 days', 'api_key', 'general')
     RETURNING id`,
    [userId, workspaceId],
  );
  const inserted = await pool.query(
    `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date, channels, status)
     VALUES ($1, $2, $3, 7, CURRENT_DATE, $4::jsonb, $5)
     RETURNING id`,
    [userId, token.rows[0].id, `manual-retry:${crypto.randomUUID()}`, JSON.stringify(channels), status],
  );
  return { ...(await loadAlert(inserted.rows[0].id)), workspaceId, tokenId: token.rows[0].id };
}

test("manual retry does not cross an active delivery claim", async () => {
  migrate();
  const ledger = {
    version: 1,
    retry: ["webhooks"],
    required: ["email", "webhooks"],
    outcomes: {
      email: { state: "sent", terminal: true },
      webhooks: { state: "failed", terminal: false, reason: "provider" },
    },
  };

  const idle = await seedAlert(ledger, "failed");
  const planned = verification.planManualRetry(idle.channels, "webhooks");
  assert.equal(planned.ok, true);
  assert.equal(verification.planManualRetry(idle.channels, "email").code, "ALREADY_DELIVERED");
  const idleWrite = await applyRetry(idle, planned.channels);
  assert.equal(idleWrite.rowCount, 1);
  const idleAfter = await loadAlert(idle.id);
  assert.equal(idleAfter.status, "pending");
  assert.equal(idleAfter.delivery_claim_id, null);
  assert.equal(idleAfter.channels.outcomes.email.state, "sent");
  assert.deepEqual(idleAfter.channels.retry, ["webhooks"]);

  const claimed = await seedAlert(ledger, "failed");
  const claimId = crypto.randomUUID();
  await pool.query(
    `UPDATE alert_queue
        SET delivery_claim_id = $2, next_attempt_at = NOW() + INTERVAL '10 minutes'
      WHERE id = $1`,
    [claimed.id, claimId],
  );
  const held = await loadAlert(claimed.id);
  const heldState = await pool.query(
    `SELECT (delivery_claim_id IS NOT NULL AND next_attempt_at > NOW()) AS claim_active
       FROM alert_queue WHERE id = $1`,
    [claimed.id],
  );
  assert.equal(heldState.rows[0].claim_active, true);
  const refused = await applyRetry(held, verification.planManualRetry(held.channels, "webhooks").channels);
  assert.equal(refused.rowCount, 0);
  const stillHeld = await loadAlert(claimed.id);
  assert.equal(stillHeld.delivery_claim_id, claimId);
  assert.equal(stillHeld.channels.outcomes.email.state, "sent");

  const concurrent = await seedAlert(ledger, "failed");
  const basePlan = verification.planManualRetry(concurrent.channels, "webhooks").channels;
  const left = JSON.parse(JSON.stringify(basePlan));
  const right = JSON.parse(JSON.stringify(basePlan));
  left.outcomes.webhooks.marker = "left";
  right.outcomes.webhooks.marker = "right";
  const [firstResult, secondResult] = await Promise.all([
    applyRetry(concurrent, left),
    applyRetry(concurrent, right),
  ]);
  assert.equal(firstResult.rowCount + secondResult.rowCount, 1);
  const concurrentAfter = await loadAlert(concurrent.id);
  assert.equal(["left", "right"].includes(concurrentAfter.channels.outcomes.webhooks.marker), true);
  assert.equal(concurrentAfter.channels.outcomes.email.state, "sent");
  assert.equal(concurrentAfter.delivery_claim_id, null);

  const racing = await seedAlert(ledger, "failed");
  const owner = await pool.connect();
  try {
    await owner.query("BEGIN");
    await owner.query("SELECT id FROM alert_queue WHERE id = $1 FOR UPDATE", [racing.id]);
    const waiting = applyRetry(racing, verification.planManualRetry(racing.channels, "webhooks").channels);
    await new Promise((resolve) => setTimeout(resolve, 150));
    const acquired = crypto.randomUUID();
    await owner.query(
      `UPDATE alert_queue
          SET delivery_claim_id = $2, next_attempt_at = NOW() + INTERVAL '10 minutes', updated_at = NOW()
        WHERE id = $1`,
      [racing.id, acquired],
    );
    await owner.query("COMMIT");
    assert.equal((await waiting).rowCount, 0);
    assert.equal((await loadAlert(racing.id)).delivery_claim_id, acquired);
  } finally {
    await owner.query("ROLLBACK").catch(() => {});
    owner.release();
  }

  const finishing = await seedAlert(ledger, "failed");
  const finishClaim = crypto.randomUUID();
  await pool.query(
    `UPDATE alert_queue
        SET delivery_claim_id = $2, next_attempt_at = NOW() + INTERVAL '10 minutes'
      WHERE id = $1`,
    [finishing.id, finishClaim],
  );
  const finishingRow = await loadAlert(finishing.id);
  const workerChannels = {
    version: 1,
    retry: [],
    required: ["email", "webhooks"],
    outcomes: {
      email: { state: "sent", terminal: true },
      webhooks: { state: "sent", terminal: true },
    },
  };
  const finisher = await pool.connect();
  try {
    await finisher.query("BEGIN");
    await finisher.query("SELECT id FROM alert_queue WHERE id = $1 FOR UPDATE", [finishing.id]);
    const waitingRetry = applyRetry(
      finishingRow,
      verification.planManualRetry(ledger, "webhooks").channels,
    );
    await new Promise((resolve) => setTimeout(resolve, 150));
    const completed = await finisher.query(
      `UPDATE alert_queue
          SET status = 'sent', channels = $2, next_attempt_at = NULL, delivery_claim_id = NULL, updated_at = NOW()
        WHERE id = $1 AND delivery_claim_id = $3`,
      [finishing.id, JSON.stringify(workerChannels), finishClaim],
    );
    assert.equal(completed.rowCount, 1);
    await finisher.query("COMMIT");
    assert.equal((await waitingRetry).rowCount, 0);
  } finally {
    await finisher.query("ROLLBACK").catch(() => {});
    finisher.release();
  }
  const finished = await loadAlert(finishing.id);
  assert.equal(finished.status, "sent");
  assert.equal(finished.channels.outcomes.webhooks.state, "sent");

  const cleared = await seedAlert(ledger, "failed");
  const clearedWrite = await applyRetry(cleared, verification.planManualRetry(cleared.channels, "webhooks").channels);
  assert.equal(clearedWrite.rowCount, 1);
  const staleWorker = await pool.query(
    `UPDATE alert_queue
        SET status = 'sent', channels = $2, delivery_claim_id = NULL
      WHERE id = $1 AND delivery_claim_id = $3`,
    [cleared.id, JSON.stringify(workerChannels), crypto.randomUUID()],
  );
  assert.equal(staleWorker.rowCount, 0);
  const clearedAfter = await loadAlert(cleared.id);
  assert.equal(clearedAfter.status, "pending");
  assert.deepEqual(clearedAfter.channels.retry, ["webhooks"]);
  assert.equal(clearedAfter.channels.outcomes.email.state, "sent");

  const expired = await seedAlert(ledger, "failed");
  const expiredClaim = crypto.randomUUID();
  await pool.query(
    `UPDATE alert_queue
        SET delivery_claim_id = $2, next_attempt_at = NOW() - INTERVAL '1 hour'
      WHERE id = $1`,
    [expired.id, expiredClaim],
  );
  const expiredRow = await loadAlert(expired.id);
  const expiredState = await pool.query(
    `SELECT (delivery_claim_id IS NOT NULL AND next_attempt_at > NOW()) AS claim_active
       FROM alert_queue WHERE id = $1`,
    [expired.id],
  );
  assert.equal(expiredState.rows[0].claim_active, false);
  await pool.query(
    `INSERT INTO alert_delivery_log (alert_queue_id, user_id, token_id, workspace_id, channel, status, metadata)
     VALUES ($1, $2, $3, $4, 'webhooks', 'failed', $5)`,
    [expired.id, expired.user_id, expired.tokenId, expired.workspaceId, JSON.stringify({ terminal: true, urlHash: "old", retryGeneration: 0 })],
  );
  const recovered = await applyRetry(expiredRow, verification.planManualRetry(expiredRow.channels, "webhooks").channels);
  assert.equal(recovered.rowCount, 1);
  const recoveredAfter = await loadAlert(expired.id);
  assert.equal(recoveredAfter.delivery_claim_id, null);
  assert.equal(recoveredAfter.status, "pending");
  assert.equal(recoveredAfter.channels.outcomes.email.state, "sent");
  const oldWrite = await pool.query(
    `UPDATE alert_queue SET status = 'sent' WHERE id = $1 AND delivery_claim_id = $2`,
    [expired.id, expiredClaim],
  );
  assert.equal(oldWrite.rowCount, 0);
  const logCount = await pool.query(
    `SELECT COUNT(*)::int AS n FROM alert_delivery_log WHERE alert_queue_id = $1`,
    [expired.id],
  );
  assert.equal(logCount.rows[0].n, 1);

  const cooldown = await seedAlert(ledger, "failed");
  await pool.query(
    `UPDATE alert_queue SET next_attempt_at = NOW() + INTERVAL '10 minutes', delivery_claim_id = NULL WHERE id = $1`,
    [cooldown.id],
  );
  const cooling = await loadAlert(cooldown.id);
  assert.equal((await applyRetry(cooling, verification.planManualRetry(cooling.channels, "webhooks").channels)).rowCount, 0);
  assert.equal((await loadAlert(cooldown.id)).delivery_claim_id, null);

  const isolated = await seedAlert(ledger, "failed");
  const outsider = await pool.query(
    `INSERT INTO users (email, display_name, auth_method, password_hash, email_verified)
     VALUES ($1, 'Outsider', 'local', 'hash', true) RETURNING id`,
    [`manual-retry-outsider-${crypto.randomUUID()}@example.com`],
  );
  const outsiderId = outsider.rows[0].id;
  assert.equal((await applyRetry(isolated, verification.planManualRetry(isolated.channels, "webhooks").channels, outsiderId)).rowCount, 0);
  await pool.query("UPDATE alert_queue SET user_id = $2 WHERE id = $1", [isolated.id, outsiderId]);
  const moved = await loadAlert(isolated.id);
  assert.equal((await applyRetry(moved, verification.planManualRetry(moved.channels, "webhooks").channels, outsiderId)).rowCount, 0);
  assert.equal((await applyRetry(moved, verification.planManualRetry(moved.channels, "webhooks").channels, isolated.user_id)).rowCount, 0);
  assert.equal((await loadAlert(isolated.id)).status, "failed");

  const hits = [];
  let openHold = () => {};
  const hold = new Promise((resolve) => {
    openHold = resolve;
  });
  const httpServer = http.createServer((req, res) => {
    if (req.url.split("?")[0] !== "/hold") {
      res.writeHead(404);
      res.end("no");
      return;
    }
    hits.push("/hold");
    hold.then(() => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
  });
  await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const port = httpServer.address().port;
  try {
    const user = await pool.query(
      `INSERT INTO users (email, display_name, auth_method, password_hash, email_verified)
       VALUES ($1, 'Hold', 'local', 'hash', true) RETURNING id`,
      [`manual-retry-hold-${crypto.randomUUID()}@example.com`],
    );
    const workspaceId = crypto.randomUUID();
    await pool.query(
      `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1, 'Hold', 'oss', $2)`,
      [workspaceId, user.rows[0].id],
    );
    await pool.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by) VALUES ($1, $2, 'admin', $1)`,
      [user.rows[0].id, workspaceId],
    );
    await pool.query(
      `INSERT INTO workspace_settings
         (workspace_id, contact_groups, default_contact_group_id, webhook_urls, email_alerts_enabled,
          webhooks_alerts_enabled, alert_thresholds, delivery_window_start, delivery_window_end, delivery_window_tz)
       VALUES ($1, $2::jsonb, 'default', $3::jsonb, true, true, '[7]'::jsonb, '00:00', '23:59', 'UTC')`,
      [
        workspaceId,
        JSON.stringify([{ id: "default", name: "Default", webhook_names: ["Hold"] }]),
        JSON.stringify([{ name: "Hold", url: `http://127.0.0.1:${port}/hold`, kind: "generic" }]),
      ],
    );
    const token = await pool.query(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
       VALUES ($1, $2, $1, 'Hold', CURRENT_DATE + INTERVAL '7 days', 'api_key', 'general') RETURNING id`,
      [user.rows[0].id, workspaceId],
    );
    await pool.query(
      `INSERT INTO token_contact_groups (token_id, workspace_id, contact_group_id) VALUES ($1, $2, 'default')`,
      [token.rows[0].id, workspaceId],
    );
    const queued = await pool.query(
      `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date, channels, status)
       VALUES ($1, $2, $3, 7, CURRENT_DATE, '["webhooks"]'::jsonb, 'pending') RETURNING id`,
      [user.rows[0].id, token.rows[0].id, `manual-retry:${crypto.randomUUID()}`],
    );
    await pool.query(
      `UPDATE alert_queue SET status = 'limit_exceeded'
        WHERE id <> $1 AND status IN ('pending', 'failed', 'partial')`,
      [queued.rows[0].id],
    );
    const { deliveryWorkerJob } = await import("../../apps/worker/src/delivery-worker.js");
    let job = null;
    job = deliveryWorkerJob({ closePool: false, incidentEmailSender: async () => ({ success: true }) });
    const started = Date.now();
    let live = null;
    while (Date.now() - started < 8000) {
      live = await loadAlert(queued.rows[0].id);
      if (live.delivery_claim_id && hits.length > 0) break;
      await new Promise((resolve) => setTimeout(resolve, 30));
    }
    assert.ok(live.delivery_claim_id);
    assert.equal(hits.length, 1);
    const duringSend = await applyRetry(live, ["webhooks"]);
    assert.equal(duringSend.rowCount, 0);
    openHold();
    await job;
    assert.equal(hits.length, 1);
    const delivered = await loadAlert(queued.rows[0].id);
    assert.equal(delivered.delivery_claim_id, null);
    assert.notEqual(delivered.status, "pending");
  } finally {
    openHold();
    await new Promise((resolve, reject) => httpServer.close((err) => (err ? reject(err) : resolve())));
  }
});

test.after(async () => {
  await pool.end();
  try {
    const db = require("../../apps/api/db/database");
    await db.pool.end();
  } catch {
    // The API pool is created when the workspace predicate helper is loaded.
  }
  try {
    const workerDb = await import("../../apps/worker/src/db.js");
    await workerDb.pool.end();
  } catch {
    // The worker pool exists only after the in-flight delivery imports it.
  }
});
