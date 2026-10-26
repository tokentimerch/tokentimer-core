"use strict";

// Runs the delivery worker against a fully migrated application database.
// Start Postgres first:
//   docker run --name tt-rv-worker-pg -e POSTGRES_USER=tokentimer -e POSTGRES_PASSWORD=password -e POSTGRES_DB=tokentimer_delivery_worker -p 54330:5432 -d postgres:16

process.env.NODE_ENV = "test";
process.env.DB_HOST = process.env.DELIVERY_WORKER_DB_HOST || "127.0.0.1";
process.env.DB_PORT = process.env.DELIVERY_WORKER_DB_PORT || "54330";
process.env.DB_NAME = process.env.DELIVERY_WORKER_DB_NAME || "tokentimer_delivery_worker";
process.env.DB_USER = process.env.DELIVERY_WORKER_DB_USER || "tokentimer";
process.env.DB_PASSWORD = process.env.DELIVERY_WORKER_DB_PASSWORD || "password";
process.env.TT_DEPLOYMENT = "self-hosted";
process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
process.env.RECIPIENT_FINGERPRINT_SECRET = "delivery-worker-ledger-test-secret";
delete process.env.DB_SSL;
delete process.env.ENABLE_METRICS;

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const test = require("node:test");
const { Pool } = require("pg");
const verification = require("../../packages/recipient-verification");

const ROOT = path.join(__dirname, "..", "..");
const pool = new Pool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  max: 4,
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

async function createWorkspace(label, { contact, group, webhooks }) {
  const user = await pool.query(
    `INSERT INTO users (email, display_name, auth_method, password_hash, email_verified)
     VALUES ($1, $2, 'local', 'hash', true)
     RETURNING id`,
    [`ledger-worker-${label}-${Date.now()}@example.com`, label],
  );
  const userId = user.rows[0].id;
  const workspaceId = crypto.randomUUID();
  await pool.query(
    `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1, $2, 'oss', $3)`,
    [workspaceId, label, userId],
  );
  await pool.query(
    `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
     VALUES ($1, $2, 'admin', $1)`,
    [userId, workspaceId],
  );
  const contactId = crypto.randomUUID();
  await pool.query(
    `INSERT INTO workspace_contacts (id, workspace_id, first_name, last_name, phone_e164, details)
     VALUES ($1, $2, 'Ada', 'Lovelace', $3, $4::jsonb)`,
    [contactId, workspaceId, contact.phone || null, JSON.stringify({ email: contact.email || null })],
  );
  if (contact.verification) {
    const normalized = verification.normalizeDestination(contact.verification.channel, contact.verification.destination);
    await pool.query(
      `INSERT INTO contact_channel_verifications
         (workspace_id, contact_id, channel, destination_normalized, destination_fingerprint, status, opted_out_at, opt_out_method)
       VALUES ($1, $2, $3, $4, $5, $6, NOW(), 'recipient')`,
      [
        workspaceId,
        contactId,
        contact.verification.channel,
        normalized.value,
        verification.destinationFingerprint(contact.verification.channel, normalized.value),
        contact.verification.status,
      ],
    );
  }
  await pool.query(
    `INSERT INTO workspace_settings
       (workspace_id, contact_groups, default_contact_group_id, webhook_urls, email_alerts_enabled,
        webhooks_alerts_enabled, alert_thresholds, delivery_window_start, delivery_window_end, delivery_window_tz)
     VALUES ($1, $2::jsonb, $3, $4::jsonb, true, true, $5::jsonb, '00:00', '23:59', 'UTC')`,
    [
      workspaceId,
      JSON.stringify([{ id: "default", name: "Default", ...group }]),
      "default",
      JSON.stringify(webhooks),
      JSON.stringify([7]),
    ],
  );
  const token = await pool.query(
    `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
     VALUES ($1, $2, $1, $3, CURRENT_DATE + INTERVAL '7 days', 'api_key', 'general')
     RETURNING id`,
    [userId, workspaceId, label],
  );
  const tokenId = token.rows[0].id;
  await pool.query(
    `INSERT INTO token_contact_groups (token_id, workspace_id, contact_group_id)
     VALUES ($1, $2, 'default')`,
    [tokenId, workspaceId],
  );
  return { userId, workspaceId, contactId, tokenId };
}

async function enqueue(row, channels) {
  const inserted = await pool.query(
    `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date, channels, status)
     VALUES ($1, $2, $3, 7, CURRENT_DATE, $4::jsonb, 'pending')
     RETURNING id`,
    [row.userId, row.tokenId, `ledger-worker:${row.tokenId}:${crypto.randomUUID()}`, JSON.stringify(channels)],
  );
  return inserted.rows[0].id;
}

async function loadAlert(id) {
  const result = await pool.query(
    `SELECT status, attempts, channels, error_message, delivery_claim_id
       FROM alert_queue WHERE id = $1`,
    [id],
  );
  return result.rows[0];
}

test("delivery worker records ledger outcomes and notifications on a migrated database", async () => {
  migrate();
  await pool.query(
    `DELETE FROM alert_delivery_log
      WHERE alert_queue_id IN (SELECT id FROM alert_queue WHERE alert_key LIKE 'ledger-worker:%')`,
  );
  await pool.query("DELETE FROM alert_queue WHERE alert_key LIKE 'ledger-worker:%'");
  const mixed = await createWorkspace("mixed", {
    contact: { email: "unverified@example.com" },
    group: { email_contact_ids: [], webhook_names: ["Private"] },
    webhooks: [{ name: "Private", url: "http://127.0.0.1/__permanent__", kind: "generic" }],
  });
  await pool.query(
    `UPDATE workspace_settings
        SET contact_groups = $2::jsonb
      WHERE workspace_id = $1`,
    [mixed.workspaceId, JSON.stringify([{
      id: "default",
      name: "Default",
      email_contact_ids: [mixed.contactId],
      webhook_names: ["Private"],
    }])],
  );
  const transient = await createWorkspace("transient", {
    contact: { email: "nobody@example.com" },
    group: { webhook_names: ["Slack"] },
    webhooks: [{ name: "Slack", url: "https://hooks.slack.com/services/T0/B0/__fail__", kind: "slack" }],
  });
  const opted = await createWorkspace("opted", {
    contact: {
      phone: "+14155550100",
      verification: { channel: "whatsapp", destination: "+14155550100", status: "opted_out" },
    },
    group: { whatsapp_contact_ids: [] },
    webhooks: [],
  });
  await pool.query(
    `UPDATE workspace_settings SET contact_groups = $2::jsonb WHERE workspace_id = $1`,
    [opted.workspaceId, JSON.stringify([{
      id: "default",
      name: "Default",
      whatsapp_contact_ids: [opted.contactId],
    }])],
  );

  const mixedId = await enqueue(mixed, ["email", "webhooks"]);
  const transientId = await enqueue(transient, ["webhooks"]);
  const optedId = await enqueue(opted, ["whatsapp"]);

  const { deliveryWorkerJob } = await import("../../apps/worker/src/delivery-worker.js");
  const sender = async () => ({ success: true });
  await deliveryWorkerJob({ closePool: false, incidentEmailSender: sender });

  const mixedRow = await loadAlert(mixedId);
  assert.equal(mixedRow.status, "blocked");
  assert.equal(mixedRow.delivery_claim_id, null);
  assert.equal(mixedRow.channels.version, 1);
  assert.equal(mixedRow.channels.outcomes.email.state, "blocked");
  assert.equal(mixedRow.channels.outcomes.email.reason, "eligibility");
  assert.equal(mixedRow.channels.outcomes.webhooks.reason, "provider");
  assert.equal(mixedRow.channels.outcomes.webhooks.terminal, true);
  assert.deepEqual(mixedRow.channels.retry, []);
  assert.match(mixedRow.error_message, /NO_VERIFIED_RECIPIENTS/);
  assert.match(mixedRow.error_message, /PERMANENT_DELIVERY_FAILURE/);
  const mixedNotes = await pool.query(
    `SELECT type, message FROM operational_notifications
      WHERE workspace_id = $1 AND resolved_at IS NULL
      ORDER BY type`,
    [mixed.workspaceId],
  );
  const mixedTypes = mixedNotes.rows.map((row) => row.type).sort();
  assert.deepEqual(mixedTypes, ["delivery_unverified_recipients", "delivery_webhook_permanent"]);
  const unverified = mixedNotes.rows.find((row) => row.type === "delivery_unverified_recipients");
  assert.match(unverified.message, /confirmed/);
  assert.doesNotMatch(unverified.message, /webhook/i);

  const transientRow = await loadAlert(transientId);
  assert.equal(transientRow.status, "failed");
  assert.equal(transientRow.channels.version, 1);
  assert.deepEqual(transientRow.channels.retry, ["webhooks"]);
  assert.equal(transientRow.channels.outcomes.webhooks.terminal, false);
  const transientNotes = await pool.query(
    `SELECT type FROM operational_notifications WHERE workspace_id = $1`,
    [transient.workspaceId],
  );
  assert.deepEqual(transientNotes.rows, []);

  const optedRow = await loadAlert(optedId);
  assert.equal(optedRow.status, "blocked");
  assert.equal(optedRow.channels.outcomes.whatsapp.reason, "eligibility");
  assert.match(optedRow.error_message, /RECIPIENT_OPTED_OUT/);
  const optedNote = await pool.query(
    `SELECT message FROM operational_notifications
      WHERE workspace_id = $1 AND type = 'delivery_unverified_recipients'`,
    [opted.workspaceId],
  );
  assert.match(optedNote.rows[0].message, /opted out/);

  const listed = verification.publicDeliveryChannels(mixedRow.channels);
  assert.deepEqual(listed.map((row) => row.channel), ["email", "webhooks"]);
  assert.equal(listed[0].channel_state, "blocked");
  assert.equal(Object.hasOwn(listed[0], "endpoints"), false);

  const reconciled = verification.reconcileDeliveryChannels(transientRow.channels, ["webhooks"]);
  assert.equal(reconciled.changed, false);
  const wiped = await pool.query(
    `UPDATE alert_queue
        SET channels = $1, updated_at = NOW()
      WHERE id = $2
        AND status = ANY($3::text[])
        AND delivery_claim_id IS NULL
        AND channels = $4`,
    [JSON.stringify(["email"]), transientId, ["pending", "failed", "partial"], JSON.stringify({ version: 0 })],
  );
  assert.equal(wiped.rowCount, 0);
  const stillThere = await loadAlert(transientId);
  assert.equal(stillThere.channels.outcomes.webhooks.state, "failed");

  const added = verification.reconcileDeliveryChannels(stillThere.channels, ["webhooks", "email"]);
  assert.equal(added.changed, true);
  assert.equal(added.channels.outcomes.webhooks.terminal, false);
  assert.ok(added.channels.retry.includes("email"));
  assert.ok(added.channels.retry.includes("webhooks"));
  const repeat = verification.reconcileDeliveryChannels(added.channels, ["webhooks", "email"]);
  assert.equal(repeat.changed, false);

  const emailLogsBefore = await pool.query(
    `SELECT COUNT(*)::int AS n FROM alert_delivery_log WHERE alert_queue_id = $1 AND channel = 'email'`,
    [mixedId],
  );
  const webhookLogsBefore = await pool.query(
    `SELECT COUNT(*)::int AS n FROM alert_delivery_log WHERE alert_queue_id = $1 AND channel = 'webhooks'`,
    [mixedId],
  );
  const retry = verification.planManualRetry(mixedRow.channels, "email");
  assert.equal(retry.ok, false);
  assert.equal(retry.code, "NO_VERIFIED_RECIPIENTS");
  const reopen = verification.planManualRetry(mixedRow.channels, "webhooks");
  assert.equal(reopen.ok, true);
  assert.equal(reopen.channels.outcomes.email.reason, "eligibility");
  assert.equal(reopen.channels.outcomes.webhooks.reopened, true);
  await pool.query(
    `UPDATE alert_queue
        SET status = 'pending', channels = $2, next_attempt_at = NOW(), delivery_claim_id = NULL
      WHERE id = $1 AND user_id = $3`,
    [mixedId, JSON.stringify(reopen.channels), mixed.userId],
  );
  await pool.query(
    `UPDATE alert_queue SET status = 'limit_exceeded' WHERE id = ANY($1::int[])`,
    [[transientId, optedId]],
  );

  await deliveryWorkerJob({ closePool: false, incidentEmailSender: sender });
  const afterRetry = await loadAlert(mixedId);
  assert.equal(afterRetry.channels.version, 1);
  assert.equal(afterRetry.channels.outcomes.email.state, "blocked");
  assert.equal(afterRetry.channels.outcomes.email.reason, "eligibility");
  assert.deepEqual(afterRetry.channels.retry, []);
  const emailLogsAfter = await pool.query(
    `SELECT COUNT(*)::int AS n FROM alert_delivery_log WHERE alert_queue_id = $1 AND channel = 'email'`,
    [mixedId],
  );
  const webhookLogsAfter = await pool.query(
    `SELECT COUNT(*)::int AS n FROM alert_delivery_log WHERE alert_queue_id = $1 AND channel = 'webhooks'`,
    [mixedId],
  );
  assert.equal(emailLogsAfter.rows[0].n, emailLogsBefore.rows[0].n);
  assert.ok(webhookLogsAfter.rows[0].n > webhookLogsBefore.rows[0].n);
});

test.after(async () => {
  await pool.end();
  try {
    const db = await import("../../apps/worker/src/db.js");
    await db.pool.end();
  } catch {
    // The worker pool exists only after the job imported it.
  }
});
