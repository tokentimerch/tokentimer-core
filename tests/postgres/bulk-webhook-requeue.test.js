"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const Module = require("node:module");
const path = require("node:path");
const fs = require("node:fs");
const { randomBytes } = require("node:crypto");
const { Pool } = require("pg");
const verification = require("../../packages/recipient-verification");

const workspaceId = "11111111-1111-4111-8111-111111111111";
const cloud = fs.existsSync(path.resolve(__dirname, "../../apps/saas/services/alertQueue.js"));
const servicePath = path.resolve(__dirname, cloud
  ? "../../apps/saas/services/alertQueue.js"
  : "../../apps/api/services/alertQueue.js");
const schema = `bulk_requeue_${randomBytes(8).toString("hex")}`;
const database = process.env.DB_NAME;
if (!database?.endsWith("_test") || process.env.DB_HOST !== "127.0.0.1" || !process.env.DB_PORT) {
  throw new Error("An isolated loopback database ending in _test is required");
}
const pool = new Pool({
  host: "127.0.0.1", port: Number(process.env.DB_PORT), user: process.env.DB_USER,
  password: process.env.DB_PASSWORD, database, max: 2, options: `-c search_path=${schema}`,
});

function loadService() {
  const original = Module._load;
  delete require.cache[servicePath];
  Module._load = function (request, parent, isMain) {
    if (parent?.filename === servicePath && request === "../db/database") return { pool };
    if (parent?.filename === servicePath && request === "./rbac") return { currentWorkspaceAccessSql: (_workspace, actor) => `${actor}::integer IS NOT NULL` };
    if (parent?.filename === servicePath && request === "@tokentimer/alert-eligibility") return { resolvedTokenWorkspaceSql: () => "t.workspace_id" };
    return original.call(this, request, parent, isMain);
  };
  try { return require(servicePath); } finally { Module._load = original; }
}

test.before(async () => {
  await pool.query(`CREATE SCHEMA ${schema}`);
  await pool.query(`
    CREATE TABLE tokens(id int PRIMARY KEY, workspace_id uuid);
    CREATE TABLE certops_agents(id int PRIMARY KEY, workspace_id uuid);
    CREATE TABLE alert_queue(
      id int PRIMARY KEY, user_id int, token_id int, certops_agent_id int, status text,
      error_message text, channels jsonb, attempts int DEFAULT 1, attempts_email int DEFAULT 1,
      attempts_webhooks int DEFAULT 1, attempts_whatsapp int DEFAULT 1,
      next_attempt_at timestamptz, updated_at timestamptz
    );
    CREATE TABLE pagerduty_incidents(
      id int PRIMARY KEY, workspace_id uuid, trigger_alert_queue_id int, retry_exhausted boolean,
      action_attempts int, next_attempt_at timestamptz, updated_at timestamptz,
      state text, claimed_until timestamptz
    );
    CREATE TABLE operational_notifications(workspace_id uuid, dedupe_key text, resolved_at timestamptz, updated_at timestamptz);
  `);
  await pool.query("INSERT INTO tokens VALUES (1, $1)", [workspaceId]);
});
test.after(async () => {
  try { await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); } finally { await pool.end(); }
});

for (const scoped of [true, false]) {
  test(`bulk ${scoped ? "workspace" : "account"} requeue reopens only the failed webhook generation`, async () => {
    await pool.query("TRUNCATE alert_queue");
    const ledger = {
      version: 1, retry: [], required: ["email", "webhooks"],
      outcomes: {
        email: { state: "sent", terminal: true },
        webhooks: { state: "partial", terminal: true, reason: "provider", retryGeneration: 0,
          endpoints: { sent: "sent", failed: "permanent" } },
      },
    };
    await pool.query("INSERT INTO alert_queue (id,user_id,token_id,status,error_message,channels) VALUES (1,1,1,'partial','provider failed',$1::jsonb)", [JSON.stringify(ledger)]);
    const count = await loadService().requeueAlertsCore({ userId: 1, workspaceId: scoped ? workspaceId : null });
    assert.equal(count, 1);
    const result = (await pool.query("SELECT status, channels FROM alert_queue WHERE id=1")).rows[0];
    assert.equal(result.status, "pending");
    assert.deepEqual(result.channels.retry, ["webhooks"]);
    assert.equal(result.channels.outcomes.webhooks.retryGeneration, 1);
    assert.deepEqual(result.channels.outcomes.webhooks.endpoints, ledger.outcomes.webhooks.endpoints);
    assert.equal(result.channels.outcomes.email.state, "sent");
    const oldFailure = [{ channel: "webhooks", status: "failed", metadata: { urlHash: "failed", terminal: true, retryGeneration: 0 } }];
    assert.deepEqual(verification.webhookPermanentHashes(oldFailure, result.channels), []);
  });
}

test("legacy ledgers and consent outcomes stay unchanged during bulk requeue", async () => {
  await pool.query("TRUNCATE alert_queue");
  const consent = { version: 1, retry: [], required: ["email"], outcomes: {
    email: { state: "blocked", terminal: true, reason: "eligibility", code: "RECIPIENT_OPTED_OUT" },
  } };
  await pool.query("INSERT INTO alert_queue (id,user_id,token_id,status,error_message,channels) VALUES (1,1,1,'blocked','recipient blocked',$1::jsonb),(2,1,1,'failed','temporary',$2::jsonb)", [JSON.stringify(consent), JSON.stringify(["email"])]);
  assert.equal(await loadService().requeueAlertsCore({ userId: 1, workspaceId }), 2);
  const rows = (await pool.query("SELECT id,channels FROM alert_queue ORDER BY id")).rows;
  assert.deepEqual(rows[0].channels, consent);
  assert.deepEqual(rows[1].channels, ["email"]);
});
