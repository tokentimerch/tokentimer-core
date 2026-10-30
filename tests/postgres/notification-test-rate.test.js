"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { Pool } = require("pg");
const verification = require("../../packages/recipient-verification");

const pool = new Pool({
  host: process.env.RV_TEST_DB_HOST || "127.0.0.1",
  port: Number(process.env.RV_TEST_DB_PORT || 54329),
  database: process.env.RV_TEST_DB_NAME || "notification_test_rate",
  user: process.env.RV_TEST_DB_USER || "tokentimer",
  password: process.env.RV_TEST_DB_PASSWORD || "password",
  max: 8,
});

async function applySchema() {
  await pool.query(`
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
    CREATE TABLE IF NOT EXISTS audit_events (
      id SERIAL PRIMARY KEY,
      occurred_at TIMESTAMP NOT NULL DEFAULT NOW(),
      actor_user_id INTEGER NULL,
      subject_user_id INTEGER NULL,
      action VARCHAR(64) NOT NULL,
      target_type VARCHAR(64),
      target_id INTEGER,
      channel VARCHAR(16),
      workspace_id UUID NULL,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb
    );
  `);
}

async function resetRows() {
  await pool.query("DELETE FROM audit_events");
  await pool.query("DELETE FROM workspace_contacts");
  await pool.query("DELETE FROM workspaces");
}

async function seed() {
  const workspace = await pool.query("INSERT INTO workspaces (name) VALUES ('Workspace') RETURNING id");
  const contact = await pool.query(
    `INSERT INTO workspace_contacts (workspace_id, phone_e164, details)
     VALUES ($1, $2, $3::jsonb) RETURNING id`,
    [workspace.rows[0].id, "+14155550100", JSON.stringify({ email: "person@example.com" })],
  );
  return { workspaceId: workspace.rows[0].id, contactId: contact.rows[0].id };
}

test.before(async () => {
  process.env.RECIPIENT_FINGERPRINT_SECRET = "postgres-recipient-verification-secret";
  process.env.TT_DEPLOYMENT = "self-hosted";
  delete process.env.RECIPIENT_VERIFICATION_MODE;
  await applySchema();
});

test.after(async () => {
  await pool.end();
});

test.beforeEach(async () => {
  await resetRows();
  process.env.TT_DEPLOYMENT = "self-hosted";
  delete process.env.RECIPIENT_VERIFICATION_MODE;
  process.env.RECIPIENT_TEST_PER_CONTACT_PER_DAY = "2";
  process.env.RECIPIENT_TEST_COOLDOWN_SECONDS = "120";
});

test("self-hosted off limits WhatsApp tests without the recipient verification migration", async () => {
  const seeded = await seed();
  const input = {
    pool,
    workspaceId: seeded.workspaceId,
    contactId: seeded.contactId,
    channel: "whatsapp",
    destination: "+14155550100",
  };
  const first = await verification.authorizeWorkspaceTest(input);
  assert.equal(first.destination, "+14155550100");
  await assert.rejects(
    () => verification.authorizeWorkspaceTest(input),
    (error) => error.code === "TEST_WHATSAPP_COOLDOWN",
  );
  await pool.query(
    `UPDATE audit_events SET occurred_at = NOW() - INTERVAL '10 minutes'
      WHERE metadata->>'bucket' LIKE '%:cool'`,
  );
  const second = await verification.authorizeWorkspaceTest(input);
  assert.equal(second.destination, "+14155550100");
  await pool.query(
    `UPDATE audit_events SET occurred_at = NOW() - INTERVAL '10 minutes'
      WHERE metadata->>'bucket' LIKE '%:cool'`,
  );
  await assert.rejects(
    () => verification.authorizeWorkspaceTest(input),
    (error) => error.code === "TEST_WHATSAPP_COOLDOWN" && /limit reached/.test(error.message),
  );
  const raced = await seed();
  const racedInput = { ...input, workspaceId: raced.workspaceId, contactId: raced.contactId };
  const parallel = await Promise.allSettled([
    verification.authorizeWorkspaceTest(racedInput),
    verification.authorizeWorkspaceTest(racedInput),
  ]);
  assert.equal(parallel.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(parallel.filter((result) => result.status === "rejected").length, 1);
  await assert.rejects(
    () => verification.authorizeWorkspaceTest({ ...input, destination: "+19998887777" }),
    (error) => error.code === "DESTINATION_MISMATCH",
  );
});

test("shadow still throttles tests and enforce fails closed without verification tables", async () => {
  const seeded = await seed();
  const input = {
    pool,
    workspaceId: seeded.workspaceId,
    contactId: seeded.contactId,
    channel: "whatsapp",
    destination: "+14155550100",
  };
  process.env.RECIPIENT_VERIFICATION_MODE = "shadow";
  const allowed = await verification.authorizeWorkspaceTest(input);
  assert.equal(allowed.destination, "+14155550100");
  await assert.rejects(
    () => verification.authorizeWorkspaceTest(input),
    (error) => error.code === "TEST_WHATSAPP_COOLDOWN",
  );
  process.env.TT_DEPLOYMENT = "cloud";
  delete process.env.RECIPIENT_VERIFICATION_MODE;
  await assert.rejects(
    () => verification.authorizeWorkspaceTest(input),
    (error) => error.status === 403 && error.code === "RECIPIENT_VERIFICATION_UNAVAILABLE",
  );
});
