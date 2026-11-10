"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");
const { Pool } = require("pg");
const verification = require("../../packages/recipient-verification");
const schema = `recipient_member_${process.pid}_${crypto.randomBytes(4).toString("hex")}`;
const pool = new Pool({
  host: process.env.RV_TEST_DB_HOST || "127.0.0.1", port: Number(process.env.RV_TEST_DB_PORT || 54329),
  database: process.env.RV_TEST_DB_NAME || "recipient_verification_test",
  user: process.env.RV_TEST_DB_USER || "tokentimer", password: process.env.RV_TEST_DB_PASSWORD || "password",
  max: 6, options: `-c search_path=${schema},public`,
});
const keys = ["TT_DEPLOYMENT", "RECIPIENT_VERIFICATION_MODE", "RECIPIENT_FINGERPRINT_SECRET"];
const previous = Object.fromEntries(keys.map(key => [key, process.env[key]]));
test.before(async () => {
  process.env.TT_DEPLOYMENT = "self-hosted";
  process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
  process.env.RECIPIENT_FINGERPRINT_SECRET = "member-postgres-test-only";
  await pool.query(`CREATE SCHEMA ${schema}`);
  await pool.query(`
    CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT);
    CREATE TABLE workspaces (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT DEFAULT 'Test');
    CREATE TABLE workspace_contacts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
      details JSONB NOT NULL DEFAULT '{}', phone_e164 TEXT, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await pool.query(fs.readFileSync(path.join(__dirname, "../../packages/recipient-verification/migration.sql"), "utf8"));
  await require("../helpers/recipient-member-schema.cjs")(pool);
});
test.beforeEach(async () => {
  await pool.query("DELETE FROM workspaces; DELETE FROM users; DELETE FROM notification_suppressions; DELETE FROM recipient_verification_events");
});
test.after(async () => {
  try { await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); } finally { await pool.end(); }
  for (const key of keys) {
    if (previous[key] === undefined) delete process.env[key];
    else process.env[key] = previous[key];
  }
});

async function seed({ email = "member@example.test", verified = true, method = "local", member = true } = {}) {
  const userId = (await pool.query(
    "INSERT INTO users (email,email_original,email_verified,auth_method) VALUES ($1,$1,$2,$3) RETURNING id",
    [email, verified, method])).rows[0].id;
  const workspaceId = (await pool.query("INSERT INTO workspaces DEFAULT VALUES RETURNING id")).rows[0].id;
  const contact = (await pool.query("INSERT INTO workspace_contacts (workspace_id,details,phone_e164) VALUES ($1,$2,'+14155550100') RETURNING *",
    [workspaceId, { email }])).rows[0];
  if (member) await pool.query("INSERT INTO workspace_memberships (workspace_id,user_id) VALUES ($1,$2)", [workspaceId, userId]);
  return { userId, workspaceId, contactId: contact.id, destination: email.trim().toLowerCase(), contact };
}
const decision = (row, channel = "email") => verification.canDeliverToRecipient({
  client: pool, workspaceId: row.workspaceId, contactId: row.contactId, channel,
  destination: channel === "email" ? row.destination : "+14155550100",
});
async function status(row, value, client = pool) {
  await client.query(`INSERT INTO contact_channel_verifications
    (workspace_id,contact_id,channel,destination_normalized,destination_fingerprint,status,consent_at,revoked_at)
    VALUES ($1,$2,'email',$3,$4,$5,CASE WHEN $5='verified' THEN NOW() ELSE NULL END,
      CASE WHEN $5='revoked' THEN NOW() ELSE NULL END)
    ON CONFLICT (workspace_id,contact_id,channel) DO UPDATE SET status=EXCLUDED.status,
      consent_at=EXCLUDED.consent_at,revoked_at=EXCLUDED.revoked_at`,
  [row.workspaceId, row.contactId, row.destination, verification.destinationFingerprint("email", row.destination), value]);
}

test("existing and newly joined verified members need no challenge or new consent record", async () => {
  const row = await seed({ email: " Member@Example.Test ", member: false });
  assert.equal((await decision(row)).allowed, false);
  await pool.query("INSERT INTO workspace_memberships (workspace_id,user_id) VALUES ($1,$2)", [row.workspaceId, row.userId]);
  assert.equal((await decision(row)).delivery_basis, "verified_member");
  await status(row, "pending");
  const invited = await verification.createInvitation({ pool, workspaceId: row.workspaceId, contactId: row.contactId,
    channel: "email", actorUserId: row.userId });
  assert.equal(invited.alreadyVerified, true);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM contact_verification_challenges")).rows[0].n, 0);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM contact_channel_verifications WHERE consent_at IS NOT NULL")).rows[0].n, 0);
  const listed = await verification.attachVerification(pool, row.workspaceId, [row.contact]);
  assert.equal(listed.items[0].verification.email.status, "verified");
  assert.equal(listed.items[0].verification.email.consent_at, null);
});

test("unverified members, aliases, other workspaces and WhatsApp cannot inherit email proof", async () => {
  const row = await seed({ verified: false, email: "first.last+tag@gmail.com" });
  assert.equal((await decision(row)).allowed, false);
  await pool.query("UPDATE users SET email_verified=TRUE WHERE id=$1", [row.userId]);
  assert.equal((await decision(row)).allowed, true);
  assert.equal((await decision(row, "whatsapp")).allowed, false);
  await pool.query("UPDATE users SET email_original='firstlast@gmail.com' WHERE id=$1", [row.userId]);
  assert.equal((await decision(row)).allowed, false);
  await pool.query("UPDATE users SET email_original=$2 WHERE id=$1", [row.userId, row.destination]);
  const workspaceId = (await pool.query("INSERT INTO workspaces DEFAULT VALUES RETURNING id")).rows[0].id;
  await pool.query("UPDATE workspace_memberships SET workspace_id=$2 WHERE user_id=$1", [row.userId, workspaceId]);
  assert.equal((await decision(row)).allowed, false);
});

test("federated accounts need exact provider proof, invalidated by any mailbox write", async () => {
  const row = await seed({ method: "sso" });
  assert.equal((await decision(row)).allowed, false);
  await pool.query("UPDATE users SET recipient_verified_email=$2 WHERE id=$1", [row.userId, row.destination]);
  assert.equal((await decision(row)).delivery_basis, "verified_member");
  await pool.query("UPDATE users SET email=email WHERE id=$1", [row.userId]);
  assert.equal((await decision(row)).allowed, false);
});

test("removing membership or losing account verification immediately removes inherited eligibility", async () => {
  const row = await seed();
  await pool.query("UPDATE users SET email_verified=FALSE WHERE id=$1", [row.userId]);
  assert.equal((await decision(row)).allowed, false);
  await pool.query("UPDATE users SET email_verified=TRUE WHERE id=$1", [row.userId]);
  await pool.query("DELETE FROM workspace_memberships WHERE user_id=$1", [row.userId]);
  assert.equal((await decision(row)).allowed, false);
  await status(row, "verified");
  assert.equal((await decision(row)).allowed, true);
});

test("revocation survives contact deletion and duplicate contacts until explicit reconfirmation", async () => {
  const row = await seed();
  const duplicate = (await pool.query("INSERT INTO workspace_contacts (workspace_id,details) VALUES ($1,$2) RETURNING *",
    [row.workspaceId, { email: row.destination }])).rows[0];
  await status(row, "revoked");
  const other = { ...row, contactId: duplicate.id, contact: duplicate };
  assert.equal((await decision(other)).code, "RECIPIENT_REVOKED");
  await pool.query("DELETE FROM workspace_contacts WHERE id=$1", [row.contactId]);
  assert.equal((await decision(other)).code, "RECIPIENT_REVOKED");
  await require("../helpers/recipient-member-schema.cjs")(pool);
  assert.equal((await decision(other)).allowed, false);
  await status(other, "verified");
  assert.equal((await decision(other)).allowed, true);
  await require("../helpers/recipient-member-schema.cjs")(pool);
  assert.equal((await decision(other)).allowed, true);
});

test("opt-out and active destination suppression always take precedence", async () => {
  const row = await seed();
  await status(row, "opted_out");
  assert.equal((await decision(row)).code, "RECIPIENT_OPTED_OUT");
  await status(row, "pending");
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM notification_suppressions WHERE reason='recipient_declined'")).rows[0].n, 1);
  assert.equal((await decision(row)).code, "RECIPIENT_OPTED_OUT");
  await pool.query("DELETE FROM workspace_contacts WHERE id=$1", [row.contactId]);
  row.contactId = (await pool.query("INSERT INTO workspace_contacts (workspace_id,details) VALUES ($1,$2) RETURNING id",
    [row.workspaceId, { email: row.destination }])).rows[0].id;
  assert.equal((await decision(row)).code, "RECIPIENT_OPTED_OUT");
});

test("upgrade preserves newer explicit confirmation over historical duplicate refusals", async () => {
  for (const refusal of ["opted_out", "revoked"]) {
    const row = await seed({ email: `${refusal}@example.test` });
    const duplicate = (await pool.query("INSERT INTO workspace_contacts (workspace_id,details) VALUES ($1,$2) RETURNING *",
      [row.workspaceId, { email: row.destination }])).rows[0];
    const other = { ...row, contactId: duplicate.id };
    await pool.query("ALTER TABLE contact_channel_verifications DISABLE TRIGGER USER");
    try {
      await status(row, refusal);
      await pool.query(`UPDATE contact_channel_verifications
        SET opted_out_at='2000-01-01', revoked_at='2000-01-01', updated_at='2000-01-01'
        WHERE contact_id=$1`, [row.contactId]);
      await status(other, "verified");
      await pool.query("UPDATE contact_channel_verifications SET consent_at='2001-01-01' WHERE contact_id=$1", [other.contactId]);
    } finally {
      await pool.query("ALTER TABLE contact_channel_verifications ENABLE TRIGGER USER");
    }
    await require("../helpers/recipient-member-schema.cjs")(pool);
    assert.equal((await decision(other)).allowed, true);
    await pool.query("DELETE FROM workspace_contacts WHERE id=$1", [other.contactId]);
    const recreated = (await pool.query("INSERT INTO workspace_contacts (workspace_id,details) VALUES ($1,$2) RETURNING id",
      [row.workspaceId, { email: row.destination }])).rows[0];
    await require("../helpers/recipient-member-schema.cjs")(pool);
    assert.equal((await decision({ ...row, contactId: recreated.id })).allowed, true);
  }
});

test("reconfirmation survives stale opt-outs, contact deletion and migration retries", async () => {
  for (const writer of ["current", "older"]) {
    const row = await seed({ email: `${writer}@example.test` });
    const duplicate = (await pool.query("INSERT INTO workspace_contacts (workspace_id,details) VALUES ($1,$2) RETURNING *",
      [row.workspaceId, { email: row.destination }])).rows[0];
    const other = { ...row, contactId: duplicate.id };
    await status(row, "opted_out");
    if (writer === "current") {
      const challenge = await verification.createInvitation({ pool, workspaceId: row.workspaceId,
        contactId: other.contactId, channel: "email", actorUserId: row.userId, recipientInitiated: true });
      assert.equal((await verification.consumeEmailChallenge({ pool, token: challenge.token, decision: "accept" })).ok, true);
    } else {
      await status(other, "verified");
      await pool.query("DELETE FROM notification_suppressions WHERE workspace_id=$1 AND reason='recipient_declined'", [row.workspaceId]);
    }
    await require("../helpers/recipient-member-schema.cjs")(pool);
    assert.equal((await decision(other)).allowed, true);
    await pool.query("DELETE FROM workspace_contacts WHERE id=$1", [other.contactId]);
    const recreated = (await pool.query("INSERT INTO workspace_contacts (workspace_id,details) VALUES ($1,$2) RETURNING id",
      [row.workspaceId, { email: row.destination }])).rows[0];
    await require("../helpers/recipient-member-schema.cjs")(pool);
    assert.equal((await decision({ ...row, contactId: recreated.id })).allowed, true);
    await status(row, "pending");
    await status(row, "opted_out");
    await require("../helpers/recipient-member-schema.cjs")(pool);
    assert.equal((await decision({ ...row, contactId: recreated.id })).code, "RECIPIENT_OPTED_OUT");
  }
});

test("upgrade keeps a historical refusal newer than duplicate confirmation", async () => {
  const row = await seed();
  const duplicate = (await pool.query("INSERT INTO workspace_contacts (workspace_id,details) VALUES ($1,$2) RETURNING id",
    [row.workspaceId, { email: row.destination }])).rows[0];
  await pool.query("ALTER TABLE contact_channel_verifications DISABLE TRIGGER USER");
  try {
    await status({ ...row, contactId: duplicate.id }, "verified");
    await pool.query("UPDATE contact_channel_verifications SET consent_at='2000-01-01' WHERE contact_id=$1", [duplicate.id]);
    await status(row, "opted_out");
    await pool.query("UPDATE contact_channel_verifications SET opted_out_at='2001-01-01' WHERE contact_id=$1", [row.contactId]);
  } finally {
    await pool.query("ALTER TABLE contact_channel_verifications ENABLE TRIGGER USER");
  }
  await require("../helpers/recipient-member-schema.cjs")(pool);
  assert.equal((await decision({ ...row, contactId: duplicate.id })).code, "RECIPIENT_OPTED_OUT");
});

test("concurrent reconfirmation and revocation serialize on the destination refusal", async () => {
  const row = await seed();
  const duplicate = (await pool.query("INSERT INTO workspace_contacts (workspace_id,details) VALUES ($1,$2) RETURNING id",
    [row.workspaceId, { email: row.destination }])).rows[0];
  const other = { ...row, contactId: duplicate.id };
  const first = await pool.connect();
  const second = await pool.connect();
  try {
    await first.query("BEGIN");
    await second.query("BEGIN");
    await second.query("SET LOCAL statement_timeout='3s'");
    await status(row, "verified", first);
    const revoking = status(other, "revoked", second);
    await first.query("COMMIT");
    await revoking;
    await second.query("COMMIT");
    assert.equal((await decision(row)).code, "RECIPIENT_REVOKED");
  } finally {
    await first.query("ROLLBACK");
    await second.query("ROLLBACK");
    first.release();
    second.release();
  }
});
