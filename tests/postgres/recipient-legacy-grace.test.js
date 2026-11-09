"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { Pool } = require("pg");
const verification = require("../../packages/recipient-verification");
const grace = require("../../packages/recipient-verification/legacy-grace");

const schema = `recipient_grace_${process.pid}`;
const pool = new Pool({
  host: process.env.RV_TEST_DB_HOST || "127.0.0.1", port: Number(process.env.RV_TEST_DB_PORT || 54329),
  database: process.env.RV_TEST_DB_NAME || "recipient_verification_test",
  user: process.env.RV_TEST_DB_USER || "tokentimer", password: process.env.RV_TEST_DB_PASSWORD || "password",
  max: 6, options: `-c search_path=${schema},public`,
});
const migration = fs.readFileSync(path.join(__dirname, "../../packages/recipient-verification/migration.sql"), "utf8");
const graceMigration = fs.readFileSync(path.join(__dirname, "../../packages/recipient-verification/legacy-grace-migration.sql"), "utf8");
const envKeys = ["TT_DEPLOYMENT", "RECIPIENT_VERIFICATION_MODE", "RECIPIENT_VERIFICATION_LEGACY_GRACE", "RECIPIENT_FINGERPRINT_SECRET"];
const previousEnv = Object.fromEntries(envKeys.map(key => [key, process.env[key]]));

test.before(async () => {
  process.env.TT_DEPLOYMENT = "self-hosted";
  process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
  process.env.RECIPIENT_VERIFICATION_LEGACY_GRACE = "1";
  process.env.RECIPIENT_FINGERPRINT_SECRET = "grace-postgres-test-only";
  await pool.query(`CREATE SCHEMA ${schema}`);
  await pool.query(`
    CREATE TABLE users (id SERIAL PRIMARY KEY);
    CREATE TABLE workspaces (id UUID PRIMARY KEY DEFAULT gen_random_uuid());
    CREATE TABLE workspace_contacts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id UUID NOT NULL REFERENCES workspaces(id),
      first_name TEXT, last_name TEXT, phone_e164 TEXT, details JSONB NOT NULL DEFAULT '{}',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW() - INTERVAL '2 days',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW() - INTERVAL '2 days'
    );
    CREATE TABLE audit_events (
      actor_user_id INTEGER, subject_user_id INTEGER, action TEXT, target_type TEXT,
      channel TEXT, workspace_id UUID, metadata JSONB, occurred_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await pool.query(migration);
  await pool.query(graceMigration);
  const locking = fs.readFileSync(path.join(__dirname, "../../packages/recipient-verification/legacy-grace-locking-migration.sql"), "utf8");
  await pool.query(locking);
  await pool.query(graceMigration);
  await pool.query(locking);
});
test.after(async () => {
  try { await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); } finally { await pool.end(); }
  for (const key of envKeys) {
    if (previousEnv[key] === undefined) delete process.env[key];
    else process.env[key] = previousEnv[key];
  }
});
test.beforeEach(async () => {
  await pool.query("DELETE FROM workspace_contacts");
  await pool.query("DELETE FROM recipient_legacy_grace_snapshots");
  await pool.query("DELETE FROM notification_suppressions");
  await pool.query("DELETE FROM workspaces");
  await pool.query("DELETE FROM audit_events");
});

async function seed(options = {}) {
  const workspaceId = options.workspaceId || (await pool.query("INSERT INTO workspaces DEFAULT VALUES RETURNING id")).rows[0].id;
  const contact = (await pool.query(
    "INSERT INTO workspace_contacts (workspace_id, phone_e164, details) VALUES ($1, $2, $3) RETURNING *",
    [workspaceId, options.phone || "+14155550100", { email: options.email || "legacy@example.test" }],
  )).rows[0];
  return { workspaceId, contactId: contact.id, contact };
}

async function preview(workspaceId) {
  return grace.previewLegacyGrace({ pool, workspaceId,
    cutoffAt: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() });
}

async function activate(result) {
  return grace.activateLegacyGrace({ pool, snapshot: result.snapshot, expectedSha256: result.sha256, operator: "postgres-test" });
}

async function decision(seed, channel = "email", destination) {
  return verification.canDeliverToRecipient({ client: pool, workspaceId: seed.workspaceId, contactId: seed.contactId,
    channel, destination: destination || (channel === "email" ? seed.contact.details.email : seed.contact.phone_e164) });
}

async function setStatus(seed, status, channel = "email") {
  const destination = channel === "email" ? seed.contact.details.email : seed.contact.phone_e164;
  await pool.query(`INSERT INTO contact_channel_verifications
    (workspace_id, contact_id, channel, destination_normalized, destination_fingerprint, status, consent_at)
    VALUES ($1,$2,$3,$4,$5,$6, CASE WHEN $6='verified' THEN NOW() ELSE NULL END)
    ON CONFLICT (workspace_id,contact_id,channel) DO UPDATE SET status=EXCLUDED.status, consent_at=EXCLUDED.consent_at`,
  [seed.workspaceId, seed.contactId, channel, destination, verification.destinationFingerprint(channel, destination), status]);
}

test("migration is idempotent and preview does not activate or manufacture consent", async () => {
  const existing = await seed();
  const result = await preview(existing.workspaceId);
  assert.equal(result.recipients, 2);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM contact_channel_legacy_grants")).rows[0].n, 0);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM recipient_legacy_grace_snapshots")).rows[0].n, 0);
  assert.equal((await decision(existing)).allowed, false);
  await activate(result);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM contact_channel_verifications")).rows[0].n, 0);
  for (const channel of ["email", "whatsapp"]) {
    const allowed = await decision(existing, channel);
    assert.equal(allowed.allowed, true);
    assert.equal(allowed.mode, "enforce");
    assert.equal(allowed.delivery_basis, "legacy_grace");
    assert.equal(allowed.grace_expires_at, result.snapshot.expires_at);
  }
  const views = await verification.attachVerification(pool, existing.workspaceId, [existing.contact]);
  assert.equal(views.items[0].verification.email.status, "pending");
  assert.equal(views.items[0].verification.email.delivery_basis, "legacy_grace");
  assert.equal(views.verification_summary.email.verified, 0);
  assert.equal((await activate(result)).alreadyActivated, true);
});

test("new and recently changed contacts are excluded even if their contact creation is old", async () => {
  const eligible = await seed();
  const recent = await seed({ workspaceId: eligible.workspaceId, email: "new@example.test", phone: "+14155550101" });
  await pool.query("UPDATE workspace_contacts SET created_at=NOW(), updated_at=NOW() WHERE id=$1", [recent.contactId]);
  const changed = await seed({ workspaceId: eligible.workspaceId, email: "changed@example.test", phone: "+14155550102" });
  await pool.query("UPDATE workspace_contacts SET updated_at=NOW() WHERE id=$1", [changed.contactId]);
  const result = await preview(eligible.workspaceId);
  assert.ok(result.snapshot.recipients.every(row => row.contact_id === eligible.contactId));
  await activate(result);
  assert.equal((await decision(recent)).allowed, false);
  assert.equal((await decision(changed)).allowed, false);
  assert.equal((await decision(eligible, "email", "arbitrary@example.test")).allowed, false);
  const otherWorkspace = await seed();
  assert.equal((await decision(otherWorkspace)).allowed, false);
});

test("activation detects changes and changes-back after preview without trusting updated_at", async () => {
  const existing = await seed();
  const result = await preview(existing.workspaceId);
  await pool.query("UPDATE workspace_contacts SET details=jsonb_build_object('email','other@example.test') WHERE id=$1", [existing.contactId]);
  await pool.query("UPDATE workspace_contacts SET details=$2 WHERE id=$1", [existing.contactId, existing.contact.details]);
  await assert.rejects(activate(result), /changed or was removed/);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM recipient_legacy_grace_snapshots")).rows[0].n, 0);
});

test("destination changes permanently revoke only that channel, including a change back", async () => {
  const existing = await seed();
  await activate(await preview(existing.workspaceId));
  await pool.query("UPDATE workspace_contacts SET first_name='New display name' WHERE id=$1", [existing.contactId]);
  assert.equal((await decision(existing)).allowed, true);
  await pool.query("UPDATE workspace_contacts SET details=jsonb_build_object('email','other@example.test') WHERE id=$1", [existing.contactId]);
  assert.equal((await decision(existing, "email", "other@example.test")).allowed, false);
  assert.equal((await decision(existing, "whatsapp")).allowed, true);
  await pool.query("UPDATE workspace_contacts SET details=$2 WHERE id=$1", [existing.contactId, existing.contact.details]);
  assert.equal((await decision(existing)).allowed, false);
  await pool.query("UPDATE workspace_contacts SET phone_e164='+14155550199' WHERE id=$1", [existing.contactId]);
  await pool.query("UPDATE workspace_contacts SET phone_e164=$2 WHERE id=$1", [existing.contactId, existing.contact.phone_e164]);
  assert.equal((await decision(existing, "whatsapp")).allowed, false);
});

test("opt-out and manager revocation invalidate grace permanently, even if an invitation later makes consent pending", async () => {
  for (const status of ["opted_out", "revoked"]) {
    const existing = await seed({ email: `${status}@example.test` });
    await activate(await preview(existing.workspaceId));
    await setStatus(existing, status);
    assert.equal((await decision(existing)).allowed, false);
    await setStatus(existing, "pending");
    assert.equal((await decision(existing)).allowed, false);
    await setStatus(existing, "verified");
    assert.equal((await decision(existing)).allowed, true);
  }
});

test("suppression and post-preview refusals prevent activation and delivery", async () => {
  const existing = await seed();
  const result = await preview(existing.workspaceId);
  await setStatus(existing, "revoked");
  await assert.rejects(activate(result), /no longer eligible/);
  await setStatus(existing, "pending");
  await assert.rejects(activate(await preview(existing.workspaceId)), /no longer eligible/);
  const suppressible = await seed({ email: "suppressible@example.test" });
  await activate(await preview(suppressible.workspaceId));
  await pool.query(`INSERT INTO notification_suppressions (channel,destination_fingerprint,scope,workspace_id,reason)
    VALUES ('email',$1,'global',NULL,'verification_abuse')`, [verification.destinationFingerprint("email", suppressible.contact.details.email)]);
  const blocked = await decision(suppressible);
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.code, "RECIPIENT_SUPPRESSED");
});

test("saved-contact tests and digest destination checks use the same grace policy", async () => {
  const existing = await seed();
  await activate(await preview(existing.workspaceId));
  const savedTest = await verification.authorizeWorkspaceTest({ pool, workspaceId: existing.workspaceId,
    contactId: existing.contactId, channel: "whatsapp", destination: existing.contact.phone_e164 });
  assert.equal(savedTest.destination, existing.contact.phone_e164);
  await assert.rejects(verification.authorizeWorkspaceTest({ pool, workspaceId: existing.workspaceId,
    contactId: existing.contactId, channel: "whatsapp", destination: "+14155550199" }), { code: "DESTINATION_MISMATCH" });
  const digest = await verification.canDeliverToDestination({ client: pool, workspaceId: existing.workspaceId,
    channel: "email", destination: existing.contact.details.email });
  assert.equal(digest.delivery_basis, "legacy_grace");
  assert.equal(verification.confirmDigestConsent({ mode: digest.mode, finalAllowed: digest.allowed }).send, true);
});

test("expiry is checked against the database clock and a grant cannot be extended or re-enrolled", async () => {
  const existing = await seed();
  const result = await preview(existing.workspaceId);
  await activate(result);
  await assert.rejects(pool.query("UPDATE recipient_legacy_grace_snapshots SET expires_at=expires_at+INTERVAL '1 hour' WHERE id=$1", [result.snapshot.id]), /immutable/);
  const again = { ...result.snapshot, id: crypto.randomUUID() };
  await assert.rejects(grace.activateLegacyGrace({ pool, snapshot: again, expectedSha256: grace.snapshotDigest(again), operator: "test" }), /no longer eligible/);
  const expired = await seed({ email: "expired@example.test" });
  const snapshotId = crypto.randomUUID();
  await pool.query(`INSERT INTO recipient_legacy_grace_snapshots
    (id,snapshot_sha256,cutoff_at,captured_at,expires_at,activated_at,activated_by,recipient_count)
    VALUES ($1,$2,NOW()-INTERVAL '4 days',NOW()-INTERVAL '3 days',NOW()-INTERVAL '1 day',NOW()-INTERVAL '2 days','historical-test',1)`,
  [snapshotId, "a".repeat(64)]);
  await pool.query(`INSERT INTO contact_channel_legacy_grants
    (workspace_id,contact_id,channel,snapshot_id,destination_normalized,destination_fingerprint,source_version)
    VALUES ($1,$2,'email',$3,$4,$5,'1')`, [expired.workspaceId, expired.contactId, snapshotId,
    expired.contact.details.email, verification.destinationFingerprint("email", expired.contact.details.email)]);
  assert.equal((await decision(expired)).allowed, false);
  assert.equal((await decision(expired)).code, "RECIPIENT_NOT_VERIFIED");
});

test("early snapshot revocation and disabling the opt-in stop delivery without changing consent", async () => {
  const existing = await seed();
  const result = await preview(existing.workspaceId);
  await activate(result);
  process.env.RECIPIENT_VERIFICATION_LEGACY_GRACE = "0";
  assert.equal((await decision(existing)).allowed, false);
  process.env.RECIPIENT_VERIFICATION_LEGACY_GRACE = "1";
  assert.equal((await decision(existing)).allowed, true);
  await grace.revokeLegacyGrace({ pool, snapshotId: result.snapshot.id });
  assert.equal((await decision(existing)).allowed, false);
  assert.equal((await activate(result)).revoked, true);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM contact_channel_verifications")).rows[0].n, 0);
});

test("concurrent activation of the same reviewed snapshot is idempotent", async () => {
  const existing = await seed();
  const result = await preview(existing.workspaceId);
  const responses = await Promise.all([activate(result), activate(result)]);
  assert.equal(responses.filter(row => row.alreadyActivated).length, 1);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM contact_channel_legacy_grants")).rows[0].n, 2);
});

test("operator CLI previews, activates and revokes without manufacturing consent", async () => {
  const existing = await seed();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "recipient-grace-cli-"));
  const output = path.join(directory, "preview.json");
  const env = {
    ...process.env, NODE_ENV: "test", DB_HOST: pool.options.host, DB_PORT: String(pool.options.port),
    DB_USER: pool.options.user, DB_PASSWORD: pool.options.password, DB_NAME: pool.options.database,
    PGOPTIONS: `-c search_path=${schema},public`,
  };
  delete env.DB_SSL;
  delete env.PGSSLROOTCERT;
  const command = (...args) => {
    const result = spawnSync(process.execPath, [path.resolve(__dirname, "../../scripts/recipient-legacy-grace.cjs"), ...args],
      { env, encoding: "utf8", timeout: 15000 });
    assert.equal(result.status, 0, String(result.error || result.stderr));
    return result.stdout;
  };
  try {
    command("preview", "--before", new Date(Date.now() - 86400000).toISOString(),
      "--until", new Date(Date.now() + 86400000).toISOString(), "--workspace-id", existing.workspaceId, "--output", output);
    const snapshot = JSON.parse(fs.readFileSync(output, "utf8"));
    assert.equal((await decision(existing)).allowed, false);
    command("activate", "--input", output, "--sha256", grace.snapshotDigest(snapshot), "--operator", "cli-test", "--apply");
    assert.equal((await decision(existing)).delivery_basis, "legacy_grace");
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM contact_channel_verifications")).rows[0].n, 0);
    command("revoke", "--snapshot-id", snapshot.id, "--apply");
    assert.equal((await decision(existing)).allowed, false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("contact edits and direct consent revocation complete without deadlock", { timeout: 20000 }, async () => {
  for (const status of ["revoked", "opted_out"]) {
    const existing = await seed({ email: `deadlock-${status}@example.test` });
    await setStatus(existing, "pending");
    await activate(await preview(existing.workspaceId));
    const editor = await pool.connect();
    const revoker = await pool.connect();
    let revocation;
    let invalidation;
    const observe = (client, query) => query.then(
      () => ({ ok: true }),
      async error => {
        await client.query("ROLLBACK");
        return { ok: false, code: error.code };
      },
    );
    try {
      await editor.query("BEGIN");
      await revoker.query("BEGIN");
      await editor.query("SET LOCAL statement_timeout = '8s'");
      await revoker.query("SET LOCAL statement_timeout = '8s'");
      await editor.query("SELECT id FROM workspace_contacts WHERE id=$1 FOR UPDATE", [existing.contactId]);
      await editor.query("UPDATE workspace_contacts SET details=$2 WHERE id=$1", [existing.contactId, { email: "changed@example.test" }]);
      const pid = (await revoker.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
      revocation = observe(revoker, revoker.query(
        "UPDATE contact_channel_verifications SET status=$2 WHERE contact_id=$1 AND channel='email'",
        [existing.contactId, status],
      ));
      let blocked = false;
      for (let attempt = 0; attempt < 100; attempt += 1) {
        blocked = (await pool.query("SELECT cardinality(pg_blocking_pids($1)) > 0 AS blocked", [pid])).rows[0].blocked;
        if (blocked) break;
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      assert.equal(blocked, true, "Revocation waits for the verification locked by the contact edit");
      invalidation = observe(editor, verification.invalidateChangedDestination({
        client: editor, workspaceId: existing.workspaceId, contactId: existing.contactId, channel: "email",
        previousDestination: existing.contact.details.email, nextDestination: "changed@example.test",
      }));
      assert.deepEqual(await invalidation, { ok: true });
      await editor.query("COMMIT");
      assert.deepEqual(await revocation, { ok: true });
      await revoker.query("COMMIT");
      await pool.query("UPDATE contact_channel_verifications SET status='pending' WHERE contact_id=$1 AND channel='email'", [existing.contactId]);
      await pool.query("UPDATE workspace_contacts SET details=$2 WHERE id=$1", [existing.contactId, existing.contact.details]);
      assert.equal((await decision(existing)).allowed, false);
    } finally {
      await editor.query("ROLLBACK");
      await revoker.query("ROLLBACK");
      if (revocation) await revocation;
      if (invalidation) await invalidation;
      editor.release();
      revoker.release();
    }
  }
});

test("a direct refusal can finish before a concurrent contact edit or deletion", { timeout: 20000 }, async () => {
  for (const operation of ["edit", "delete"]) {
    for (const status of ["revoked", "opted_out"]) {
      const existing = await seed({ email: `${operation}-${status}@example.test` });
      await setStatus(existing, "pending");
      await activate(await preview(existing.workspaceId));
      const revoker = await pool.connect();
      const editor = await pool.connect();
      let edit;
      try {
        await revoker.query("BEGIN");
        await editor.query("BEGIN");
        await editor.query("SET LOCAL statement_timeout = '8s'");
        await revoker.query("UPDATE contact_channel_verifications SET status=$2 WHERE contact_id=$1 AND channel='email'", [existing.contactId, status]);
        const pid = (await editor.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
        edit = editor.query(operation === "delete"
          ? "DELETE FROM workspace_contacts WHERE id=$1"
          : "UPDATE workspace_contacts SET details=jsonb_build_object('email','changed@example.test') WHERE id=$1", [existing.contactId]);
        let blocked = false;
        for (let attempt = 0; attempt < 100; attempt += 1) {
          blocked = (await pool.query("SELECT cardinality(pg_blocking_pids($1)) > 0 AS blocked", [pid])).rows[0].blocked;
          if (blocked) break;
          await new Promise(resolve => setTimeout(resolve, 10));
        }
        assert.equal(blocked, true, "The contact operation must wait for the refusal");
        await revoker.query("COMMIT");
        await edit;
        await editor.query("COMMIT");
        if (operation === "edit") {
          await setStatus(existing, "pending");
          await pool.query("UPDATE workspace_contacts SET details=$2 WHERE id=$1", [existing.contactId, existing.contact.details]);
          assert.equal((await decision(existing)).allowed, false);
        } else {
          assert.equal((await pool.query("SELECT count(*)::int AS n FROM recipient_legacy_grace_refusals WHERE contact_id=$1", [existing.contactId])).rows[0].n, 0);
        }
      } finally {
        await revoker.query("ROLLBACK");
        if (edit) await edit.catch(() => {});
        await editor.query("ROLLBACK");
        revoker.release();
        editor.release();
      }
    }
  }
});

test("activation waits for an uncommitted refusal and fails closed", { timeout: 10000 }, async () => {
  for (const status of ["revoked", "opted_out"]) {
    const existing = await seed({ email: `uncommitted-${status}@example.test` });
    await setStatus(existing, "pending");
    const result = await preview(existing.workspaceId);
    const revoker = await pool.connect();
    let activation;
    try {
      await revoker.query("BEGIN");
      await revoker.query("UPDATE contact_channel_verifications SET status=$2 WHERE contact_id=$1 AND channel='email'", [existing.contactId, status]);
      let paused;
      const ready = new Promise(resolve => { paused = resolve; });
      const observedPool = { async connect() {
        const client = await pool.connect();
        return { release: () => client.release(), async query(sql, params) {
          if (sql.includes("INSERT INTO contact_channel_legacy_grants")) paused();
          return client.query(sql, params);
        } };
      } };
      activation = grace.activateLegacyGrace({ pool: observedPool, snapshot: result.snapshot,
        expectedSha256: result.sha256, operator: "race-test" });
      await ready;
      await revoker.query("COMMIT");
      await assert.rejects(activation, /no longer eligible/);
      await setStatus(existing, "pending");
      assert.equal((await decision(existing)).allowed, false);
    } finally {
      await revoker.query("ROLLBACK");
      if (activation) await activation.catch(() => {});
      revoker.release();
    }
  }
});

test("a refusal after preview remains effective after a pending reset before activation", async () => {
  for (const status of ["revoked", "opted_out"]) {
    const existing = await seed({ email: `reset-before-activation-${status}@example.test` });
    await setStatus(existing, "pending");
    const result = await preview(existing.workspaceId);
    await setStatus(existing, status);
    await setStatus(existing, "pending");
    await assert.rejects(activate(result), /no longer eligible/);
    assert.equal((await decision(existing)).allowed, false);
  }
});

test("revocation before grant insertion survives an immediate pending reset", { timeout: 10000 }, async () => {
  for (const status of ["revoked", "opted_out"]) {
    const existing = await seed({ email: `before-grant-${status}@example.test` });
    await setStatus(existing, "pending");
    const result = await preview(existing.workspaceId);
    let pause;
    const ready = new Promise(resolve => { pause = resolve; });
    let resume;
    const proceed = new Promise(resolve => { resume = resolve; });
    const delayedPool = { async connect() {
      const client = await pool.connect();
      return { release: () => client.release(), async query(sql, params) {
        if (sql.includes("INSERT INTO recipient_legacy_grace_snapshots")) {
          pause();
          await proceed;
        }
        return client.query(sql, params);
      } };
    } };
    const activation = grace.activateLegacyGrace({ pool: delayedPool, snapshot: result.snapshot,
      expectedSha256: result.sha256, operator: "race-test" });
    try {
      await ready;
      await setStatus(existing, status);
      await setStatus(existing, "pending");
      resume();
      await assert.rejects(activation, /no longer eligible/);
      assert.equal((await pool.query("SELECT count(*)::int AS n FROM contact_channel_legacy_grants WHERE contact_id=$1", [existing.contactId])).rows[0].n, 0);
      assert.equal((await decision(existing)).allowed, false);
    } finally {
      resume();
      await activation.catch(() => {});
    }
  }
});

test("concurrent direct revocation cannot miss a grant inserted by activation", { timeout: 10000 }, async () => {
  for (const status of ["revoked", "opted_out"]) {
    const existing = await seed({ email: `race-${status}@example.test` });
    await setStatus(existing, "pending");
    const result = await preview(existing.workspaceId);
    let paused;
    const ready = new Promise(resolve => { paused = resolve; });
    let resume;
    const proceed = new Promise(resolve => { resume = resolve; });
    const delayedPool = { async connect() {
      const client = await pool.connect();
      return { release: () => client.release(), async query(sql, params) {
        if (sql === "COMMIT") {
          paused();
          await proceed;
        }
        return client.query(sql, params);
      } };
    } };
    const activation = grace.activateLegacyGrace({ pool: delayedPool, snapshot: result.snapshot,
      expectedSha256: result.sha256, operator: "race-test" });
    const revoker = await pool.connect();
    let revocation;
    try {
      await ready;
      await revoker.query("BEGIN");
      const pid = (await revoker.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
      revocation = revoker.query("UPDATE contact_channel_verifications SET status=$2 WHERE contact_id=$1 AND channel='email'", [existing.contactId, status]);
      let blocked = false;
      for (let attempt = 0; attempt < 100; attempt += 1) {
        blocked = (await pool.query("SELECT cardinality(pg_blocking_pids($1)) > 0 AS blocked", [pid])).rows[0].blocked;
        if (blocked) break;
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      assert.equal(blocked, true, "Revocation must wait for activation's grant guard");
      resume();
      await activation;
      await revocation;
      await revoker.query("COMMIT");
      await pool.query("UPDATE contact_channel_verifications SET status='pending', revoked_at=NULL, opted_out_at=NULL WHERE contact_id=$1 AND channel='email'", [existing.contactId]);
      const grant = (await pool.query("SELECT revoked_at FROM contact_channel_legacy_grants WHERE contact_id=$1 AND channel='email'", [existing.contactId])).rows[0];
      assert.ok(grant.revoked_at);
      assert.equal((await decision(existing)).allowed, false);
    } finally {
      resume();
      await activation.catch(() => {});
      if (revocation) await revocation.catch(() => {});
      await revoker.query("ROLLBACK");
      revoker.release();
    }
  }
});
