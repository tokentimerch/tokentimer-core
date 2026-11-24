"use strict";

const { before, after, test } = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { Client } = require("pg");

const name = "tt-store-upgrade-" + randomUUID();
let container, pool, migrations;
function docker(args) {
  const result = spawnSync("docker", args, { encoding: "utf8", timeout: 120000 });
  assert.equal(result.status, 0, result.stderr || String(result.error));
  return result.stdout.trim();
}
function migrate(database = process.env.DB_NAME) {
  const result = spawnSync(process.execPath, ["apps/api/migrations/migrate.js"], {
    encoding: "utf8", timeout: 120000, env: { ...process.env, DB_NAME: database },
  });
  assert.equal(result.status, 0, result.stderr || String(result.error));
}

async function applyHistory(client, registry) {
  await client.query("CREATE TABLE migrations (version INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL, executed_at TIMESTAMP DEFAULT NOW())");
  for (const entry of registry) {
    await client.query("BEGIN");
    try {
      await migrations.applyMigrationSql(client, entry);
      await client.query("INSERT INTO migrations(version,name) VALUES ($1,$2)", [entry.version, entry.name]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }
    await migrations.applyPostCommitSql(client, entry);
  }
}

async function withAppliedHistory(registry, check) {
  const database = "store_upgrade_" + randomUUID().replaceAll("-", "") + "_test";
  assert.match(database, /^store_upgrade_[a-f0-9]{32}_test$/);
  await pool.query(`CREATE DATABASE "${database}"`);
  const client = new Client({
    host: process.env.DB_HOST, port: Number(process.env.DB_PORT), database,
    user: process.env.DB_USER, password: process.env.DB_PASSWORD,
  });
  await client.connect();
  try {
    await applyHistory(client, registry);
    await check(client, database);
  } finally {
    await client.end();
  }
}

async function readLedger(client) {
  return (await client.query("SELECT version,name,executed_at FROM migrations ORDER BY version")).rows;
}

async function assertReceiptColumns(client) {
  const receiptFields = await client.query("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='certops_adcs_expected_identity_receipts'");
  for (const column of ["origin_xid", "committed_seen_at", "receipt_claim_expires_at"]) {
    assert.ok(receiptFields.rows.some(({ column_name }) => column_name === column), column);
  }
}

before(async () => {
  container = docker(["run", "-d", "--name", name, "--label", "tokentimer.test=store-migration-upgrade", "--memory=512m", "--cpus=2", "-p", "127.0.0.1::5432", "-e", "POSTGRES_USER=store_test", "-e", "POSTGRES_PASSWORD=isolated-store-only", "-e", "POSTGRES_DB=store_upgrade_ci_test", "postgres:16-alpine"]);
  const port = JSON.parse(docker(["inspect", container]))[0].NetworkSettings.Ports["5432/tcp"][0].HostPort;
  let ready = false;
  for (let i = 0; i < 240; i++) {
    if (spawnSync("docker", ["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "store_test"], { timeout: 10000 }).status === 0) { ready = true; break; }
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  assert.ok(ready, "The disposable PostgreSQL container did not become ready");
  Object.assign(process.env, { NODE_ENV: "test", DB_HOST: "127.0.0.1", DB_PORT: port, DB_NAME: "store_upgrade_ci_test", DB_USER: "store_test", DB_PASSWORD: "isolated-store-only" });
  ({ pool } = require("../../apps/api/db/database"));
  migrations = require("../../apps/api/migrations/migrate");
}, { timeout: 180000 });

after(async () => {
  if (pool) await pool.end();
  if (container) {
    const info = JSON.parse(docker(["inspect", container]))[0];
    assert.equal(info.Name, "/" + name);
    assert.equal(info.Config.Labels["tokentimer.test"], "store-migration-upgrade");
    docker(["rm", "--force", "--volumes", container]);
  }
});

test("upgrades a real main database with PagerDuty recovery at migration 114 and repeats safely", async () => {
  const client = await pool.connect();
  try {
    await applyHistory(client, migrations.migrations.filter(item => item.version <= 114));
    const before = await readLedger(client);
    assert.equal(before.at(-1).name, "distribution_pagerduty_recovery");
    migrate();
    const afterFirst = await client.query("SELECT version,name,executed_at FROM migrations WHERE version >= 109 ORDER BY version");
    assert.deepEqual(afterFirst.rows.map(({ version, name }) => [version, name]), [
      [109, "certops_period_creator_delete"],
      [110, "recipient_member_verification"],
      [111, "auto_sync_owner_username"],
      [112, "certops_retirement_dossiers"],
      [113, "certops_material_reconciliation"],
      [114, "distribution_pagerduty_recovery"],
      [115, "store_issuance_explicit_renewal_consent"],
      [116, "certops_acme_store_enrollment_identity"],
      [117, "certops_adcs_expected_identity_receipts"],
      [118, "certops_windows_iis_consent"],
      [119, "certops_material_adcs_operation_union"],
      [120, "certops_iis_absence_proofs"],
      [121, "certops_enrollment_jobs_index"],
      [122, "certops_observed_revocation"],
      [123, "agent_credential_rotations"],
      [124, "agent_credential_rotation_ack"],
      [125, "certops_adcs_preflight_lookup_index"],
      [126, "certops_adcs_receipt_deadline"],
      [127, "auto_sync_creation_expiration"],
      [128, "shared_sso_schema"],
      [129, "certops_acme_store_cancelled"],
    ]);
    const preserved = await client.query("SELECT version,name,executed_at FROM migrations WHERE version <= 114 ORDER BY version");
    assert.deepEqual(preserved.rows, before);
    const objects = await client.query("SELECT to_regclass('certops_acme_store_enrollments') AS acme, to_regclass('certops_adcs_expected_identity_receipts') AS adcs, to_regprocedure('certops_sync_open_management_automation()') AS sync");
    assert.ok(objects.rows[0].acme && objects.rows[0].adcs && objects.rows[0].sync);
    await assertReceiptColumns(client);
    const constraint = await client.query("SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conrelid='certificate_jobs'::regclass AND conname='certificate_jobs_operation_check'");
    for (const operation of ["cleanup-from-store", "reconcile-from-store", "adcs-installation-proof"]) assert.match(constraint.rows[0].definition, new RegExp(operation));
    migrate();
    const afterSecond = await client.query("SELECT version,name,executed_at FROM migrations WHERE version >= 109 ORDER BY version");
    assert.deepEqual(afterSecond.rows, afterFirst.rows);
  } finally { client.release(); }
}, { timeout: 180000 });

test("fills recovery 114 and revocation 122 without rewriting an applied canonical Store ledger", async () => {
  const missing = new Map([
    [114, "distribution_pagerduty_recovery"],
    [122, "certops_observed_revocation"],
  ]);
  const registry = migrations.migrations.filter(({ version }) => !missing.has(version));
  await withAppliedHistory(registry, async (client, database) => {
    const before = await readLedger(client);
    migrate(database);
    const upgraded = await readLedger(client);
    assert.deepEqual(upgraded.filter(({ version }) => !missing.has(version)), before);
    for (const [version, name] of missing) {
      assert.equal(upgraded.find((row) => row.version === version)?.name, name);
    }
    await assertReceiptColumns(client);
    migrate(database);
    assert.deepEqual(await readLedger(client), upgraded);
  });
}, { timeout: 180000 });

const retirementBase = ["certops_period_creator_delete", "recipient_member_verification",
  "auto_sync_owner_username", "certops_material_reconciliation"];
const recovery = "distribution_pagerduty_recovery";
const observedRevocation = "certops_observed_revocation";
const store = ["store_issuance_explicit_renewal_consent", "certops_acme_store_enrollment_identity",
  "certops_adcs_expected_identity_receipts"];
const receiptDeadline = "certops_adcs_receipt_deadline";
const iis = ["certops_windows_iis_consent", "certops_material_adcs_operation_union",
  "certops_iis_absence_proofs", "certops_enrollment_jobs_index"];
const rotationsAndPreflight = ["agent_credential_rotations", "agent_credential_rotation_ack",
  "certops_adcs_preflight_lookup_index"];
const tail = ["auto_sync_creation_expiration", "shared_sso_schema", "certops_acme_store_cancelled"];

for (const [history, applied, remaining] of [
  ["recovery-first", [recovery], [...store, ...iis, observedRevocation, ...rotationsAndPreflight, receiptDeadline, ...tail]],
  ["revocation-first", [recovery, observedRevocation], [...store, ...iis, ...rotationsAndPreflight, receiptDeadline, ...tail]],
  ["Store-first", [...store, receiptDeadline], [recovery, ...iis, observedRevocation, ...rotationsAndPreflight, ...tail]],
]) {
  test(`retirement preview with ${history} history upgrades and survives restart`, async () => {
    const findDefinition = (name) => {
      const entry = migrations.migrations.find((migration) => migration.name === name);
      assert.ok(entry, `Missing migration definition: ${name}`);
      return entry;
    };
    const recorded = [...retirementBase, ...applied];
    const registry = [
      ...migrations.migrations.filter(({ version }) => version <= 108),
      { ...findDefinition("certops_retirement_dossiers"), version: 109 },
      ...recorded.map((name, index) => ({ ...findDefinition(name), version: 110 + index })),
    ];
    await withAppliedHistory(registry, async (client, database) => {
      const before = await readLedger(client);
      migrate(database);
      const upgraded = await readLedger(client);
      assert.deepEqual(upgraded.slice(0, before.length), before);
      assert.deepEqual(upgraded.slice(before.length).map(({ version, name }) => [version, name]),
        remaining.map((name, index) => [before.at(-1).version + index + 1, name]));
      await assertReceiptColumns(client);
      migrate(database);
      assert.deepEqual(await readLedger(client), upgraded);
    });
  }, { timeout: 180000 });
}

test("settles only provably unstarted historical ACME Store cancellation", async () => {
  await withAppliedHistory(migrations.migrations.filter(({ version }) => version < 129), async (client, database) => {
    const before = await readLedger(client);
    const email = randomUUID() + "@example.test";
    const user = (await client.query(`INSERT INTO users(email,email_original,display_name,password_hash,auth_method,email_verified)
      VALUES($1::text,$1::text,'ACME Store upgrade','placeholder','local',true) RETURNING id`, [email])).rows[0].id;
    const workspaceId = randomUUID();
    await client.query("INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'ACME Store upgrade',$2,'oss')", [workspaceId, user]);
    const agentId = (await client.query(`INSERT INTO certops_agents(workspace_id,agent_id,name,agent_version,protocol_version,credential_prefix,credential_hash,status)
      VALUES($1,$2,'ACME Store','1','1.0.0',$3,$4,'active') RETURNING id`,
    [workspaceId, randomUUID(), "ttagent_" + randomUUID().replaceAll("-", "").slice(0, 16), "f".repeat(64)])).rows[0].id;
    const scenarios = [
      { status: "cancelled", attempts: 0, state: "keygen_intent", expected: "cancelled_no_effect" },
      { status: "rejected", attempts: 0, state: "keygen_intent", expected: "cancelled_no_effect" },
      { status: "cancelled", attempts: 1, state: "keygen_intent", expected: "keygen_intent" },
      { status: "cancelled", attempts: 0, state: "uncertain", expected: "uncertain" },
      { status: "orphaned_unknown_effect", attempts: 1, state: "keygen_intent", expected: "keygen_intent" },
    ];
    for (const scenario of scenarios) {
      const certificateId = (await client.query(`INSERT INTO managed_certificates(workspace_id,common_name)
        VALUES($1,'app.example.test') RETURNING id`, [workspaceId])).rows[0].id;
      const jobId = (await client.query(`INSERT INTO certificate_jobs
        (workspace_id,subject_type,subject_id,operation,status,assigned_agent_id,attempt_count,payload)
        VALUES($1,'managed_certificate',$2,'renew',$3,$4,$5,'{"target":{"type":"windows-cert-store"}}') RETURNING id`,
      [workspaceId, certificateId, scenario.status, agentId, scenario.attempts])).rows[0].id;
      scenario.id = (await client.query(`INSERT INTO certops_acme_store_enrollments
        (id,workspace_id,certificate_id,agent_id,original_job_id,current_job_id,container_name,request_bytes,request_sha256,state)
        VALUES(gen_random_uuid(),$1,$2,$3,$4,$4,$5,$6,$7,$8) RETURNING id`,
      [workspaceId, certificateId, agentId, jobId, "tokentimer-enr-" + randomUUID(),
        Buffer.from("{}"), "a".repeat(64), scenario.state])).rows[0].id;
    }
    migrate(database);
    for (const scenario of scenarios) {
      const result = await client.query("SELECT state FROM certops_acme_store_enrollments WHERE id=$1", [scenario.id]);
      assert.equal(result.rows[0].state, scenario.expected);
    }
    const upgraded = await readLedger(client);
    assert.deepEqual(upgraded.slice(0, before.length), before);
    migrate(database);
    assert.deepEqual(await readLedger(client), upgraded);
  });
}, { timeout: 180000 });
