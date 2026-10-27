"use strict";

const { it, after } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { pool } = require("../../apps/api/db/database");
const {
  migrations,
  runMigrations,
} = require("../../apps/api/migrations/migrate");

after(() => pool.end());

it("upgrades a v78 database without backfilling legacy PagerDuty incidents or losing delivery history", async () => {
  assert.match(
    process.env.DB_NAME || "",
    /_migration_issue364_test$/,
    "Use a fresh disposable migration test database",
  );
  assert.equal(
    (await pool.query("SELECT to_regclass('migrations') AS name")).rows[0].name,
    null,
    "Migration upgrade test requires an empty database",
  );
  const migration = migrations.pop();
  assert.equal(migration.version, 79);
  try {
    await runMigrations();
  } finally {
    migrations.push(migration);
  }
  const userId = (
    await pool.query(`INSERT INTO users(email,display_name,password_hash)
    VALUES('migration-issue364@example.test','Migration test','test-only') RETURNING id`)
  ).rows[0].id;
  const workspaceId = crypto.randomUUID();
  await pool.query(
    "INSERT INTO workspaces(id,name,created_by) VALUES($1,'Upgrade fixture',$2)",
    [workspaceId, userId],
  );
  const tokenId = (
    await pool.query(
      `INSERT INTO tokens(user_id,workspace_id,name,type,expiration)
    VALUES($1,$2,'Legacy asset','api_key',CURRENT_DATE+1) RETURNING id`,
      [userId, workspaceId],
    )
  ).rows[0].id;
  const alertId = (
    await pool.query(
      `INSERT INTO alert_queue(user_id,token_id,alert_key,threshold_days,due_date,channels,status)
    VALUES($1,$2,$3,1,CURRENT_DATE,'["webhooks"]','sent') RETURNING id`,
      [userId, tokenId, `token_expiry:${tokenId}:poswin:1`],
    )
  ).rows[0].id;
  const logId = (
    await pool.query(
      `INSERT INTO alert_delivery_log(alert_queue_id,user_id,token_id,workspace_id,channel,status,metadata)
    VALUES($1,$2,$3,$4,'webhooks','success','{"kind":"pagerduty","urlHash":"historic"}') RETURNING id`,
      [alertId, userId, tokenId, workspaceId],
    )
  ).rows[0].id;
  await runMigrations();
  assert.equal(
    (await pool.query("SELECT 1 FROM migrations WHERE version=79")).rowCount,
    1,
  );
  assert.equal(
    (await pool.query("SELECT 1 FROM pagerduty_incidents")).rowCount,
    0,
    "No invented legacy correlation",
  );
  assert.equal(
    (
      await pool.query(
        "SELECT expiration_snapshot FROM alert_queue WHERE id=$1",
        [alertId],
      )
    ).rows[0].expiration_snapshot,
    null,
    "Historical sent rows must not acquire an invented source-date snapshot",
  );
  assert.equal(
    (await pool.query("SELECT 1 FROM alert_delivery_log WHERE id=$1", [logId]))
      .rowCount,
    1,
  );
  await pool.query(
    "UPDATE tokens SET expiration=CURRENT_DATE+180 WHERE id=$1",
    [tokenId],
  );
  assert.match(
    (
      await pool.query("SELECT alert_key FROM alert_queue WHERE id=$1", [
        alertId,
      ])
    ).rows[0].alert_key,
    /:previous_expiration:/,
  );
  assert.equal(
    (
      await pool.query(
        "SELECT 1 FROM alert_delivery_log WHERE id=$1 AND alert_queue_id=$2",
        [logId, alertId],
      )
    ).rowCount,
    1,
  );
  assert.equal(
    (await pool.query("SELECT 1 FROM pagerduty_incidents")).rowCount,
    0,
  );
  // The real migration runner must be restart-safe and leave installed triggers
  // alone, rather than replaying CREATE TRIGGER on a committed migration.
  await runMigrations();
  assert.equal(
    (await pool.query("SELECT 1 FROM migrations WHERE version=79")).rowCount,
    1,
  );
});
