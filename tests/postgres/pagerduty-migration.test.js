"use strict";

const { it, after } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const { pool } = require("../../apps/api/db/database");
const {
  migrations,
  runMigrations,
  validateMigrationHistory,
} = require("../../apps/api/migrations/migrate");
const {
  reconcilePagerDutyV79,
} = require("../../scripts/reconcile-pagerduty-v79.cjs");
const upgradeFrom = process.env.PAGERDUTY_UPGRADE_FROM || "78";
const legacy = upgradeFrom === "legacy79";

after(() => pool.end());

it(`upgrades ${upgradeFrom} without replaying PagerDuty SQL or losing history`, async () => {
  assert.ok(["78", "80", "legacy79"].includes(upgradeFrom));
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
  const pagerduty = migrations.find(
    (entry) => entry.name === "pagerduty_incident_lifecycle",
  );
  assert.equal(pagerduty.version, 81);
  const pending = migrations.splice(
    migrations.findIndex(
      (entry) => entry.version > (legacy ? 78 : Number(upgradeFrom)),
    ),
  );
  try {
    await runMigrations();
  } finally {
    migrations.push(...pending);
  }
  const priorLedger = (
    await pool.query("SELECT * FROM migrations ORDER BY version")
  ).rows;
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
  let originalIncident;
  let functionIds;
  let legacyExecutedAt;
  if (legacy) {
    const client = await pool.connect();
    try {
      // Reproduce the exact published preview DDL and its original ledger slot.
      await client.query("BEGIN");
      await client.query(pagerduty.sql);
      await client.query(
        "INSERT INTO migrations(version,name,executed_at) VALUES(79,'pagerduty_incident_lifecycle','2026-10-27 10:00:00')",
      );
      await client.query("COMMIT");
      const id = crypto.randomUUID();
      originalIncident = (
        await client.query(
          `INSERT INTO pagerduty_incidents
        (id,workspace_id,token_id,token_id_snapshot,destination_id,dedup_key,original_expiration,
         expiry_authority,risk_threshold_days,state,trigger_accepted_at,trigger_attempts,action_attempts,claim_id,trigger_alert_queue_id)
        VALUES($1,$2,$3,$3,$4,'tt:expiry:preview','2026-10-27','manual',30,'open',NOW(),3,3,$5,$6) RETURNING *`,
          [
            id,
            workspaceId,
            tokenId,
            "f".repeat(64),
            crypto.randomUUID(),
            alertId,
          ],
        )
      ).rows[0];
      functionIds = (
        await client.query(
          "SELECT oid,proname FROM pg_proc WHERE proname IN ('snapshot_expiry_alert_date','archive_changed_token_expiry_alerts') ORDER BY proname",
        )
      ).rows;
      const ledger = (
        await client.query("SELECT * FROM migrations ORDER BY version")
      ).rows;
      legacyExecutedAt = ledger.at(-1).executed_at;
      assert.throws(
        () => validateMigrationHistory(ledger),
        /PagerDuty preview migration 79 conflicts/,
      );
      const rejected = spawnSync(
        process.execPath,
        [path.resolve(__dirname, "../../apps/api/migrations/migrate.js")],
        { env: process.env, encoding: "utf8" },
      );
      assert.equal(
        rejected.status,
        1,
        "Normal migration runner must reject the colliding preview history",
      );
      assert.deepEqual(
        (await client.query("SELECT * FROM migrations ORDER BY version")).rows,
        ledger,
      );
      assert.deepEqual(await reconcilePagerDutyV79(client), {
        status: "validated",
        from: 79,
        to: 81,
      });
      assert.deepEqual(
        (await client.query("SELECT * FROM migrations ORDER BY version")).rows,
        ledger,
        "Preflight is read-only for persistent state",
      );
      await client.query(
        "ALTER TABLE pagerduty_incidents ALTER COLUMN state DROP DEFAULT",
      );
      await assert.rejects(
        reconcilePagerDutyV79(client, { apply: true }),
        /ledger schema differs/,
      );
      await client.query(
        "ALTER TABLE pagerduty_incidents ALTER COLUMN state SET DEFAULT 'trigger_pending'",
      );
      await client.query(
        "ALTER TABLE tokens DISABLE TRIGGER trg_archive_changed_token_expiry_alerts",
      );
      await assert.rejects(
        reconcilePagerDutyV79(client, { apply: true }),
        /trigger.*differs/,
      );
      await client.query(
        "ALTER TABLE tokens ENABLE TRIGGER trg_archive_changed_token_expiry_alerts",
      );
      await client.query(
        "ALTER FUNCTION snapshot_expiry_alert_date() SECURITY DEFINER",
      );
      await assert.rejects(
        reconcilePagerDutyV79(client, { apply: true }),
        /function.*differs/,
      );
      await client.query(
        "ALTER FUNCTION snapshot_expiry_alert_date() SECURITY INVOKER",
      );
      await client.query(
        "CREATE TABLE auto_sync_provider_stats(dummy INTEGER)",
      );
      await assert.rejects(
        reconcilePagerDutyV79(client, { apply: true }),
        /Unrecorded telemetry schema/,
      );
      await client.query("DROP TABLE auto_sync_provider_stats");
      await client.query(
        "INSERT INTO migrations(version,name) VALUES(80,'unexpected_history')",
      );
      await assert.rejects(
        reconcilePagerDutyV79(client, { apply: true }),
        /Expected exactly migrations/,
      );
      await client.query(
        "DELETE FROM migrations WHERE version=80 AND name='unexpected_history'",
      );
      // A late failure must roll back both the history move and telemetry DDL.
      await client.query(`CREATE FUNCTION reject_pd_history_commit() RETURNS TRIGGER LANGUAGE plpgsql AS $$
        BEGIN IF NEW.version=80 THEN RAISE EXCEPTION 'forced compatibility commit failure'; END IF; RETURN NEW; END; $$;
        CREATE CONSTRAINT TRIGGER reject_pd_history_commit AFTER INSERT ON migrations
          DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_pd_history_commit()`);
      await assert.rejects(
        reconcilePagerDutyV79(client, { apply: true }),
        /forced compatibility commit failure/,
      );
      assert.deepEqual(
        (await client.query("SELECT * FROM migrations ORDER BY version")).rows,
        ledger,
      );
      assert.equal(
        (
          await client.query(
            "SELECT to_regclass('public.auto_sync_provider_stats') AS relation",
          )
        ).rows[0].relation,
        null,
      );
      await client.query(
        "DROP TRIGGER reject_pd_history_commit ON migrations; DROP FUNCTION reject_pd_history_commit()",
      );
      const check = spawnSync(
        process.execPath,
        [
          path.resolve(__dirname, "../../scripts/reconcile-pagerduty-v79.cjs"),
          "--check",
        ],
        { env: process.env, encoding: "utf8" },
      );
      assert.equal(check.status, 0, check.stdout + check.stderr);
      assert.match(check.stdout, /"status":"validated"/);
      const apply = spawnSync(
        process.execPath,
        [
          path.resolve(__dirname, "../../scripts/reconcile-pagerduty-v79.cjs"),
          "--apply",
        ],
        { env: process.env, encoding: "utf8" },
      );
      assert.equal(apply.status, 0, apply.stdout + apply.stderr);
      assert.match(apply.stdout, /"status":"reconciled"/);
      await assert.rejects(
        reconcilePagerDutyV79(client, { apply: true }),
        /Expected exactly migrations/,
      );
    } finally {
      client.release();
    }
  }
  await runMigrations();
  assert.equal(
    (
      await pool.query(
        "SELECT 1 FROM migrations WHERE version=81 AND name='pagerduty_incident_lifecycle'",
      )
    ).rowCount,
    1,
  );
  assert.equal(
    (await pool.query("SELECT 1 FROM pagerduty_incidents")).rowCount,
    legacy ? 1 : 0,
    "No invented legacy correlation",
  );
  assert.deepEqual(
    (
      await pool.query(
        "SELECT * FROM migrations WHERE version<=$1 ORDER BY version",
        [legacy ? 78 : Number(upgradeFrom)],
      )
    ).rows,
    priorLedger,
  );
  const tail = (
    await pool.query(
      "SELECT version,name FROM migrations WHERE version>=79 ORDER BY version",
    )
  ).rows;
  assert.deepEqual(tail, [
    { version: 79, name: "auto_sync_provider_stats" },
    { version: 80, name: "auto_sync_run_metrics" },
    { version: 81, name: "pagerduty_incident_lifecycle" },
  ]);
  if (legacy) {
    assert.deepEqual(
      (
        await pool.query("SELECT * FROM pagerduty_incidents WHERE id=$1", [
          originalIncident.id,
        ])
      ).rows[0],
      originalIncident,
    );
    assert.equal(
      (
        await pool.query("SELECT executed_at FROM migrations WHERE version=81")
      ).rows[0].executed_at.getTime(),
      legacyExecutedAt.getTime(),
    );
    assert.deepEqual(
      (
        await pool.query(
          "SELECT oid,proname FROM pg_proc WHERE proname IN ('snapshot_expiry_alert_date','archive_changed_token_expiry_alerts') ORDER BY proname",
        )
      ).rows,
      functionIds,
      "Existing functions are never replaced",
    );
  }
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
    legacy ? 1 : 0,
  );
  // The real migration runner must be restart-safe and leave installed triggers
  // alone, rather than replaying CREATE TRIGGER on a committed migration.
  await runMigrations();
  assert.equal(
    (await pool.query("SELECT 1 FROM migrations WHERE version=81")).rowCount,
    1,
  );
});
