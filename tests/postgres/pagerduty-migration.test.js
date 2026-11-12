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
const legacy = upgradeFrom.startsWith("legacy");
const previewVersion = legacy ? Number(upgradeFrom.slice(6)) : null;

after(() => pool.end());

it(`upgrades ${upgradeFrom} without replaying PagerDuty SQL or losing history`, async () => {
  assert.ok(
    ["78", "80", "81", "82", "92", "94", "legacy79", "legacy81"].includes(upgradeFrom),
  );
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
  assert.equal(pagerduty.version, 92);
  const pending = migrations.splice(
    migrations.findIndex(
      (entry) =>
        entry.version > (legacy ? previewVersion - 1 : Number(upgradeFrom)),
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
  const existingTelemetry =
    (legacy ? previewVersion - 1 : Number(upgradeFrom)) >= 79;
  if (existingTelemetry)
    await pool.query(
      "UPDATE auto_sync_provider_stats SET items_created_total=17 WHERE provider='github'",
    );
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
  const originalExpirationSnapshot = ["92", "94"].includes(upgradeFrom) ? (await pool.query(
    "SELECT expiration_snapshot::text FROM alert_queue WHERE id=$1", [alertId],
  )).rows[0]?.expiration_snapshot : null;
  let functionIds;
  let legacyExecutedAt;
  let operatorIncident;
  if (upgradeFrom === "94") {
    operatorIncident = (await pool.query(`INSERT INTO pagerduty_incidents
      (id,workspace_id,token_id,token_id_snapshot,destination_id,dedup_key,original_expiration,
       expiry_authority,risk_threshold_days,state,trigger_accepted_at,trigger_alert_queue_id,
       resolution_reason,operator_reason,requested_by,manual_suppression_active,resolve_requested_at,recovery_expiration,resolved_at)
      VALUES($1,$2,$3,$3,$4,'tt:expiry:operator',CURRENT_DATE+1,'manual',7,'resolved',NOW(),$5,
       'manual_resolve','Handled by operations',$6,TRUE,NOW(),CURRENT_DATE+1,NOW()) RETURNING *`,
    [crypto.randomUUID(),workspaceId,tokenId,"f".repeat(64),alertId,userId])).rows[0];
    await pool.query("INSERT INTO pagerduty_ack_requests(incident_id,requested_by,accepted_at,attempts) VALUES($1,$2,NOW(),1)",[operatorIncident.id,userId]);
    await pool.query("INSERT INTO pagerduty_lookup_credentials(workspace_id,destination_id,token_encrypted,region) VALUES($1,$2,'synthetic-retired-credential','eu')",[workspaceId,"f".repeat(64)]);
  }
  if (legacy) {
    const client = await pool.connect();
    try {
      // Reproduce the exact published preview DDL and its original ledger slot.
      await client.query("BEGIN");
      await client.query(pagerduty.sql);
      await client.query(
        "INSERT INTO migrations(version,name,executed_at) VALUES($1,'pagerduty_incident_lifecycle','2026-10-27 10:00:00')",
        [previewVersion],
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
        /PagerDuty preview migration (79|81) conflicts/,
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
        from: previewVersion,
        to: 92,
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
      await client.query("CREATE TABLE auto_sync_kind_stats(dummy INTEGER)");
      await assert.rejects(
        reconcilePagerDutyV79(client, { apply: true }),
        /Unrecorded telemetry schema/,
      );
      await client.query("DROP TABLE auto_sync_kind_stats");
      await client.query("ALTER TABLE system_settings ADD COLUMN auto_sync_metrics JSONB NOT NULL DEFAULT '{}'::jsonb");
      await assert.rejects(reconcilePagerDutyV79(client, { apply: true }), /Unrecorded telemetry schema/);
      await client.query("ALTER TABLE system_settings DROP COLUMN auto_sync_metrics");
      await client.query(
        "INSERT INTO migrations(version,name) VALUES($1,'unexpected_history')",
        [previewVersion + 1],
      );
      await assert.rejects(
        reconcilePagerDutyV79(client, { apply: true }),
        /Expected exactly/,
      );
      await client.query(
        "DELETE FROM migrations WHERE version=$1 AND name='unexpected_history'",
        [previewVersion + 1],
      );
      // A late failure must roll back both the history move and telemetry DDL.
      await client.query(`CREATE FUNCTION reject_pd_history_commit() RETURNS TRIGGER LANGUAGE plpgsql AS $$
        BEGIN IF NEW.version=81 THEN RAISE EXCEPTION 'forced compatibility commit failure'; END IF; RETURN NEW; END; $$;
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
            "SELECT to_regclass('public.auto_sync_kind_stats') AS relation",
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
        /Expected exactly/,
      );
    } finally {
      client.release();
    }
  }
  await runMigrations();
  assert.equal(
    (
      await pool.query(
        "SELECT 1 FROM migrations WHERE version=92 AND name='pagerduty_incident_lifecycle'",
      )
    ).rowCount,
    1,
  );
  assert.equal(
    (await pool.query("SELECT 1 FROM pagerduty_incidents")).rowCount,
    legacy || operatorIncident ? 1 : 0,
    "No invented legacy correlation",
  );
  assert.deepEqual(
    (
      await pool.query(
        "SELECT * FROM migrations WHERE version<=$1 ORDER BY version",
        [legacy ? previewVersion - 1 : Number(upgradeFrom)],
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
    { version: 81, name: "auto_sync_metric_labels" },
    { version: 82, name: "auto_sync_system_metrics" },
    { version: 83, name: "certops_material_providers" },
    { version: 84, name: "recipient_channel_verification" },
    { version: 85, name: "weekly_digest_recipient_claim_token" },
    { version: 92, name: "pagerduty_incident_lifecycle" },
    { version: 93, name: "pagerduty_resolution_reason" },
    { version: 94, name: "pagerduty_operator_actions" },
    { version: 95, name: "remove_pagerduty_rest_lookup" },
    { version: 98, name: "certops_manual_rollout_authority" },
    { version: 99, name: "operator_connections" },
    { version: 100, name: "operator_enrollment_grants" },
    { version: 101, name: "operator_action_requests" },
    { version: 102, name: "operator_oauth" },
    { version: 103, name: "operator_connection_lifetimes" },
    { version: 104, name: "operator_inventory" },
    { version: 105, name: "operator_oauth_retention" },
    { version: 106, name: "operator_issuance" },
    { version: 107, name: "certops_issuance_job_identity" },
    { version: 108, name: "certops_issuance_identity_transfer" },
    { version: 109, name: "certops_period_creator_delete" },
    { version: 110, name: "recipient_member_verification" },
    { version: 111, name: "auto_sync_owner_username" },
  ]);
  assert.equal(
    (
      await pool.query(
        "SELECT items_created_total::int AS count FROM auto_sync_provider_stats WHERE provider='github'",
      )
    ).rows[0].count,
    existingTelemetry ? 17 : 0,
  );
  assert.equal(
    (
      await pool.query(
        "SELECT 1 FROM migrations WHERE version BETWEEN 83 AND 91",
      )
    ).rowCount,
    3,
    "Only integrated companion schemas receive migration history",
  );
  if (legacy) {
    assert.deepEqual(
      (
        await pool.query("SELECT * FROM pagerduty_incidents WHERE id=$1", [
          originalIncident.id,
        ])
      ).rows[0],
      { ...originalIncident, resolution_reason: null, operator_reason: null,
        manual_suppression_active: false, requested_by: null, acknowledged_at: null,
      },
    );
    assert.equal(
      (
        await pool.query("SELECT executed_at FROM migrations WHERE version=92")
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
  assert.equal((await pool.query("SELECT to_regclass('pagerduty_lookup_credentials') AS name")).rows[0].name,null);
  assert.equal((await pool.query("SELECT 1 FROM information_schema.columns WHERE table_name='pagerduty_incidents' AND column_name IN ('remote_incident_id','remote_incident_url','remote_status','lookup_at','lookup_error')")).rowCount,0);
  if (operatorIncident) {
    const preserved={...operatorIncident};
    for (const key of ['remote_incident_id','remote_incident_url','remote_status','lookup_at','lookup_error']) delete preserved[key];
    assert.deepEqual((await pool.query("SELECT * FROM pagerduty_incidents WHERE id=$1",[operatorIncident.id])).rows[0],preserved);
    assert.equal((await pool.query("SELECT 1 FROM pagerduty_ack_requests WHERE incident_id=$1 AND accepted_at IS NOT NULL AND attempts=1",[operatorIncident.id])).rowCount,1);
  }
  assert.equal(
    (
      await pool.query(
        "SELECT expiration_snapshot::text FROM alert_queue WHERE id=$1",
        [alertId],
      )
    ).rows[0].expiration_snapshot,
    originalExpirationSnapshot,
    "Migration must preserve the existing source-date snapshot",
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
    legacy || operatorIncident ? 1 : 0,
  );
  if (operatorIncident) assert.equal((await pool.query("SELECT manual_suppression_active FROM pagerduty_incidents WHERE id=$1",[operatorIncident.id])).rows[0].manual_suppression_active,false);
  // The real migration runner must be restart-safe and leave installed triggers
  // alone, rather than replaying CREATE TRIGGER on a committed migration.
  await runMigrations();
  assert.equal(
    (await pool.query("SELECT 1 FROM migrations WHERE version=92")).rowCount,
    1,
  );
  if (upgradeFrom === "81" && process.env.PAGERDUTY_COMPANION_ROOT) {
    // With recipient verification integrated, composition and replay must
    // preserve every ledger timestamp and incident rather than inject a second
    // copy into a formerly free slot.
    const { composeMigrations } = require("../../apps/api/migrations/compose-migrations");
    const recorded = (await pool.query("SELECT * FROM migrations ORDER BY version")).rows;
    const incidents = (await pool.query("SELECT * FROM pagerduty_incidents ORDER BY id")).rows;
    assert.equal(recorded.find(row => row.version === 84)?.name, "recipient_channel_verification");
    assert.deepEqual(composeMigrations(migrations, recorded), migrations);
    assert.ok((await pool.query("SELECT to_regclass('public.contact_channel_verifications') AS name")).rows[0].name);
    await runMigrations();
    assert.deepEqual((await pool.query("SELECT * FROM migrations ORDER BY version")).rows, recorded);
    assert.deepEqual((await pool.query("SELECT * FROM pagerduty_incidents ORDER BY id")).rows, incidents);
  }
});
