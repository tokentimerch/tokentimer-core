"use strict";

// Explicit maintenance tool for the unpublished PagerDuty v79 preview only.
// Normal migration execution never rewrites history or aliases this collision.
const assert = require("node:assert/strict");
const {
  migrations,
  validateMigrationHistory,
  applyMigrationSql,
} = require("../apps/api/migrations/migrate");

const normalize = (value) => value.replaceAll("\r\n", "\n").trim();

async function tableShape(client, relation) {
  const columns = await client.query(
    `SELECT a.attname, format_type(a.atttypid,a.atttypmod) AS type,
       a.attnotnull, a.attgenerated, pg_get_expr(d.adbin,d.adrelid) AS default_value
     FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
     WHERE a.attrelid=$1::regclass AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`,
    [relation],
  );
  const constraints = await client.query(
    `SELECT pg_get_constraintdef(oid) AS definition, convalidated, condeferrable, condeferred
     FROM pg_constraint WHERE conrelid=$1::regclass ORDER BY definition`,
    [relation],
  );
  const indexes = await client.query(
    `SELECT regexp_replace(pg_get_indexdef(indexrelid), 'INDEX [^ ]+ ON [^ ]+ USING',
       'INDEX ON relation USING') AS definition, indisvalid, indisready
     FROM pg_index WHERE indrelid=$1::regclass ORDER BY definition`,
    [relation],
  );
  return {
    columns: columns.rows,
    constraints: constraints.rows.map((row) => ({
      ...row,
      definition: row.definition.replace(
        /REFERENCES (?:pg_temp(?:_\d+)?\.)?pd_history_expected_(workspaces|tokens|alert_queue)/g,
        "REFERENCES $1",
      ),
    })),
    indexes: indexes.rows,
  };
}

async function verifyPagerDutySchema(client, sql) {
  const boundary = sql.indexOf("-- Freeze the date");
  assert.ok(boundary > 0, "PagerDuty schema reference is missing");
  for (const table of ["workspaces", "tokens", "alert_queue"]) {
    await client.query(`CREATE TEMP TABLE pd_history_expected_${table}
      (LIKE public.${table} INCLUDING INDEXES) ON COMMIT DROP`);
  }
  // Reference DDL creates only temporary, empty relations. It never replays
  // the queue backfill, replaces a real function, or touches customer records.
  const reference = sql
    .slice(0, boundary)
    .replace(
      "CREATE TABLE IF NOT EXISTS pagerduty_incidents",
      "CREATE TEMP TABLE pd_history_expected_incidents",
    )
    .replace(/\r?\n\);/, "\n) ON COMMIT DROP;")
    .replaceAll(
      "ON pagerduty_incidents",
      "ON pg_temp.pd_history_expected_incidents",
    )
    .replace(
      /REFERENCES (workspaces|tokens|alert_queue)\(/g,
      "REFERENCES pg_temp.pd_history_expected_$1(",
    );
  await client.query(reference);
  assert.deepEqual(
    await tableShape(client, "public.pagerduty_incidents"),
    await tableShape(client, "pg_temp.pd_history_expected_incidents"),
    "PagerDuty ledger schema differs from the original preview; manual review required",
  );
  const snapshot =
    await client.query(`SELECT data_type, is_nullable, column_default
    FROM information_schema.columns WHERE table_schema='public'
      AND table_name='alert_queue' AND column_name='expiration_snapshot'`);
  assert.deepEqual(
    snapshot.rows,
    [{ data_type: "date", is_nullable: "YES", column_default: null }],
    "PagerDuty expiration snapshot column differs; manual review required",
  );

  const functions = [
    ...sql.matchAll(
      /CREATE OR REPLACE FUNCTION (\w+)\(\)\s+RETURNS TRIGGER LANGUAGE plpgsql AS \$\$([\s\S]*?)\$\$;/g,
    ),
  ];
  assert.equal(functions.length, 2, "PagerDuty function reference is missing");
  for (const match of functions) {
    const actual = await client.query(
      `SELECT p.prosrc, l.lanname, p.prorettype::regtype::text AS result,
        p.prosecdef, p.proisstrict, p.proleakproof, p.provolatile, p.proparallel, p.proconfig
      FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      JOIN pg_language l ON l.oid=p.prolang
      WHERE n.nspname='public' AND p.proname=$1 AND p.pronargs=0`,
      [match[1]],
    );
    assert.deepEqual(
      actual.rows.map((row) => ({ ...row, prosrc: normalize(row.prosrc) })),
      [
        {
          prosrc: normalize(match[2]),
          lanname: "plpgsql",
          result: "trigger",
          prosecdef: false,
          proisstrict: false,
          proleakproof: false,
          provolatile: "v",
          proparallel: "u",
          proconfig: null,
        },
      ],
      `PagerDuty function ${match[1]} differs; manual review required`,
    );
  }
  const triggers = [
    ...sql.matchAll(
      /CREATE TRIGGER (\w+) (BEFORE INSERT ON alert_queue|AFTER UPDATE OF expiration ON tokens)[\s\S]*?EXECUTE FUNCTION \w+\(\);/g,
    ),
  ];
  assert.equal(triggers.length, 2, "PagerDuty trigger reference is missing");
  for (const match of triggers) {
    const table = match[2].endsWith("alert_queue") ? "alert_queue" : "tokens";
    const temporary = `pd_history_expected_${table}`;
    await client.query(
      match[0].replace(`ON ${table}`, `ON pg_temp.${temporary}`),
    );
    const definition = async (relation) =>
      (
        await client.query(
          `SELECT regexp_replace(pg_get_triggerdef(oid), 'ON [^ ]+ ', 'ON relation ') AS definition,
         tgenabled FROM pg_trigger WHERE tgrelid=$1::regclass AND tgname=$2 AND NOT tgisinternal`,
          [relation, match[1]],
        )
      ).rows;
    assert.deepEqual(
      await definition(`public.${table}`),
      await definition(`pg_temp.${temporary}`),
      `PagerDuty trigger ${match[1]} differs; manual review required`,
    );
  }
}

async function reconcilePagerDutyV79(client, { apply = false } = {}) {
  await client.query("BEGIN");
  try {
    await client.query("SET LOCAL search_path TO public, pg_temp");
    await client.query("SET LOCAL lock_timeout = '5s'");
    await client.query("LOCK TABLE public.migrations IN ACCESS EXCLUSIVE MODE");
    const recorded = (
      await client.query(
        "SELECT version,name,executed_at FROM public.migrations ORDER BY version",
      )
    ).rows;
    assert.deepEqual(
      recorded.map((row) => row.version),
      Array.from({ length: 79 }, (_, i) => i + 1),
      "Expected exactly migrations 1-78 plus the PagerDuty v79 preview; manual review required",
    );
    assert.equal(
      recorded.at(-1).name,
      "pagerduty_incident_lifecycle",
      "Not a legacy PagerDuty v79 installation",
    );
    validateMigrationHistory(recorded.slice(0, -1));
    const pagerduty = migrations.find(
      (entry) => entry.name === "pagerduty_incident_lifecycle",
    );
    assert.equal(pagerduty.version, 81);
    const telemetry = migrations.filter(
      (entry) => entry.version === 79 || entry.version === 80,
    );
    assert.deepEqual(
      telemetry.map((entry) => entry.name),
      ["auto_sync_provider_stats", "auto_sync_run_metrics"],
    );
    const artifacts = await client.query(`SELECT name FROM unnest(ARRAY[
      'public.auto_sync_provider_stats','public.auto_sync_run_outcome_stats','public.auto_sync_run_freshness'
    ]) name WHERE to_regclass(name) IS NOT NULL
    UNION ALL SELECT 'record_auto_sync_run_metrics' WHERE to_regprocedure('public.record_auto_sync_run_metrics()') IS NOT NULL`);
    assert.equal(
      artifacts.rowCount,
      0,
      "Unrecorded telemetry schema exists; manual review required",
    );
    await verifyPagerDutySchema(client, pagerduty.sql);
    if (!apply) {
      await client.query("ROLLBACK");
      return { status: "validated", from: 79, to: 81 };
    }
    // Move only the proven preview entry, retaining its name and executed_at.
    // Fill both released telemetry slots in the same transaction so the strict
    // history composer never sees an intermediate 78 -> 81 gap.
    const moved = await client.query(`UPDATE public.migrations SET version=81
      WHERE version=79 AND name='pagerduty_incident_lifecycle' RETURNING version`);
    assert.equal(moved.rowCount, 1);
    for (const migration of telemetry) {
      await applyMigrationSql(client, migration);
      await client.query(
        "INSERT INTO public.migrations(version,name) VALUES($1,$2)",
        [migration.version, migration.name],
      );
    }
    validateMigrationHistory(
      (
        await client.query(
          "SELECT version,name FROM public.migrations ORDER BY version",
        )
      ).rows,
    );
    await client.query("COMMIT");
    return { status: "reconciled", from: 79, to: 81 };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length !== 1 || !["--check", "--apply"].includes(args[0])) {
    console.error(
      "Usage: node scripts/reconcile-pagerduty-v79.cjs --check|--apply (stop all writers and back up first; see docs/PAGERDUTY.md)",
    );
    process.exitCode = 1;
  } else {
    const { pool } = require("../apps/api/db/database");
    (async () => {
      const client = await pool.connect();
      try {
        console.log(
          JSON.stringify(
            await reconcilePagerDutyV79(client, {
              apply: args[0] === "--apply",
            }),
          ),
        );
      } finally {
        client.release();
      }
    })()
      .catch(() => {
        // Never print raw database errors or connection/provider credentials.
        console.error(
          "pagerduty_v79_reconciliation_failed: no changes committed; inspect history/schema and the operator procedure",
        );
        process.exitCode = 1;
      })
      .finally(() => pool.end());
  }
}

module.exports = { reconcilePagerDutyV79 };
