"use strict";

// Reproducible EXPLAIN evidence; always creates and drops its own database.
const { Pool, Client } = require("pg");
const { migrations } = require("../apps/api/migrations/migrate");
const {
  listCertificateIdentities,
} = require("../apps/api/services/certops/certificateIdentity");
const fs = require("node:fs");
const config = {
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || "tokentimer",
  password: process.env.DB_PASSWORD || "password",
};
const database = `certops_identity_performance_${process.pid}_${Date.now()}`;

async function main() {
  const admin = new Client({
    ...config,
    database: process.env.DB_NAME || "tokentimer",
  });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${database}`);
  const db = new Pool({ ...config, database });
  const plans = [];
  const explain = async (label, sql, args) => {
    const row = (
      await db.query(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${sql}`, args)
    ).rows[0]["QUERY PLAN"][0];
    plans.push({
      label,
      planningMs: row["Planning Time"],
      executionMs: row["Execution Time"],
      plan: row.Plan,
    });
  };
  try {
    for (const migration of migrations) await db.query(migration.sql);
    const userId = (
      await db.query(`INSERT INTO users(email,email_original,display_name,password_hash,auth_method)
      VALUES('performance@example.test','performance@example.test','Performance Test','x','local') RETURNING id`)
    ).rows[0].id;
    const ws = (
      await db.query(
        "INSERT INTO workspaces(id,name,plan,created_by) VALUES(gen_random_uuid(),'Performance workspace','oss',$1) RETURNING id",
        [userId],
      )
    ).rows[0].id;
    const other = (
      await db.query(
        "INSERT INTO workspaces(id,name,plan,created_by) VALUES(gen_random_uuid(),'Other workspace','oss',$1) RETURNING id",
        [userId],
      )
    ).rows[0].id;
    for (const workspaceId of [ws, other]) {
      await db.query(
        `INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256,name,common_name,not_after)
        SELECT $1,'agent_filesystem','agent/slot/' || n, lpad(to_hex(n % 5000),64,'0'),
          'Certificate ' || n, 'cert-' || n % 5000, NOW() + ((n % 5000) % 365) * INTERVAL '1 day'
        FROM generate_series(1,10000) n`,
        [workspaceId],
      );
    }
    await db.query(
      `INSERT INTO managed_certificates(workspace_id,source,source_ref,name,status)
      SELECT $1,'agent_issuance','provisional/'||n,'Provisional '||n,'provisioning' FROM generate_series(1,100) n`,
      [ws],
    );
    const target = (
      await db.query(
        "INSERT INTO certificate_targets(workspace_id,name,target_type) VALUES($1,'Performance host','host') RETURNING id",
        [ws],
      )
    ).rows[0].id;
    await db.query(
      `INSERT INTO certificate_instances(workspace_id,managed_certificate_id,target_id,source,source_ref,
      observed_fingerprint_sha256,observed_at,location_kind,deployment_reference)
      SELECT workspace_id,id,$2,'agent_filesystem',source_ref,fingerprint_sha256,NOW(),'filesystem','file:///'||source_ref
      FROM managed_certificates WHERE workspace_id=$1 AND fingerprint_sha256 IS NOT NULL`,
      [ws, target],
    );
    await db.query("ANALYZE");
    const tracedClient = {
      async query(sql, args) {
        const label = sql.includes("WITH representatives AS")
          ? "grouped inventory (expiry, 50 rows)"
          : sql.includes("all_locations")
            ? "location lookup (50 identities)"
            : "source history (50 identities)";
        await explain(label, sql, args);
        return db.query(sql, args);
      },
    };
    const inventory = await listCertificateIdentities({
      workspaceId: ws,
      limit: 50,
      client: tracedClient,
    });
    const id = (
      await db.query(
        "SELECT id,fingerprint_sha256 FROM certops_certificate_identities WHERE workspace_id=$1 LIMIT 1",
        [ws],
      )
    ).rows[0];
    await explain(
      "fingerprint lookup",
      "SELECT * FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2",
      [ws, id.fingerprint_sha256],
    );
    await explain(
      "quota count",
      `SELECT (COUNT(DISTINCT current_identity_id) + COUNT(*) FILTER (WHERE current_identity_id IS NULL))::int
      FROM certops_management_periods WHERE workspace_id=$1 AND ended_at IS NULL`,
      [ws],
    );
    await explain(
      "quota admission predicate: existing identity",
      "SELECT 1 FROM certops_management_periods WHERE workspace_id=$1 AND current_identity_id=$2 AND ended_at IS NULL LIMIT 1",
      [ws, id.id],
    );
    const excludedPeriod = (
      await db.query(
        "SELECT id FROM certops_management_periods WHERE workspace_id=$1 AND current_identity_id=$2 LIMIT 1",
        [ws, id.id],
      )
    ).rows[0].id;
    await explain(
      "quota admission predicate: new identity",
      `SELECT (COUNT(DISTINCT current_identity_id) + COUNT(*) FILTER (WHERE current_identity_id IS NULL))::int
      FROM certops_management_periods WHERE workspace_id=$1 AND ended_at IS NULL AND id IS DISTINCT FROM $2::uuid`,
      [ws, excludedPeriod],
    );
    await db.query(
      "UPDATE workspaces SET certops_managed_identity_limit=5101 WHERE id=$1",
      [ws],
    );
    await explain(
      "quota admission function: existing identity",
      "SELECT certops_admit_management($1::uuid,$2::uuid)",
      [ws, id.id],
    );
    await explain(
      "quota admission function: new identity",
      "SELECT certops_admit_management($1::uuid,gen_random_uuid())",
      [ws],
    );
    const report = {
      postgres: (await db.query("SELECT version() version")).rows[0].version,
      population: {
        workspaces: 2,
        identitiesPerWorkspace: 5000,
        sourcesPerWorkspace: 10000,
        provisionalSources: 100,
        observations: 10000,
        listedTotal: inventory.pagination.total,
      },
      plans,
    };
    const output = process.argv[2];
    if (output)
      fs.writeFileSync(output, JSON.stringify(report, null, 2) + "\n");
    console.log(
      JSON.stringify(
        {
          population: report.population,
          plans: plans.map(({ label, planningMs, executionMs }) => ({
            label,
            planningMs,
            executionMs,
          })),
        },
        null,
        2,
      ),
    );
  } finally {
    await db.end();
    await admin.query(`DROP DATABASE ${database}`);
    await admin.end();
  }
}
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
