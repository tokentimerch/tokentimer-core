const { expect } = require("chai");
const { Client } = require("pg");
const { execFileSync } = require("node:child_process");
const path = require("node:path");
const { migrations } = require("../../apps/api/migrations/migrate");

const dbConfig = {
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || process.env.TT_TEST_DB_PORT || 5432),
  user: process.env.DB_USER || "tokentimer",
  password: process.env.DB_PASSWORD || "password",
};
const adminDatabase = process.env.DB_NAME || "tokentimer";
const databaseName = `tt_op_notification_history_${process.pid}`;
const migratePath = path.resolve(
  __dirname,
  "../../apps/api/migrations/migrate.js",
);

async function withClient(database, callback) {
  const client = new Client({ ...dbConfig, database });
  await client.connect();
  try {
    return await callback(client);
  } finally {
    await client.end();
  }
}

function runMigrations(database) {
  try {
    execFileSync(process.execPath, [migratePath], {
      cwd: path.dirname(migratePath),
      env: {
        ...process.env,
        DB_HOST: dbConfig.host,
        DB_PORT: String(dbConfig.port),
        DB_USER: dbConfig.user,
        DB_PASSWORD: dbConfig.password,
        DB_NAME: database,
        NODE_ENV: "test",
      },
      stdio: "pipe",
      timeout: 120000,
    });
  } catch (error) {
    throw new Error(
      `Migration runner failed: ${String(error.stdout || "").slice(-3000)} ${String(error.stderr || "").slice(-3000)}`,
    );
  }
}

async function apply(client, migration) {
  await client.query("BEGIN");
  try {
    await client.query(migration.sql);
    await client.query(
      "INSERT INTO migrations(version, name) VALUES ($1, $2)",
      [migration.version, migration.name],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
}

describe("operational notification migration history repair", function () {
  this.timeout(180000);

  beforeEach(async () => {
    await withClient(adminDatabase, async (client) => {
      await client.query(
        `DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`,
      );
      await client.query(`CREATE DATABASE ${databaseName}`);
    });
  });

  afterEach(async () => {
    await withClient(adminDatabase, async (client) => {
      await client.query(
        `DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`,
      );
    });
  });

  it("migrates a fresh database and safely reapplies v56-v58 SQL", async () => {
    runMigrations(databaseName);
    runMigrations(databaseName);
    await withClient(databaseName, async (client) => {
      for (const version of [56, 57, 58]) {
        await client.query(
          migrations.find((entry) => entry.version === version).sql,
        );
      }
      const ledger = await client.query(
        "SELECT version, name FROM migrations ORDER BY version",
      );
      expect(ledger.rows).to.have.length(migrations.length);
      expect(ledger.rows.at(-1).name).to.equal(
        "repair_certops_observation_locality_history",
      );
    });
  });

  it("repairs the exact PR #72 v39-v45 ledger without rewriting historical versions", async () => {
    await withClient(databaseName, async (client) => {
      await client.query(`CREATE TABLE migrations (
        version INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL,
        executed_at TIMESTAMP DEFAULT NOW())`);
      for (const migration of migrations.filter(
        (entry) => entry.version <= 38,
      )) {
        await apply(client, migration);
      }
      // PR #72's v39 had the notification table, reads and counter, but no
      // email claim columns or unread-reset trigger.
      await client.query(migrations.find((entry) => entry.version === 56).sql);
      await client.query(
        "DROP TRIGGER trg_operational_notification_escalation_unread ON operational_notifications",
      );
      await client.query(
        "ALTER TABLE operational_notifications DROP COLUMN email_claim_id, DROP COLUMN email_claimed_at",
      );
      await client.query(
        "INSERT INTO migrations(version, name) VALUES (39, 'operational_notifications_schema')",
      );
      for (const migration of migrations.filter(
        (entry) => entry.version >= 39 && entry.version <= 44,
      )) {
        await client.query("BEGIN");
        try {
          await client.query(migration.sql);
          await client.query(
            "INSERT INTO migrations(version, name) VALUES ($1, $2)",
            [migration.version + 1, migration.name],
          );
          await client.query("COMMIT");
        } catch (error) {
          await client.query("ROLLBACK");
          throw error;
        }
      }
      const pre = await client.query(
        `SELECT name FROM migrations WHERE version = 45`,
      );
      expect(pre.rows[0].name).to.equal("certops_trust_anchor_jobs");
      const missing =
        await client.query(`SELECT 1 FROM information_schema.columns
        WHERE table_name = 'certificate_targets' AND column_name = 'location_kind'`);
      expect(missing.rows).to.be.empty;
    });

    runMigrations(databaseName);
    runMigrations(databaseName);
    await withClient(databaseName, async (client) => {
      const ledger = await client.query(
        "SELECT version, name FROM migrations ORDER BY version",
      );
      expect(ledger.rows).to.have.length(migrations.length);
      expect(ledger.rows.find((row) => row.version === 39).name).to.equal(
        "operational_notifications_schema",
      );
      expect(ledger.rows.find((row) => row.version === 45).name).to.equal(
        "certops_trust_anchor_jobs",
      );
      expect(ledger.rows.at(-1).version).to.equal(58);
      for (const [tableName, columnName] of [
        ["certificate_targets", "location_kind"],
        ["certificate_instances", "location_kind"],
        ["certops_agents", "downtime_alerts_enabled"],
        ["certops_agents", "contact_group_id"],
        ["certops_agent_bootstrap_tokens", "downtime_alerts_enabled"],
        ["certops_agent_bootstrap_tokens", "contact_group_id"],
      ]) {
        const column = await client.query(
          `SELECT 1 FROM information_schema.columns
          WHERE table_name = $1 AND column_name = $2`,
          [tableName, columnName],
        );
        expect(column.rows).to.have.length(1);
      }
      for (const constraintName of [
        "managed_certificates_source_check",
        "certificate_targets_source_check",
        "certificate_instances_source_check",
      ]) {
        const constraint = await client.query(
          `SELECT pg_get_constraintdef(oid) AS definition
             FROM pg_constraint WHERE conname = $1`,
          [constraintName],
        );
        expect(constraint.rows[0].definition).to.include("agent_windows");
      }
      for (const indexName of [
        "uq_managed_certificates_workspace_source_ref",
        "uq_managed_certificates_workspace_fingerprint_import",
        "uq_certificate_targets_workspace_agent_windows_source_ref",
      ]) {
        const index = await client.query(
          `SELECT indexdef FROM pg_indexes
            WHERE schemaname = current_schema() AND indexname = $1`,
          [indexName],
        );
        expect(index.rows[0].indexdef).to.include("agent_windows");
      }
    });
  });

  it("repairs a partially missing v45 column even when the ledger name is canonical", async () => {
    runMigrations(databaseName);
    await withClient(databaseName, async (client) => {
      await client.query(
        "ALTER TABLE certificate_instances DROP COLUMN location_kind",
      );
      await client.query("DELETE FROM migrations WHERE version = 58");
    });
    runMigrations(databaseName);
    await withClient(databaseName, async (client) => {
      const column =
        await client.query(`SELECT 1 FROM information_schema.columns
        WHERE table_name = 'certificate_instances' AND column_name = 'location_kind'`);
      expect(column.rows).to.have.length(1);
      const ledger = await client.query(
        "SELECT name FROM migrations WHERE version = 58",
      );
      expect(ledger.rows[0].name).to.equal(
        "repair_certops_observation_locality_history",
      );
    });
  });
});
