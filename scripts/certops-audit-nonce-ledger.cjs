#!/usr/bin/env node
"use strict";

// Operator audit-SQL advisory for the nonce replay ledger, modeled on
// scripts/certops-integrity-check.cjs (same DB-connection approach, same
// CLI invocation pattern, same exit-code and output conventions).
//
// Background: apps/api/services/certops/jobSigning.js maintains
// certops_consumed_nonces, the ADR-0003 server-side dispatch replay ledger.
// Every signed job dispatch records issued_to_agent_id (the agent the nonce
// was issued to; nullable). apps/api/services/certops/agentDispatch.js's
// ingestResult re-proves claim ownership against certificate_jobs before
// consuming that nonce, and consumeNonce's own SQL only lets a nonce be
// consumed by the agent it was issued to (or by any agent when
// issued_to_agent_id is NULL). Under that code path the two should always
// agree, so this script is a defense-in-depth consistency check: it looks
// for certificate_jobs rows whose claimed_by_agent_id (the agent that holds
// the claim and is therefore the one that submitted/would submit the
// result for that job) disagrees with issued_to_agent_id on the
// certops_consumed_nonces row that was actually consumed for that job -- a
// state that should be unreachable through the normal ingestResult path,
// but could still appear from a direct data edit, a migration backfill, a
// future code path that updates claimed_by_agent_id without touching the
// ledger, or a bug in either enforcement point.
//
// LIMITATION (read before treating a clean run as proof of anything
// stronger): this SQL can identify ledger/result anomalies an operator
// should look at (a job whose result came from an agent it was not
// dispatched to), but it cannot conclusively prove a misrouted job was
// never received or acted on by the wrong agent. It only shows that a
// job's result, if one was submitted and ingested, is inconsistent with
// the nonce ledger; it cannot see delivery or execution that never reached
// (or never completed) the result-ingestion path this repo's schema
// records.

const { Pool } = require("pg");

function buildPool() {
  const sslMode = process.env.DB_SSL;
  const sslConfig =
    sslMode === "require"
      ? { rejectUnauthorized: process.env.NODE_ENV === "production" }
      : sslMode === "require-no-verify"
        ? { rejectUnauthorized: false }
        : false;
  return new Pool({
    host: process.env.DB_HOST || "localhost",
    database: process.env.DB_NAME || "tokentimer",
    user: process.env.DB_USER || "tokentimer",
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT || 5432,
    ssl: sslConfig,
    max: 2,
    connectionTimeoutMillis: 10000,
  });
}

// Read-only. Joins the two real tables (column/table names verified against
// apps/api/migrations/migrate.js, not guessed): certificate_jobs.id /
// certificate_jobs.claimed_by_agent_id (migration 24, "7.3 claim/lease
// execution columns") and certops_consumed_nonces.job_id /
// certops_consumed_nonces.issued_to_agent_id (migration 24, "ADR-0003
// server-side replay ledger"). Only the nonce row that was actually
// consumed (consumed_at IS NOT NULL) is considered: an unconsumed nonce
// never had a result attributed to it, so it cannot itself be a
// result/ledger anomaly. Both agent ids must be non-null to count as a
// mismatch: a NULL on either side means "not attributable to a specific
// agent", not "attributed to the wrong one".
const NONCE_LEDGER_ANOMALY_QUERY = `
  SELECT
    cj.id AS job_id,
    cj.workspace_id,
    cj.claimed_by_agent_id AS result_agent_id,
    cn.issued_to_agent_id,
    cn.nonce,
    cn.consumed_at,
    cj.status,
    cj.completed_at
  FROM certificate_jobs cj
  JOIN certops_consumed_nonces cn
    ON cn.job_id = cj.id
   AND cn.workspace_id = cj.workspace_id
  WHERE cn.consumed_at IS NOT NULL
    AND cj.claimed_by_agent_id IS NOT NULL
    AND cn.issued_to_agent_id IS NOT NULL
    AND cj.claimed_by_agent_id <> cn.issued_to_agent_id
  ORDER BY cn.consumed_at DESC
  LIMIT 200
`;

/**
 * Runs the anomaly query against the given DB client/pool and returns the
 * raw rows. Exported (and given a real query text, not a mock) so a unit
 * test can inject an in-memory client instead of a live Postgres
 * connection; see tests/unit/certops-audit-nonce-ledger.test.js.
 * @param {{ query: (sql: string) => Promise<{ rows: any[] }> }} db
 * @returns {Promise<Array<Record<string, unknown>>>}
 */
async function findNonceLedgerAnomalies(db) {
  const result = await db.query(NONCE_LEDGER_ANOMALY_QUERY);
  return result.rows;
}

function formatAnomalyRow(row) {
  const consumedAt =
    row.consumed_at instanceof Date
      ? row.consumed_at.toISOString()
      : row.consumed_at;
  const completedAt =
    row.completed_at instanceof Date
      ? row.completed_at.toISOString()
      : row.completed_at;
  return (
    `  job ${row.job_id} (workspace ${row.workspace_id}, status ${row.status}): ` +
    `result recorded for agent ${row.result_agent_id}, but nonce ${row.nonce} ` +
    `was issued to agent ${row.issued_to_agent_id} (consumed_at=${consumedAt}, ` +
    `completed_at=${completedAt})`
  );
}

async function main() {
  const pool = buildPool();

  try {
    await pool.query("SELECT 1");
  } catch (err) {
    console.error(
      `certops-audit-nonce-ledger: could not connect to the database (${err.message}). ` +
        "This script needs a real Postgres connection; set DB_HOST/DB_PORT/" +
        "DB_NAME/DB_USER/DB_PASSWORD or run against the docker-compose.test.yml " +
        "postgres service (pnpm run test:up).",
    );
    await pool.end().catch(() => {});
    process.exit(1);
    return;
  }

  let anomalies;
  try {
    anomalies = await findNonceLedgerAnomalies(pool);
  } catch (err) {
    console.error(`certops-audit-nonce-ledger: query failed: ${err.message}`);
    await pool.end().catch(() => {});
    process.exit(1);
    return;
  }

  if (anomalies.length === 0) {
    console.log(
      "[PASS] no certificate_jobs row's claimed_by_agent_id disagrees with " +
        "issued_to_agent_id on its consumed certops_consumed_nonces row.",
    );
  } else {
    console.log(
      `[FAIL] ${anomalies.length} job(s) whose recorded result agent does not ` +
        "match the nonce ledger's issued_to_agent_id. Each finding below is " +
        "worth an operator's manual look (see the limitation note in this " +
        "script's header: this cannot on its own prove the wrong agent " +
        "actually received or acted on the job, only that its ingested " +
        "result is inconsistent with the dispatch ledger).",
    );
    for (const row of anomalies) {
      console.log(formatAnomalyRow(row));
    }
  }

  await pool.end().catch(() => {});
  if (anomalies.length > 0) process.exit(1);
}

module.exports = {
  NONCE_LEDGER_ANOMALY_QUERY,
  findNonceLedgerAnomalies,
  formatAnomalyRow,
};

if (require.main === module) {
  main();
}
