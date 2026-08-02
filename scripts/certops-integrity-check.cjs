#!/usr/bin/env node
"use strict";

// Quality/CI backlog item 13: post-migration invariant-check script,
// modeled on the certctl integrity_check.sql pattern (a set of standalone
// SQL assertions run against a real database connection, reported
// pass/fail, never silently skipped without saying so).
//
// Connects using the same DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD/DB_SSL
// environment variables as apps/api/migrations/migrate.js, so it runs
// against whatever database `pnpm migrate` already targets (including the
// docker-compose.test.yml postgres service).
//
// ASSUMPTIONS AND LIMITATIONS (read before trusting a green run):
//
//   1/2. certops_trust_anchors and its ownership-reference rows do not
//        exist in this codebase's migration history yet (only in
//        docs/adr/0012-certops-windows-execution-surface-and-trust-anchors.md
//        as a planned decision). Both assertions are written defensively:
//        they check for the table via information_schema.tables first and
//        report SKIPPED (not-yet-applicable), never a false pass or a
//        crash, until a future migration introduces it. A reasonable
//        reconciliation-sweep interval constant
//        (ASSUMED_RECONCILIATION_SWEEP_INTERVAL_MS below) is pre-declared
//        for whoever wires assertion 2 up once the table exists.
//
//   3. certops_agents.capabilities_updated_at is real and checked for real:
//      no row may have a value in the future.
//
//   4. "every declared_capabilities change since the last check has a
//      matching CERTOPS_AGENT_CAPABILITIES_CHANGED audit row" is
//      genuinely best-effort, as the task anticipates: this schema has no
//      change-history table, only the current value of
//      declared_capabilities and a single capabilities_updated_at
//      timestamp per agent, so an agent that changed capabilities twice
//      only shows its latest state. What IS checked: every certops_agents
//      row with a non-null capabilities_updated_at has AT LEAST ONE
//      CERTOPS_AGENT_CAPABILITIES_CHANGED audit_events row for that
//      agent_id. This proves "some audit trail exists for every agent that
//      has ever reported capabilities", not "every individual change was
//      separately audited" (that stronger claim is unverifiable against
//      the current schema).

const { Pool } = require("pg");

// Placeholder for assertion 2 (ownership-reference rows must not sit in
// pending_install/pending_remove past one reconciliation sweep). No sweep
// interval is defined anywhere in this codebase yet (the reconciler itself
// does not exist), so this is a documented assumption, not a value read
// from real configuration. Whoever implements the reconciler should replace
// this with the real configured interval.
const ASSUMED_RECONCILIATION_SWEEP_INTERVAL_MS = 5 * 60 * 1000;

const CAPABILITIES_CHANGED_AUDIT_ACTION = "CERTOPS_AGENT_CAPABILITIES_CHANGED";

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

async function tableExists(pool, tableName) {
  const result = await pool.query(
    `SELECT 1 FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name = $1`,
    [tableName],
  );
  return result.rowCount > 0;
}

async function columnExists(pool, tableName, columnName) {
  const result = await pool.query(
    `SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2`,
    [tableName, columnName],
  );
  return result.rowCount > 0;
}

/**
 * @typedef {{ name: string, status: "pass"|"fail"|"skip", detail: string }} AssertionResult
 */

/**
 * Assertion 1: every certops_trust_anchors row's derived COUNT(*) of its
 * ownership-reference rows is consistent with its stored status.
 * @param {import("pg").Pool} pool
 * @returns {Promise<AssertionResult>}
 */
async function assertTrustAnchorOwnershipCountsConsistent(pool) {
  const name = "trust-anchor ownership counts consistent with status";
  if (!(await tableExists(pool, "certops_trust_anchors"))) {
    return {
      name,
      status: "skip",
      detail:
        "certops_trust_anchors does not exist yet in this codebase's " +
        "migration history (planned in ADR-0012, not yet implemented); " +
        "not yet applicable.",
    };
  }
  // Table exists: this branch intentionally left unimplemented until the
  // real ownership-reference table/column names are known, rather than
  // guessing a schema that would silently check the wrong thing.
  return {
    name,
    status: "skip",
    detail:
      "certops_trust_anchors exists but this script has not been updated " +
      "with the real ownership-reference table/column names yet; update " +
      "this assertion when that schema lands.",
  };
}

/**
 * Assertion 2: no ownership-reference row has sat in pending_install /
 * pending_remove longer than one reconciliation-sweep interval.
 * @param {import("pg").Pool} pool
 * @returns {Promise<AssertionResult>}
 */
async function assertNoStalePendingOwnershipReferences(pool) {
  const name = "no ownership-reference row stuck in pending_install/pending_remove";
  if (!(await tableExists(pool, "certops_trust_anchors"))) {
    return {
      name,
      status: "skip",
      detail:
        "no ownership-reference table exists yet (see assertion 1); not " +
        "yet applicable. Assumed reconciliation-sweep interval for when " +
        `this becomes applicable: ${ASSUMED_RECONCILIATION_SWEEP_INTERVAL_MS}ms ` +
        "(not read from real configuration; no reconciler exists yet).",
    };
  }
  return {
    name,
    status: "skip",
    detail:
      "certops_trust_anchors exists but this script has not been updated " +
      "with the real ownership-reference table/column names yet.",
  };
}

/**
 * Assertion 3: no certops_agents.capabilities_updated_at value is in the
 * future.
 * @param {import("pg").Pool} pool
 * @returns {Promise<AssertionResult>}
 */
async function assertNoFutureCapabilitiesUpdatedAt(pool) {
  const name = "certops_agents.capabilities_updated_at never in the future";
  const hasTable = await tableExists(pool, "certops_agents");
  const hasColumn =
    hasTable && (await columnExists(pool, "certops_agents", "capabilities_updated_at"));
  if (!hasTable || !hasColumn) {
    return {
      name,
      status: "skip",
      detail: !hasTable
        ? "certops_agents does not exist; not yet applicable."
        : "certops_agents.capabilities_updated_at does not exist; not yet applicable.",
    };
  }

  const result = await pool.query(
    `SELECT id, agent_id, capabilities_updated_at
       FROM certops_agents
      WHERE capabilities_updated_at > NOW()
      ORDER BY capabilities_updated_at DESC
      LIMIT 20`,
  );
  if (result.rowCount === 0) {
    return {
      name,
      status: "pass",
      detail: "no certops_agents row has a future capabilities_updated_at.",
    };
  }
  const sample = result.rows
    .map((row) => `${row.agent_id} (${row.capabilities_updated_at.toISOString()})`)
    .join(", ");
  return {
    name,
    status: "fail",
    detail: `${result.rowCount} row(s) with a future capabilities_updated_at: ${sample}`,
  };
}

/**
 * Assertion 4 (best-effort; see header comment for the exact limitation):
 * every certops_agents row that has ever reported declared_capabilities
 * (capabilities_updated_at IS NOT NULL) has at least one matching
 * CERTOPS_AGENT_CAPABILITIES_CHANGED audit_events row.
 * @param {import("pg").Pool} pool
 * @returns {Promise<AssertionResult>}
 */
async function assertCapabilitiesChangesHaveAuditRows(pool) {
  const name =
    "declared_capabilities changes have a matching audit row (best-effort)";
  const hasAgentsTable = await tableExists(pool, "certops_agents");
  const hasAuditTable = await tableExists(pool, "audit_events");
  const hasColumn =
    hasAgentsTable &&
    (await columnExists(pool, "certops_agents", "capabilities_updated_at"));
  if (!hasAgentsTable || !hasAuditTable || !hasColumn) {
    return {
      name,
      status: "skip",
      detail:
        "certops_agents.capabilities_updated_at and/or audit_events do " +
        "not exist yet; not yet applicable.",
    };
  }

  const result = await pool.query(
    `SELECT a.agent_id
       FROM certops_agents a
      WHERE a.capabilities_updated_at IS NOT NULL
        AND NOT EXISTS (
          SELECT 1 FROM audit_events e
           WHERE e.action = $1
             AND e.metadata->>'agentId' = a.agent_id
        )
      ORDER BY a.agent_id
      LIMIT 20`,
    [CAPABILITIES_CHANGED_AUDIT_ACTION],
  );
  if (result.rowCount === 0) {
    return {
      name,
      status: "pass",
      detail:
        "every certops_agents row with a non-null capabilities_updated_at " +
        `has at least one ${CAPABILITIES_CHANGED_AUDIT_ACTION} audit row ` +
        "(best-effort: existence, not a 1:1 change-history match; see " +
        "header comment).",
    };
  }
  const sample = result.rows.map((row) => row.agent_id).join(", ");
  return {
    name,
    status: "fail",
    detail:
      `${result.rowCount} agent(s) with capabilities_updated_at set but no ` +
      `${CAPABILITIES_CHANGED_AUDIT_ACTION} audit row at all: ${sample}`,
  };
}

async function main() {
  const pool = buildPool();
  const assertions = [
    assertTrustAnchorOwnershipCountsConsistent,
    assertNoStalePendingOwnershipReferences,
    assertNoFutureCapabilitiesUpdatedAt,
    assertCapabilitiesChangesHaveAuditRows,
  ];

  let results;
  try {
    await pool.query("SELECT 1");
    results = [];
    for (const assertion of assertions) {
      // eslint-disable-next-line no-await-in-loop
      results.push(await assertion(pool));
    }
  } catch (err) {
    console.error(
      `certops-integrity-check: could not connect to the database (${err.message}). ` +
        "This script needs a real Postgres connection; set DB_HOST/DB_PORT/" +
        "DB_NAME/DB_USER/DB_PASSWORD or run against the docker-compose.test.yml " +
        "postgres service (pnpm run test:up).",
    );
    await pool.end().catch(() => {});
    process.exit(1);
    return;
  }

  let failed = 0;
  let skipped = 0;
  for (const result of results) {
    const marker =
      result.status === "pass" ? "PASS" : result.status === "skip" ? "SKIP" : "FAIL";
    console.log(`[${marker}] ${result.name}`);
    console.log(`       ${result.detail}`);
    if (result.status === "fail") failed += 1;
    if (result.status === "skip") skipped += 1;
  }

  const passed = results.length - failed - skipped;
  console.log("");
  console.log(
    `certops-integrity-check: ${results.length} assertion(s), ${passed} passed, ` +
      `${skipped} skipped (not yet applicable), ${failed} failed`,
  );

  await pool.end().catch(() => {});
  if (failed > 0) process.exit(1);
}

main();
