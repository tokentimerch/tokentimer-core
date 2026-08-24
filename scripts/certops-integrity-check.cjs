#!/usr/bin/env node
"use strict";

// Post-migration invariant-check script: a set of standalone SQL assertions
// run against a real database connection, reported pass/fail/skip, never
// silently treated as green when something it should have verified could
// not run.
//
// Connects using the same DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD/DB_SSL
// environment variables as apps/api/migrations/migrate.js, so it runs
// against whatever database `pnpm migrate` already targets (including the
// docker-compose.test.yml postgres service).
//
// EXIT BEHAVIOR: any assertion that reports "skip" (its target table/column
// does not exist yet) makes this script exit non-zero, UNLESS the caller
// passes --allow-missing-tables. This is deliberate: a skip means a real
// check did not run, and treating that the same as a pass would let a
// downstream schema change silently stop being verified. Pass
// --allow-missing-tables only against a database that genuinely predates a
// migration these assertions target; CI's seeded-database job runs the full
// migration set first and does NOT pass it, so a migration that changes the
// schema in an unexpected way still fails loudly here instead of skipping
// quietly.
//
// ASSUMPTIONS AND LIMITATIONS (read before trusting a green run):
//
//   1/2. The trust-anchor assertions check certops_trust_anchors and
//        certops_trust_anchor_installations for real, against the schema
//        migration 48 added. They still probe information_schema.tables
//        first and report SKIPPED rather than crashing if run against an
//        older database that predates that migration.
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

// Mirrors DEFAULT_RECONCILE_DELAY_MS in
// apps/api/services/certops/trustAnchors.js, which is how long the sweep
// waits before looking at a pending row again. Kept as a literal rather than
// imported so this script stays a standalone .cjs check with no app imports.
const RECONCILIATION_SWEEP_INTERVAL_MS = 15 * 60 * 1000;

// The sweep gives up on a row after DEFAULT_MAX_RECONCILE_AGE_MS (6 sweep
// intervals) and clears next_reconcile_at. Allow that plus one interval of
// slack before calling a still-scheduled row a real failure.
const STALE_PENDING_GRACE_MULTIPLIER = 7;

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
  if (
    !(await tableExists(pool, "certops_trust_anchors")) ||
    !(await tableExists(pool, "certops_trust_anchor_installations"))
  ) {
    return {
      name,
      status: "skip",
      detail:
        "certops_trust_anchors and/or certops_trust_anchor_installations " +
        "does not exist yet in this database; not yet applicable.",
    };
  }

  // A retired ('revoked') anchor may still have 'installed' rows awaiting
  // removal and 'pending_remove' rows in flight, but a 'pending_install'
  // row means a distribution was created after retirement.
  const retiredWithPendingInstall = await pool.query(
    `SELECT ta.id, COUNT(tai.id)::int AS pending_installs
       FROM certops_trust_anchors ta
       JOIN certops_trust_anchor_installations tai
         ON tai.workspace_id = ta.workspace_id
        AND tai.trust_anchor_id = ta.id
      WHERE ta.status = 'revoked'
        AND tai.transition_state = 'pending_install'
      GROUP BY ta.id`,
  );

  // Anchor rows are additive-only, so every installation row must resolve
  // to an existing anchor in the same workspace.
  const orphanedInstallations = await pool.query(
    `SELECT tai.id, tai.trust_anchor_id
       FROM certops_trust_anchor_installations tai
       LEFT JOIN certops_trust_anchors ta
         ON ta.workspace_id = tai.workspace_id AND ta.id = tai.trust_anchor_id
      WHERE ta.id IS NULL`,
  );

  const problems = [];
  if (retiredWithPendingInstall.rowCount > 0) {
    problems.push(
      `${retiredWithPendingInstall.rowCount} retired anchor(s) still have ` +
        "pending_install rows: " +
        retiredWithPendingInstall.rows
          .map((row) => `${row.id} (${row.pending_installs})`)
          .join(", "),
    );
  }
  if (orphanedInstallations.rowCount > 0) {
    problems.push(
      `${orphanedInstallations.rowCount} installation row(s) reference a ` +
        "missing anchor: " +
        orphanedInstallations.rows
          .map((row) => `${row.id} -> ${row.trust_anchor_id}`)
          .join(", "),
    );
  }

  if (problems.length > 0) {
    return { name, status: "fail", detail: problems.join("; ") };
  }
  return {
    name,
    status: "pass",
    detail:
      "no retired anchor has a pending_install row, and every installation " +
      "row resolves to an existing anchor in its workspace.",
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
  if (!(await tableExists(pool, "certops_trust_anchor_installations"))) {
    return {
      name,
      status: "skip",
      detail:
        "certops_trust_anchor_installations does not exist yet in this " +
        "database; not yet applicable.",
    };
  }

  // The sweep clears next_reconcile_at when it gives up on a row and marks
  // it stale, so a row that is still pending WITH next_reconcile_at set and
  // well past due is one the sweep is failing to process. A row whose
  // next_reconcile_at is NULL has already been reported and is excluded.
  const staleGraceMs = STALE_PENDING_GRACE_MULTIPLIER * RECONCILIATION_SWEEP_INTERVAL_MS;
  const stale = await pool.query(
    `SELECT id, transition_state, last_attempt_at, next_reconcile_at
       FROM certops_trust_anchor_installations
      WHERE transition_state IN ('pending_install', 'pending_remove')
        AND next_reconcile_at IS NOT NULL
        AND next_reconcile_at < NOW() - ($1::bigint * INTERVAL '1 millisecond')
      ORDER BY next_reconcile_at
      LIMIT 20`,
    [staleGraceMs],
  );

  if (stale.rowCount > 0) {
    return {
      name,
      status: "fail",
      detail:
        `${stale.rowCount} row(s) still pending more than ${staleGraceMs}ms ` +
        "past their next_reconcile_at, which means the reconciliation sweep " +
        "is not draining them: " +
        stale.rows
          .map((row) => `${row.id} (${row.transition_state})`)
          .join(", "),
    };
  }
  return {
    name,
    status: "pass",
    detail:
      "every pending_install/pending_remove row is either within its " +
      `${staleGraceMs}ms reconciliation budget or already reported ` +
      "(next_reconcile_at cleared).",
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
  const allowMissingTables = process.argv.slice(2).includes("--allow-missing-tables");
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

  if (failed > 0) {
    process.exit(1);
  }
  if (skipped > 0 && !allowMissingTables) {
    console.error(
      `certops-integrity-check: ${skipped} assertion(s) skipped and ` +
        "--allow-missing-tables was not passed. A skip means a real check " +
        "did not run; exiting non-zero so this cannot be mistaken for a " +
        "clean pass. Pass --allow-missing-tables only when the skipped " +
        "table(s) are genuinely expected to be absent from this database.",
    );
    process.exit(1);
  }
}

main();
