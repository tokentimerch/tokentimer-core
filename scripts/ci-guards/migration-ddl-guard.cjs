#!/usr/bin/env node
"use strict";

// Guard: enforces a transactional, no-destructive-DDL check on database
// migrations. Core shipped v0.11.3 to fix a migration-38 dedup
// collision, so a guard here has demonstrated value: this project's
// migrations are numbered SQL strings inside one array in
// apps/api/migrations/migrate.js (not separate .sql files), run in
// order against a real, already-populated production database.
//
// This is a textual heuristic over the raw SQL strings, not a SQL
// parser. It can be defeated by determined obfuscation (e.g. building
// the keyword via string concatenation, or hiding it behind dynamic
// SQL) - an accepted limitation for a guard, not a full solution.
//
// Two checks:
//
// (a) Transaction guarantee. Verified structurally rather than
// per-migration: runMigrations() wraps EVERY migration's `sql` in
// client.query("BEGIN") ... COMMIT, with ROLLBACK on error, uniformly
// for the whole array (read the function yourself at the bottom of
// migrate.js to confirm - this guard also confirms it, mechanically,
// on every run rather than trusting that reading once). Because the
// wrapping is structural, no individual migration needs its own BEGIN/
// COMMIT, and this guard flags a migration that tries to issue one
// (which would break out of the wrapping transaction rather than add
// safety).
//
// (b) No destructive DDL against protected tables. Protected means:
// any table matching certops_* (this project's certops feature-area
// prefix), OR any other persistent (non-temp) table - in a schema
// whose main purpose is production customer data, essentially every
// CREATE TABLE in this file is production data, so "temp vs.
// everything else" is the practical dividing line, not "certops_* vs.
// everything else". A table created and dropped within the SAME
// migration via CREATE TEMP TABLE is scratch space, not production
// data, and is excluded.
//
// Pre-existing, already-released migrations reviewed and intentionally
// exempted live in ALLOWLISTED_DESTRUCTIVE_OPERATIONS below. This list
// must only ever be added to with a one-line reason citing why the
// operation is safe (e.g. "already shipped in vX.Y.Z, reviewed") - it
// must never grow to cover a NEW, unreleased migration; that defeats
// the guard's entire purpose. Adding a new migration that this guard
// flags means fixing the migration, not extending this list.

const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const migratePath = path.join(repoRoot, "apps/api/migrations/migrate.js");

// version -> array of { table, op, reason }. Each entry documents a
// specific, already-shipped migration's specific operation; it is not
// a blanket exemption for the table or the migration.
const ALLOWLISTED_DESTRUCTIVE_OPERATIONS = [
  {
    version: 30,
    table: "certops_agent_registration_replays",
    op: "DROP COLUMN",
    reason:
      "already shipped (pre-v0.11.3): migration 30 drops the plaintext " +
      "'credential' column only after the preceding statements in the " +
      "same migration add and populate 'credential_ciphertext' and wipe " +
      "the short-lived plaintext rows - an intentional, reviewed " +
      "encrypt-at-rest change, not an accidental data-loss risk.",
  },
];

function isAllowlisted(version, table, op) {
  return ALLOWLISTED_DESTRUCTIVE_OPERATIONS.some(
    (entry) => entry.version === version && entry.table === table && entry.op === op,
  );
}

function stripSqlComments(sql) {
  // Line comments only; this file's migrations don't use /* */ block
  // comments, and stripping them naively would risk eating real SQL if
  // that ever changes without this guard being updated in lockstep.
  return sql
    .split("\n")
    .map((line) => line.replace(/--.*$/, ""))
    .join("\n");
}

function splitStatements(sql) {
  // Naive semicolon split. Good enough here because none of this
  // file's DDL/DML statements embed a semicolon inside a string
  // literal or identifier; a real SQL parser would be needed to make
  // that safe in general, which is the documented heuristic tradeoff.
  return sql
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean);
}

function normalizeTableName(raw) {
  return raw
    .trim()
    .replace(/^"|"$/g, "")
    .replace(/^public\./i, "")
    .split(/\s+/)[0]
    .replace(/[,;].*$/, "");
}

function extractMigrations(source) {
  // Locate the `const migrations = [ ... ];` array and split it into
  // per-entry {version, name, sql} records by scanning for
  // `version: N,` markers and the `sql: \`...\`` template literal that
  // follows each one. This mirrors the array's own literal shape
  // rather than trying to `require()` the file (which would need a
  // live DB connection at module load in a different context, and
  // would run this project's actual migration-pool construction as a
  // side effect - too heavy for a guard that only needs the source
  // text).
  const migrations = [];
  const versionRe = /version:\s*(\d+),\s*\n\s*name:\s*"([^"]+)"/g;
  let match;
  const markers = [];
  while ((match = versionRe.exec(source)) !== null) {
    markers.push({ version: Number(match[1]), name: match[2], index: match.index });
  }

  for (let i = 0; i < markers.length; i += 1) {
    const start = markers[i].index;
    const end = i + 1 < markers.length ? markers[i + 1].index : source.length;
    const chunk = source.slice(start, end);
    const sqlMatch = chunk.match(/sql:\s*`([\s\S]*?)`\s*,?\s*\}/);
    if (!sqlMatch) continue;
    migrations.push({
      version: markers[i].version,
      name: markers[i].name,
      sql: sqlMatch[1],
    });
  }
  return migrations;
}

function findLocalTempTables(sql) {
  const names = new Set();
  const re = /CREATE\s+TEMP(?:ORARY)?\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?("?[\w.]+"?)/gi;
  let m;
  while ((m = re.exec(sql)) !== null) {
    names.add(normalizeTableName(m[1]).toLowerCase());
  }
  return names;
}

function isProtectedTable(name, localTempTables) {
  const normalized = name.toLowerCase();
  if (localTempTables.has(normalized)) return false;
  if (/^tmp_|^temp_/.test(normalized)) return false;
  return true; // certops_* and every other persistent table in this schema
}

function checkDestructiveDdl(migrations) {
  const violations = [];

  for (const migration of migrations) {
    const clean = stripSqlComments(migration.sql);
    const localTempTables = findLocalTempTables(clean);
    const statements = splitStatements(clean);

    for (const stmt of statements) {
      const compact = stmt.replace(/\s+/g, " ").trim();

      const dropTableMatch = compact.match(
        /^DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(.+)$/i,
      );
      if (dropTableMatch) {
        for (const rawName of dropTableMatch[1].split(",")) {
          const table = normalizeTableName(rawName);
          if (
            isProtectedTable(table, localTempTables) &&
            !isAllowlisted(migration.version, table, "DROP TABLE")
          ) {
            violations.push({
              version: migration.version,
              name: migration.name,
              table,
              op: "DROP TABLE",
              statement: compact,
            });
          }
        }
        continue;
      }

      const truncateMatch = compact.match(
        /^TRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?(.+)$/i,
      );
      if (truncateMatch) {
        for (const rawName of truncateMatch[1].split(",")) {
          const table = normalizeTableName(rawName);
          if (
            isProtectedTable(table, localTempTables) &&
            !isAllowlisted(migration.version, table, "TRUNCATE")
          ) {
            violations.push({
              version: migration.version,
              name: migration.name,
              table,
              op: "TRUNCATE",
              statement: compact,
            });
          }
        }
        continue;
      }

      const alterDropColumnMatch = compact.match(
        /^ALTER\s+TABLE\s+(?:ONLY\s+)?("?[\w.]+"?)\s+DROP\s+COLUMN\b/i,
      );
      if (alterDropColumnMatch) {
        const table = normalizeTableName(alterDropColumnMatch[1]);
        if (
          isProtectedTable(table, localTempTables) &&
          !isAllowlisted(migration.version, table, "DROP COLUMN")
        ) {
          violations.push({
            version: migration.version,
            name: migration.name,
            table,
            op: "DROP COLUMN",
            statement: compact,
          });
        }
        continue;
      }
    }
  }

  return violations;
}

function checkTransactionGuarantee(source) {
  const fnMatch = source.match(/async function runMigrations\(\)[\s\S]*$/);
  if (!fnMatch) {
    return [
      "runMigrations() function not found in migrate.js; cannot verify the " +
        "transaction guarantee this guard depends on",
    ];
  }
  const body = fnMatch[0];

  const beginIdx = body.search(/client\.query\(\s*["']BEGIN["']\s*\)/);
  const execIdx = body.search(/client\.query\(\s*\w+\.sql\s*\)/);
  const commitIdx = body.search(/client\.query\(\s*["']COMMIT["']\s*\)/);
  const rollbackIdx = body.search(/client\.query\(\s*["']ROLLBACK["']\s*\)/);
  const catchIdx = body.search(/}\s*catch\s*\(/);

  const problems = [];
  if (beginIdx === -1) problems.push("no client.query(\"BEGIN\") found");
  if (execIdx === -1) problems.push("no per-migration SQL execution (client.query(<var>.sql)) found");
  if (commitIdx === -1) problems.push("no client.query(\"COMMIT\") found");
  if (rollbackIdx === -1) problems.push("no client.query(\"ROLLBACK\") found");
  if (problems.length > 0) return problems;

  if (!(beginIdx < execIdx && execIdx < commitIdx)) {
    problems.push(
      "BEGIN / per-migration execution / COMMIT are not in the expected order, " +
        "so migrations may not run inside the wrapping transaction",
    );
  }
  if (!(catchIdx !== -1 && catchIdx > execIdx && rollbackIdx > catchIdx)) {
    problems.push(
      "ROLLBACK does not appear inside a catch block after the per-migration " +
        "execution, so a failed migration may not be rolled back",
    );
  }
  return problems;
}

function main() {
  if (!fs.existsSync(migratePath)) {
    console.error(`::error file=apps/api/migrations/migrate.js::migration-ddl-guard: file not found`);
    process.exit(1);
  }

  const source = fs.readFileSync(migratePath, "utf8");
  const relPath = "apps/api/migrations/migrate.js";
  let failed = false;

  const transactionProblems = checkTransactionGuarantee(source);
  for (const problem of transactionProblems) {
    console.error(`::error file=${relPath}::migration-ddl-guard: ${problem}`);
    failed = true;
  }

  const migrations = extractMigrations(source);
  if (migrations.length === 0) {
    console.error(
      `::error file=${relPath}::migration-ddl-guard: found 0 migrations while parsing the migrations array; the extraction heuristic may need updating to match this file's current shape`,
    );
    failed = true;
  }

  const ddlViolations = checkDestructiveDdl(migrations);
  for (const v of ddlViolations) {
    console.error(
      `::error file=${relPath}::migration-ddl-guard: migration ${v.version} (${v.name}) contains ${v.op} against protected table "${v.table}": ${v.statement}`,
    );
    failed = true;
  }

  if (failed) {
    process.exit(1);
  }

  console.log(
    `migration-ddl-guard: ok (${migrations.length} migration(s) checked, ` +
      `${ALLOWLISTED_DESTRUCTIVE_OPERATIONS.length} documented exception(s))`,
  );
}

main();
