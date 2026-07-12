"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { migrations } = require(
  path.resolve(__dirname, "../../apps/api/migrations/migrate.js"),
);
const baselineMinimumSchema = JSON.parse(
  fs.readFileSync(
    path.resolve(
      __dirname,
      "../../packages/contracts/db/baseline-minimum.schema.json",
    ),
    "utf8",
  ),
);

const CERTOPS_TABLES = [
  "managed_certificates",
  "certificate_instances",
  "certificate_profiles",
  "certificate_targets",
];

const CERTOPS_JOB_TABLES = [
  "certificate_jobs",
  "certificate_job_log",
  "certificate_evidence",
];

const CERTOPS_EXECUTOR_EVENT_TABLES = ["certificate_executor_events"];

const BASELINE_CERTOPS_COLUMNS = {
  certificate_profiles: [
    "id",
    "workspace_id",
    "name",
    "status",
    "source",
    "public_metadata",
    "created_at",
    "updated_at",
  ],
  managed_certificates: [
    "id",
    "workspace_id",
    "token_id",
    "profile_id",
    "status",
    "source",
    "common_name",
    "subject_alt_names",
    "fingerprint_sha256",
    "spki_fingerprint_sha256",
    "certificate_pem",
    "key_mode",
    "key_reference",
    "public_metadata",
    "created_at",
    "updated_at",
  ],
  certificate_targets: [
    "id",
    "workspace_id",
    "profile_id",
    "domain_monitor_id",
    "token_id",
    "name",
    "target_type",
    "status",
    "source",
    "hostname",
    "url",
    "deployment_reference",
    "public_metadata",
    "created_at",
    "updated_at",
  ],
  certificate_instances: [
    "id",
    "workspace_id",
    "managed_certificate_id",
    "target_id",
    "domain_monitor_id",
    "token_id",
    "status",
    "source",
    "observed_fingerprint_sha256",
    "observed_serial_number",
    "observed_subject",
    "observed_issuer",
    "observed_not_after",
    "deployment_reference",
    "observed_at",
    "public_metadata",
    "created_at",
    "updated_at",
  ],
};

const BASELINE_TOKEN_COLUMNS = [
  "id",
  "workspace_id",
  "type",
  "category",
  "cert_lifecycle_status",
];

const FORBIDDEN_CUSTODY_COLUMNS = [
  "privateKey",
  "private_key",
  "privateKeyPem",
  "private_key_pem",
  "key_pem",
  "key_der",
  "key_material",
  "raw_key",
  "pkcs12",
  "pfx",
  "backup",
  "secret",
  "credential",
  "password",
];

const certOpsMigration = migrations.find(
  (migration) => migration.name === "certops_inventory_schema",
);
const certOpsTokenLifecycleMigration = migrations.find(
  (migration) => migration.name === "certops_token_lifecycle_status",
);
const certOpsApiTokensMigration = migrations.find(
  (migration) => migration.name === "certops_api_tokens_schema",
);
const certOpsJobsEvidenceMigration = migrations.find(
  (migration) => migration.name === "certops_jobs_evidence_schema",
);
const certOpsExecutorEventMigration = migrations.find(
  (migration) => migration.name === "certops_executor_event_idempotency",
);

function getTableBlock(tableName, migration = certOpsMigration) {
  const marker = `CREATE TABLE IF NOT EXISTS ${tableName} (`;
  const start = migration.sql.indexOf(marker);
  assert.notEqual(start, -1, `missing ${marker}`);
  const bodyStart = start + marker.length;
  const end = migration.sql.indexOf("\n      );", bodyStart);
  assert.notEqual(end, -1, `missing end of ${tableName} definition`);
  return migration.sql.slice(bodyStart, end);
}

function getColumnNames(tableName, migration = certOpsMigration) {
  return getTableBlock(tableName, migration)
    .split(/\r?\n/)
    .map((line) => line.trim().replace(/,$/, ""))
    .map((line) => /^([a-z][a-z0-9_]*)\s+/i.exec(line)?.[1])
    .filter(Boolean)
    .filter(
      (name) =>
        ![
          "CHECK",
          "CONSTRAINT",
          "FOREIGN",
          "ON",
          "REFERENCES",
        ].includes(name.toUpperCase()),
    );
}

function resolveBaselineSchema(schema) {
  if (!schema.$ref) {
    return schema;
  }
  const prefix = "#/definitions/";
  assert.ok(
    schema.$ref.startsWith(prefix),
    `unsupported schema ref ${schema.$ref}`,
  );
  return baselineMinimumSchema.definitions[schema.$ref.slice(prefix.length)];
}

describe("CertOps inventory migration", () => {
  it("defines the M1 inventory migration", () => {
    assert.ok(certOpsMigration, "expected certops_inventory_schema migration");
    assert.equal(certOpsMigration.version, 10);
  });

  it("defines the token lifecycle migration after the inventory migration", () => {
    assert.ok(
      certOpsTokenLifecycleMigration,
      "expected certops_token_lifecycle_status migration",
    );
    assert.equal(certOpsTokenLifecycleMigration.version, 11);
    assert.deepEqual(
      migrations.slice(-5).map((migration) => migration.version),
      [10, 11, 12, 13, 14],
    );
    assert.match(
      certOpsTokenLifecycleMigration.sql,
      /ALTER TABLE tokens\s+ADD COLUMN IF NOT EXISTS cert_lifecycle_status TEXT NULL/,
    );
    assert.match(
      certOpsTokenLifecycleMigration.sql,
      /tokens_cert_lifecycle_status_check/,
    );
    assert.match(
      certOpsTokenLifecycleMigration.sql,
      /'revoked'/,
    );
    assert.match(
      certOpsTokenLifecycleMigration.sql,
      /'decommissioned'/,
    );
    assert.match(
      certOpsTokenLifecycleMigration.sql,
      /CREATE INDEX IF NOT EXISTS idx_tokens_workspace_cert_lifecycle_status/,
    );
  });

  it("defines the CertOps API token migration after M1 schema migrations", () => {
    assert.ok(
      certOpsApiTokensMigration,
      "expected certops_api_tokens_schema migration",
    );
    assert.equal(certOpsApiTokensMigration.version, 12);
    assert.match(
      certOpsApiTokensMigration.sql,
      /CREATE TABLE IF NOT EXISTS api_tokens \(/,
    );
    assert.match(certOpsApiTokensMigration.sql, /workspace_id UUID NOT NULL/);
    assert.match(certOpsApiTokensMigration.sql, /token_prefix TEXT NOT NULL/);
    assert.match(certOpsApiTokensMigration.sql, /token_hash TEXT NOT NULL/);
    assert.match(certOpsApiTokensMigration.sql, /scopes TEXT\[\] NOT NULL/);
    assert.match(
      certOpsApiTokensMigration.sql,
      /api_tokens_token_prefix_check/,
    );
    assert.match(
      certOpsApiTokensMigration.sql,
      /token_prefix ~ '\^ttx_\[A-Za-z0-9\]\+\$'/,
    );
    assert.doesNotMatch(
      certOpsApiTokensMigration.sql,
      /left\(token_prefix,\s*5\)\s*=\s*'ttx__'/,
    );
    for (const scope of [
      "certops:read",
      "certops:events:write",
      "certops:jobs:read",
      "certops:evidence:write",
    ]) {
      assert.match(certOpsApiTokensMigration.sql, new RegExp(`'${scope}'`));
    }
    for (const staleOrDeferredScope of [
      "certops:executor:events",
      "certops:jobs:write",
      "certops:jobs:claim",
    ]) {
      assert.doesNotMatch(
        certOpsApiTokensMigration.sql,
        new RegExp(`'${staleOrDeferredScope}'`),
      );
    }
    assert.match(certOpsApiTokensMigration.sql, /uq_api_tokens_token_prefix/);
    assert.match(certOpsApiTokensMigration.sql, /uq_api_tokens_token_hash/);
    assert.doesNotMatch(
      certOpsApiTokensMigration.sql,
      /private_key|privateKey|key_material|pfx|jks|password|credential|secret/i,
    );
  });

  it("defines the CertOps jobs and evidence migration after M2 auth migrations", () => {
    assert.ok(
      certOpsJobsEvidenceMigration,
      "expected certops_jobs_evidence_schema migration",
    );
    assert.equal(certOpsJobsEvidenceMigration.version, 13);

    for (const tableName of CERTOPS_JOB_TABLES) {
      assert.match(
        certOpsJobsEvidenceMigration.sql,
        new RegExp(`CREATE TABLE IF NOT EXISTS ${tableName} \\(`),
      );
    }

    assert.match(
      certOpsJobsEvidenceMigration.sql,
      /operation TEXT NOT NULL\s+CHECK \(operation IN \('renew', 'deploy', 'reload', 'revoke', 'noop'\)\)/,
    );
    assert.match(
      certOpsJobsEvidenceMigration.sql,
      /status TEXT NOT NULL DEFAULT 'pending'\s+CHECK \(status IN \('pending_approval', 'approved', 'rejected', 'pending', 'claimed', 'running', 'succeeded', 'failed', 'blocked', 'cancelled'\)\)/,
    );
    assert.match(
      certOpsJobsEvidenceMigration.sql,
      /status TEXT NULL\s+CHECK \(status IS NULL OR status IN \('pending_approval', 'approved', 'rejected', 'pending', 'claimed', 'running', 'succeeded', 'failed', 'blocked', 'cancelled'\)\)/,
    );
    assert.doesNotMatch(
      certOpsJobsEvidenceMigration.sql,
      /status IN \([^)]*'queued'|status IN \([^)]*'canceled'/,
      "CertOps job status checks must not retain stale plan values",
    );
    assert.match(
      certOpsJobsEvidenceMigration.sql,
      /payload JSONB NOT NULL DEFAULT '\{\}'::jsonb/,
    );
    assert.match(
      certOpsJobsEvidenceMigration.sql,
      /result_metadata JSONB NOT NULL DEFAULT '\{\}'::jsonb/,
    );
    assert.match(
      certOpsJobsEvidenceMigration.sql,
      /metadata JSONB NOT NULL DEFAULT '\{\}'::jsonb/,
    );
    assert.match(
      certOpsJobsEvidenceMigration.sql,
      /uq_certificate_jobs_workspace_idempotency_key/,
    );
    assert.match(
      certOpsJobsEvidenceMigration.sql,
      /fk_certificate_jobs_api_token/,
    );
  });

  it("defines idempotent, workspace-scoped executor event records", () => {
    assert.ok(
      certOpsExecutorEventMigration,
      "expected certops_executor_event_idempotency migration",
    );
    assert.equal(certOpsExecutorEventMigration.version, 14);

    for (const tableName of CERTOPS_EXECUTOR_EVENT_TABLES) {
      assert.match(
        certOpsExecutorEventMigration.sql,
        new RegExp(`CREATE TABLE IF NOT EXISTS ${tableName} \\(`),
      );
      assert.match(
        getTableBlock(tableName, certOpsExecutorEventMigration),
        /workspace_id UUID NOT NULL REFERENCES workspaces\(id\) ON DELETE CASCADE/,
      );
    }

    const table = getTableBlock(
      "certificate_executor_events",
      certOpsExecutorEventMigration,
    );
    assert.match(
      table,
      /UNIQUE \(workspace_id, job_id, executor_event_id\)/,
    );
    assert.match(
      table,
      /FOREIGN KEY \(workspace_id, job_id\)\s+REFERENCES certificate_jobs\(workspace_id, id\)\s+ON DELETE CASCADE/,
    );
    assert.match(
      table,
      /FOREIGN KEY \(workspace_id, created_by_api_token_id\)\s+REFERENCES api_tokens\(workspace_id, id\)\s+ON DELETE SET NULL \(created_by_api_token_id\)/,
    );
    assert.match(table, /request_hash TEXT NOT NULL/);
    assert.match(table, /response JSONB NOT NULL DEFAULT '\{\}'::jsonb/);
    assert.doesNotMatch(
      table,
      /private_key|privateKey|key_material|pfx|jks|password|credential|secret|authorization|token_hash/i,
    );
    for (const indexName of [
      "idx_certificate_executor_events_workspace_job_created",
      "idx_certificate_executor_events_workspace_event",
    ]) {
      assert.match(certOpsExecutorEventMigration.sql, new RegExp(indexName));
    }
  });

  it("creates every CertOps table idempotently", () => {
    for (const tableName of CERTOPS_TABLES) {
      assert.match(
        certOpsMigration.sql,
        new RegExp(`CREATE TABLE IF NOT EXISTS ${tableName} \\(`),
      );
    }
    assert.doesNotMatch(
      certOpsMigration.sql,
      /CREATE TABLE (?!IF NOT EXISTS)/,
    );
    assert.doesNotMatch(
      certOpsMigration.sql,
      /CREATE (?:UNIQUE )?INDEX (?!IF NOT EXISTS)/,
    );
  });

  it("creates every CertOps job and evidence table idempotently", () => {
    for (const tableName of CERTOPS_JOB_TABLES) {
      assert.match(
        certOpsJobsEvidenceMigration.sql,
        new RegExp(`CREATE TABLE IF NOT EXISTS ${tableName} \\(`),
      );
    }
    assert.doesNotMatch(
      certOpsJobsEvidenceMigration.sql,
      /CREATE TABLE (?!IF NOT EXISTS)/,
    );
    assert.doesNotMatch(
      certOpsJobsEvidenceMigration.sql,
      /CREATE (?:UNIQUE )?INDEX (?!IF NOT EXISTS)/,
    );
  });

  it("creates executor event records idempotently", () => {
    for (const tableName of CERTOPS_EXECUTOR_EVENT_TABLES) {
      assert.match(
        certOpsExecutorEventMigration.sql,
        new RegExp(`CREATE TABLE IF NOT EXISTS ${tableName} \\(`),
      );
    }
    assert.doesNotMatch(
      certOpsExecutorEventMigration.sql,
      /CREATE TABLE (?!IF NOT EXISTS)/,
    );
    assert.doesNotMatch(
      certOpsExecutorEventMigration.sql,
      /CREATE (?:UNIQUE )?INDEX (?!IF NOT EXISTS)/,
    );
  });

  it("keeps every CertOps table workspace-scoped", () => {
    for (const tableName of CERTOPS_TABLES) {
      assert.match(
        getTableBlock(tableName),
        /workspace_id UUID NOT NULL REFERENCES workspaces\(id\) ON DELETE CASCADE/,
        `${tableName} must have a non-null workspace FK`,
      );
    }
  });

  it("keeps every CertOps job and evidence table workspace-scoped", () => {
    for (const tableName of CERTOPS_JOB_TABLES) {
      assert.match(
        getTableBlock(tableName, certOpsJobsEvidenceMigration),
        /workspace_id UUID NOT NULL REFERENCES workspaces\(id\) ON DELETE CASCADE/,
        `${tableName} must have a non-null workspace FK`,
      );
    }
    assert.match(
      getTableBlock("certificate_job_log", certOpsJobsEvidenceMigration),
      /FOREIGN KEY \(workspace_id, job_id\)\s+REFERENCES certificate_jobs\(workspace_id, id\)\s+ON DELETE CASCADE/,
    );
    assert.match(
      getTableBlock("certificate_evidence", certOpsJobsEvidenceMigration),
      /FOREIGN KEY \(workspace_id, job_id\)\s+REFERENCES certificate_jobs\(workspace_id, id\)\s+ON DELETE SET NULL \(job_id\)/,
    );
  });

  it("uses workspace-scoped profile foreign keys", () => {
    assert.match(
      getTableBlock("managed_certificates"),
      /CONSTRAINT fk_managed_certificates_profile\s+FOREIGN KEY \(workspace_id, profile_id\)\s+REFERENCES certificate_profiles\(workspace_id, id\)\s+ON DELETE SET NULL \(profile_id\)/,
    );
    assert.match(
      getTableBlock("certificate_targets"),
      /CONSTRAINT fk_certificate_targets_profile\s+FOREIGN KEY \(workspace_id, profile_id\)\s+REFERENCES certificate_profiles\(workspace_id, id\)\s+ON DELETE SET NULL \(profile_id\)/,
    );
    assert.doesNotMatch(
      getTableBlock("managed_certificates"),
      /profile_id UUID NULL REFERENCES certificate_profiles\(id\)/,
    );
    assert.doesNotMatch(
      getTableBlock("certificate_targets"),
      /profile_id UUID NULL REFERENCES certificate_profiles\(id\)/,
    );
  });

  it("does not define private-key custody columns", () => {
    for (const tableName of CERTOPS_TABLES) {
      for (const columnName of getColumnNames(tableName)) {
        const hit = FORBIDDEN_CUSTODY_COLUMNS.find((fragment) =>
          columnName.toLowerCase().includes(fragment.toLowerCase()),
        );
        assert.equal(
          hit,
          undefined,
          `${tableName}.${columnName} looks like private-key custody`,
        );
      }
    }
  });

  it("does not define private-key custody columns in job/evidence tables", () => {
    for (const tableName of CERTOPS_JOB_TABLES) {
      for (const columnName of getColumnNames(
        tableName,
        certOpsJobsEvidenceMigration,
      )) {
        const hit = FORBIDDEN_CUSTODY_COLUMNS.find((fragment) =>
          columnName.toLowerCase().includes(fragment.toLowerCase()),
        );
        assert.equal(
          hit,
          undefined,
          `${tableName}.${columnName} looks like private-key custody`,
        );
      }
    }
  });

  it("does not define private-key custody columns in executor event records", () => {
    for (const tableName of CERTOPS_EXECUTOR_EVENT_TABLES) {
      for (const columnName of getColumnNames(
        tableName,
        certOpsExecutorEventMigration,
      )) {
        const hit = FORBIDDEN_CUSTODY_COLUMNS.find((fragment) =>
          columnName.toLowerCase().includes(fragment.toLowerCase()),
        );
        assert.equal(
          hit,
          undefined,
          `${tableName}.${columnName} looks like private-key custody`,
        );
      }
    }
  });

  it("includes the CertOps inventory tables in the baseline DB contract", () => {
    const tableSchema =
      baselineMinimumSchema.properties.tables.properties;
    const requiredTables = baselineMinimumSchema.properties.tables.required;

    for (const [tableName, expectedColumns] of Object.entries(
      BASELINE_CERTOPS_COLUMNS,
    )) {
      assert.ok(
        requiredTables.includes(tableName),
        `${tableName} must be required by the baseline contract`,
      );
      assert.ok(tableSchema[tableName], `${tableName} schema is missing`);

      const resolvedTableSchema = resolveBaselineSchema(tableSchema[tableName]);
      const requiredColumns =
        resolvedTableSchema.properties.requiredColumns;
      for (const columnName of expectedColumns) {
        assert.match(
          JSON.stringify(requiredColumns),
          new RegExp(`"const":"${columnName}"`),
          `${tableName} must require ${columnName}`,
        );
      }

      const forbiddenHit = FORBIDDEN_CUSTODY_COLUMNS.find((columnName) =>
        JSON.stringify(requiredColumns)
          .toLowerCase()
          .includes(`"${columnName.toLowerCase()}"`),
      );
      assert.equal(
        forbiddenHit,
        undefined,
        `${tableName} baseline contract allows ${forbiddenHit}`,
      );
    }
  });

  it("requires the token certificate lifecycle column in the baseline DB contract", () => {
    const tableSchema = baselineMinimumSchema.properties.tables.properties;
    const requiredTables = baselineMinimumSchema.properties.tables.required;

    assert.ok(
      requiredTables.includes("tokens"),
      "tokens must be required by the baseline contract",
    );
    assert.ok(tableSchema.tokens, "tokens schema is missing");

    const resolvedTableSchema = resolveBaselineSchema(tableSchema.tokens);
    const requiredColumns = resolvedTableSchema.properties.requiredColumns;
    for (const columnName of BASELINE_TOKEN_COLUMNS) {
      assert.match(
        JSON.stringify(requiredColumns),
        new RegExp(`"const":"${columnName}"`),
        `tokens must require ${columnName}`,
      );
    }

    const forbiddenHit = FORBIDDEN_CUSTODY_COLUMNS.find((columnName) =>
      JSON.stringify(requiredColumns)
        .toLowerCase()
        .includes(`"${columnName.toLowerCase()}"`),
    );
    assert.equal(
      forbiddenHit,
      undefined,
      `tokens baseline contract allows ${forbiddenHit}`,
    );
  });

  it("links certificates to existing tokens without making tokens depend on CertOps", () => {
    assert.match(
      getTableBlock("managed_certificates"),
      /token_id INTEGER NULL REFERENCES tokens\(id\) ON DELETE SET NULL/,
    );
    assert.match(
      getTableBlock("certificate_targets"),
      /token_id INTEGER NULL REFERENCES tokens\(id\) ON DELETE SET NULL/,
    );
    assert.match(
      getTableBlock("certificate_instances"),
      /token_id INTEGER NULL REFERENCES tokens\(id\) ON DELETE SET NULL/,
    );
  });

  it("adds lookup and dedupe indexes for inventory queries", () => {
    for (const indexName of [
      "idx_managed_certificates_workspace",
      "idx_managed_certificates_workspace_expiry",
      "uq_managed_certificates_workspace_fingerprint",
      "idx_certificate_instances_certificate",
      "idx_certificate_instances_workspace_fingerprint",
      "idx_certificate_targets_domain_monitor",
      "idx_certificate_profiles_workspace_status",
    ]) {
      assert.match(certOpsMigration.sql, new RegExp(indexName));
    }
  });

  it("adds lookup, lifecycle, and idempotency indexes for job/evidence queries", () => {
    for (const indexName of [
      "idx_certificate_jobs_workspace_created",
      "idx_certificate_jobs_workspace_status_created",
      "uq_certificate_jobs_workspace_idempotency_key",
      "idx_certificate_job_log_workspace_job_created",
      "idx_certificate_evidence_workspace_job_created",
      "idx_certificate_evidence_workspace_subject_created",
    ]) {
      assert.match(
        certOpsJobsEvidenceMigration.sql,
        new RegExp(indexName),
        `missing ${indexName}`,
      );
    }
  });

  it("defers dedicated security events and audit hash-chain storage beyond M2", () => {
    assert.doesNotMatch(
      certOpsJobsEvidenceMigration.sql,
      /\bsecurity_events\b|\bprev_hash\b|\brow_hash\b|\balert_queue\b/i,
    );
    assert.doesNotMatch(
      certOpsExecutorEventMigration.sql,
      /\bsecurity_events\b|\bprev_hash\b|\brow_hash\b|\balert_queue\b/i,
    );
  });
});
