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

function getTableBlock(tableName) {
  const marker = `CREATE TABLE IF NOT EXISTS ${tableName} (`;
  const start = certOpsMigration.sql.indexOf(marker);
  assert.notEqual(start, -1, `missing ${marker}`);
  const bodyStart = start + marker.length;
  const end = certOpsMigration.sql.indexOf("\n      );", bodyStart);
  assert.notEqual(end, -1, `missing end of ${tableName} definition`);
  return certOpsMigration.sql.slice(bodyStart, end);
}

function getColumnNames(tableName) {
  return getTableBlock(tableName)
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

  it("keeps every CertOps table workspace-scoped", () => {
    for (const tableName of CERTOPS_TABLES) {
      assert.match(
        getTableBlock(tableName),
        /workspace_id UUID NOT NULL REFERENCES workspaces\(id\) ON DELETE CASCADE/,
        `${tableName} must have a non-null workspace FK`,
      );
    }
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
});
