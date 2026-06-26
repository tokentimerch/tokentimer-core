"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { migrations } = require(
  path.resolve(__dirname, "../../apps/api/migrations/migrate.js"),
);

const CERTOPS_TABLES = [
  "managed_certificates",
  "certificate_instances",
  "certificate_profiles",
  "certificate_targets",
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

  it("does not define private-key custody columns", () => {
    const forbiddenFragments = [
      "private",
      "pkcs12",
      "pfx",
      "key_material",
      "key_pem",
      "key_der",
      "raw_key",
      "backup",
      "secret",
      "credential",
      "password",
    ];

    for (const tableName of CERTOPS_TABLES) {
      for (const columnName of getColumnNames(tableName)) {
        const hit = forbiddenFragments.find((fragment) =>
          columnName.includes(fragment),
        );
        assert.equal(
          hit,
          undefined,
          `${tableName}.${columnName} looks like private-key custody`,
        );
      }
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
