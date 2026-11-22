"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { migrations } = require("../../apps/api/migrations/migrate");
const { composeMigrations } = require("../../apps/api/migrations/compose-migrations");

test("revoked issuer fingerprint remains a valid OpenAPI schema property", () => {
  const fs = require("node:fs");
  const apiRequire = require("node:module").createRequire(require.resolve("../../apps/api/package.json"));
  const yaml = require("node:module").createRequire(apiRequire.resolve("swagger-jsdoc"))("yaml");
  const doc = yaml.parse(fs.readFileSync(require("node:path").join(__dirname, "../../packages/contracts/openapi/openapi.yaml"), "utf8"));
  const property = doc.components.schemas.CertOpsManagedCertificate.properties.observedRevocation.properties.revokedIssuerFingerprintSha256;
  assert.deepEqual(Object.keys(property).sort(), ["description", "pattern", "type"]);
  assert.equal(property.type, "string");
  assert.match(property.description, /when supplied by a qualified agent/);
});

test("Windows Store, IIS and observed revocation use their shared canonical reservations", () => {
  for (const history of [migrations.filter((row) => row.version <= 114), migrations.filter((row) => row.version === 122 || row.version <= 114), migrations]) {
    const plan = composeMigrations(migrations, history);
    assert.deepEqual(plan.filter((row) => row.version >= 115).map(({ version, name }) => ({ version, name })), [
      { version: 115, name: "store_issuance_explicit_renewal_consent" },
      { version: 116, name: "certops_acme_store_enrollment_identity" },
      { version: 117, name: "certops_adcs_expected_identity_receipts" },
      { version: 118, name: "certops_windows_iis_consent" },
      { version: 119, name: "certops_material_adcs_operation_union" },
      { version: 120, name: "certops_iis_absence_proofs" },
      { version: 121, name: "certops_enrollment_jobs_index" },
      { version: 122, name: "certops_observed_revocation" },
      { version: 123, name: "agent_credential_rotations" },
      { version: 124, name: "agent_credential_rotation_ack" },
      { version: 125, name: "certops_adcs_preflight_lookup_index" },
      { version: 126, name: "certops_adcs_receipt_deadline" },
      { version: 127, name: "auto_sync_creation_expiration" },
      { version: 128, name: "shared_sso_schema" },
    ]);
  }
});

test("observed revocation appends after the unchanged main migrations", () => {
  const isolatedRegistry = migrations.filter(({ version }) => version <= 114 || [122, 123, 124, 127].includes(version));
  const base = isolatedRegistry.filter((item) => item.version < 122);
  const histories = [base, isolatedRegistry];
  for (const history of histories) {
    const plan = composeMigrations(isolatedRegistry, history.map(({ version, name }) => ({ version, name })));
    assert.deepEqual(plan.slice(0, base.length), base);
    assert.deepEqual(plan.slice(base.length).map(({ version, name }) => ({ version, name })), [
      { version: 122, name: "certops_observed_revocation" },
      { version: 123, name: "agent_credential_rotations" },
      { version: 124, name: "agent_credential_rotation_ack" },
      { version: 127, name: "auto_sync_creation_expiration" },
    ]);
    assert.equal(plan.find((item) => item.version === 112).name, "certops_retirement_dossiers");
    assert.equal(plan.filter((item) => item.name.startsWith("store_issuance")).length, 0);
  }
});

test("preserves the integrated Windows preview identities at every applied prefix", () => {
  const oldOrder = [
    "certops_observed_revocation",
    ...migrations.filter((row) => row.version >= 115 && row.version < 122).map(({ name }) => name),
  ];
  const released = migrations.filter((row) => row.version <= 114);
  for (let length = 1; length <= oldOrder.length; length++) {
    const ledger = [...released, ...oldOrder.slice(0, length).map((name, index) => ({ version: 115 + index, name }))];
    const plan = composeMigrations(migrations, ledger);
    for (const row of ledger) {
      assert.equal(plan.find((entry) => entry.version === row.version)?.name, row.name);
    }
    assert.deepEqual(composeMigrations(migrations, plan), plan);
  }
});

test("preserves the observed-revocation preview ledger and appends main migrations", () => {
  const absent = new Set([86, 87, 88, 89, 90, 91, 96, 97]);
  const history = migrations.filter(item => item.version <= 111 && !absent.has(item.version))
    .map(({version, name}) => ({version, name}));
  const names = ["certops_observed_revocation", "store_issuance_explicit_renewal_consent", "certops_acme_store_enrollment_identity", "certops_adcs_expected_identity_receipts", "certops_windows_iis_consent"];
  names.forEach((name, index) => history.push({version: 112 + index, name}));
  const plan = composeMigrations(migrations, history);
  for (const row of history) assert.equal(plan.find(item => item.name === row.name).version, row.version);
  assert.ok(plan.find(item => item.name === "certops_retirement_dossiers").version > 116);
  assert.ok(plan.find(item => item.name === "certops_material_reconciliation").version > 116);
  for (let count = 1; count <= names.length; count++) {
    const partial = history.filter(row => row.version < 112 + count);
    const completed = composeMigrations(migrations, partial).map(({version, name}) => ({version, name}));
    assert.deepEqual(composeMigrations(migrations, completed).map(({version, name}) => ({version, name})), completed);
  }
  const malformed = history.map(row => ({...row}));
  malformed[malformed.length - 1].name = "certops_observed_revocation";
  assert.throws(() => composeMigrations(migrations, malformed), /Unsupported Core migration history/);
});

test("rejects an unrecognized legacy store preview ledger rather than aliasing main migrations", () => {
  const history = migrations.filter(item => item.version <= 108).map(({version, name}) => ({version, name}));
  history.push(
    { version: 109, name: "store_issuance_explicit_renewal_consent" },
    { version: 110, name: "certops_acme_store_enrollment_identity" },
    { version: 111, name: "certops_adcs_expected_identity_receipts" },
  );
  assert.throws(() => composeMigrations(migrations, history), /Unsupported Core migration history/);
});
