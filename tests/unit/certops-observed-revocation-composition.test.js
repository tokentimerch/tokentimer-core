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

test("reserved Windows store migrations and observed revocation compose in either order", () => {
  const store = [
    { version: 113, name: "store_issuance_explicit_renewal_consent" },
    { version: 114, name: "certops_acme_store_enrollment_identity" },
    { version: 115, name: "certops_adcs_expected_identity_receipts" },
  ];
  const consent = { version: 116, name: "certops_windows_iis_consent" };
  const histories = [migrations.filter((item) => item.version <= 110), migrations.filter((item) => item.version !== 112 && item.version !== 116)];
  for (const history of histories) {
    const plan = composeMigrations(migrations, history.map(({ version, name }) => ({ version, name })));
    assert.deepEqual(plan.filter((item) => item.version >= 112).map(({ version, name }) => ({ version, name })), [
      { version: 112, name: "certops_observed_revocation" },
      ...store,
      consent,
    ]);
  }
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
