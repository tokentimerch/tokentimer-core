"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { migrations } = require("../../apps/api/migrations/migrate");
const { composeMigrations } = require("../../apps/api/migrations/compose-migrations");

test("reserved Windows store migrations and observed revocation compose in either order", () => {
  const store = [
    { version: 113, name: "store_issuance_explicit_renewal_consent" },
    { version: 114, name: "certops_acme_store_enrollment_identity" },
    { version: 115, name: "certops_adcs_expected_identity_receipts" },
  ];
  const combined = [...migrations, ...store];
  const histories = [migrations, [...migrations.filter((item) => item.version !== 112), ...store]];
  for (const history of histories) {
    const plan = composeMigrations(combined, history.map(({ version, name }) => ({ version, name })));
    assert.deepEqual(plan.filter((item) => item.version >= 112).map(({ version, name }) => ({ version, name })), [
      { version: 112, name: "certops_observed_revocation" },
      ...store,
    ]);
  }
});
