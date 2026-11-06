"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { migrations } = require("../../apps/api/migrations/migrate");
const { composeMigrations } = require("../../apps/api/migrations/compose-migrations");

test("reserved Windows store migrations and observed revocation compose in either order", () => {
  const store = [
    { version: 109, name: "store_issuance_explicit_renewal_consent" },
    { version: 110, name: "certops_acme_store_enrollment_identity" },
    { version: 111, name: "certops_adcs_expected_identity_receipts" },
  ];
  const combined = [...migrations, ...store];
  const histories = [migrations, [...migrations.filter((item) => item.version !== 112), ...store]];
  for (const history of histories) {
    const plan = composeMigrations(combined, history.map(({ version, name }) => ({ version, name })));
    assert.deepEqual(plan.filter((item) => item.version >= 109).map(({ version, name }) => ({ version, name })), [
      ...store,
      { version: 112, name: "certops_observed_revocation" },
    ]);
  }
});
