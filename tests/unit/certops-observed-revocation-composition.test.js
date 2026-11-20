"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { migrations } = require("../../apps/api/migrations/migrate");
const { composeMigrations } = require("../../apps/api/migrations/compose-migrations");

test("observed revocation appends after the unchanged main migrations", () => {
  const base = migrations.filter((item) => item.version < 122);
  const histories = [base, migrations];
  for (const history of histories) {
    const plan = composeMigrations(migrations, history.map(({ version, name }) => ({ version, name })));
    assert.deepEqual(plan.slice(0, base.length), base);
    assert.equal(plan.find((item) => item.name === "certops_observed_revocation").version, 122);
    assert.equal(plan.find((item) => item.version === 127).name, "auto_sync_creation_expiration");
    assert.equal(plan.at(-1).name, "shared_sso_schema");
    assert.equal(plan.find((item) => item.version === 112).name, "certops_retirement_dossiers");
    assert.equal(plan.filter((item) => item.name.startsWith("store_issuance")).length, 0);
  }
});
