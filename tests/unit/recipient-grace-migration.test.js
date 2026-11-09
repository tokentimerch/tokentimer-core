"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { migrations } = require("../../apps/api/migrations/migrate");
const { composeMigrations } = require("../../apps/api/migrations/compose-migrations");

test("grace installs after consent without changing released ledger identities", () => {
  for (const last of [0, 78, 81, 82, 84, 85, 98, 106, 107, 108, 109]) {
    const recorded = migrations.filter(row => row.version <= last).map(({ version, name }) => ({ version, name }));
    const plan = composeMigrations(migrations, recorded);
    const grace = plan.find(row => row.name === "recipient_legacy_delivery_grace");
    assert.equal(grace.version, 109);
    assert.ok(plan.find(row => row.name === "recipient_channel_verification").version < grace.version);
    for (const row of recorded) {
      assert.equal(plan.find(entry => entry.name === row.name).version, row.version);
    }
    assert.match(grace.sql, /CREATE TABLE IF NOT EXISTS recipient_legacy_grace_refusals/);
    assert.match(grace.sql, /CREATE TRIGGER recipient_legacy_grace_guard_insert/);
    assert.match(grace.sql, /CREATE TRIGGER recipient_legacy_grace_before_contact_delete/);
  }
});
