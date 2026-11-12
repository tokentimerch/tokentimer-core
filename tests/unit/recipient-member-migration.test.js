"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { migrations } = require("../../apps/api/migrations/migrate");
const { composeMigrations } = require("../../apps/api/migrations/compose-migrations");

test("member verification follows consent without changing released ledger identities", () => {
  for (const last of [0, 78, 81, 82, 84, 85, 98, 106, 107, 108, 109, 110]) {
    const recorded = migrations.filter(row => row.version <= last).map(({ version, name }) => ({ version, name }));
    const plan = composeMigrations(migrations, recorded);
    const member = plan.find(row => row.name === "recipient_member_verification");
    assert.equal(member.version, 110);
    assert.ok(plan.find(row => row.name === "recipient_channel_verification").version < member.version);
    for (const row of recorded) {
      assert.equal(plan.find(entry => entry.name === row.name).version, row.version);
    }
    assert.match(member.sql, /ADD COLUMN IF NOT EXISTS recipient_verified_email/);
    assert.match(member.sql, /CREATE TRIGGER recipient_member_verification_preserve_revocation/);
  }
});
