"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { migrations } = require("../../apps/api/migrations/migrate");

test("recipient rollout guidance uses the actual canonical migration identities", () => {
  const version = (name) => {
    const found = migrations.filter((migration) => migration.name === name);
    assert.equal(found.length, 1, name);
    return found[0].version;
  };
  const expected = [
    version("recipient_channel_verification"),
    version("weekly_digest_recipient_claim_token"),
  ];
  const numbering = readFileSync(join(__dirname, "../../docs/migrations/open-pr-numbering.md"), "utf8");
  for (const name of ["recipient_channel_verification", "weekly_digest_recipient_claim_token", "recipient_member_verification"]) {
    assert.match(numbering, new RegExp(`\\| ${version(name)} \\| ${name} \\|`));
  }
  for (const [file, pattern] of [
    ["CHANGELOG.md", /canonical main uses (\d+) for recipient verification and (\d+) for digest claims/],
  ]) {
    const match = readFileSync(join(__dirname, "../..", file), "utf8").match(pattern);
    assert.ok(match, `${file} must identify the canonical migration plan`);
    assert.deepEqual(match.slice(1).map(Number), expected, file);
  }
});
