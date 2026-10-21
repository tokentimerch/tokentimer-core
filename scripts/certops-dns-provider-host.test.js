/**
 * Regression coverage: DNS janitor preserves live boundary future and unowned values.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { staleValues, providers } = require("./certops-dns-provider-host");
const now = 1800000000000;
const value = (time) => `certops-qualification-${time}-${"a".repeat(32)}`;
test("DNS janitor preserves live boundary future and unowned values", () => {
  const old = value(now - 7200001);
  assert.deepEqual(staleValues([old, old, value(now - 7200000), value(now), value(now + 10000), "production-validation", `${old}-extra`, old.replace("qualification", "qualifications")], now), [old]);
});
test("DNS janitor refuses malformed inventory and invalid clock instead of broad cleanup", () => {
  assert.throws(() => staleValues(null, now)); assert.throws(() => staleValues([{}], now)); assert.throws(() => staleValues([value(now)], NaN));
});
test("Real provider fixture inventory excludes test-only solver", () => {
  assert.equal(providers.length, 11); assert.equal(new Set(providers).size, 11); assert.equal(providers.includes("pebble-challtestsrv"), false);
});

test("DNS janitor never prints environment credentials or configuration", () => {
  const { spawnSync } = require("node:child_process");
  const marker = "private-janitor-environment-sentinel";
  const result = spawnSync(process.execPath, [require.resolve("./certops-dns-provider-host"), "--janitor"], {
    encoding: "utf8", timeout: 10000,
    env: { ...process.env, GITHUB_ACTIONS: "true", RUNNER_ENVIRONMENT: "github-hosted", CERTOPS_DNS_DEDICATED_FIXTURE: "1", CERTOPS_DNS_PROVIDER: "acme-dns", CERTOPS_DNS_ZONE: "fixture.invalid", CERTOPS_DNS_RESOLVERS_JSON: '["127.0.0.1"]', CERTOPS_DNS_CREDENTIALS_JSON: JSON.stringify({ baseUrl: "https://fixture.invalid", username: marker, password: marker, subdomain: marker }) },
  });
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), "DNS cleanup is not applicable to the two-slot provider");
  assert.equal((result.stdout + result.stderr).includes(marker), false);
});
