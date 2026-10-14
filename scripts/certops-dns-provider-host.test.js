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
