"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { revocationStatus } = require("./status");

test("fresh results become stale instead of continuing to imply current health", () => {
  const result = { verdict: "good", checkedAt: "2026-01-01T00:00:00Z", validUntil: "2026-01-01T01:00:00Z" };
  assert.equal(revocationStatus(result, Date.parse("2026-01-01T00:30:00Z")).freshness, "fresh");
  assert.equal(revocationStatus(result, Date.parse("2026-01-01T01:00:00Z")).freshness, "stale");
});

test("unavailable and malformed results never become verified good", () => {
  const now = Date.parse("2026-01-01T02:00:00Z");
  for (const value of [null, {}, { verdict: "good", checkedAt: "invalid", validUntil: "2026-01-02T00:00:00Z" }, { verdict: "good", checkedAt: "2026-01-03T00:00:00Z", validUntil: "2026-01-04T00:00:00Z" }]) {
    assert.equal(revocationStatus(value, now).verdict, "unknown");
  }
  assert.equal(revocationStatus({ verdict: "unknown", checkedAt: "2026-01-01T01:00:00Z" }, now).freshness, "unknown");
});

test("revoked leaf and issuer remain distinct even after freshness expires", () => {
  const now = Date.parse("2026-01-01T02:00:00Z");
  for (const verdict of ["revoked", "issuer_revoked"]) {
    const state = revocationStatus({ verdict, checkedAt: "2026-01-01T00:00:00Z", validUntil: "2026-01-01T01:00:00Z" }, now);
    assert.equal(state.verdict, verdict);
    assert.equal(state.freshness, "stale");
  }
});
