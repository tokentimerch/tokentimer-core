"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { normalizeObservedRevocation } = require("../../apps/api/services/certops/observedRevocation");

const serverAt = "2026-01-01T00:30:00Z";
const valid = { observedRevocationVerdict: "revoked", observedChainStatus: "valid", observedRevocationCheckedAt: "2026-01-01T00:00:00Z", observedRevocationValidUntil: "2026-01-01T01:00:00Z" };

test("authenticated observations preserve a typed and dated revocation result", () => {
  const value = normalizeObservedRevocation(valid, serverAt);
  assert.equal(value.verdict, "revoked");
  assert.equal(value.chainStatus, "valid");
  assert.equal(value.checkedAt, "2026-01-01T00:00:00.000Z");
  assert.equal(value.validUntil, "2026-01-01T01:00:00.000Z");
});

test("malformed or untrusted facts cannot claim a healthy result", () => {
  assert.equal(normalizeObservedRevocation({}, serverAt), null);
  for (const change of [
    { observedRevocationVerdict: "good", observedChainStatus: "invalid" },
    { observedRevocationVerdict: "good", observedRevocationValidUntil: null },
    { observedRevocationCheckedAt: "2026-01-01T00:40:00Z" },
    { observedRevocationValidUntil: "2025-12-31T23:59:00Z" },
    { observedRevocationVerdict: "bogus" },
  ]) assert.equal(normalizeObservedRevocation({ ...valid, ...change }, serverAt), null);
});

test("unavailable verification may report an attempt without a validity deadline", () => {
  const value = normalizeObservedRevocation({ ...valid, observedRevocationVerdict: "unknown", observedChainStatus: "unknown", observedRevocationValidUntil: null }, serverAt);
  assert.equal(value.verdict, "unknown");
  assert.equal(value.validUntil, null);
});
