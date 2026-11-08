"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { normalizeObservedRevocation } = require("../../apps/api/services/certops/observedRevocation");

const serverAt = "2026-01-01T00:30:00Z";
const valid = { observedRevocationVerdict: "revoked", observedChainStatus: "valid", observedRevocationCheckedAt: "2026-01-01T00:00:00Z", observedRevocationValidUntil: "2026-01-01T01:00:00Z" };

test("configuration states are not checks and use only server time for ordering", () => {
  for (const state of ["not_configured", "disabled"]) {
    const value = normalizeObservedRevocation({ observedRevocationState: state }, serverAt);
    assert.equal(value.verdict, state);
    assert.equal(value.checkedAt, null);
    assert.equal(value.validUntil, null);
    assert.equal(value.reportedAt, "2026-01-01T00:30:00.000Z");
  }
  assert.equal(normalizeObservedRevocation({ observedRevocationState: "not_configured" }, "invalid"), null);
});

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
  ]) assert.equal(normalizeObservedRevocation({ ...valid, ...change }, serverAt).verdict, "invalid_observation");
});

test("unavailable verification may report an attempt without a validity deadline", () => {
  const value = normalizeObservedRevocation({ ...valid, observedRevocationVerdict: "unknown", observedChainStatus: "unknown", observedRevocationValidUntil: null }, serverAt);
  assert.equal(value.verdict, "unknown");
  assert.equal(value.validUntil, null);
});


test("scan revisions are positive safe integers carried by policy and verification", () => {
  for (const metadata of [valid, { observedRevocationState: "disabled" }]) {
    assert.equal(normalizeObservedRevocation({ ...metadata, observedRevocationRevision: "9007199254740991" }, serverAt).revision, Number.MAX_SAFE_INTEGER);
    for (const revision of ["0", "-1", "1.5", "9007199254740992", "01", 1]) {
      const invalid = normalizeObservedRevocation({ ...metadata, observedRevocationRevision: revision }, serverAt);
      assert.equal(invalid.verdict, "invalid_observation");
      assert.equal(invalid.checkedAt, null);
      assert.equal(invalid.revision, undefined);
    }
  }
});
