"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { classifyCertificateSecurity } = require("../../apps/api/services/certops/certificateSecurity");

describe("certificate security state", () => {
  const now = Date.parse("2026-11-11T12:00:00Z");
  const observation = (verdict, overrides = {}) => ({ verdict, chainStatus: "valid",
    checkedAt: "2026-11-11T11:00:00Z", validUntil: "2026-11-11T13:00:00Z", ...overrides });
  const state = (result, lifecycleStatus = "active") => classifyCertificateSecurity({ observedRevocation: result, lifecycleStatus, now }).state;

  it("distinguishes a revoked certificate from a revoked issuer", () => {
    assert.equal(state(observation("revoked")), "revoked");
    assert.equal(state(observation("issuer_revoked")), "issuer_revoked");
  });
  it("keeps a stale or unavailable adverse result without claiming freshness", () => {
    assert.equal(state(observation("revoked", { validUntil: "2026-11-11T11:30:00Z" })), "last_known_revoked");
    assert.equal(state({ verdict: "unknown", lastVerified: observation("issuer_revoked") }), "last_known_issuer_revoked");
    assert.equal(state(observation("unknown", { lastVerified: observation("revoked") })), "last_known_revoked");
    assert.equal(state(observation("good", { lastVerified: observation("revoked") })), "revocation_good");
    assert.equal(state(observation("revoked", { checkedAt: "2026-11-11T12:30:00Z" })), "unknown");
    assert.equal(state(observation("revoked", { chainStatus: "invalid" })), "chain_untrusted");
  });
  it("does not turn unavailable, disabled, untrusted or stale good into a good result", () => {
    assert.equal(state(null), "unknown");
    assert.equal(state({ verdict: "disabled" }), "unknown");
    assert.equal(state({ verdict: "unknown", chainStatus: "invalid" }), "chain_untrusted");
    assert.equal(state(observation("good", { validUntil: "2026-11-11T11:30:00Z" })), "unknown");
  });
  it("reflects a new good observation without changing management lifecycle", () => {
    assert.equal(state(observation("good")), "revocation_good");
    assert.equal(state(observation("good"), "revoked"), "revoked");
    assert.equal(state(observation("good"), "decommissioned"), "revocation_good");
  });
});
