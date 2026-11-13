"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { classifyBinding, classifyPendingCutover, iisSelectorKey, planPendingCutovers } = require("../../apps/api/services/certops/windowsRenewalOwnership");

const owner = { workspaceId: "w", agentId: "a", managementPeriodId: "period", storeName: "My", fingerprintSha256: "ab".repeat(32), managementActive: true, renewalEligible: true };
const binding = { id: "iis", workspaceId: "w", agentId: "a", storeName: "MY", fingerprintSha256: "AB".repeat(32), presence: "confirmed_present" };
const classify = (overrides = {}, more = {}) => classifyBinding({ owner, binding: { ...binding, ...overrides }, agentOnline: true, observationFresh: true, ...more });

describe("Windows Store renewal dependencies", () => {
  it("identifies the actual HTTP.sys selector, regardless of site name or SNI case", () => {
    assert.equal(iisSelectorKey({ port: 443, site: "A" }), iisSelectorKey({ port: 443, site: "B" }));
    assert.equal(iisSelectorKey({ port: 443, sniHost: "WWW.Example.test" }),
      iisSelectorKey({ port: 443, sniHost: "www.example.test" }));
    assert.notEqual(iisSelectorKey({ port: 443 }), iisSelectorKey({ port: 443, sniHost: "www.example.test" }));
    assert.throws(() => iisSelectorKey({ port: 443, sniHost: "bad host" }), /invalid/);
    assert.throws(() => iisSelectorKey({ port: 443, address: "192.0.2.1" }), /address/);
  });
  it("requires explicit authorization for a matching observed binding", () => {
    assert.deepEqual(classify(), { relationship: "observed", deployment: "observed_only" });
    assert.deepEqual(classify({ automaticUpdate: true }), { relationship: "observed", deployment: "authorized" });
  });
  it("never inherits authorization across workspace, agent, or store", () => {
    for (const overrides of [{ workspaceId: "other" }, { agentId: "other" }, { storeName: "Root" }]) {
      assert.deepEqual(classify({ ...overrides, automaticUpdate: true }), { relationship: "unrelated", deployment: "unavailable" });
    }
  });
  it("does not treat offline or stale evidence as removal or permission", () => {
    assert.deepEqual(classify({ automaticUpdate: true }, { agentOnline: false }), { relationship: "unknown", deployment: "unavailable" });
    assert.deepEqual(classify({ automaticUpdate: true }, { observationFresh: false }), { relationship: "unknown", deployment: "unavailable" });
    assert.deepEqual(classify({ presence: "unknown", automaticUpdate: true }), { relationship: "unknown", deployment: "unavailable" });
    assert.deepEqual(classify({ presence: "confirmed_absent", automaticUpdate: true }), { relationship: "absent", deployment: "unavailable" });
  });
  it("refuses mismatched or missing fingerprint evidence", () => {
    assert.deepEqual(classify({ fingerprintSha256: "cd".repeat(32), automaticUpdate: true }), { relationship: "changed", deployment: "unavailable" });
    for (const fingerprintSha256 of ["", null]) {
      assert.deepEqual(classify({ fingerprintSha256, automaticUpdate: true }), { relationship: "unknown", deployment: "unavailable" });
    }
  });
  it("requires explicit consolidation of an existing independent profile", () => {
    assert.deepEqual(classify({ renewalProfileId: "existing", automaticUpdate: true }), { relationship: "observed", deployment: "conflict" });
  });
  it("does not establish ownership without a stable management period", () => {
    assert.deepEqual(classify({}, { owner: { ...owner, managementPeriodId: null } }), { relationship: "unrelated", deployment: "unavailable" });
    assert.deepEqual(classify({ automaticUpdate: true }, { owner: { ...owner, managementActive: false } }), { relationship: "unknown", deployment: "unavailable" });
    assert.deepEqual(classify({ automaticUpdate: true }, { owner: { ...owner, renewalEligible: false } }), { relationship: "unknown", deployment: "unavailable" });
  });
  it("uses the recorded predecessor during cutover and recognizes an idempotent retry", () => {
    const replacementSha256 = "cd".repeat(32);
    const input = { owner: { ...owner, fingerprintSha256: replacementSha256 },
      binding: { ...binding, automaticUpdate: true }, agentOnline: true, observationFresh: true,
      predecessorSha256: owner.fingerprintSha256, replacementSha256 };
    assert.deepEqual(classifyPendingCutover(input), { relationship: "observed", deployment: "authorized" });
    assert.deepEqual(classifyPendingCutover({ ...input, binding: { ...input.binding, fingerprintSha256: replacementSha256 } }),
      { relationship: "observed", deployment: "verify_only" });
    assert.deepEqual(classifyPendingCutover({ ...input, binding: { ...input.binding, fingerprintSha256: replacementSha256, renewalProfileId: "other" } }),
      { relationship: "observed", deployment: "conflict" });
    assert.deepEqual(classifyPendingCutover({ ...input, binding: { ...input.binding, fingerprintSha256: "ef".repeat(32) } }),
      { relationship: "changed", deployment: "unavailable" });
    assert.deepEqual(classifyPendingCutover({ ...input, predecessorSha256: null }),
      { relationship: "unknown", deployment: "unavailable" });
  });
  it("plans several bindings independently and rejects duplicate identities", () => {
    const replacementSha256 = "cd".repeat(32);
    const input = { owner: { ...owner, fingerprintSha256: replacementSha256 }, agentOnline: true,
      predecessorSha256: owner.fingerprintSha256, replacementSha256,
      bindings: [{ ...binding, binding: { port: 443 }, observationFresh: true, automaticUpdate: true },
        { ...binding, id: "second", binding: { port: 443, sniHost: "b.example.test" }, observationFresh: true, automaticUpdate: false },
        { ...binding, id: "removed", binding: { port: 8443 }, observationFresh: true, automaticUpdate: true, presence: "confirmed_absent" },
        { ...binding, id: "stale", binding: { port: 9443 }, observationFresh: false, automaticUpdate: true }] };
    assert.deepEqual(planPendingCutovers(input), [
      { bindingId: "iis", relationship: "observed", deployment: "authorized" },
      { bindingId: "second", relationship: "observed", deployment: "observed_only" },
      { bindingId: "removed", relationship: "absent", deployment: "unavailable" },
      { bindingId: "stale", relationship: "unknown", deployment: "unavailable" },
    ]);
    assert.throws(() => planPendingCutovers({ ...input, bindings: [input.bindings[0], input.bindings[0]] }), /unique/);
    assert.throws(() => planPendingCutovers({ ...input, bindings: [input.bindings[0], { ...input.bindings[0], id: "duplicate" }] }), /unique/);
    assert.throws(() => planPendingCutovers({ ...input, bindings: [binding] }), /port/);
  });
});
