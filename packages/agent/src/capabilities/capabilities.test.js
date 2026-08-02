"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  GATED_CAPABILITIES,
  loadQualifiedCapabilitiesManifest,
  filterQualifiedCapabilities,
} = require("./index.js");

describe("qualified-capabilities manifest gate (ADR-0012 decision 14)", () => {
  it("names exactly the three real-host-evidence-gated capability strings", () => {
    assert.deepEqual(
      [...GATED_CAPABILITIES],
      ["windows-cert-store-v1", "iis-binding-v1", "trust-anchor-deploy-v1"],
    );
  });

  it("ships with an empty default manifest (nothing qualified yet)", () => {
    const manifest = loadQualifiedCapabilitiesManifest();
    assert.deepEqual([...manifest.qualified], []);
  });

  it("never advertises a gated capability when the default manifest names none, even though the underlying candidate list claims it exists", () => {
    // Simulates a future build where the Windows/trust-anchor code paths
    // (Wave 2b / Wave 3) are implemented and some caller assembles a
    // candidate capability list that already includes all three gated
    // strings. The manifest shipped in THIS change is empty, so none of
    // them may reach the wire.
    const candidateCapabilities = [
      "evidence-claim-binding-v1",
      "windows-cert-store-v1",
      "iis-binding-v1",
      "trust-anchor-deploy-v1",
    ];
    const declared = filterQualifiedCapabilities(candidateCapabilities);
    assert.deepEqual([...declared], ["evidence-claim-binding-v1"]);
    for (const gated of GATED_CAPABILITIES) {
      assert.ok(
        !declared.includes(gated),
        `${gated} must not be advertised while the manifest is empty`,
      );
    }
  });

  it("lets an ungated capability through unconditionally", () => {
    const declared = filterQualifiedCapabilities(["evidence-claim-binding-v1"]);
    assert.deepEqual([...declared], ["evidence-claim-binding-v1"]);
  });

  it("drops unrecognized candidate strings that happen to collide with nothing (defensive: only known gated strings are ever filtered)", () => {
    const declared = filterQualifiedCapabilities(["some-future-ungated-thing"]);
    assert.deepEqual([...declared], ["some-future-ungated-thing"]);
  });

  it("treats a missing/non-array candidate list as advertising nothing rather than throwing", () => {
    assert.deepEqual([...filterQualifiedCapabilities(undefined)], []);
    assert.deepEqual([...filterQualifiedCapabilities(null)], []);
  });
});
