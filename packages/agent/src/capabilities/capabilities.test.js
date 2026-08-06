"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  GATED_CAPABILITIES,
  DEFAULT_MANIFEST_MODULE_PATH,
  loadQualifiedCapabilitiesManifest,
  filterQualifiedCapabilities,
  _setManifestModulePathForTests,
  _resetQualifiedCapabilitiesCacheForTests,
} = require("./index.js");

describe("qualified-capabilities manifest gate (ADR-0012 decision 14)", () => {
  it("names exactly the three real-host-evidence-gated capability strings", () => {
    assert.deepEqual(
      [...GATED_CAPABILITIES],
      ["windows-cert-store-v1", "iis-binding-v1", "trust-anchor-deploy-v1"],
    );
  });

  it("ships with windows-cert-store-v1 and iis-binding-v1 qualified after real-host verification, trust-anchor-deploy-v1 still empty", () => {
    // windows-cert-store-v1 and iis-binding-v1 passed real-host verification
    // on tokentimer-winverify-vm (WCNG/WIIS/WRET/WDISC, section 9 of the
    // post-ship checklist); trust-anchor-deploy-v1 has no executor at all yet
    // (Wave 3) and stays gated.
    const manifest = loadQualifiedCapabilitiesManifest();
    assert.deepEqual([...manifest.qualified].sort(), [
      "iis-binding-v1",
      "windows-cert-store-v1",
    ]);
  });

  it("advertises only the real-host-verified gated capabilities, never trust-anchor-deploy-v1", () => {
    const candidateCapabilities = [
      "evidence-claim-binding-v1",
      "windows-cert-store-v1",
      "iis-binding-v1",
      "trust-anchor-deploy-v1",
    ];
    const declared = filterQualifiedCapabilities(candidateCapabilities);
    assert.deepEqual(
      [...declared].sort(),
      ["evidence-claim-binding-v1", "iis-binding-v1", "windows-cert-store-v1"],
    );
    assert.ok(
      !declared.includes("trust-anchor-deploy-v1"),
      "trust-anchor-deploy-v1 must not be advertised: no executor exists yet",
    );
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

  it("loads the real manifest from the build-generated module, not from JSON at runtime", () => {
    // ADR-0012 decision 14's whole point is that this is NOT operator
    // configurable at runtime: an fs.readFileSync of a sibling JSON file
    // would let anyone who can edit that file and restart the agent change
    // what it advertises. DEFAULT_MANIFEST_MODULE_PATH must point at the
    // generated module, and the file it names must actually exist (the
    // freshness describe block below proves it matches the committed
    // qualified-capabilities.json).
    assert.match(DEFAULT_MANIFEST_MODULE_PATH, /qualified-capabilities\.generated\.js$/);
    assert.ok(fs.existsSync(DEFAULT_MANIFEST_MODULE_PATH));
  });
});

describe("qualified-capabilities loader startup rejection (defense in depth against a corrupted or hand-edited generated module)", () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "qualified-capabilities-loader-"));
  });

  afterEach(() => {
    _resetQualifiedCapabilitiesCacheForTests();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function writeFixtureModule(source) {
    const fixturePath = path.join(tempDir, "fixture-manifest.js");
    fs.writeFileSync(fixturePath, source);
    return fixturePath;
  }

  it("rejects a missing manifest module at load time (startup rejection, not silent acceptance)", () => {
    // Points at a path that has never existed, simulating the generated
    // module being absent (e.g. build step never ran).
    _setManifestModulePathForTests(path.join(tempDir, "does-not-exist.js"));
    assert.throws(
      () => loadQualifiedCapabilitiesManifest(),
      /qualified-capabilities manifest module is missing or failed to load/,
    );
  });

  it("rejects a manifest module that fails to parse as JavaScript (the generated-module analogue of invalid JSON)", () => {
    const fixturePath = writeFixtureModule("this is not { valid javascript (((");
    _setManifestModulePathForTests(fixturePath);
    assert.throws(
      () => loadQualifiedCapabilitiesManifest(),
      /qualified-capabilities manifest module is missing or failed to load/,
    );
  });

  it("rejects a manifest module that does not export a qualified array", () => {
    const fixturePath = writeFixtureModule("module.exports = { notQualified: [] };");
    _setManifestModulePathForTests(fixturePath);
    assert.throws(
      () => loadQualifiedCapabilitiesManifest(),
      /must export a "qualified" array/,
    );
  });

  it("rejects a manifest module naming an unrecognized capability entry", () => {
    const fixturePath = writeFixtureModule(
      'module.exports = { qualified: ["windows-cert-store-v1", "some-typo-v1"] };',
    );
    _setManifestModulePathForTests(fixturePath);
    assert.throws(
      () => loadQualifiedCapabilitiesManifest(),
      /names unrecognized capability "some-typo-v1"/,
    );
  });

  it("accepts a well-formed fixture manifest naming a subset of the gated capabilities", () => {
    const fixturePath = writeFixtureModule(
      'module.exports = { qualified: ["iis-binding-v1"] };',
    );
    _setManifestModulePathForTests(fixturePath);
    const manifest = loadQualifiedCapabilitiesManifest();
    assert.deepEqual([...manifest.qualified], ["iis-binding-v1"]);

    const declared = filterQualifiedCapabilities([
      "evidence-claim-binding-v1",
      "windows-cert-store-v1",
      "iis-binding-v1",
    ]);
    assert.deepEqual([...declared].sort(), ["evidence-claim-binding-v1", "iis-binding-v1"]);
  });

  it("resets back to the real generated module after a test override", () => {
    const fixturePath = writeFixtureModule('module.exports = { qualified: [] };');
    _setManifestModulePathForTests(fixturePath);
    loadQualifiedCapabilitiesManifest();

    _resetQualifiedCapabilitiesCacheForTests();
    const manifest = loadQualifiedCapabilitiesManifest();
    assert.deepEqual([...manifest.qualified].sort(), [
      "iis-binding-v1",
      "windows-cert-store-v1",
    ]);
  });
});

describe("qualified-capabilities.generated.js freshness", () => {
  it("stays in sync with qualified-capabilities.json (regenerating reproduces the committed file byte-for-byte)", () => {
    // Mirrors scripts/vendor-sync.test.js's pattern for
    // agent-protocol-validator.generated.js: a diff here means someone
    // edited qualified-capabilities.json (or the generated file itself)
    // without re-running the build step.
    const { main } = require("../../scripts/build-qualified-capabilities.js");
    const before = fs.readFileSync(DEFAULT_MANIFEST_MODULE_PATH, "utf8");

    main();

    const after = fs.readFileSync(DEFAULT_MANIFEST_MODULE_PATH, "utf8");
    try {
      assert.equal(
        after,
        before,
        "qualified-capabilities.generated.js is stale; run " +
          "node packages/agent/scripts/build-qualified-capabilities.js and commit the result",
      );
    } finally {
      fs.writeFileSync(DEFAULT_MANIFEST_MODULE_PATH, before);
    }
  });
});
