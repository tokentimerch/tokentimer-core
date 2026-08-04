"use strict";

const { describe, it, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  main,
  readAndValidateManifest,
  renderGeneratedModule,
  QualifiedCapabilitiesBuildError,
  DEFAULT_INPUT_PATH,
  DEFAULT_OUTPUT_PATH,
} = require("./build-qualified-capabilities.js");
const { GATED_CAPABILITIES } = require("../src/capabilities/gated-capabilities.js");

describe("build-qualified-capabilities (ADR-0012 decision 14: build-time, not runtime-readable)", () => {
  let tempDir;

  after(() => {
    if (tempDir) fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function tempPath(name) {
    if (!tempDir) {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "build-qualified-capabilities-"));
    }
    return path.join(tempDir, name);
  }

  it("rejects a missing input manifest", () => {
    assert.throws(
      () => readAndValidateManifest(tempPath("does-not-exist.json")),
      QualifiedCapabilitiesBuildError,
    );
  });

  it("rejects invalid JSON", () => {
    const inputPath = tempPath("invalid.json");
    fs.writeFileSync(inputPath, "{ not valid json");
    assert.throws(
      () => readAndValidateManifest(inputPath),
      QualifiedCapabilitiesBuildError,
    );
  });

  it("rejects a manifest missing the qualified array", () => {
    const inputPath = tempPath("no-qualified.json");
    fs.writeFileSync(inputPath, JSON.stringify({ somethingElse: [] }));
    assert.throws(
      () => readAndValidateManifest(inputPath),
      QualifiedCapabilitiesBuildError,
    );
  });

  it("rejects an unrecognized capability entry", () => {
    const inputPath = tempPath("unrecognized.json");
    fs.writeFileSync(inputPath, JSON.stringify({ qualified: ["not-a-real-capability"] }));
    assert.throws(
      () => readAndValidateManifest(inputPath),
      (error) =>
        error instanceof QualifiedCapabilitiesBuildError &&
        /unrecognized capability "not-a-real-capability"/.test(error.message),
    );
  });

  it("accepts a manifest naming every gated capability", () => {
    const inputPath = tempPath("all-qualified.json");
    fs.writeFileSync(inputPath, JSON.stringify({ qualified: [...GATED_CAPABILITIES] }));
    const qualified = readAndValidateManifest(inputPath);
    assert.deepEqual([...qualified].sort(), [...GATED_CAPABILITIES].sort());
  });

  it("renders a generated module that freezes the qualified list and round-trips through require()", () => {
    const outputPath = tempPath("qualified-capabilities.generated.test-output.js");
    const source = renderGeneratedModule(["iis-binding-v1"]);
    fs.writeFileSync(outputPath, source);

    delete require.cache[require.resolve(outputPath)];
    const loaded = require(outputPath);
    assert.deepEqual([...loaded.qualified], ["iis-binding-v1"]);
    assert.throws(() => {
      loaded.qualified.push("nope");
    }, TypeError);
  });

  it("main() writes the output module and returns the validated qualified list", () => {
    const inputPath = tempPath("main-input.json");
    const outputPath = tempPath("main-output.js");
    fs.writeFileSync(inputPath, JSON.stringify({ qualified: ["trust-anchor-deploy-v1"] }));

    const result = main({ inputPath, outputPath });
    assert.deepEqual(result.qualified, ["trust-anchor-deploy-v1"]);
    assert.ok(fs.existsSync(outputPath));

    delete require.cache[require.resolve(outputPath)];
    const loaded = require(outputPath);
    assert.deepEqual([...loaded.qualified], ["trust-anchor-deploy-v1"]);
  });

  it("main() fails the build (throws) rather than silently writing a bad manifest", () => {
    const inputPath = tempPath("bad-main-input.json");
    const outputPath = tempPath("bad-main-output.js");
    fs.writeFileSync(inputPath, JSON.stringify({ qualified: ["typo-v1"] }));

    assert.throws(
      () => main({ inputPath, outputPath }),
      QualifiedCapabilitiesBuildError,
    );
    assert.equal(fs.existsSync(outputPath), false);
  });

  it("defaults resolve to the real qualified-capabilities.json input and generated.js output", () => {
    assert.match(DEFAULT_INPUT_PATH, /qualified-capabilities\.json$/);
    assert.match(DEFAULT_OUTPUT_PATH, /qualified-capabilities\.generated\.js$/);
    assert.ok(fs.existsSync(DEFAULT_INPUT_PATH));
  });
});
