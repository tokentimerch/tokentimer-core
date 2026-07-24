"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const packageRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(packageRoot, "..", "..");

function stripVendoredAttribution(source) {
  if (!source.startsWith("/*")) return source;
  const end = source.indexOf("*/");
  if (end === -1) return source;
  const header = source.slice(0, end + 2);
  if (!header.includes("VENDORED COPY")) return source;
  return source.slice(end + 2).replace(/^\r?\n/, "");
}

describe("vendor sync", () => {
  it("keeps secret-material identical to @tokentimer/log-scrub (aside from attribution)", () => {
    const upstream = fs.readFileSync(
      path.join(repoRoot, "packages", "log-scrub", "secret-material.js"),
      "utf8",
    );
    const vendored = fs.readFileSync(
      path.join(packageRoot, "vendor", "log-scrub", "secret-material.js"),
      "utf8",
    );
    assert.equal(stripVendoredAttribution(vendored), upstream);
  });

  it("keeps canonical-json identical to @tokentimer/contracts (aside from attribution)", () => {
    const upstream = fs.readFileSync(
      path.join(repoRoot, "packages", "contracts", "certops", "canonical-json.cjs"),
      "utf8",
    );
    const vendored = fs.readFileSync(
      path.join(packageRoot, "vendor", "contracts", "canonical-json.cjs"),
      "utf8",
    );
    assert.equal(stripVendoredAttribution(vendored), upstream);
  });

  it("keeps agent-protocol.schema.json byte-identical to @tokentimer/contracts", () => {
    const upstream = fs.readFileSync(
      path.join(
        repoRoot,
        "packages",
        "contracts",
        "certops",
        "agent-protocol.schema.json",
      ),
      "utf8",
    );
    const vendored = fs.readFileSync(
      path.join(
        packageRoot,
        "vendor",
        "contracts",
        "agent-protocol.schema.json",
      ),
      "utf8",
    );
    assert.equal(vendored, upstream);
  });

  it("keeps the generated protocol validator in sync with the vendored schema and free of ajv/ajv-formats runtime requires", () => {
    const { execFileSync } = require("node:child_process");
    const generatedPath = path.join(
      packageRoot,
      "vendor",
      "contracts",
      "agent-protocol-validator.generated.js",
    );
    const before = fs.readFileSync(generatedPath, "utf8");

    // Regenerating from the current vendored schema must reproduce the
    // committed file byte-for-byte; a diff here means someone edited the
    // schema (or the generator) without re-running the build step.
    execFileSync(
      process.execPath,
      [path.join(__dirname, "build-protocol-validator.js")],
      { stdio: "inherit" },
    );
    const after = fs.readFileSync(generatedPath, "utf8");
    try {
      assert.equal(
        after,
        before,
        "vendor/contracts/agent-protocol-validator.generated.js is stale; " +
          "run node packages/agent/scripts/build-protocol-validator.js (or sync-vendor.js) and commit the result",
      );
    } finally {
      fs.writeFileSync(generatedPath, before);
    }

    assert.doesNotMatch(
      before,
      /require\(["'](?!\.\.\/ajv-runtime\/ucs2length)/,
      "generated validator must not require ajv/ajv-formats or anything outside vendor/ajv-runtime at runtime",
    );

    delete require.cache[require.resolve(generatedPath)];
    const validate = require(generatedPath);
    assert.equal(typeof validate, "function");
    assert.equal(
      validate({
        schemaVersion: 1,
        protocolVersion: "1.0.0",
        messageType: "register",
        agentId: "00000000-0000-4000-8000-000000000000",
        sentAt: "2026-07-24T12:00:00Z",
        body: {
          bootstrapTokenId: "boot-1",
          agentVersion: "1.0.0",
          hostname: "host",
          platform: "linux",
        },
      }),
      true,
      JSON.stringify(validate.errors),
    );
    assert.equal(validate({}), false);
  });
});
