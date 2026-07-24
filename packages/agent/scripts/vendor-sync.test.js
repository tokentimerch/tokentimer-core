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
});
