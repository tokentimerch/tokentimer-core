"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");

const repoRoot = path.resolve(__dirname, "../..");
const dashboardRequire = createRequire(
  require.resolve("../../apps/dashboard/package.json"),
);
const yaml = dashboardRequire("js-yaml");

describe("release workflow promote-latest structure", () => {
  it("verifies digests and builds the release manifest before any :latest promotion", () => {
    const raw = fs.readFileSync(
      path.join(repoRoot, ".github/workflows/release.yml"),
      "utf8",
    );
    const doc = yaml.load(raw);
    const job = doc.jobs?.["promote-latest"];
    assert.ok(job, "promote-latest job must exist");

    const steps = Array.isArray(job.steps) ? job.steps : [];
    assert.ok(steps.length > 0, "promote-latest must have steps");

    const indexed = steps.map((step, index) => ({
      index,
      name: String(step.name || ""),
      run: String(step.run || ""),
    }));

    const verifyIdx = indexed.findIndex(
      (step) =>
        /verify/i.test(step.name) &&
        /imagetools inspect/i.test(step.run) &&
        /digest/i.test(`${step.name}\n${step.run}`),
    );
    assert.ok(
      verifyIdx >= 0,
      "promote-latest must include a digest verification step (imagetools inspect)",
    );

    const manifestIdx = indexed.findIndex(
      (step) =>
        /build release manifest/i.test(step.name) ||
        (/manifest/i.test(step.name) &&
          /release-manifest\.json/.test(step.run)),
    );
    assert.ok(
      manifestIdx >= 0,
      "promote-latest must include a release-manifest build step",
    );

    const promoteIdxs = indexed
      .filter(
        (step) =>
          /imagetools create/.test(step.run) && /:latest/.test(step.run),
      )
      .map((step) => step.index);
    assert.ok(
      promoteIdxs.length > 0,
      "promote-latest must include an imagetools create ... :latest promotion step",
    );

    const firstPromoteIdx = Math.min(...promoteIdxs);
    assert.ok(
      verifyIdx < firstPromoteIdx,
      "digest verification must run before any :latest imagetools create",
    );
    assert.ok(
      manifestIdx < firstPromoteIdx,
      "release manifest build must run before any :latest imagetools create",
    );

    const promoteStep = indexed[firstPromoteIdx];
    assert.match(
      promoteStep.run,
      /release-manifest\.json/,
      "promotion must read digests from release-manifest.json",
    );
    assert.match(
      promoteStep.run,
      /@[^\s"']+|@\$\{|@"\$\{|"\$\{[^}]+\}@\$\{/,
      "promotion must tag :latest from digest references (@digest), not by re-resolving :VERSION",
    );
    assert.doesNotMatch(
      promoteStep.run,
      /imagetools create -t [^\n]*:latest[^\n]*:\$\{?VER\}?/,
      "promotion must not use the mutable version tag as the imagetools create source",
    );
  });
});
