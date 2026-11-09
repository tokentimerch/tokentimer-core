"use strict";
const { it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const { createRequire } = require("node:module");
const yaml = createRequire(require.resolve("mocha/package.json"))("js-yaml");
const { validateManifest } = require("../../scripts/check-integrations-manifest");
const manifest = yaml.load(fs.readFileSync("integrations.watch.yaml", "utf8"));
it("rejects malformed integration metadata", () => {
  for (const [field, value] of [["api_version", 42], ["api_version", "wrong-version"], ["base_urls", "bad"], ["base_urls", ["http://bad.example"]], ["endpoints", [{ method: "BOGUS", pattern: "/x" }]], ["webhook_formats", { sent: [""] }]]) {
    const copy = structuredClone(manifest);
    copy.integrations.github[field] = value;
    assert.throws(() => validateManifest(copy), /github:/);
  }
});


it("checks that the GitHub client uses the server default API version", () => {
  const os = require("node:os");
  const path = require("node:path");
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "tt-integration-watch-"));
  try {
    const integration = structuredClone(manifest.integrations.github);
    assert.equal(integration.api_version, null);
    const partial = { schema_version: manifest.schema_version, integrations: { github: integration } };
    for (const file of ["apps/api/services/githubIntegration.js", "apps/api/package.json"]) {
      const dest = path.join(temp, file);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.copyFileSync(path.resolve(file), dest);
    }
    assert.equal(validateManifest(partial, temp), 1);
    const sourcePath = path.join(temp, "apps/api/services/githubIntegration.js");
    fs.appendFileSync(sourcePath, '\nconst headers = { "x-github-api-version": "2022-11-28" };\n');
    assert.throws(() => validateManifest(partial, temp), /github:.*excluded source text.*present/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

it("does not override the GitHub CLI API version in workflows", () => {
  for (const file of [
    ".github/workflows/certops-linux-published-upgrade.yml",
    ".github/workflows/certops-windows-e2e.yml",
    ".github/workflows/certops-windows-published-baseline.yml",
    ".github/workflows/discord-release-backfill.yml",
    ".github/workflows/discord-release-notify.yml",
  ]) {
    const source = fs.readFileSync(file, "utf8");
    assert.doesNotThrow(() => yaml.load(source), file);
    assert.doesNotMatch(source, /X-GitHub-Api-Version/i, file);
  }
});
