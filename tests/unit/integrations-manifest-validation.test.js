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


it("checks the GitHub API version against the client header", () => {
  const os = require("node:os");
  const path = require("node:path");
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "tt-integration-watch-"));
  try {
    const integration = structuredClone(manifest.integrations.github);
    const partial = { schema_version: manifest.schema_version, integrations: { github: integration } };
    for (const file of ["apps/api/services/githubIntegration.js", "apps/api/package.json"]) {
      const dest = path.join(temp, file);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.copyFileSync(path.resolve(file), dest);
    }
    assert.equal(validateManifest(partial, temp), 1);
    const sourcePath = path.join(temp, "apps/api/services/githubIntegration.js");
    const original = fs.readFileSync(sourcePath, "utf8");
    const header = `"X-GitHub-Api-Version": "${integration.api_version}",`;
    assert.ok(original.includes(header), "expected actual client header");
    fs.writeFileSync(sourcePath, original.replace(header, ""));
    assert.throws(() => validateManifest(partial, temp), /github:.*source text.*missing/);
    fs.writeFileSync(sourcePath, original.replace(header, '"X-GitHub-Api-Version": "2099-01-01",'));
    assert.throws(() => validateManifest(partial, temp), /github:.*source text.*missing/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
