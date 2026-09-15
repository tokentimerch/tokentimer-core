"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const integrationsPath = path.resolve(
  __dirname,
  "../../apps/api/routes/integrations.js",
);

describe("Vault scan audit metadata", () => {
  it("does not put token, roleId, or secretId in INTEGRATION_SCAN audit metadata", () => {
    const src = fs.readFileSync(integrationsPath, "utf8");
    const start = src.indexOf('action: "INTEGRATION_SCAN"');
    assert.ok(start > 0, "expected INTEGRATION_SCAN audit write");
    const vaultBlock = src.indexOf('provider: "vault"', start);
    assert.ok(vaultBlock > start, "expected vault provider audit metadata");
    const metadata = src.slice(vaultBlock, vaultBlock + 250);
    assert.match(metadata, /itemsFound/);
    assert.doesNotMatch(metadata, /\btoken\b/);
    assert.doesNotMatch(metadata, /roleId/);
    assert.doesNotMatch(metadata, /secretId/);
  });
});
