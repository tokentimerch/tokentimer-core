"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { scanVault } = require(
  process.env.TT_VAULT_SCAN_MODULE ||
    path.resolve(__dirname, "../../apps/api/services/vaultIntegration.js"),
);

test("Vault scanner never requests material bundle bytes, including an exact prefix", async (t) => {
  const version = "22222222-2222-4222-8222-222222222222";
  const hits = [];
  // Node's HTTP server rejects Vault's nonstandard LIST verb. Stub the HTTP
  // boundary, leaving the production scanner and Vault request code intact.
  t.mock.method(globalThis, "fetch", async (url, options) => {
    const pathname = new URL(url).pathname;
    hits.push({ pathname, method: options.method });
    let body;
    if (pathname === "/v1/sys/mounts") {
      body = { data: { "secret/": { type: "kv", options: { version: "2" } } } };
    } else if (pathname === "/v1/secret/metadata/") {
      assert.equal(options.method, "LIST");
      body = { data: { keys: ["public", "bundles/"] } };
    } else if (pathname === "/v1/secret/metadata/bundles/") {
      assert.equal(options.method, "LIST");
      body = { data: { keys: [version, `${version}/`, "legacy-public"] } };
    } else if (
      pathname === "/v1/secret/data/public" ||
      pathname === "/v1/secret/data/bundles/legacy-public"
    ) {
      body = {
        data: { data: { expires_at: "2027-01-01" }, metadata: { version: 1 } },
      };
    }
    return new Response(JSON.stringify(body || {}), {
      status: body ? 200 : 404,
      headers: { "Content-Type": "application/json" },
    });
  });
  const options = {
    address: "https://vault.fixture.invalid",
    token: "fixture-scanner",
    include: { kv: true, pki: false },
  };
  const all = await scanVault(options);
  assert.equal(all.items.length, 2);
  for (const prefix of [
    `bundles/${version}`,
    `secret/bundles/${version}`,
    `secret/bundles/${version}/nested`,
  ]) {
    const exact = await scanVault({ ...options, pathPrefix: prefix });
    assert.equal(exact.items.length, 0);
  }
  assert.equal(
    hits.some(({ pathname }) => pathname.includes(version)),
    false,
    "No data or metadata request may target a reserved material object",
  );
  assert.ok(
    hits.some(
      ({ pathname }) => pathname === "/v1/secret/data/bundles/legacy-public",
    ),
    "Legacy public inventory remains scannable",
  );
});
