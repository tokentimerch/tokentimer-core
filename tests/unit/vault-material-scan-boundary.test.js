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
    `%62undles/${version}`,
    `bundles/%32${version.slice(1)}`,
    `bundles//${version}`,
    `bundles/./${version}`,
    `bundles%2f${version}`,
    `%2562undles/${version}`,
    `bundles\\${version}`,
    `bundles/${version}?version=1`,
    `bundles/${version}#ignored`,
    `public/../bundles/${version}`,
    `public/%2e%2e/bundles/${version}`,
    `bundles/%2e/${version}`,
    `public\\..\\bundles\\${version}`,
    `%2562undles%252f${version}`,
    `bundles/${version}%3fversion=1`,
    `bundles/${version}%23fragment`,
    `bundles/${version}/nested//leaf`,
    `bundles/%ZZ`,
  ]) {
    const before = hits.length;
    const exact = await scanVault({ ...options, pathPrefix: prefix });
    assert.equal(exact.items.length, 0);
    assert.ok(
      hits.slice(before).every(({ pathname }) => pathname === "/v1/sys/mounts"),
      `Reserved prefix must be rejected before any object request: ${prefix}`,
    );
    assert.equal(
      exact.summary[0].complete,
      false,
      `An excluded prefix cannot prove absence for cleanup: ${prefix}`,
    );
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
  assert.equal(
    all.summary[0].complete,
    false,
    "A mixed mount with deliberately excluded objects is not fully inspected",
  );
});

function fixture(t, respond, mounts = ["secret/"]) {
  const hits = [];
  t.mock.method(globalThis, "fetch", async (url, options) => {
    const pathname = new URL(url).pathname;
    hits.push({ pathname, method: options.method });
    const response =
      pathname === "/v1/sys/mounts"
        ? {
            body: {
              data: Object.fromEntries(
                mounts.map((mount) => [
                  mount,
                  { type: "kv", options: { version: "2" } },
                ]),
              ),
            },
          }
        : respond(pathname, options.method);
    return new Response(JSON.stringify(response?.body || {}), {
      status: response?.status || (response ? 200 : 404),
      headers: { "Content-Type": "application/json" },
    });
  });
  return {
    hits,
    options: {
      address: "https://vault.fixture.invalid",
      token: "synthetic-scanner",
      include: { kv: true, pki: false },
    },
  };
}
const publicSecret = {
  body: {
    data: { data: { expires_at: "2027-01-01" }, metadata: { version: 1 } },
  },
};

test("public KV, legacy bundles paths and UUID-suffix public siblings stay cleanup-eligible", async (t) => {
  const publicSuffix = "22222222-2222-4222-8222-222222222222-public";
  const { options } = fixture(t, (pathname) => {
    if (pathname === "/v1/secret/metadata/")
      return { body: { data: { keys: ["public", "bundles/"] } } };
    if (pathname === "/v1/secret/metadata/bundles/")
      return { body: { data: { keys: ["legacy-public", publicSuffix] } } };
    if (
      ["public", "bundles/legacy-public", "bundles/" + publicSuffix].some(
        (key) => pathname === "/v1/secret/data/" + key,
      )
    )
      return publicSecret;
  });
  const all = await scanVault(options);
  assert.equal(all.items.length, 3);
  assert.equal(all.summary[0].complete, true);
  for (const pathPrefix of [
    "bundles/legacy-public",
    "secret/bundles/legacy-public",
    "bundles/" + publicSuffix,
  ]) {
    const exact = await scanVault({ ...options, pathPrefix });
    assert.equal(exact.items.length, 1);
    assert.equal(exact.summary[0].complete, true);
  }
});

test("excluded material makes only its KV mount incomplete while public discovery continues", async (t) => {
  const version = "22222222-2222-4222-8222-222222222222";
  const { options, hits } = fixture(
    t,
    (pathname) => {
      if (pathname === "/v1/secret/metadata/")
        return { body: { data: { keys: ["bundles/"] } } };
      if (pathname === "/v1/secret/metadata/bundles/")
        return {
          body: { data: { keys: [version, version + "/", "legacy-public"] } },
        };
      if (pathname === "/v1/ordinary/metadata/")
        return { body: { data: { keys: ["public"] } } };
      if (
        [
          "/v1/secret/data/bundles/legacy-public",
          "/v1/ordinary/data/public",
        ].includes(pathname)
      )
        return publicSecret;
      assert.fail("Unexpected request: " + pathname);
    },
    ["secret/", "ordinary/"],
  );
  const result = await scanVault(options);
  assert.equal(result.items.length, 2);
  assert.equal(
    result.summary.find((scope) => scope.mount === "secret/").complete,
    false,
  );
  assert.equal(
    result.summary.find((scope) => scope.mount === "secret/").hasExcludedPaths,
    true,
  );
  assert.equal(
    result.summary.find((scope) => scope.mount === "ordinary/").complete,
    true,
  );
  assert.equal(
    hits.some((hit) => hit.pathname.includes(version)),
    false,
  );
});

test("denied or failed exact-leaf probes cannot prove an empty prefix complete", async (t) => {
  for (const status of [403, 500]) {
    await t.test("HTTP " + status, async (subtest) => {
      const { options } = fixture(subtest, (pathname) => {
        if (pathname === "/v1/secret/data/public")
          return { status, body: { errors: ["synthetic read failure"] } };
      });
      const result = await scanVault({ ...options, pathPrefix: "public" });
      assert.equal(result.items.length, 0);
      assert.equal(result.summary[0].complete, false);
      assert.equal(result.summary[0].hasErrors, true);
      assert.equal(result.summary[0].permissionDenied, status === 403);
    });
  }
});
