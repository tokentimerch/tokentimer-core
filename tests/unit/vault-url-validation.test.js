"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const util = require("node:util");
const modulePath =
  process.env.TT_VAULT_SCAN_MODULE ||
  path.resolve(__dirname, "../../apps/api/services/vaultIntegration.js");
const { scanVault } = require(modulePath);
const { logger } = require(
  path.resolve(path.dirname(modulePath), "../utils/logger"),
);

test("malformed credential-bearing Vault URLs never escape through logs or exception causes", async (t) => {
  const logs = [];
  t.mock.method(logger, "error", (...args) => logs.push(args));
  t.mock.method(globalThis, "fetch", () => {
    assert.fail("An invalid address must fail before a network request");
  });
  for (const address of [
    "https://vault-user:fake-password@[invalid-host",
    "https://vault-user:fake-password@vault.invalid:bad-port",
    "//vault-user:fake-password@vault.invalid",
  ]) {
    await assert.rejects(
      scanVault({ address, token: "fake-token" }),
      (error) => {
        const serialized =
          util.inspect(error, { depth: 10 }) + JSON.stringify(error);
        assert.doesNotMatch(
          serialized,
          /vault-user|fake-password|fake-token|invalid-host|bad-port/,
        );
        assert.equal(
          error.cause,
          undefined,
          "Do not retain a raw URL parser error",
        );
        assert.match(error.message, /Invalid Vault address/);
        return true;
      },
    );
  }
  assert.equal(logs.length, 3);
  assert.doesNotMatch(
    util.inspect(logs, { depth: 10 }),
    /vault-user|fake-password|fake-token|invalid-host|bad-port/,
  );
});
