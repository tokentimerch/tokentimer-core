"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const util = require("node:util");
const { ConfigError, loadConfig } = require("./config");

const CREDENTIAL = `ttopc_${"0123456789abcdef"}_${"a".repeat(64)}`;
const base = (overrides = {}) => ({
  TOKENTIMER_API_URL: "https://tokentimer.example.com",
  TOKENTIMER_MCP_CREDENTIAL: CREDENTIAL,
  ...overrides,
});
const fail = (env, pattern, options) =>
  assert.throws(() => loadConfig(env, options), (error) => error instanceof ConfigError && pattern.test(error.message));

describe("adapter configuration", () => {
  it("loads a valid configuration with safe defaults", () => {
    const config = loadConfig(base());
    assert.equal(config.origin, "https://tokentimer.example.com");
    assert.equal(config.basePath, "");
    assert.equal(config.legacy, "serve");
    assert.equal(config.requestTimeoutMs, 15000);
    assert.equal(config.maxResponseBytes, 1048576);
    assert.ok(Object.isFrozen(config));
  });

  it("keeps a path prefix for deployments behind a sub-path, without a trailing slash", () => {
    const config = loadConfig(base({ TOKENTIMER_API_URL: "https://example.com/tokentimer/" }));
    assert.equal(config.basePath, "/tokentimer");
  });

  it("refuses to send a credential over clear text, except to localhost", () => {
    fail(base({ TOKENTIMER_API_URL: "http://tokentimer.example.com" }), /https/);
    fail(base({ TOKENTIMER_API_URL: "ftp://example.com" }), /https/);
    for (const host of ["localhost", "127.0.0.1"]) {
      assert.equal(loadConfig(base({ TOKENTIMER_API_URL: `http://${host}:4000` })).origin, `http://${host}:4000`);
    }
    fail(base({ TOKENTIMER_API_URL: "http://127.0.0.1.evil.example.com" }), /https/);
    fail(base({ TOKENTIMER_API_URL: "http://localhost.evil.example.com" }), /https/);
  });

  it("refuses URLs that carry credentials, a query or a fragment", () => {
    fail(base({ TOKENTIMER_API_URL: "https://user:pw@example.com" }), /credentials/);
    fail(base({ TOKENTIMER_API_URL: "https://example.com?x=1" }), /query string/);
    fail(base({ TOKENTIMER_API_URL: "https://example.com#frag" }), /query string or fragment/);
    fail(base({ TOKENTIMER_API_URL: "not a url" }), /valid URL/);
    fail(base({ TOKENTIMER_API_URL: "" }), /required/);
    fail({ TOKENTIMER_MCP_CREDENTIAL: CREDENTIAL }, /required/);
  });

  it("requires a credential in the right format and never echoes it", () => {
    fail(base({ TOKENTIMER_MCP_CREDENTIAL: "" }), /credential is required/);
    const wrong = [`ttagent_${"0123456789abcdef"}_${"b".repeat(64)}`, `ttx_${"0123456789abcdef"}_${"c".repeat(64)}`, "ttopc_short", CREDENTIAL + "x"];
    for (const value of wrong) {
      try {
        loadConfig(base({ TOKENTIMER_MCP_CREDENTIAL: value }));
        assert.fail("expected a ConfigError");
      } catch (error) {
        assert.ok(error instanceof ConfigError);
        assert.ok(!error.message.includes(value), "the error must not contain the value");
        assert.match(error.message, /expected format/);
      }
    }
  });

  it("reads the credential from a file and trims it", () => {
    const config = loadConfig(
      { TOKENTIMER_API_URL: "https://example.com", TOKENTIMER_MCP_CREDENTIAL_FILE: "/run/secrets/tt" },
      { readFile: (file) => (file === "/run/secrets/tt" ? `${CREDENTIAL}\n` : "") },
    );
    assert.equal(config.authorizationHeader(), `Bearer ${CREDENTIAL}`);
  });

  it("refuses both sources at once and names the variable, not the path, when a file fails", () => {
    fail(base({ TOKENTIMER_MCP_CREDENTIAL_FILE: "/x" }), /not both/);
    try {
      loadConfig(
        { TOKENTIMER_API_URL: "https://example.com", TOKENTIMER_MCP_CREDENTIAL_FILE: "/very/secret/path" },
        {
          readFile() {
            throw new Error("ENOENT /very/secret/path");
          },
        },
      );
      assert.fail("expected a ConfigError");
    } catch (error) {
      assert.ok(error instanceof ConfigError);
      assert.ok(!error.message.includes("/very/secret/path"));
    }
  });

  it("cannot be made to reveal the credential by serializing or inspecting the config", () => {
    const config = loadConfig(base());
    for (const rendered of [
      JSON.stringify(config),
      util.inspect(config, { showHidden: false, depth: 5 }),
      String(Object.entries(config)),
      JSON.stringify({ ...config }),
    ]) {
      assert.ok(!rendered.includes(CREDENTIAL), "credential leaked");
      assert.ok(!rendered.includes("0123456789abcdef"), "credential id leaked");
    }
    assert.deepEqual(Object.keys(config).sort(), ["basePath", "legacy", "maxResponseBytes", "origin", "requestTimeoutMs"]);
  });

  it("validates the optional settings", () => {
    assert.equal(loadConfig(base({ TOKENTIMER_MCP_LEGACY: "REJECT" })).legacy, "reject");
    fail(base({ TOKENTIMER_MCP_LEGACY: "maybe" }), /serve or reject/);
    assert.equal(loadConfig(base({ TOKENTIMER_MCP_TIMEOUT_MS: "5000" })).requestTimeoutMs, 5000);
    fail(base({ TOKENTIMER_MCP_TIMEOUT_MS: "10" }), /TIMEOUT_MS/);
    fail(base({ TOKENTIMER_MCP_TIMEOUT_MS: "5000ms" }), /TIMEOUT_MS/);
    fail(base({ TOKENTIMER_MCP_MAX_RESPONSE_BYTES: "99999999" }), /MAX_RESPONSE_BYTES/);
  });
});
