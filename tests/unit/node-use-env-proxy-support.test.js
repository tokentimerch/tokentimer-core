"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");

const {
  isNodeUseEnvProxySupported,
  isNodeHttpProxySupported,
} = require("../../packages/node-compat");

describe("isNodeUseEnvProxySupported (fetch/undici floor)", () => {
  const cases = [
    ["21.7.3", false],
    ["22.20.9", false],
    ["22.21.0", true],
    ["22.99.0", true],
    ["23.0.0", false],
    ["23.9.9", false],
    // fetch()/undici honor NODE_USE_ENV_PROXY from 24.0.0, not 24.5.0 -
    // see https://nodejs.org/en/blog/release/v24.0.0/ (PR #57165).
    ["24.0.0", true],
    ["24.4.9", true],
    ["24.5.0", true],
    ["24.9.0", true],
    ["25.0.0", true],
  ];

  for (const [version, expected] of cases) {
    it(`${version} -> ${expected}`, () => {
      assert.strictEqual(isNodeUseEnvProxySupported(version), expected);
    });
  }

  it("accepts a leading 'v' prefix", () => {
    assert.strictEqual(isNodeUseEnvProxySupported("v22.21.0"), true);
    assert.strictEqual(isNodeUseEnvProxySupported("v23.0.0"), false);
  });

  it("defaults to process.version when no argument is passed", () => {
    const result = isNodeUseEnvProxySupported();
    assert.strictEqual(typeof result, "boolean");
  });
});

describe("isNodeHttpProxySupported (node:http/node:https floor)", () => {
  const cases = [
    ["21.7.3", false],
    ["22.20.9", false],
    ["22.21.0", true],
    ["22.99.0", true],
    ["23.0.0", false],
    ["23.9.9", false],
    // node:http/node:https (and --use-env-proxy) need 24.5.0, unlike fetch.
    ["24.0.0", false],
    ["24.4.9", false],
    ["24.5.0", true],
    ["24.9.0", true],
    ["25.0.0", true],
  ];

  for (const [version, expected] of cases) {
    it(`${version} -> ${expected}`, () => {
      assert.strictEqual(isNodeHttpProxySupported(version), expected);
    });
  }

  it("accepts a leading 'v' prefix", () => {
    assert.strictEqual(isNodeHttpProxySupported("v24.5.0"), true);
    assert.strictEqual(isNodeHttpProxySupported("v24.0.0"), false);
  });
});
