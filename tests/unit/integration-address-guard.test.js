"use strict";

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert");

const {
  BLOCKED_CODE,
  shouldEnforceIntegrationAddressCheck,
  checkIntegrationAddress,
} = require("../../apps/api/utils/integrationAddressGuard");

const ORIGINAL_NODE_ENV = process.env.NODE_ENV;

afterEach(() => {
  process.env.NODE_ENV = ORIGINAL_NODE_ENV;
  delete process.env.INTEGRATION_ALLOW_PRIVATE_IPS;
  delete process.env.INTEGRATION_ENFORCE_PRIVATE_IP_CHECK;
});

const publicLookup = async () => [{ address: "93.184.216.34", family: 4 }];

describe("integration address guard", () => {
  it("enforces by default outside test mode and not in test mode", () => {
    process.env.NODE_ENV = "production";
    assert.strictEqual(shouldEnforceIntegrationAddressCheck(), true);
    process.env.NODE_ENV = "test";
    assert.strictEqual(shouldEnforceIntegrationAddressCheck(), false);
    process.env.INTEGRATION_ENFORCE_PRIVATE_IP_CHECK = "true";
    assert.strictEqual(shouldEnforceIntegrationAddressCheck(), true);
  });

  it("blocks private, loopback, link-local and localhost literals", async () => {
    process.env.NODE_ENV = "production";
    for (const raw of [
      "http://10.0.0.5",
      "https://192.168.1.20:8443/api/v4",
      "http://127.0.0.1:8200",
      "http://169.254.169.254/latest",
      "http://[::1]:8200",
      "http://[::ffff:127.0.0.1]",
      "http://localhost:8200",
      "https://vault.localhost",
    ]) {
      const res = await checkIntegrationAddress(new URL(raw), {
        lookup: publicLookup,
      });
      assert.strictEqual(res.allowed, false, raw);
      assert.strictEqual(res.code, BLOCKED_CODE);
      assert.match(res.message, /private or internal network/);
      assert.match(res.message, /INTEGRATION_ALLOW_PRIVATE_IPS=true/);
    }
  });

  it("blocks a hostname when any answer is private", async () => {
    process.env.NODE_ENV = "production";
    const res = await checkIntegrationAddress(new URL("https://gitlab.corp"), {
      lookup: async () => [
        { address: "93.184.216.34", family: 4 },
        { address: "10.1.2.3", family: 4 },
      ],
    });
    assert.strictEqual(res.allowed, false);
  });

  it("allows public literals and public hostnames", async () => {
    process.env.NODE_ENV = "production";
    assert.strictEqual(
      (await checkIntegrationAddress(new URL("https://8.8.8.8"))).allowed,
      true,
    );
    assert.strictEqual(
      (
        await checkIntegrationAddress(new URL("https://gitlab.com"), {
          lookup: publicLookup,
        })
      ).allowed,
      true,
    );
  });

  it("lets an unresolvable name through so the scan reports the connection error", async () => {
    process.env.NODE_ENV = "production";
    const res = await checkIntegrationAddress(new URL("https://nope.example"), {
      lookup: async () => {
        throw new Error("ENOTFOUND");
      },
    });
    assert.strictEqual(res.allowed, true);
  });

  it("allows private addresses when INTEGRATION_ALLOW_PRIVATE_IPS=true", async () => {
    process.env.NODE_ENV = "production";
    process.env.INTEGRATION_ALLOW_PRIVATE_IPS = "true";
    process.env.INTEGRATION_ENFORCE_PRIVATE_IP_CHECK = "true";
    for (const raw of ["http://10.0.0.5", "http://localhost:8200"]) {
      assert.strictEqual(
        (await checkIntegrationAddress(new URL(raw))).allowed,
        true,
      );
    }
  });

  it("does not check anything in test mode without the enforce flag", async () => {
    process.env.NODE_ENV = "test";
    assert.strictEqual(
      (await checkIntegrationAddress(new URL("http://127.0.0.1"))).allowed,
      true,
    );
  });
});
