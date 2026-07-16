"use strict";

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { pathToFileURL } = require("url");

const {
  isPrivateOrReservedIP,
  allowPrivateWebhookIPs,
  shouldEnforcePrivateIpCheck,
  validateResolvedIP,
} = require("../../apps/api/utils/webhookSafety");

async function importFresh(relativePath) {
  const abs = path.join(__dirname, "..", "..", relativePath);
  const href = `${pathToFileURL(abs).href}?t=${Date.now()}-${Math.random()}`;
  return import(href);
}

const ORIGINAL_NODE_ENV = process.env.NODE_ENV;

afterEach(() => {
  process.env.NODE_ENV = ORIGINAL_NODE_ENV;
  delete process.env.WEBHOOK_ALLOW_PRIVATE_IPS;
  delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
});

describe("webhookSafety.isPrivateOrReservedIP", () => {
  it("flags private and reserved IPv4 ranges", () => {
    for (const ip of [
      "10.1.2.3",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.1.1",
      "127.0.0.1",
      "169.254.169.254",
      "0.0.0.0",
      "100.64.0.1",
      "198.18.0.1",
    ]) {
      assert.strictEqual(isPrivateOrReservedIP(ip), true, `${ip} should be private`);
    }
  });

  it("allows public IPv4 addresses", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "172.15.0.1", "172.32.0.1", "100.63.0.1"]) {
      assert.strictEqual(isPrivateOrReservedIP(ip), false, `${ip} should be public`);
    }
  });
});

describe("WEBHOOK_ALLOW_PRIVATE_IPS gate", () => {
  it("defaults to false when unset", () => {
    delete process.env.WEBHOOK_ALLOW_PRIVATE_IPS;
    assert.strictEqual(allowPrivateWebhookIPs(), false);
  });

  it("is true only for the string 'true' (case-insensitive)", () => {
    process.env.WEBHOOK_ALLOW_PRIVATE_IPS = "true";
    assert.strictEqual(allowPrivateWebhookIPs(), true);
    process.env.WEBHOOK_ALLOW_PRIVATE_IPS = "TRUE";
    assert.strictEqual(allowPrivateWebhookIPs(), true);
    process.env.WEBHOOK_ALLOW_PRIVATE_IPS = "1";
    assert.strictEqual(allowPrivateWebhookIPs(), false);
    process.env.WEBHOOK_ALLOW_PRIVATE_IPS = "false";
    assert.strictEqual(allowPrivateWebhookIPs(), false);
  });

  it("worker module exposes the same gate semantics", async () => {
    const webhooks = await importFresh("apps/worker/src/notify/webhooks.js");
    delete process.env.WEBHOOK_ALLOW_PRIVATE_IPS;
    assert.strictEqual(webhooks.allowPrivateWebhookIPs(), false);
    process.env.WEBHOOK_ALLOW_PRIVATE_IPS = "true";
    assert.strictEqual(webhooks.allowPrivateWebhookIPs(), true);
  });
});

describe("shouldEnforcePrivateIpCheck gate", () => {
  it("skips enforcement in test mode by default", () => {
    process.env.NODE_ENV = "test";
    assert.strictEqual(shouldEnforcePrivateIpCheck(), false);
  });

  it("enforces outside test mode by default", () => {
    process.env.NODE_ENV = "production";
    assert.strictEqual(shouldEnforcePrivateIpCheck(), true);
  });

  it("WEBHOOK_ENFORCE_PRIVATE_IP_CHECK=true forces enforcement in test mode", () => {
    process.env.NODE_ENV = "test";
    process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK = "true";
    assert.strictEqual(shouldEnforcePrivateIpCheck(), true);
  });

  it("WEBHOOK_ALLOW_PRIVATE_IPS=true always wins over enforcement", () => {
    process.env.NODE_ENV = "production";
    process.env.WEBHOOK_ALLOW_PRIVATE_IPS = "true";
    assert.strictEqual(shouldEnforcePrivateIpCheck(), false);
    process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK = "true";
    assert.strictEqual(shouldEnforcePrivateIpCheck(), false);
  });

  it("worker module exposes the same enforcement gate", async () => {
    const webhooks = await importFresh("apps/worker/src/notify/webhooks.js");
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
    assert.strictEqual(webhooks.shouldEnforcePrivateIpCheck(), false);
    process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK = "true";
    assert.strictEqual(webhooks.shouldEnforcePrivateIpCheck(), true);
    process.env.WEBHOOK_ALLOW_PRIVATE_IPS = "true";
    assert.strictEqual(webhooks.shouldEnforcePrivateIpCheck(), false);
  });
});

describe("validateResolvedIP", () => {
  it("rejects private IP literals", async () => {
    assert.strictEqual(await validateResolvedIP("192.168.10.20"), false);
    assert.strictEqual(await validateResolvedIP("10.0.0.1"), false);
  });

  it("accepts public IP literals", async () => {
    assert.strictEqual(await validateResolvedIP("8.8.8.8"), true);
  });
});

describe("worker postJson private-IP blocking", () => {
  it("blocks delivery to a private IP by default outside test mode", async () => {
    process.env.NODE_ENV = "production";
    delete process.env.WEBHOOK_ALLOW_PRIVATE_IPS;
    const webhooks = await importFresh("apps/worker/src/notify/webhooks.js");
    const result = await webhooks.postJson(
      "https://192.168.50.10/hooks/rocketchat",
      { text: "hello" },
      "generic",
    );
    assert.strictEqual(result.success, false);
    assert.match(String(result.error), /private\/reserved IP/i);
    assert.match(String(result.error), /WEBHOOK_ALLOW_PRIVATE_IPS/);
  });
});
