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

  it("flags private and reserved IPv6 ranges", () => {
    for (const ip of [
      "::1",
      "::",
      "fe80::1",
      "fe80::aabb:ccff:fedd:eeff",
      "fc00::1",
      "fd12:3456:789a:1::1",
      "ff02::1",
      "2001:db8::1",
      "100::1",
    ]) {
      assert.strictEqual(isPrivateOrReservedIP(ip), true, `${ip} should be private`);
    }
  });

  it("flags IPv4-mapped and other IPv4-embedded IPv6 forms of blocked ranges", () => {
    for (const ip of [
      "::ffff:127.0.0.1",
      "::ffff:7f00:1",
      "[::ffff:127.0.0.1]",
      "::ffff:10.0.0.1",
      "::ffff:192.168.1.1",
      "::ffff:169.254.169.254",
      "::ffff:0:127.0.0.1",
      "64:ff9b::10.1.2.3",
      "2002:7f00:1::1",
    ]) {
      assert.strictEqual(
        isPrivateOrReservedIP(ip),
        true,
        `${ip} should be private`,
      );
    }
  });

  it("allows public IPv6 and mapped public IPv4", () => {
    for (const ip of [
      "2001:4860:4860::8888",
      "2606:4700:4700::1111",
      "::ffff:8.8.8.8",
      "::ffff:1.1.1.1",
    ]) {
      assert.strictEqual(isPrivateOrReservedIP(ip), false, `${ip} should be public`);
    }
  });

  it("shares the classifier with the canonical package", () => {
    const shared = require("../../packages/webhook-safety");
    assert.strictEqual(isPrivateOrReservedIP, shared.isPrivateOrReservedIP);
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

  it("rejects IPv6 loopback and IPv4-mapped loopback literals", async () => {
    assert.strictEqual(await validateResolvedIP("::1"), false);
    assert.strictEqual(await validateResolvedIP("::ffff:127.0.0.1"), false);
    assert.strictEqual(await validateResolvedIP("[::ffff:127.0.0.1]"), false);
  });

  it("rejects a private AAAA answer even when A records are public", async () => {
    const ok = await validateResolvedIP("dual.example", {
      resolve4: async () => ["8.8.8.8"],
      resolve6: async () => ["fd00::1"],
    });
    assert.strictEqual(ok, false);
  });

  it("rejects a private AAAA-only answer", async () => {
    const nodata = Object.assign(new Error("no A records"), { code: "ENODATA" });
    const ok = await validateResolvedIP("aaaa-only.example", {
      resolve4: async () => {
        throw nodata;
      },
      resolve6: async () => ["fe80::1"],
    });
    assert.strictEqual(ok, false);
  });

  it("accepts public A and AAAA answers", async () => {
    const ok = await validateResolvedIP("public.example", {
      resolve4: async () => ["1.1.1.1"],
      resolve6: async () => ["2606:4700:4700::1111"],
    });
    assert.strictEqual(ok, true);
  });

  it("rejects mapped private IPv4 in an AAAA answer", async () => {
    const ok = await validateResolvedIP("mapped.example", {
      resolve4: async () => {
        throw Object.assign(new Error("no A records"), { code: "ENODATA" });
      },
      resolve6: async () => ["::ffff:192.168.1.1"],
    });
    assert.strictEqual(ok, false);
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

  it("blocks IPv6 loopback and IPv4-mapped loopback literals", async () => {
    process.env.NODE_ENV = "production";
    delete process.env.WEBHOOK_ALLOW_PRIVATE_IPS;
    const webhooks = await importFresh("apps/worker/src/notify/webhooks.js");
    for (const url of [
      "https://[::1]/hooks/rocketchat",
      "https://[::ffff:127.0.0.1]/hooks/rocketchat",
      "https://[::ffff:192.168.1.1]/hooks/rocketchat",
    ]) {
      const result = await webhooks.postJson(url, { text: "hello" }, "generic");
      assert.strictEqual(result.success, false, `${url} should be blocked`);
      assert.match(String(result.error), /private\/reserved IP/i);
    }
  });
});
