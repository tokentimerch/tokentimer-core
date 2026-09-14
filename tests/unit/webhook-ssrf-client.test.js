"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert");
const http = require("node:http");
const { postWebhook, WebhookRequestError } = require("../../packages/webhook-safety");
const { createForwardProxy } = require("../../scripts/proxy-smoke/fixtures");

const ORIGINAL_NODE_ENV = process.env.NODE_ENV;

function clearProxyEnv() {
  delete process.env.HTTP_PROXY;
  delete process.env.http_proxy;
  delete process.env.HTTPS_PROXY;
  delete process.env.https_proxy;
  delete process.env.NO_PROXY;
  delete process.env.no_proxy;
  delete process.env.NODE_USE_ENV_PROXY;
}

beforeEach(clearProxyEnv);

afterEach(() => {
  process.env.NODE_ENV = ORIGINAL_NODE_ENV;
  delete process.env.WEBHOOK_ALLOW_PRIVATE_IPS;
  delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
  clearProxyEnv();
});

function listen(server, host = "127.0.0.1") {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, host, () => {
      server.removeListener("error", reject);
      resolve(server.address().port);
    });
  });
}

function close(server) {
  return new Promise((resolve) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close(() => resolve());
  });
}

describe("postWebhook SSRF client", () => {
  it("refuses 302/307/308 redirects so the Location host is never contacted", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;

    for (const status of [302, 307, 308]) {
      let originHits = 0;
      let canaryHits = 0;
      const canary = http.createServer((_req, res) => {
        canaryHits += 1;
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end("canary");
      });
      const canaryPort = await listen(canary);
      const origin = http.createServer((_req, res) => {
        originHits += 1;
        res.writeHead(status, {
          Location: `http://127.0.0.1:${canaryPort}/secret`,
        });
        res.end();
      });
      const originPort = await listen(origin);
      try {
        await assert.rejects(
          () =>
            postWebhook(`http://127.0.0.1:${originPort}/hook`, {
              body: { ping: true },
            }),
          (err) => {
            assert.ok(err instanceof WebhookRequestError);
            assert.strictEqual(err.code, "WEBHOOK_REDIRECT_REFUSED");
            assert.strictEqual(err.status, status);
            return true;
          },
        );
        assert.strictEqual(originHits, 1, `${status} should hit the origin once`);
        assert.strictEqual(canaryHits, 0, `${status} must not follow Location`);
      } finally {
        await close(origin);
        await close(canary);
      }
    }
  });

  it("refuses redirects to link-local and RFC1918 Locations", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
    const locations = [
      "http://169.254.169.254/",
      "http://10.0.0.1/",
    ];
    for (const location of locations) {
      const origin = http.createServer((_req, res) => {
        res.writeHead(302, { Location: location });
        res.end();
      });
      const originPort = await listen(origin);
      try {
        await assert.rejects(
          () => postWebhook(`http://127.0.0.1:${originPort}/hook`, { body: {} }),
          (err) => err && err.code === "WEBHOOK_REDIRECT_REFUSED",
        );
      } finally {
        await close(origin);
      }
    }
  });

  it("pins DNS so a later private answer cannot be used for the connection", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;

    let originHits = 0;
    let canaryHits = 0;
    const origin = http.createServer((_req, res) => {
      originHits += 1;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true}');
    });
    const originPort = await listen(origin, "127.0.0.1");

    let canary;
    let canaryBound = false;
    try {
      canary = http.createServer((_req, res) => {
        canaryHits += 1;
        res.writeHead(200);
        res.end("rebound");
      });
      await listen(canary, "127.0.0.2");
      canaryBound = true;
    } catch (_) {
      canary = null;
    }

    let lookupCalls = 0;
    try {
      const result = await postWebhook(`http://pin-test.example:${originPort}/hook`, {
        body: { ping: true },
        lookupAll: async () => {
          lookupCalls += 1;
          if (lookupCalls === 1) {
            return [{ address: "127.0.0.1", family: 4 }];
          }
          return [{ address: "127.0.0.2", family: 4 }];
        },
      });
      assert.strictEqual(result.status, 200);
      assert.strictEqual(lookupCalls, 1);
      assert.strictEqual(originHits, 1);
      assert.strictEqual(canaryHits, 0);
    } finally {
      await close(origin);
      if (canaryBound) await close(canary);
    }
  });

  it("rejects a public A plus private AAAA set before connecting", async () => {
    process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK = "true";
    delete process.env.WEBHOOK_ALLOW_PRIVATE_IPS;

    let originHits = 0;
    const origin = http.createServer((_req, res) => {
      originHits += 1;
      res.writeHead(200);
      res.end("ok");
    });
    const originPort = await listen(origin);
    try {
      await assert.rejects(
        () =>
          postWebhook(`http://mixed.example:${originPort}/hook`, {
            body: {},
            lookupAll: async () => [
              { address: "8.8.8.8", family: 4 },
              { address: "::1", family: 6 },
            ],
          }),
        (err) => err && err.code === "WEBHOOK_PRIVATE_IP_BLOCKED",
      );
      assert.strictEqual(originHits, 0);
    } finally {
      await close(origin);
    }
  });

  it("delivers JSON to a loopback origin when private-IP enforcement is off", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
    const origin = http.createServer((req, res) => {
      assert.strictEqual(req.method, "POST");
      res.writeHead(204);
      res.end();
    });
    const originPort = await listen(origin);
    try {
      const result = await postWebhook(`http://127.0.0.1:${originPort}/hook`, {
        body: { hello: "world" },
      });
      assert.strictEqual(result.status, 204);
    } finally {
      await close(origin);
    }
  });

  it("sends HTTP via the proxy as an absolute-URI request", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;

    const origin = http.createServer((req, res) => {
      assert.strictEqual(req.method, "POST");
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
    });
    const originPort = await listen(origin);
    const proxy = createForwardProxy();
    const proxyPort = await proxy.listen();
    process.env.HTTP_PROXY = `http://127.0.0.1:${proxyPort}`;
    try {
      const result = await postWebhook(`http://127.0.0.1:${originPort}/hook`, {
        body: { ping: true },
        proxyMode: "always",
      });
      assert.strictEqual(result.status, 200);
      assert.ok(proxy.wasConnectedTo("127.0.0.1"));
    } finally {
      await proxy.close();
      await close(origin);
    }
  });

  it("reaches a DNS-unresolved host when a proxy aliases it", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;

    const origin = http.createServer((_req, res) => {
      res.writeHead(200);
      res.end("ok");
    });
    const originPort = await listen(origin);
    const proxy = createForwardProxy({
      hostAliases: {
        "proxy-smoke-unreachable.invalid": {
          host: "127.0.0.1",
          port: originPort,
        },
      },
    });
    const proxyPort = await proxy.listen();
    process.env.HTTP_PROXY = `http://127.0.0.1:${proxyPort}`;
    try {
      const result = await postWebhook(
        `http://proxy-smoke-unreachable.invalid:${originPort}/hook`,
        {
          body: {},
          proxyMode: "always",
          lookupAll: async () => [],
        },
      );
      assert.strictEqual(result.status, 200);
      assert.ok(proxy.wasConnectedTo("proxy-smoke-unreachable.invalid"));
    } finally {
      await proxy.close();
      await close(origin);
    }
  });

  it("skips the proxy when NO_PROXY matches the destination host", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;

    const origin = http.createServer((_req, res) => {
      res.writeHead(204);
      res.end();
    });
    const originPort = await listen(origin);
    const proxy = createForwardProxy();
    const proxyPort = await proxy.listen();
    process.env.HTTP_PROXY = `http://127.0.0.1:${proxyPort}`;
    process.env.NO_PROXY = "127.0.0.1";
    try {
      const result = await postWebhook(`http://127.0.0.1:${originPort}/hook`, {
        body: {},
        proxyMode: "always",
      });
      assert.strictEqual(result.status, 204);
      assert.strictEqual(proxy.wasConnectedTo("127.0.0.1"), false);
    } finally {
      await proxy.close();
      await close(origin);
    }
  });

  it("does not proxy in node-flag mode unless NODE_USE_ENV_PROXY is set", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
    delete process.env.NODE_USE_ENV_PROXY;

    const origin = http.createServer((_req, res) => {
      res.writeHead(200);
      res.end("ok");
    });
    const originPort = await listen(origin);
    const proxy = createForwardProxy();
    const proxyPort = await proxy.listen();
    process.env.HTTP_PROXY = `http://127.0.0.1:${proxyPort}`;
    try {
      const result = await postWebhook(`http://127.0.0.1:${originPort}/hook`, {
        body: {},
        proxyMode: "node-flag",
      });
      assert.strictEqual(result.status, 200);
      assert.strictEqual(proxy.wasConnectedTo("127.0.0.1"), false);

      process.env.NODE_USE_ENV_PROXY = "1";
      const proxied = await postWebhook(`http://127.0.0.1:${originPort}/hook`, {
        body: {},
        proxyMode: "node-flag",
      });
      assert.strictEqual(proxied.status, 200);
      assert.ok(proxy.wasConnectedTo("127.0.0.1"));
    } finally {
      await proxy.close();
      await close(origin);
    }
  });

  it("blocks a private destination before contacting the proxy", async () => {
    process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK = "true";
    delete process.env.WEBHOOK_ALLOW_PRIVATE_IPS;

    const origin = http.createServer((_req, res) => {
      res.writeHead(200);
      res.end("ok");
    });
    const originPort = await listen(origin);
    const proxy = createForwardProxy();
    const proxyPort = await proxy.listen();
    process.env.HTTP_PROXY = `http://127.0.0.1:${proxyPort}`;
    try {
      await assert.rejects(
        () =>
          postWebhook(`http://127.0.0.1:${originPort}/hook`, {
            body: {},
            proxyMode: "always",
          }),
        (err) => err && err.code === "WEBHOOK_PRIVATE_IP_BLOCKED",
      );
      assert.strictEqual(proxy.wasConnectedTo("127.0.0.1"), false);
    } finally {
      await proxy.close();
      await close(origin);
    }
  });

  it("refuses redirects when the response arrived through a proxy", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;

    const origin = http.createServer((_req, res) => {
      res.writeHead(302, { Location: "http://169.254.169.254/" });
      res.end();
    });
    const originPort = await listen(origin);
    const proxy = createForwardProxy();
    const proxyPort = await proxy.listen();
    process.env.HTTP_PROXY = `http://127.0.0.1:${proxyPort}`;
    try {
      await assert.rejects(
        () =>
          postWebhook(`http://127.0.0.1:${originPort}/hook`, {
            body: {},
            proxyMode: "always",
          }),
        (err) => err && err.code === "WEBHOOK_REDIRECT_REFUSED",
      );
    } finally {
      await proxy.close();
      await close(origin);
    }
  });
});
