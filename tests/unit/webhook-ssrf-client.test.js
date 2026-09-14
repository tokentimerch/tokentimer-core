"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { postWebhook, WebhookRequestError } = require("../../packages/webhook-safety");
const {
  hostMatchesNoProxy,
  orderPinnedAddresses,
} = require("../../packages/webhook-safety/request");
const { generateSelfSignedCert } = require("../../scripts/proxy-smoke/cert-gen");
const {
  createForwardProxy,
  createHttpsTarget,
} = require("../../scripts/proxy-smoke/fixtures");

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
  delete process.env.NODE_EXTRA_CA_CERTS;
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

  it("pins the proxy hop to the validated IP instead of the hostname", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;

    const origin = http.createServer((_req, res) => {
      res.writeHead(200);
      res.end("ok");
    });
    const originPort = await listen(origin);
    const proxy = createForwardProxy();
    const proxyPort = await proxy.listen();
    process.env.HTTP_PROXY = `http://127.0.0.1:${proxyPort}`;
    try {
      const result = await postWebhook(
        `http://pin-proxy.example:${originPort}/hook`,
        {
          body: {},
          proxyMode: "always",
          lookupAll: async () => [{ address: "127.0.0.1", family: 4 }],
        },
      );
      assert.strictEqual(result.status, 200);
      assert.ok(proxy.wasConnectedTo("127.0.0.1"));
      assert.strictEqual(proxy.wasConnectedTo("pin-proxy.example"), false);
    } finally {
      await proxy.close();
      await close(origin);
    }
  });

  it("does not let the proxy resolve when enforcement is on and DNS is empty", async () => {
    process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK = "true";
    delete process.env.WEBHOOK_ALLOW_PRIVATE_IPS;

    const origin = http.createServer((_req, res) => {
      res.writeHead(200);
      res.end("ok");
    });
    const originPort = await listen(origin);
    const proxy = createForwardProxy({
      hostAliases: {
        "proxy-only.invalid": { host: "127.0.0.1", port: originPort },
      },
    });
    const proxyPort = await proxy.listen();
    process.env.HTTP_PROXY = `http://127.0.0.1:${proxyPort}`;
    try {
      await assert.rejects(
        () =>
          postWebhook(`http://proxy-only.invalid:${originPort}/hook`, {
            body: {},
            proxyMode: "always",
            lookupAll: async () => [],
          }),
        (err) => err && err.code === "WEBHOOK_DNS_UNRESOLVED",
      );
      assert.strictEqual(proxy.wasConnectedTo("proxy-only.invalid"), false);
      assert.strictEqual(proxy.wasConnectedTo("127.0.0.1"), false);
    } finally {
      await proxy.close();
      await close(origin);
    }
  });

  it("counts DNS toward the total request deadline", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
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
          postWebhook(`http://slow-dns.example:${originPort}/hook`, {
            body: {},
            timeoutMs: 80,
            lookupAll: async () => {
              await new Promise((resolve) => setTimeout(resolve, 200));
              return [{ address: "127.0.0.1", family: 4 }];
            },
          }),
        (err) => err && err.code === "WEBHOOK_TIMEOUT",
      );
      assert.strictEqual(originHits, 0);
    } finally {
      await close(origin);
    }
  });

  it("enforces the total deadline against a trickle response", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
    const origin = http.createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      const timer = setInterval(() => {
        res.write("x");
      }, 40);
      res.on("close", () => clearInterval(timer));
    });
    const originPort = await listen(origin);
    try {
      await assert.rejects(
        () =>
          postWebhook(`http://127.0.0.1:${originPort}/hook`, {
            body: {},
            timeoutMs: 120,
          }),
        (err) => err && err.code === "WEBHOOK_TIMEOUT",
      );
    } finally {
      await close(origin);
    }
  });

  it("falls back to another validated address when the first hop fails", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
    const origin = http.createServer((_req, res) => {
      res.writeHead(204);
      res.end();
    });
    const originPort = await listen(origin);
    try {
      const result = await postWebhook(
        `http://fallback.example:${originPort}/hook`,
        {
          body: {},
          lookupAll: async () => [
            { address: "127.0.0.2", family: 4 },
            { address: "127.0.0.1", family: 4 },
          ],
        },
      );
      assert.strictEqual(result.status, 204);
    } finally {
      await close(origin);
    }
  });

  it("treats a premature origin disconnect as unreachable", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
    const origin = http.createServer((req) => {
      req.socket.destroy();
    });
    const originPort = await listen(origin);
    try {
      await assert.rejects(
        () =>
          postWebhook(`http://127.0.0.1:${originPort}/hook`, { body: {} }),
        (err) => err && err.code === "WEBHOOK_UNREACHABLE",
      );
    } finally {
      await close(origin);
    }
  });

  it("matches NO_PROXY wildcards and host:port entries", () => {
    assert.strictEqual(hostMatchesNoProxy("foo.example.com", "*.example.com"), true);
    assert.strictEqual(hostMatchesNoProxy("example.com", "*.example.com"), true);
    assert.strictEqual(hostMatchesNoProxy("evil.com", "*.example.com"), false);
    assert.strictEqual(
      hostMatchesNoProxy("example.com", "example.com:8080", 443),
      false,
    );
    assert.strictEqual(
      hostMatchesNoProxy("example.com", "example.com:8080", 8080),
      true,
    );
    assert.strictEqual(
      hostMatchesNoProxy("127.0.0.1", "127.0.0.1:9", 9),
      true,
    );
  });

  it("blocks IPv6 loopback and IPv4-mapped loopback when enforcement is on", async () => {
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
          postWebhook(`http://mapped.example:${originPort}/hook`, {
            body: {},
            lookupAll: async () => [
              { address: "::ffff:127.0.0.1", family: 6 },
            ],
          }),
        (err) => err && err.code === "WEBHOOK_PRIVATE_IP_BLOCKED",
      );
      await assert.rejects(
        () =>
          postWebhook(`http://[::1]:${originPort}/hook`, { body: {} }),
        (err) => err && err.code === "WEBHOOK_PRIVATE_IP_BLOCKED",
      );
      assert.strictEqual(originHits, 0);
    } finally {
      await close(origin);
    }
  });

  it("delivers to loopback when WEBHOOK_ALLOW_PRIVATE_IPS=true even if enforcement is requested", async () => {
    process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK = "true";
    process.env.WEBHOOK_ALLOW_PRIVATE_IPS = "true";
    const origin = http.createServer((req, res) => {
      assert.strictEqual(req.method, "POST");
      res.writeHead(204);
      res.end();
    });
    const originPort = await listen(origin);
    try {
      const result = await postWebhook(`http://127.0.0.1:${originPort}/hook`, {
        body: { ping: true },
      });
      assert.strictEqual(result.status, 204);
    } finally {
      await close(origin);
    }
  });

  it("sends Proxy-Authorization and keeps the original Host on an HTTP proxy hop", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
    const origin = http.createServer((req, res) => {
      assert.ok(
        String(req.headers.host).startsWith("proxy-auth.example"),
        `Host should stay the original hostname, got ${req.headers.host}`,
      );
      res.writeHead(200);
      res.end("ok");
    });
    const originPort = await listen(origin);
    const proxy = createForwardProxy();
    const proxyPort = await proxy.listen();
    process.env.HTTP_PROXY = `http://proxy-user:proxy-pass@127.0.0.1:${proxyPort}`;
    try {
      const result = await postWebhook(
        `http://proxy-auth.example:${originPort}/hook`,
        {
          body: {},
          proxyMode: "always",
          lookupAll: async () => [{ address: "127.0.0.1", family: 4 }],
        },
      );
      assert.strictEqual(result.status, 200);
      const hop = proxy.connections.find((row) => row.via === "http");
      assert.ok(hop);
      assert.strictEqual(hop.host, "127.0.0.1");
      assert.match(hop.proxyAuthorization, /^Basic /);
      const decoded = Buffer.from(
        hop.proxyAuthorization.slice("Basic ".length),
        "base64",
      ).toString("utf8");
      assert.strictEqual(decoded, "proxy-user:proxy-pass");
    } finally {
      await proxy.close();
      await close(origin);
    }
  });

  it("uses HTTPS CONNECT to the pinned IP and refuses an untrusted certificate", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
    const origin = createHttpsTarget({
      commonName: "localhost",
      dnsNames: ["localhost"],
      ipAddresses: ["127.0.0.1"],
    });
    const originPort = await origin.listen();
    const proxy = createForwardProxy();
    const proxyPort = await proxy.listen();
    process.env.HTTPS_PROXY = `http://127.0.0.1:${proxyPort}`;
    try {
      await assert.rejects(
        () =>
          postWebhook(`https://sni-check.example:${originPort}/hook`, {
            body: {},
            proxyMode: "always",
            lookupAll: async () => [{ address: "127.0.0.1", family: 4 }],
          }),
        (err) => {
          assert.ok(err instanceof WebhookRequestError);
          assert.strictEqual(err.code, "WEBHOOK_UNREACHABLE");
          assert.match(
            err.message,
            /certificate|unable to verify|self[- ]signed|UNABLE_TO_VERIFY|hostname\/ip does not match|altnames/i,
          );
          return true;
        },
      );
      const hop = proxy.connections.find((row) => row.via === "connect");
      assert.ok(hop, "proxy should see a CONNECT tunnel");
      assert.strictEqual(hop.host, "127.0.0.1");
      assert.strictEqual(
        proxy.wasConnectedTo("sni-check.example"),
        false,
        "CONNECT must not send the hostname to the proxy to resolve",
      );
    } finally {
      await proxy.close();
      await origin.close();
    }
  });

  it("completes HTTPS CONNECT with SNI and Host when NODE_EXTRA_CA_CERTS trusts the leaf", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
    const hostname = "sni-ok.example";
    const { certPem, keyPem } = generateSelfSignedCert({
      commonName: hostname,
      dnsNames: [hostname],
      ipAddresses: ["127.0.0.1"],
    });
    let seenHost = null;
    let seenSni = null;
    const origin = https.createServer(
      { cert: certPem, key: keyPem },
      (req, res) => {
        seenHost = req.headers.host;
        seenSni = req.socket && req.socket.servername;
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end("OK");
      },
    );
    const originPort = await listen(origin);
    const proxy = createForwardProxy();
    const proxyPort = await proxy.listen();
    process.env.HTTPS_PROXY = `http://127.0.0.1:${proxyPort}`;
    const caDir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-webhook-ca-"));
    const caPath = path.join(caDir, "ca.pem");
    fs.writeFileSync(caPath, certPem);
    process.env.NODE_EXTRA_CA_CERTS = caPath;
    try {
      const result = await postWebhook(
        `https://${hostname}:${originPort}/hook`,
        {
          body: { ping: true },
          proxyMode: "always",
          lookupAll: async () => [{ address: "127.0.0.1", family: 4 }],
        },
      );
      assert.strictEqual(result.status, 200);
      assert.strictEqual(result.bodyText, "OK");
      assert.strictEqual(seenHost, `${hostname}:${originPort}`);
      assert.strictEqual(seenSni, hostname);
      const hop = proxy.connections.find((row) => row.via === "connect");
      assert.ok(hop, "proxy should see a CONNECT tunnel");
      assert.strictEqual(hop.host, "127.0.0.1");
      assert.strictEqual(proxy.wasConnectedTo(hostname), false);
    } finally {
      await proxy.close();
      await close(origin);
      fs.rmSync(caDir, { recursive: true, force: true });
    }
  });

  it("counts a hung HTTPS CONNECT toward the total deadline", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
    const sockets = new Set();
    const proxy = http.createServer();
    proxy.on("connection", (socket) => sockets.add(socket));
    proxy.on("connect", (_req, clientSocket) => {
      sockets.add(clientSocket);
    });
    const proxyPort = await listen(proxy);
    process.env.HTTPS_PROXY = `http://127.0.0.1:${proxyPort}`;
    const started = Date.now();
    try {
      await assert.rejects(
        () =>
          postWebhook("https://hung-connect.example:443/hook", {
            body: {},
            proxyMode: "always",
            timeoutMs: 120,
            lookupAll: async () => [{ address: "127.0.0.1", family: 4 }],
          }),
        (err) => {
          assert.ok(err instanceof WebhookRequestError);
          assert.strictEqual(err.code, "WEBHOOK_TIMEOUT");
          return true;
        },
      );
      const elapsed = Date.now() - started;
      assert.ok(elapsed < 2000, `hung CONNECT took ${elapsed}ms`);
    } finally {
      for (const socket of sockets) socket.destroy();
      await close(proxy);
    }
  });

  it("cancels an in-flight request and still delivers afterward", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
    let hits = 0;
    const origin = http.createServer((_req, res) => {
      hits += 1;
      if (hits === 1) {
        res.writeHead(200, { "Content-Type": "text/plain" });
        const timer = setInterval(() => {
          res.write("x");
        }, 40);
        res.on("close", () => clearInterval(timer));
        return;
      }
      res.writeHead(204);
      res.end();
    });
    const originPort = await listen(origin);
    const ac = new AbortController();
    const pending = postWebhook(`http://127.0.0.1:${originPort}/hook`, {
      body: {},
      timeoutMs: 5000,
      signal: ac.signal,
    });
    setTimeout(() => ac.abort(), 40);
    try {
      await assert.rejects(
        () => pending,
        (err) => err && err.code === "WEBHOOK_TIMEOUT",
      );
      const result = await postWebhook(`http://127.0.0.1:${originPort}/hook`, {
        body: {},
      });
      assert.strictEqual(result.status, 204);
      assert.strictEqual(hits, 2);
    } finally {
      await close(origin);
    }
  });

  it("fails promptly when the body is cut off and delivers the next request", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
    let hits = 0;
    const origin = http.createServer((_req, res) => {
      hits += 1;
      if (hits === 1) {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.write("partial");
        res.destroy();
        return;
      }
      res.writeHead(204);
      res.end();
    });
    const originPort = await listen(origin);
    try {
      await assert.rejects(
        () =>
          postWebhook(`http://127.0.0.1:${originPort}/hook`, {
            body: { n: 1 },
          }),
        (err) => err && err.code === "WEBHOOK_UNREACHABLE",
      );
      const result = await postWebhook(`http://127.0.0.1:${originPort}/hook`, {
        body: { n: 2 },
      });
      assert.strictEqual(result.status, 204);
      assert.strictEqual(hits, 2);
    } finally {
      await close(origin);
    }
  });

  it("does not POST to a second address after the first hop may have received the body", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
    let firstHits = 0;
    let secondHits = 0;
    const first = http.createServer((_req, res) => {
      firstHits += 1;
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.write("partial");
      setImmediate(() => res.destroy());
    });
    const firstPort = await listen(first, "127.0.0.1");
    let second;
    let secondBound = false;
    try {
      second = http.createServer((_req, res) => {
        secondHits += 1;
        res.writeHead(204);
        res.end();
      });
      await new Promise((resolve, reject) => {
        second.once("error", reject);
        second.listen(firstPort, "127.0.0.2", () => {
          second.removeListener("error", reject);
          resolve();
        });
      });
      secondBound = true;
    } catch (err) {
      await close(first);
      throw new Error(
        `127.0.0.2:${firstPort} must be bindable for this fallback test: ${err.message}`,
      );
    }
    try {
      await assert.rejects(
        () =>
          postWebhook(`http://no-retry.example:${firstPort}/hook`, {
            body: { once: true },
            lookupAll: async () => [
              { address: "127.0.0.1", family: 4 },
              { address: "127.0.0.2", family: 4 },
            ],
          }),
        (err) => err && err.code === "WEBHOOK_UNREACHABLE",
      );
      assert.strictEqual(firstHits, 1);
      assert.strictEqual(
        secondHits,
        0,
        "must not retry a POST after the first hop may have received it",
      );
    } finally {
      await close(first);
      if (secondBound) await close(second);
    }
  });

  it("falls back from an unreachable IPv4 candidate to a validated IPv6 listener", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
    const origin = http.createServer((_req, res) => {
      res.writeHead(204);
      res.end();
    });
    let originPort;
    try {
      originPort = await listen(origin, "::1");
    } catch (err) {
      await close(origin);
      throw new Error(`::1 must be bindable for this fallback test: ${err.message}`);
    }
    try {
      const result = await postWebhook(
        `http://dual.example:${originPort}/hook`,
        {
          body: {},
          lookupAll: async () => [
            { address: "127.0.0.2", family: 4 },
            { address: "::1", family: 6 },
          ],
        },
      );
      assert.strictEqual(result.status, 204);
    } finally {
      await close(origin);
    }
  });

  it("orders IPv4 candidates ahead of IPv6 without duplicating addresses", () => {
    const ordered = orderPinnedAddresses([
      { address: "::1", family: 6 },
      { address: "127.0.0.1", family: 4 },
      { address: "127.0.0.1", family: 4 },
      { address: "2001:db8::1", family: 6 },
    ]);
    assert.deepStrictEqual(
      ordered.map((row) => row.address),
      ["127.0.0.1", "::1", "2001:db8::1"],
    );
  });

  it("skips the proxy for a host:port NO_PROXY entry on that port", async () => {
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
    process.env.NO_PROXY = `127.0.0.1:${originPort}`;
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
});
