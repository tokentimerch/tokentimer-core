"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const path = require("node:path");

const servicesDir = path.resolve(__dirname, "../../apps/api/services");

function loadService(fileName) {
  const abs = path.join(servicesDir, fileName);
  const resolved = require.resolve(abs);
  delete require.cache[resolved];
  try {
    delete require.cache[
      require.resolve(path.join(servicesDir, "integrationUtils.js"))
    ];
  } catch (_) {}
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = "test";
  try {
    return require(resolved);
  } finally {
    process.env.NODE_ENV = previous;
  }
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve(server.address().port);
    });
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

async function withRedirectPair(run) {
  const sinkHits = [];
  const sink = http.createServer((req, res) => {
    sinkHits.push({
      url: req.url,
      vaultToken: req.headers["x-vault-token"] || null,
      privateToken: req.headers["private-token"] || null,
      authorization: req.headers.authorization || null,
    });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
  });
  const sinkPort = await listen(sink);
  const origin = http.createServer((_req, res) => {
    res.writeHead(302, { Location: `http://127.0.0.1:${sinkPort}/stolen` });
    res.end();
  });
  const originPort = await listen(origin);
  try {
    await run({
      originUrl: `http://127.0.0.1:${originPort}`,
      sinkHits,
    });
  } finally {
    await closeServer(origin);
    await closeServer(sink);
  }
}

describe("integration follow-up URL origin checks", () => {
  const {
    assertSameOriginFollowUp,
    isHttpRedirectStatus,
    CREDENTIALED_AXIOS_REDIRECTS,
  } = require(path.join(servicesDir, "integrationUtils.js"));

  it("accepts same-origin absolute and relative follow-up URLs", () => {
    const relative = assertSameOriginFollowUp(
      "/secrets?$skiptoken=abc",
      "https://vault.example.com",
      "pagination URL",
    );
    assert.equal(relative.origin, "https://vault.example.com");
    assert.match(relative.search, /skiptoken=abc/);

    const absolute = assertSameOriginFollowUp(
      "https://vault.example.com/secrets?api-version=7.4",
      "https://vault.example.com",
      "pagination URL",
    );
    assert.equal(absolute.origin, "https://vault.example.com");
  });

  it("rejects follow-up URLs that leave the expected host", () => {
    assert.throws(
      () =>
        assertSameOriginFollowUp(
          "http://127.0.0.1:9/secrets",
          "https://vault.example.com",
          "Azure Key Vault pagination URL",
        ),
      /left the expected host/,
    );
    assert.throws(
      () =>
        assertSameOriginFollowUp(
          "https://graph.microsoft.com.evil.example/v1.0/applications",
          "https://graph.microsoft.com/v1.0",
          "Microsoft Graph pagination URL",
        ),
      /left the expected host/,
    );
    assert.throws(
      () =>
        assertSameOriginFollowUp(
          "https://user:pass@vault.example.com/secrets",
          "https://vault.example.com",
          "pagination URL",
        ),
      /must not include credentials/,
    );
  });

  it("treats 3xx hop statuses as redirects and disables axios following", () => {
    assert.equal(isHttpRedirectStatus(302), true);
    assert.equal(isHttpRedirectStatus(304), false);
    assert.equal(CREDENTIALED_AXIOS_REDIRECTS.maxRedirects, 0);
  });
});

describe("credentialed integration clients refuse redirects", () => {
  it("Vault fetch does not follow a 302 to loopback or forward the token", async () => {
    const vault = loadService("vaultIntegration.js");
    await withRedirectPair(async ({ originUrl, sinkHits }) => {
      await assert.rejects(
        () =>
          vault._test.vaultRequest({
            address: originUrl,
            token: "vault-secret-token",
            path: "/v1/sys/mounts",
          }),
        (err) => {
          assert.match(err.message, /refused redirect/);
          // Must surface as a client error, never as the provider's 3xx
          // (a 3xx API response would invite the caller to follow it).
          assert.equal(err.status, 400);
          return true;
        },
      );
      assert.equal(sinkHits.length, 0);
    });
  });

  it("GitLab axios does not follow a 302 to loopback or forward the token", async () => {
    const gitlab = loadService("gitlabIntegration.js");
    await withRedirectPair(async ({ originUrl, sinkHits }) => {
      await assert.rejects(
        () =>
          gitlab._test.gitlabRequest({
            baseUrl: originUrl,
            token: "gitlab-secret-token",
            path: "/api/v4/user",
            timeout: 5000,
          }),
        /redirect|status 302/i,
      );
      assert.equal(sinkHits.length, 0);
    });
  });

  it("GitHub axios does not follow a 302 to loopback or forward the token", async () => {
    const github = loadService("githubIntegration.js");
    await withRedirectPair(async ({ originUrl, sinkHits }) => {
      await assert.rejects(
        () =>
          github._test.githubRequest({
            baseUrl: originUrl,
            token: "github-secret-token",
            path: "/user",
            timeout: 5000,
          }),
        /redirect|status 302/i,
      );
      assert.equal(sinkHits.length, 0);
    });
  });
});
