"use strict";

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");

const {
  buildAllowPolicy,
  validateUrlScheme,
  validateResolvedIp,
  isPrivateOrBlockedIp,
  ipInCidrV4,
  isLocalhostHost,
  pickPreferredAddress,
  safeFetch,
  validateOutboundUrl,
  outboundBlockHint,
  resolveSafeFetchTimeoutMs,
} = require("../../apps/api/sso/safe-fetch");

describe("safe-fetch", () => {
  const envBackup = { ...process.env };

  afterEach(() => {
    process.env = { ...envBackup };
  });

  it("applies the shared outbound policy before resolving an IdP host", async () => {
    process.env.OUTBOUND_ALLOWLIST = "allowed-idp.example";
    const url = "https://blocked-idp.example/.well-known/openid-configuration";
    const denied = { ok: false, reason: "OUTBOUND_POLICY_DENIED" };
    assert.deepStrictEqual(await validateOutboundUrl(url), denied);
    assert.deepStrictEqual(await safeFetch(url), denied);
    assert.match(outboundBlockHint(denied.reason), /OUTBOUND_ALLOWLIST/);
  });

  it("outboundBlockHint names the private IPv4 allowlist for blocked_ip only", () => {
    const hint = outboundBlockHint("blocked_ip");
    assert.ok(hint.includes("SSO_ALLOWED_IDP_CIDRS"));
    assert.ok(hint.includes("private IPv4 IdP"));
    assert.strictEqual(outboundBlockHint("dns_failed"), null);
    assert.strictEqual(outboundBlockHint(undefined), null);
  });

  it("blocks metadata IP 169.254.169.254 by default", () => {
    const allow = buildAllowPolicy({});
    assert.throws(
      () => validateResolvedIp("example.com", "169.254.169.254", allow),
      (err) => err.code === "blocked_ip",
    );
  });

  it("blocks private ranges by default", () => {
    const allow = buildAllowPolicy({});
    assert.throws(
      () => validateResolvedIp("internal.corp", "10.0.0.5", allow),
      (err) => err.code === "blocked_ip",
    );
  });

  it("blocks mapped and translated private addresses unless explicitly allowed", () => {
    const allow = buildAllowPolicy({});
    for (const ip of ["::ffff:10.0.0.5", "0:0:0:0:0:ffff:a00:5", "64:ff9b::a00:5", "::ffff:0:a00:5", "fe90::1234", "0:0:0:0:0:0:0:1"]) {
      assert.throws(() => validateResolvedIp("idp.example", ip, allow),
        (err) => err.code === "blocked_ip", ip);
    }
    const explicit = buildAllowPolicy({ SSO_ALLOWED_IDP_CIDRS: "10.0.0.0/8" });
    assert.doesNotThrow(() => validateResolvedIp("idp.example", "::ffff:a00:5", explicit));
    assert.doesNotThrow(() => validateResolvedIp("idp.example", "::ffff:a00:5",
      buildAllowPolicy({ SSO_ALLOW_PRIVATE_IDP_URLS: "true" })));
    assert.doesNotThrow(() => validateResolvedIp("idp.example", "::ffff:808:808", allow));
    assert.doesNotThrow(() => validateResolvedIp("idp.example", "2606:4700:4700::1111", allow));
  });

  it("never allows mapped metadata or disguised remote loopback", () => {
    const allow = buildAllowPolicy({ SSO_ALLOW_PRIVATE_IDP_URLS: "true", SSO_ALLOWED_IDP_CIDRS: "169.254.0.0/16" });
    for (const ip of ["::ffff:169.254.169.254", "0:0:0:0:0:ffff:a9fe:a9fe", "64:ff9b::a9fe:a9fe", "::ffff:0:a9fe:a9fe", "fd00:0ec2:0:0:0:0:0:0254", "::ffff:7f00:1"]) {
      assert.throws(() => validateResolvedIp("idp.example", ip, allow),
        (err) => err.code === "blocked_ip", ip);
    }
    assert.doesNotThrow(() => validateResolvedIp("localhost", "::ffff:7f00:1", allow));
  });

  it("checks every DNS answer before an SSO request can send credentials", async () => {
    const dns = require("node:dns").promises;
    const https = require("node:https");
    const lookup = dns.lookup, request = https.request;
    let requests = 0;
    dns.lookup = async () => [{ address: "8.8.8.8", family: 4 },
      { address: "::ffff:a9fe:a9fe", family: 6 }];
    https.request = () => { requests += 1; throw new Error("Unexpected outbound request"); };
    try {
      assert.deepStrictEqual(await safeFetch("https://idp.example/token", {
        method: "POST", body: "synthetic-test-only",
        env: { SSO_ALLOW_PRIVATE_IDP_URLS: "true" },
      }), { ok: false, reason: "blocked_ip" });
      assert.strictEqual(requests, 0);
    } finally {
      dns.lookup = lookup;
      https.request = request;
    }
  });

  it("allows private ranges when SSO_ALLOW_PRIVATE_IDP_URLS=true", () => {
    const allow = buildAllowPolicy({ SSO_ALLOW_PRIVATE_IDP_URLS: "true" });
    assert.doesNotThrow(() => validateResolvedIp("internal.corp", "10.0.0.5", allow));
  });

  it("honours SSO_ALLOWED_IDP_CIDRS", () => {
    const allow = buildAllowPolicy({ SSO_ALLOWED_IDP_CIDRS: "10.0.0.0/8" });
    assert.doesNotThrow(() => validateResolvedIp("idp.bank", "10.1.2.3", allow));
    assert.throws(
      () => validateResolvedIp("idp.bank", "172.16.0.1", allow),
      (err) => err.code === "blocked_ip",
    );
  });

  it("blocks loopback IP when hostname is not localhost", () => {
    const allow = buildAllowPolicy({});
    assert.throws(
      () => validateResolvedIp("evil.example.com", "127.0.0.1", allow),
      (err) => err.code === "blocked_ip",
    );
  });

  it("allows loopback IP when hostname is localhost", () => {
    const allow = buildAllowPolicy({ SSO_ALLOW_PRIVATE_IDP_URLS: "true" });
    assert.doesNotThrow(() => validateResolvedIp("localhost", "127.0.0.1", allow));
  });

  it("rejects http in production except localhost dev rule", () => {
    assert.throws(
      () =>
        validateUrlScheme(new URL("http://idp.example.com/path"), {
          NODE_ENV: "production",
        }),
      (err) => err.code === "scheme_not_allowed",
    );
    assert.doesNotThrow(() =>
      validateUrlScheme(new URL("http://127.0.0.1/path"), { NODE_ENV: "development" }),
    );
  });

  it("preserves TLS SNI / Host / checkServerIdentity contract in source", () => {
    const src = fs.readFileSync(
      path.join(__dirname, "../../apps/api/sso/safe-fetch.js"),
      "utf8",
    );
    assert.match(src, /servername:\s*isHttps\s*\?\s*hostname/);
    assert.match(src, /checkServerIdentity/);
    assert.match(src, /Host:\s*parsedUrl\.host/);
    assert.match(src, /host:\s*resolvedIp/);
  });

  it("preserves the configured authority when fetching OIDC discovery on a nondefault port", async (t) => {
    const http = require("node:http");
    const { createProviderStrategyConfig } = require("../../apps/api/sso/strategy-config.js");
    const server = http.createServer((req, res) => {
      const issuer = "http://" + req.headers.host + "/realms/test";
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({
        issuer,
        authorization_endpoint: issuer + "/protocol/openid-connect/auth",
        token_endpoint: issuer + "/protocol/openid-connect/token",
        jwks_uri: issuer + "/protocol/openid-connect/certs",
      }));
    });
    await new Promise((done) => server.listen(0, "127.0.0.1", done));
    t.after(() => new Promise((done) => server.close(done)));

    const issuer = "http://127.0.0.1:" + server.address().port + "/realms/test";
    const strategy = await createProviderStrategyConfig().buildOidcStrategyConfigFromProvider(
      null,
      { slug: "test", config: { issuer, client_id: "test" } },
      { client_secret: "synthetic" },
    );
    assert.strictEqual(strategy.discoverySource, "discovery");
    assert.strictEqual(strategy.authorizationURL, issuer + "/protocol/openid-connect/auth");
    assert.strictEqual(strategy.tokenURL, issuer + "/protocol/openid-connect/token");
    assert.strictEqual(strategy.jwksURL, issuer + "/protocol/openid-connect/certs");
  });

  it("bounds streamed IdP responses and reports an invalid redirect", async (t) => {
    const http = require("node:http");
    const server = http.createServer((req, res) => {
      if (req.url === "/redirect") {
        res.writeHead(302, { Location: "http://[" });
        return res.end();
      }
      const chunk = Buffer.alloc(1024 * 1024);
      res.write(chunk);
      res.write(chunk);
      res.end(Buffer.from("beyond the response limit"));
    });
    await new Promise((done) => server.listen(0, "127.0.0.1", done));
    t.after(() => new Promise((done) => server.close(done)));

    const origin = "http://127.0.0.1:" + server.address().port;
    assert.deepStrictEqual(await safeFetch(origin + "/metadata"), {
      ok: false, reason: "response_too_large",
    });
    assert.deepStrictEqual(await safeFetch(origin + "/redirect"), {
      ok: false, reason: "invalid_url",
    });
  });

  it("pickPreferredAddress prefers IPv4 when both A and AAAA exist", () => {
    const chosen = pickPreferredAddress([
      { address: "2001:db8::1", family: 6 },
      { address: "203.0.113.10", family: 4 },
    ]);
    assert.strictEqual(chosen.address, "203.0.113.10");
    assert.strictEqual(chosen.family, 4);
  });

  it("pickPreferredAddress falls back to first entry when only IPv6 exists", () => {
    const chosen = pickPreferredAddress([{ address: "2001:db8::1", family: 6 }]);
    assert.strictEqual(chosen.address, "2001:db8::1");
  });

  it("defaults outbound timeout to SSO_IDP_HTTP_TIMEOUT_MS", () => {
    delete process.env.SSO_IDP_HTTP_TIMEOUT_MS;
    assert.strictEqual(resolveSafeFetchTimeoutMs({}, {}), 20_000);
    assert.strictEqual(
      resolveSafeFetchTimeoutMs({}, { SSO_IDP_HTTP_TIMEOUT_MS: "45000" }),
      45_000,
    );
    assert.strictEqual(
      resolveSafeFetchTimeoutMs({ timeoutMs: 8_000 }, { SSO_IDP_HTTP_TIMEOUT_MS: "45000" }),
      8_000,
    );
    const src = fs.readFileSync(
      path.join(__dirname, "../../apps/api/sso/safe-fetch.js"),
      "utf8",
    );
    assert.doesNotMatch(src, /Connect timed out/);
    assert.doesNotMatch(src, /DEFAULT_CONNECT_TIMEOUT_MS/);
  });

  it("ipInCidrV4 and isLocalhostHost helpers behave as expected", () => {
    assert.strictEqual(ipInCidrV4("10.2.3.4", "10.0.0.0", 8), true);
    assert.strictEqual(isLocalhostHost("localhost"), true);
    assert.strictEqual(
      isPrivateOrBlockedIp("127.0.0.1", { ranges: false, localhost: false }),
      true,
    );
  });
});
