"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");
const { Readable } = require("node:stream");
const p = require("../../apps/api/services/operator/oauthProtocol");
const { remoteConfig, MCP_PATH } = require("../../apps/api/services/operator/remoteConfig");
const { forwardingHeaders, remoteRateKey } = require("../../apps/api/services/operator/remoteForwarding");
const { isOperatorBearerCsrfExemptRequest } = require("../../apps/api/middleware/csrf-exempt");
const { scrubLogString, redactSensitiveFields } = require("../../packages/log-scrub");

const env = { NODE_ENV: "test", MCP_OPERATOR_INTERFACE_ENABLED: "true", MCP_OPERATOR_REMOTE_ENABLED: "true", MCP_PUBLIC_URL: "https://api.example.test" + MCP_PATH, APP_URL: "https://app.example.test" };
const config = remoteConfig(env);
const metadata = { client_id: "https://client.example.test/oauth.json", client_name: "Operator assistant", redirect_uris: ["http://127.0.0.1:1234/callback", "https://client.example.test/callback"], grant_types: ["authorization_code", "refresh_token"] };
const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
const error = (code) => (value) => value.oauthCode === code;

test("remote access requires both flags and a safe public URL", () => {
  assert.equal(remoteConfig({}), null);
  assert.equal(remoteConfig({ ...env, MCP_OPERATOR_REMOTE_ENABLED: "false" }), null);
  assert.equal(remoteConfig({ ...env, MCP_OPERATOR_INTERFACE_ENABLED: "false" }), null);
  for (const url of ["http://api.example.test" + MCP_PATH, "https://user:pass@api.example.test" + MCP_PATH, env.MCP_PUBLIC_URL + "?token=x", "https://api.example.test/other"]) assert.throws(() => remoteConfig({ ...env, MCP_PUBLIC_URL: url }));
  assert.throws(() => remoteConfig({ ...env, MCP_ALLOWED_ORIGINS: "*" }));
  assert.throws(() => remoteConfig({ ...env, MCP_ALLOWED_ORIGINS: "https://client.example.test/path" }));
  assert.equal(remoteConfig({ ...env, APP_URL: undefined, FRONTEND_URL: env.APP_URL }).appUrl, env.APP_URL);
});

test("production HTTP is refused except an explicitly local qualification", () => {
  const local = { ...env, NODE_ENV: "production", MCP_PUBLIC_URL: "http://127.0.0.1:4000" + MCP_PATH, APP_URL: "http://127.0.0.1:5173" };
  assert.throws(() => remoteConfig(local));
  assert.ok(remoteConfig({ ...local, SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE: "true" }));
  assert.equal(remoteConfig({ ...env, MCP_CLIENT_REGISTRATION_MODE: "dynamic-only" }).clientMetadataEnabled, false);
});

test("redirect binding permits only the native loopback port to vary", () => {
  assert.equal(p.redirectMatches(metadata.redirect_uris, "http://127.0.0.1:2345/callback"), true);
  for (const uri of ["http://localhost:1234/callback", "http://127.0.0.1:2345/other", "https://client.example.test/other", "https://client.example.test.evil/callback"]) assert.equal(p.redirectMatches(metadata.redirect_uris, uri), false);
  for (const uri of ["javascript:alert(1)", "https://user:pass@example.test/cb", "http://example.test/cb", "https://example.test/cb#code", "https://example.test/cb?code=existing"]) assert.throws(() => p.validRedirect(uri));
});

test("client metadata rejects implicit, machine and secret-based grants", () => {
  assert.equal(p.clientMetadata(metadata, metadata.client_id).token_endpoint_auth_method, "none");
  for (const input of [{ ...metadata, grant_types: ["client_credentials"] }, { ...metadata, response_types: ["token"] }, { ...metadata, token_endpoint_auth_method: "client_secret_basic" }, { ...metadata, client_id: "https://other.example.test/meta.json" }, { ...metadata, client_name: p.ACCESS.generate() }]) assert.throws(() => p.clientMetadata(input, metadata.client_id));
});

test("authorization requires S256, the exact resource and a registered redirect", () => {
  const request = { response_type: "code", redirect_uri: metadata.redirect_uris[1], code_challenge_method: "S256", code_challenge: challenge, resource: config.resource, scope: "mcp:connect", state: "opaque-client-state" };
  assert.equal(p.validateAuthorize(request, metadata, config).challenge, challenge);
  for (const patch of [{ code_challenge_method: "plain" }, { resource: "https://other.example.test" + MCP_PATH }, { redirect_uri: "https://evil.example.test/cb" }, { scope: "mcp:renew:request" }, { response_type: "token" }]) assert.throws(() => p.validateAuthorize({ ...request, ...patch }, metadata, config));
  assert.equal(p.validVerifier(verifier, challenge), true);
  assert.equal(p.validVerifier("a".repeat(43), challenge), false);
  assert.equal(p.validVerifier("short", challenge), false);
});

test("callback preserves state and identifies this issuer without exposing the verifier", () => {
  const callback = new URL(p.callbackUrl({ redirect_uri: metadata.redirect_uris[1], state: "value with spaces & punctuation" }, config, { code: p.CODE.generate() }));
  assert.equal(callback.searchParams.get("iss"), config.issuer);
  assert.equal(callback.searchParams.get("state"), "value with spaces & punctuation");
  assert.equal(callback.searchParams.has("code_verifier"), false);
});

function mockRequest(body, { status = 200, contentType = "application/json", pinned } = {}) {
  return (_url, options, callback) => {
    if (pinned) options.lookup("client.example.test", {}, (_err, address, family) => pinned(address, family));
    const req = new EventEmitter();
    req.end = () => queueMicrotask(() => { const res = Readable.from([Buffer.from(body)]); res.statusCode = status; res.headers = { "content-type": contentType }; callback(res); });
    req.destroy = (err) => {
      if (req.destroyed) return req;
      req.destroyed = true;
      queueMicrotask(() => {
        if (err) req.emit("error", err);
        req.emit("close");
      });
      return req;
    };
    options.signal.addEventListener("abort", () => req.destroy(new Error("aborted")), { once: true });
    return req;
  };
}
const publicDns = async () => [{ address: "93.184.216.34", family: 4 }];

test("metadata fetch rejects private, mixed and mapped addresses before connecting", async () => {
  for (const records of [[{ address: "127.0.0.1", family: 4 }], [{ address: "93.184.216.34", family: 4 }, { address: "10.0.0.1", family: 4 }], [{ address: "::ffff:127.0.0.1", family: 6 }]]) {
    await assert.rejects(p.fetchClientMetadata(metadata.client_id, { lookup: async () => records, request: () => assert.fail("must not connect") }), error("invalid_client"));
  }
});

test("metadata fetch pins the validated address and validates client identity", async () => {
  let pin;
  const result = await p.fetchClientMetadata(metadata.client_id, { lookup: publicDns, request: mockRequest(JSON.stringify(metadata), { pinned: (address, family) => { pin = [address, family]; } }) });
  assert.deepEqual(pin, ["93.184.216.34", 4]);
  assert.equal(result.client_name, metadata.client_name);
  await assert.rejects(p.fetchClientMetadata(metadata.client_id, { lookup: publicDns, request: mockRequest(JSON.stringify({ ...metadata, client_id: "https://evil.example.test/meta.json" })) }), error("invalid_client_metadata"));
});

test("metadata redirects, non-JSON and oversized bodies are refused", async () => {
  for (const options of [{ status: 302 }, { contentType: "text/html" }]) await assert.rejects(p.fetchClientMetadata(metadata.client_id, { lookup: publicDns, request: mockRequest("{}", options) }), error("invalid_client"));
  await assert.rejects(p.fetchClientMetadata(metadata.client_id, { lookup: publicDns, request: mockRequest("x".repeat(65537)) }), error("invalid_client"));
  await assert.rejects(p.fetchClientMetadata(metadata.client_id, { timeoutMs: 10, lookup: () => new Promise(() => {}) }), error("invalid_client"));
});

for (const [label, status, contentType] of [["redirect", 302, "application/json"], ["non-JSON", 200, "text/html"]]) {
  test(`metadata fetch closes streaming ${label} responses before releasing capacity`, async () => {
    const transports = [];
    let responsesReady;
    const allResponses = new Promise((resolve) => { responsesReady = resolve; });
    let responses = 0;
    const request = (_url, options, callback) => {
      const req = new EventEmitter();
      const res = new Readable({ read() {} });
      res.statusCode = status;
      res.headers = { "content-type": contentType };
      // This body never ends on its own, unlike the finite metadata fixtures.
      const stream = setInterval(() => res.push(Buffer.alloc(256)), 1);
      res.once("close", () => clearInterval(stream));
      req.destroy = (err) => {
        if (req.destroyed) return req;
        req.destroyed = true;
        res.destroy();
        if (err) queueMicrotask(() => req.emit("error", err));
        return req;
      };
      req.end = () => queueMicrotask(() => {
        callback(res);
        if (++responses === 8) responsesReady();
      });
      options.signal.addEventListener("abort", () => req.destroy(new Error("aborted")), { once: true });
      // Hold the asynchronous close event so capacity cannot be released just
      // because destroy() was called while the transport is still closing.
      transports.push({ req, res, close: () => req.emit("close") });
      return req;
    };
    const completed = Promise.allSettled(Array.from({ length: 8 }, () => p.fetchClientMetadata(metadata.client_id, { lookup: publicDns, request })));
    let settled = false;
    completed.then(() => { settled = true; });
    let results;
    try {
      await allResponses;
      await new Promise(setImmediate);
      for (const { req, res } of transports) {
        assert.equal(res.destroyed, true, "the refused body must stop streaming");
        assert.equal(req.destroyed, true, "the refused request must be destroyed");
      }
      assert.equal(settled, false, "fetches must wait for their transports to close");
      await assert.rejects(p.fetchClientMetadata(metadata.client_id, { lookup: () => assert.fail("closing transports still occupy all eight slots") }), error("temporarily_unavailable"));
    } finally {
      for (const { req, close } of transports) { req.destroy(); close(); }
      results = await completed;
    }
    assert.ok(results.every((result) => result.status === "rejected" && result.reason.oauthCode === "invalid_client"));
    // Once close has completed, the slot is available for a valid response.
    assert.equal((await p.fetchClientMetadata(metadata.client_id, { lookup: publicDns, request: mockRequest(JSON.stringify(metadata)) })).client_name, metadata.client_name);
  });
}

test("only an intact, recent same-process forwarding proof changes the rate key", () => {
  const token = p.ACCESS.generate(), id = crypto.randomUUID(), path = "/api/v1/operator/jobs";
  const headers = { authorization: `Bearer ${token}`, ...forwardingHeaders(token, id)({ method: "GET", path }) };
  const req = { headers, method: "GET", originalUrl: path + "?limit=25" };
  assert.equal(remoteRateKey(req), `mcp-${id}`);
  assert.equal(remoteRateKey({ ...req, method: "POST" }), null);
  assert.equal(remoteRateKey({ ...req, originalUrl: path + "/other" }), null);
  assert.equal(remoteRateKey({ ...req, headers: { ...headers, authorization: `Bearer ${p.ACCESS.generate()}` } }), null);
  const now = Date.now;
  try { Date.now = () => now() + 6000; assert.equal(remoteRateKey(req), null); } finally { Date.now = now; }
});

test("CSRF exemptions cover OAuth proof routes, never consent or cookie requests", () => {
  const req = { method: "POST", headers: {} };
  for (const path of [MCP_PATH, "/api/v1/mcp/oauth/token", "/api/v1/mcp/oauth/register", "/api/v1/mcp/oauth/revoke"]) {
    assert.equal(isOperatorBearerCsrfExemptRequest(path, req), true);
    assert.equal(isOperatorBearerCsrfExemptRequest(path, { ...req, headers: { cookie: "sessionId=example" } }), false);
  }
  assert.equal(isOperatorBearerCsrfExemptRequest("/api/v1/mcp/oauth/requests/id/decision", req), false);
  assert.equal(isOperatorBearerCsrfExemptRequest("/api/v1/mcp/oauth/token/extra", req), false);
});

test("new credentials, verifier fields and encoded OAuth query keys are scrubbed", () => {
  for (const family of [p.ACCESS, p.REFRESH, p.CODE]) {
    const token = family.generate();
    assert.equal(scrubLogString("opaque " + token).includes(token), false);
  }
  assert.equal(redactSensitiveFields({ code_verifier: verifier }).code_verifier.includes(verifier), false);
  const cleaned = scrubLogString("https://client.example.test/cb?%73tate=private-state&code_verifier=" + verifier);
  assert.equal(cleaned.includes(verifier), false);
  assert.equal(cleaned.includes("private-state"), false);
  assert.equal(redactSensitiveFields({ code: "OPERATOR_SCOPE_DENIED" }).code, "OPERATOR_SCOPE_DENIED");
});
