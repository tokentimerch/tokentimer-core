"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createDnsSolver } = require("../index.js");
const { validateCredentials } = require("./acme-dns.js");

const CREDENTIALS = {
  baseUrl: "https://acmedns.example.net",
  username: "user-uuid",
  password: "api-key-SECRET",
  subdomain: "subdomain-uuid",
};

const CHALLENGE = {
  zone: "example.com",
  recordName: "_acme-challenge.example.com",
  txtValue: "token-value",
};

function makeFetchStub(respond) {
  const calls = [];
  async function fetchStub(url, options) {
    calls.push({ url, options });
    const { status = 200, body = "{}" } = respond(url, options) || {};
    return { status, text: async () => body };
  }
  fetchStub.calls = calls;
  return fetchStub;
}

// ---------------------------------------------------------------------------
// credential validation
// ---------------------------------------------------------------------------

test("acme-dns: every credential field is required", () => {
  for (const field of ["baseUrl", "username", "password", "subdomain"]) {
    const broken = { ...CREDENTIALS };
    delete broken[field];
    assert.throws(() => validateCredentials(broken), new RegExp(field));
  }
});

test("acme-dns: a non-URL baseUrl throws at construction", () => {
  assert.throws(
    () => validateCredentials({ ...CREDENTIALS, baseUrl: "not a url" }),
    /not a valid URL/,
  );
});

test("acme-dns: a baseUrl with embedded credentials throws at construction", () => {
  assert.throws(
    () => validateCredentials({ ...CREDENTIALS, baseUrl: "https://user:pass@acmedns.example.net" }),
    /embed credentials/,
  );
});

test("acme-dns: a baseUrl with a hash fragment throws at construction", () => {
  assert.throws(
    () => validateCredentials({ ...CREDENTIALS, baseUrl: "https://acmedns.example.net#frag" }),
    /hash fragment/,
  );
});

test("acme-dns: a plain-http non-local baseUrl throws at construction", () => {
  assert.throws(
    () => validateCredentials({ ...CREDENTIALS, baseUrl: "http://acmedns.example.net" }),
    /https/,
  );
  // Even with the escape hatch, a non-loopback http host is rejected.
  assert.throws(
    () =>
      validateCredentials({
        ...CREDENTIALS,
        baseUrl: "http://acmedns.example.net",
        allowInsecureLocalHttp: true,
      }),
    /loopback/,
  );
});

test("acme-dns: http://127.0.0.1 is accepted with allowInsecureLocalHttp", () => {
  const normalized = validateCredentials({
    ...CREDENTIALS,
    baseUrl: "http://127.0.0.1:8053",
    allowInsecureLocalHttp: true,
  });
  assert.equal(normalized.baseUrl, "http://127.0.0.1:8053");
});

test("acme-dns: a trailing slash on baseUrl is normalized away", () => {
  const normalized = validateCredentials({
    ...CREDENTIALS,
    baseUrl: "https://acmedns.example.net/",
  });
  assert.equal(normalized.baseUrl, "https://acmedns.example.net");
});

// ---------------------------------------------------------------------------
// present
// ---------------------------------------------------------------------------

test("acme-dns: present POSTs /update with the api headers and body", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: '{"txt":"token-value"}' }));
  const solver = createDnsSolver({
    provider: "acme-dns",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 1);
  const call = fetchStub.calls[0];
  assert.equal(call.url, "https://acmedns.example.net/update");
  assert.equal(call.options.method, "POST");
  assert.equal(call.options.headers["X-Api-User"], "user-uuid");
  assert.equal(call.options.headers["X-Api-Key"], "api-key-SECRET");
  assert.deepEqual(JSON.parse(call.options.body), {
    subdomain: "subdomain-uuid",
    txt: "token-value",
  });
});

test("acme-dns: HTTP error maps to ok:false with statusCode", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 401, body: '{"error":"unauthorized"}' }));
  const solver = createDnsSolver({
    provider: "acme-dns",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 401);
  assert.match(result.detail, /HTTP 401/);
});

test("acme-dns: error body echoing the api key is redacted wholesale", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 401,
    body: 'key api-key-SECRET was rejected',
  }));
  const solver = createDnsSolver({
    provider: "acme-dns",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);
  assert.equal(result.detail, "[redacted]");
});

// ---------------------------------------------------------------------------
// cleanup (documented no-op)
// ---------------------------------------------------------------------------

test("acme-dns: cleanup is a no-op success and performs no fetch", async () => {
  const fetchStub = makeFetchStub(() => ({}));
  const solver = createDnsSolver({
    provider: "acme-dns",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.deepEqual(result, { provider: "acme-dns", ok: true });
  assert.equal(fetchStub.calls.length, 0);
});

test("acme-dns: declares cleanupVerifiable: false", () => {
  const { capabilities } = require("./acme-dns.js");
  assert.equal(capabilities.cleanupVerifiable, false);

  const solver = createDnsSolver({
    provider: "acme-dns",
    credentials: CREDENTIALS,
    fetchImpl: makeFetchStub(() => ({})),
  });
  assert.equal(solver.capabilities.cleanupVerifiable, false);
});
