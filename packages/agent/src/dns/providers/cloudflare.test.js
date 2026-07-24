"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createDnsSolver } = require("../index.js");
const { validateCredentials, API_BASE_URL } = require("./cloudflare.js");

const CHALLENGE = {
  zone: "example.com",
  recordName: "_acme-challenge.example.com",
  txtValue: "token-value",
};

function makeFetchStub(respond) {
  const calls = [];
  async function fetchStub(url, options) {
    calls.push({ url, options });
    const { status = 200, body = "{}" } = respond(url, options, calls.length) || {};
    return { status, text: async () => body };
  }
  fetchStub.calls = calls;
  return fetchStub;
}

function solverWith(fetchImpl, credentials = { apiToken: "cf-token" }) {
  return createDnsSolver({ provider: "cloudflare", credentials, fetchImpl });
}

// ---------------------------------------------------------------------------
// credential validation
// ---------------------------------------------------------------------------

test("cloudflare: missing apiToken throws at construction", () => {
  assert.throws(() => validateCredentials({}), /apiToken/);
  assert.throws(() => validateCredentials({ apiToken: "" }), /apiToken/);
});

test("cloudflare: non-string zoneId throws at construction", () => {
  assert.throws(() => validateCredentials({ apiToken: "t", zoneId: 42 }), /zoneId/);
});

// ---------------------------------------------------------------------------
// present
// ---------------------------------------------------------------------------

test("cloudflare: present with configured zoneId POSTs the TXT record directly", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: '{"success":true}' }));
  const solver = solverWith(fetchStub, { apiToken: "cf-token", zoneId: "zone123" });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 1);
  const call = fetchStub.calls[0];
  assert.equal(call.url, `${API_BASE_URL}/zones/zone123/dns_records`);
  assert.equal(call.options.method, "POST");
  assert.equal(call.options.headers.Authorization, "Bearer cf-token");
  assert.deepEqual(JSON.parse(call.options.body), {
    type: "TXT",
    name: CHALLENGE.recordName,
    content: CHALLENGE.txtValue,
    ttl: 60,
  });
});

test("cloudflare: present without zoneId looks the zone up by name first", async () => {
  const fetchStub = makeFetchStub((url) => {
    if (url.includes("/zones?name=")) {
      return { status: 200, body: '{"result":[{"id":"looked-up-zone"}]}' };
    }
    return { status: 200, body: '{"success":true}' };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 2);
  assert.equal(
    fetchStub.calls[0].url,
    `${API_BASE_URL}/zones?name=example.com`,
  );
  assert.match(fetchStub.calls[1].url, /\/zones\/looked-up-zone\/dns_records$/);
});

test("cloudflare: zone lookup finding no zone maps to ok:false", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: '{"result":[]}' }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.match(result.detail, /no zone named/);
});

test("cloudflare: HTTP error on create maps to ok:false with statusCode", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 403,
    body: '{"errors":[{"message":"forbidden"}]}',
  }));
  const solver = solverWith(fetchStub, { apiToken: "cf-token", zoneId: "zone123" });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 403);
  assert.match(result.detail, /HTTP 403/);
  assert.match(result.detail, /forbidden/);
});

// ---------------------------------------------------------------------------
// cleanup
// ---------------------------------------------------------------------------

test("cloudflare: cleanup looks up the exact record and DELETEs it", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return { status: 200, body: '{"result":[{"id":"rec1"}]}' };
    }
    return { status: 200, body: '{"success":true}' };
  });
  const solver = solverWith(fetchStub, { apiToken: "cf-token", zoneId: "zone123" });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 2);
  const listUrl = fetchStub.calls[0].url;
  assert.match(listUrl, /type=TXT/);
  assert.match(listUrl, /name=_acme-challenge\.example\.com/);
  assert.match(listUrl, /content=token-value/);
  assert.equal(fetchStub.calls[1].options.method, "DELETE");
  assert.match(fetchStub.calls[1].url, /\/dns_records\/rec1$/);
});

test("cloudflare: cleanup of an already-absent record is idempotent success", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: '{"result":[]}' }));
  const solver = solverWith(fetchStub, { apiToken: "cf-token", zoneId: "zone123" });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 1);
});

test("cloudflare: failing DELETE maps to ok:false", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return { status: 200, body: '{"result":[{"id":"rec1"}]}' };
    }
    return { status: 500, body: "server error" };
  });
  const solver = solverWith(fetchStub, { apiToken: "cf-token", zoneId: "zone123" });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 500);
});

// ---------------------------------------------------------------------------
// redaction
// ---------------------------------------------------------------------------

test("cloudflare: error body echoing the apiToken is redacted wholesale", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 400,
    body: 'bad token "cf-token" rejected',
  }));
  const solver = solverWith(fetchStub, { apiToken: "cf-token", zoneId: "zone123" });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.detail, "[redacted]");
});
