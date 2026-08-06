"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createDnsSolver } = require("../index.js");
const { validateCredentials } = require("./pebble-challtestsrv.js");

const CREDENTIALS = {
  baseUrl: "http://127.0.0.1:8055",
  allowInsecureLocalHttp: true,
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

test("pebble-challtestsrv: baseUrl is required", () => {
  assert.throws(() => validateCredentials({}), /baseUrl/);
});

test("pebble-challtestsrv: a non-URL baseUrl throws at construction", () => {
  assert.throws(
    () => validateCredentials({ baseUrl: "not a url" }),
    /not a valid URL/,
  );
});

test("pebble-challtestsrv: a plain-http non-local baseUrl throws even with the escape hatch", () => {
  assert.throws(
    () =>
      validateCredentials({
        baseUrl: "http://challtestsrv.example.net:8055",
        allowInsecureLocalHttp: true,
      }),
    /loopback/,
  );
});

test("pebble-challtestsrv: http://127.0.0.1 is accepted with allowInsecureLocalHttp", () => {
  const normalized = validateCredentials(CREDENTIALS);
  assert.equal(normalized.baseUrl, "http://127.0.0.1:8055");
});

test("pebble-challtestsrv: a trailing slash on baseUrl is normalized away", () => {
  const normalized = validateCredentials({
    ...CREDENTIALS,
    baseUrl: "http://127.0.0.1:8055/",
  });
  assert.equal(normalized.baseUrl, "http://127.0.0.1:8055");
});

// ---------------------------------------------------------------------------
// present
// ---------------------------------------------------------------------------

test("pebble-challtestsrv: present POSTs /set-txt with a dotted host and the value", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: "{}" }));
  const solver = createDnsSolver({
    provider: "pebble-challtestsrv",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 1);
  const call = fetchStub.calls[0];
  assert.equal(call.url, "http://127.0.0.1:8055/set-txt");
  assert.equal(call.options.method, "POST");
  assert.deepEqual(JSON.parse(call.options.body), {
    host: "_acme-challenge.example.com.",
    value: "token-value",
  });
});

test("pebble-challtestsrv: present does not double-append the trailing dot", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: "{}" }));
  const solver = createDnsSolver({
    provider: "pebble-challtestsrv",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  await solver.presentChallenge({
    zone: "example.com.",
    recordName: "_acme-challenge.example.com.",
    txtValue: "token-value",
  });

  assert.deepEqual(JSON.parse(fetchStub.calls[0].options.body), {
    host: "_acme-challenge.example.com.",
    value: "token-value",
  });
});

test("pebble-challtestsrv: HTTP error on present maps to ok:false with statusCode", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 500, body: "boom" }));
  const solver = createDnsSolver({
    provider: "pebble-challtestsrv",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 500);
  assert.match(result.detail, /HTTP 500/);
});

// ---------------------------------------------------------------------------
// cleanup
// ---------------------------------------------------------------------------

test("pebble-challtestsrv: cleanup POSTs /clear-txt with only the dotted host", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: "{}" }));
  const solver = createDnsSolver({
    provider: "pebble-challtestsrv",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 1);
  const call = fetchStub.calls[0];
  assert.equal(call.url, "http://127.0.0.1:8055/clear-txt");
  assert.deepEqual(JSON.parse(call.options.body), {
    host: "_acme-challenge.example.com.",
  });
});

test("pebble-challtestsrv: HTTP error on cleanup maps to ok:false with statusCode", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 404, body: "not found" }));
  const solver = createDnsSolver({
    provider: "pebble-challtestsrv",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 404);
  assert.match(result.detail, /HTTP 404/);
});

test("pebble-challtestsrv: declares cleanupVerifiable: true", () => {
  const { capabilities } = require("./pebble-challtestsrv.js");
  assert.equal(capabilities.cleanupVerifiable, true);

  const solver = createDnsSolver({
    provider: "pebble-challtestsrv",
    credentials: CREDENTIALS,
    fetchImpl: makeFetchStub(() => ({})),
  });
  assert.equal(solver.capabilities.cleanupVerifiable, true);
});
