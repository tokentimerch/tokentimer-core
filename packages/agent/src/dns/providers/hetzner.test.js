"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createDnsSolver } = require("../index.js");
const { validateCredentials, API_BASE_URL, quoteTxtValue } = require("./hetzner.js");

const CHALLENGE = {
  zone: "example.com",
  recordName: "_acme-challenge.example.com",
  txtValue: "token-value",
};

function makeFetchStub(respond) {
  const calls = [];
  function fetchStub(url, options) {
    calls.push({ url, options });
    const { status = 200, body = "{}" } = respond(url, options, calls.length) || {};
    return Promise.resolve({ status, text: () => Promise.resolve(body) });
  }
  fetchStub.calls = calls;
  return fetchStub;
}

function solverWith(fetchImpl, credentials = { apiToken: "hetzner-token" }) {
  return createDnsSolver({
    provider: "hetzner",
    credentials,
    fetchImpl,
    useFileLock: false,
  });
}

// ---------------------------------------------------------------------------
// credential validation
// ---------------------------------------------------------------------------

test("hetzner: missing apiToken throws at construction", () => {
  assert.throws(() => validateCredentials({}), /apiToken/);
  assert.throws(() => validateCredentials({ apiToken: "" }), /apiToken/);
});

test("hetzner: non-string zoneId throws at construction", () => {
  assert.throws(() => validateCredentials({ apiToken: "t", zoneId: 42 }), /zoneId/);
});

test("hetzner: quoteTxtValue double-quotes and escapes", () => {
  assert.equal(quoteTxtValue("abc"), '"abc"');
  assert.equal(quoteTxtValue('a"b'), '"a\\"b"');
});

// ---------------------------------------------------------------------------
// present (Cloud API add_records)
// ---------------------------------------------------------------------------

test("hetzner: present with configured zoneId POSTs add_records with Bearer auth", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 201, body: '{"action":{"id":1}}' }));
  const solver = solverWith(fetchStub, { apiToken: "hetzner-token", zoneId: "zone123" });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 1);
  const call = fetchStub.calls[0];
  assert.equal(
    call.url,
    `${API_BASE_URL}/zones/zone123/rrsets/_acme-challenge/TXT/actions/add_records`,
  );
  assert.equal(call.options.method, "POST");
  assert.equal(call.options.headers.Authorization, "Bearer hetzner-token");
  assert.deepEqual(JSON.parse(call.options.body), {
    ttl: 60,
    records: [{ value: '"token-value"' }],
  });
});

test("hetzner: present without zoneId looks the zone up by name first", async () => {
  const fetchStub = makeFetchStub((url) => {
    if (url.includes("/zones?name=")) {
      return {
        status: 200,
        body: '{"zones":[{"id":"looked-up-zone","name":"example.com"}]}',
      };
    }
    return { status: 201, body: '{"action":{"id":1}}' };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 2);
  assert.equal(fetchStub.calls[0].url, `${API_BASE_URL}/zones?name=example.com`);
  assert.match(fetchStub.calls[1].url, /\/zones\/looked-up-zone\/rrsets\//);
});

test("hetzner: a zone lookup returning a non-matching zone maps to ok:false", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 200,
    body: '{"zones":[{"id":"zother","name":"other.example.org"}]}',
  }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.match(result.detail, /no zone named/);
});

test("hetzner: apex record name maps to @ in the rrset path", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 201 }));
  const solver = solverWith(fetchStub, { apiToken: "hetzner-token", zoneId: "zone123" });

  const result = await solver.presentChallenge({
    zone: "example.com",
    recordName: "example.com",
    txtValue: "v",
  });

  assert.equal(result.ok, true);
  assert.match(fetchStub.calls[0].url, /\/rrsets\/%40\/TXT\/actions\/add_records$/);
});

test("hetzner: HTTP error on add_records maps to ok:false with statusCode", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 422,
    body: '{"error":{"message":"invalid record"}}',
  }));
  const solver = solverWith(fetchStub, { apiToken: "hetzner-token", zoneId: "zone123" });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 422);
  assert.match(result.detail, /HTTP 422/);
  assert.match(result.detail, /invalid record/);
});

// ---------------------------------------------------------------------------
// cleanup (Cloud API remove_records — value-specific)
// ---------------------------------------------------------------------------

test("hetzner: cleanup POSTs remove_records for the exact quoted value only", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 201, body: '{"action":{"id":2}}' }));
  const solver = solverWith(fetchStub, { apiToken: "hetzner-token", zoneId: "zone123" });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 1);
  assert.equal(
    fetchStub.calls[0].url,
    `${API_BASE_URL}/zones/zone123/rrsets/_acme-challenge/TXT/actions/remove_records`,
  );
  assert.equal(fetchStub.calls[0].options.method, "POST");
  assert.deepEqual(JSON.parse(fetchStub.calls[0].options.body), {
    records: [{ value: '"token-value"' }],
  });
});

test("hetzner: cleanup of an already-absent record (HTTP 404) is idempotent success", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 404,
    body: '{"error":{"message":"rrset not found"}}',
  }));
  const solver = solverWith(fetchStub, { apiToken: "hetzner-token", zoneId: "zone123" });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
});

test("hetzner: failing remove_records maps to ok:false", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 500, body: "server error" }));
  const solver = solverWith(fetchStub, { apiToken: "hetzner-token", zoneId: "zone123" });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 500);
});

// ---------------------------------------------------------------------------
// redaction
// ---------------------------------------------------------------------------

test("hetzner: error body echoing the apiToken is redacted wholesale", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 401,
    body: 'invalid token "hetzner-token" supplied',
  }));
  const solver = solverWith(fetchStub, { apiToken: "hetzner-token", zoneId: "zone123" });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.detail, "[redacted]");
});

test("hetzner: API_BASE_URL points at the Cloud Console API", () => {
  assert.equal(API_BASE_URL, "https://api.hetzner.cloud/v1");
});

// ---------------------------------------------------------------------------
// listManagedZones (pagination)
// ---------------------------------------------------------------------------

test("hetzner: listManagedZones follows meta.pagination.next_page across multiple pages", async () => {
  const { listManagedZones } = require("./hetzner.js");
  const pages = {
    1: {
      zones: [{ name: "a.example.com." }, { name: "b.example.com" }],
      meta: { pagination: { page: 1, next_page: 2 } },
    },
    2: {
      zones: [{ name: "c.example.com" }],
      meta: { pagination: { page: 2, next_page: null } },
    },
  };
  const fetchStub = makeFetchStub((url) => {
    const match = /[?&]page=(\d+)/.exec(url);
    const page = match ? Number(match[1]) : 1;
    return { status: 200, body: JSON.stringify(pages[page]) };
  });

  const zones = await listManagedZones({
    credentials: { apiToken: "hetzner-token" },
    fetchImpl: fetchStub,
    timeoutMs: 5000,
  });

  assert.deepEqual(zones, ["a.example.com", "b.example.com", "c.example.com"]);
  assert.equal(fetchStub.calls.length, 2, "must fetch both pages, not stop at the first");
});

test("hetzner: listManagedZones stops when next_page is absent (single page, backward compatible)", async () => {
  const { listManagedZones } = require("./hetzner.js");
  const fetchStub = makeFetchStub(() => ({
    status: 200,
    body: '{"zones":[{"name":"only.example.com"}]}',
  }));

  const zones = await listManagedZones({
    credentials: { apiToken: "hetzner-token" },
    fetchImpl: fetchStub,
    timeoutMs: 5000,
  });

  assert.deepEqual(zones, ["only.example.com"]);
  assert.equal(fetchStub.calls.length, 1);
});

test("hetzner: listManagedZones request URLs carry page and per_page params", async () => {
  const { listManagedZones } = require("./hetzner.js");
  const fetchStub = makeFetchStub(() => ({ status: 200, body: '{"zones":[]}' }));

  await listManagedZones({
    credentials: { apiToken: "hetzner-token" },
    fetchImpl: fetchStub,
    timeoutMs: 5000,
  });

  assert.match(fetchStub.calls[0].url, /\/zones\?page=1&per_page=50$/);
});

