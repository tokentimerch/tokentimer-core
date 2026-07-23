"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createDnsSolver } = require("../index.js");
const { validateCredentials, API_BASE_URL } = require("./hetzner.js");

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
  return createDnsSolver({ provider: "hetzner", credentials, fetchImpl });
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

// ---------------------------------------------------------------------------
// present
// ---------------------------------------------------------------------------

test("hetzner: present with configured zoneId POSTs the TXT record directly", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: '{"record":{"id":"r1"}}' }));
  const solver = solverWith(fetchStub, { apiToken: "hetzner-token", zoneId: "zone123" });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 1);
  const call = fetchStub.calls[0];
  assert.equal(call.url, `${API_BASE_URL}/records`);
  assert.equal(call.options.method, "POST");
  assert.equal(call.options.headers["Auth-API-Token"], "hetzner-token");
  assert.deepEqual(JSON.parse(call.options.body), {
    zone_id: "zone123",
    type: "TXT",
    name: "_acme-challenge",
    value: CHALLENGE.txtValue,
    ttl: 60,
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
    return { status: 200, body: '{"record":{"id":"r1"}}' };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 2);
  assert.equal(fetchStub.calls[0].url, `${API_BASE_URL}/zones?name=example.com`);
  assert.equal(
    JSON.parse(fetchStub.calls[1].options.body).zone_id,
    "looked-up-zone",
  );
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

test("hetzner: apex record name maps to @", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200 }));
  const solver = solverWith(fetchStub, { apiToken: "hetzner-token", zoneId: "zone123" });

  const result = await solver.presentChallenge({
    zone: "example.com",
    recordName: "example.com",
    txtValue: "v",
  });

  assert.equal(result.ok, true);
  assert.equal(JSON.parse(fetchStub.calls[0].options.body).name, "@");
});

test("hetzner: HTTP error on create maps to ok:false with statusCode", async () => {
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
// cleanup
// ---------------------------------------------------------------------------

test("hetzner: cleanup lists zone records and DELETEs the exact match only", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return {
        status: 200,
        body: JSON.stringify({
          records: [
            { id: "keep-1", type: "TXT", name: "_acme-challenge", value: "other-value" },
            { id: "keep-2", type: "A", name: "_acme-challenge", value: "token-value" },
            { id: "del-1", type: "TXT", name: "_acme-challenge", value: "token-value" },
          ],
        }),
      };
    }
    return { status: 200, body: "{}" };
  });
  const solver = solverWith(fetchStub, { apiToken: "hetzner-token", zoneId: "zone123" });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 2);
  assert.match(fetchStub.calls[0].url, /\/records\?zone_id=zone123$/);
  assert.equal(fetchStub.calls[1].options.method, "DELETE");
  assert.match(fetchStub.calls[1].url, /\/records\/del-1$/);
});

test("hetzner: cleanup of an already-absent record is idempotent success", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: '{"records":[]}' }));
  const solver = solverWith(fetchStub, { apiToken: "hetzner-token", zoneId: "zone123" });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 1);
});

test("hetzner: a 404 on record delete is idempotent success", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return {
        status: 200,
        body: '{"records":[{"id":"gone","type":"TXT","name":"_acme-challenge","value":"token-value"}]}',
      };
    }
    return { status: 404, body: '{"error":{"message":"record not found"}}' };
  });
  const solver = solverWith(fetchStub, { apiToken: "hetzner-token", zoneId: "zone123" });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
});

test("hetzner: failing DELETE maps to ok:false", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return {
        status: 200,
        body: '{"records":[{"id":"del-1","type":"TXT","name":"_acme-challenge","value":"token-value"}]}',
      };
    }
    return { status: 500, body: "server error" };
  });
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
