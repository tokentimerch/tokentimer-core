"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createDnsSolver } = require("../index.js");
const { validateCredentials, API_BASE_URL } = require("./infomaniak.js");

const CHALLENGE = {
  zone: "example.com",
  recordName: "_acme-challenge.example.com",
  txtValue: "token-value",
};

function makeFetchStub(respond) {
  const calls = [];
  function fetchStub(url, options) {
    calls.push({ url, options });
    const { status = 200, body = '{"result":"success","data":null}' } =
      respond(url, options, calls.length) || {};
    return Promise.resolve({ status, text: () => Promise.resolve(body) });
  }
  fetchStub.calls = calls;
  return fetchStub;
}

function solverWith(fetchImpl, credentials = { apiToken: "infomaniak-token" }) {
  return createDnsSolver({ provider: "infomaniak", credentials, fetchImpl });
}

// ---------------------------------------------------------------------------
// credential validation
// ---------------------------------------------------------------------------

test("infomaniak: missing apiToken throws at construction", () => {
  assert.throws(() => validateCredentials({}), /apiToken/);
  assert.throws(() => validateCredentials({ apiToken: "" }), /apiToken/);
});

// ---------------------------------------------------------------------------
// present
// ---------------------------------------------------------------------------

test("infomaniak: present POSTs the TXT record with a relative source and Bearer auth", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 200,
    body: '{"result":"success","data":{"id":77}}',
  }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 1);
  const call = fetchStub.calls[0];
  assert.equal(call.url, `${API_BASE_URL}/2/zones/example.com/records`);
  assert.equal(call.options.method, "POST");
  assert.equal(call.options.headers.Authorization, "Bearer infomaniak-token");
  assert.deepEqual(JSON.parse(call.options.body), {
    type: "TXT",
    source: "_acme-challenge",
    target: CHALLENGE.txtValue,
    ttl: 60,
  });
});

test("infomaniak: apex record source maps to .", async () => {
  const fetchStub = makeFetchStub(() => ({}));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge({
    zone: "example.com",
    recordName: "example.com",
    txtValue: "v",
  });

  assert.equal(result.ok, true);
  assert.equal(JSON.parse(fetchStub.calls[0].options.body).source, ".");
});

test("infomaniak: an error envelope on HTTP 200 maps to ok:false", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 200,
    body: '{"result":"error","error":{"code":"not_authorized"}}',
  }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 200);
  assert.match(result.detail, /non-success envelope/);
  assert.match(result.detail, /not_authorized/);
});

test("infomaniak: HTTP error maps to ok:false with statusCode", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 422,
    body: '{"result":"error","error":{"code":"invalid_record"}}',
  }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 422);
  assert.match(result.detail, /HTTP 422/);
});

// ---------------------------------------------------------------------------
// cleanup
// ---------------------------------------------------------------------------

test("infomaniak: cleanup lists zone records and DELETEs the exact match only", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return {
        status: 200,
        body: JSON.stringify({
          result: "success",
          data: [
            { id: 1, type: "TXT", source: "_acme-challenge", target: "other-value" },
            { id: 2, type: "A", source: "_acme-challenge", target: "token-value" },
            { id: 3, type: "TXT", source: "_acme-challenge", target: "token-value" },
          ],
        }),
      };
    }
    return { status: 200, body: '{"result":"success","data":true}' };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 2);
  assert.equal(fetchStub.calls[0].url, `${API_BASE_URL}/2/zones/example.com/records`);
  assert.equal(fetchStub.calls[1].options.method, "DELETE");
  assert.match(fetchStub.calls[1].url, /\/2\/zones\/example\.com\/records\/3$/);
});

test("infomaniak: cleanup matches a quoted TXT target (API wire representation) and still deletes it", async () => {
  // Regression: Infomaniak's record lookup can return TXT targets quoted
  // (e.g. `"token-value"`); an exact unquoted comparison would find no
  // match, silently no-op, and orphan the challenge record forever.
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return {
        status: 200,
        body: JSON.stringify({
          result: "success",
          data: [
            { id: 7, type: "TXT", source: "_acme-challenge", target: '"token-value"' },
          ],
        }),
      };
    }
    return { status: 200, body: '{"result":"success","data":true}' };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 2);
  assert.equal(fetchStub.calls[1].options.method, "DELETE");
  assert.match(fetchStub.calls[1].url, /\/2\/zones\/example\.com\/records\/7$/);
});

test("infomaniak: cleanup of an already-absent record is idempotent success", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 200,
    body: '{"result":"success","data":[]}',
  }));
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 1);
});

test("infomaniak: a 404 on record delete is idempotent success", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return {
        status: 200,
        body: '{"result":"success","data":[{"id":9,"type":"TXT","source":"_acme-challenge","target":"token-value"}]}',
      };
    }
    return { status: 404, body: '{"result":"error","error":{"code":"not_found"}}' };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
});

test("infomaniak: an error envelope on delete maps to ok:false", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return {
        status: 200,
        body: '{"result":"success","data":[{"id":9,"type":"TXT","source":"_acme-challenge","target":"token-value"}]}',
      };
    }
    return { status: 200, body: '{"result":"error","error":{"code":"locked"}}' };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.match(result.detail, /non-success envelope/);
});

// ---------------------------------------------------------------------------
// redaction
// ---------------------------------------------------------------------------

test("infomaniak: error body echoing the apiToken is redacted wholesale", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 401,
    body: 'invalid token "infomaniak-token" supplied',
  }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.detail, "[redacted]");
});
