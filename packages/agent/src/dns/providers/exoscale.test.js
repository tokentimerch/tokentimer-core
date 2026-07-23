"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createDnsSolver } = require("../index.js");
const {
  validateCredentials,
  signExoscaleRequest,
  DEFAULT_API_ENDPOINT,
} = require("./exoscale.js");

const CREDENTIALS = { apiKey: "EXOexample", apiSecret: "exo-secret" };

const CHALLENGE = {
  zone: "example.com",
  recordName: "_acme-challenge.example.com",
  txtValue: "token-value",
};

const DOMAIN_LIST_BODY = JSON.stringify({
  "dns-domains": [
    { id: "d0", "unicode-name": "other.org" },
    { id: "d1", "unicode-name": "example.com" },
  ],
});

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

function solverWith(fetchImpl, credentials = CREDENTIALS) {
  return createDnsSolver({ provider: "exoscale", credentials, fetchImpl });
}

// ---------------------------------------------------------------------------
// credential validation
// ---------------------------------------------------------------------------

test("exoscale: apiKey and apiSecret are required", () => {
  assert.throws(() => validateCredentials({ apiSecret: "s" }), /apiKey/);
  assert.throws(() => validateCredentials({ apiKey: "k" }), /apiSecret/);
});

test("exoscale: apiEndpoint defaults to ch-gva-2 and trailing slashes are stripped", () => {
  assert.equal(validateCredentials(CREDENTIALS).apiEndpoint, DEFAULT_API_ENDPOINT);
  assert.equal(
    validateCredentials({ ...CREDENTIALS, apiEndpoint: "https://api-de-fra-1.exoscale.com/v2/" }).apiEndpoint,
    "https://api-de-fra-1.exoscale.com/v2",
  );
});

// ---------------------------------------------------------------------------
// EXO2-HMAC-SHA256 fixed vectors (deterministic given expires)
// ---------------------------------------------------------------------------

test("exoscale: bodyless request signature matches the fixed vector", () => {
  const { message, signature, authorizationHeader } = signExoscaleRequest({
    apiKey: "EXOexample",
    apiSecret: "exo-secret",
    method: "GET",
    path: "/v2/dns-domain",
    body: "",
    expires: 1767226200,
  });

  assert.equal(message, "GET /v2/dns-domain\n\n\n\n1767226200");
  // base64(HMAC-SHA256("exo-secret", message))
  assert.equal(signature, "OF0CBDTW+FO/o5wT9j9K6+7gm0hcaW/RWZWAkzzHaEE=");
  assert.equal(
    authorizationHeader,
    "EXO2-HMAC-SHA256 credential=EXOexample,expires=1767226200," +
      "signature=OF0CBDTW+FO/o5wT9j9K6+7gm0hcaW/RWZWAkzzHaEE=",
  );
});

test("exoscale: request signature with a body matches the fixed vector", () => {
  const body = '{"name":"_acme-challenge","type":"TXT","content":"token-value","ttl":60}';
  const { signature } = signExoscaleRequest({
    apiKey: "EXOexample",
    apiSecret: "exo-secret",
    method: "POST",
    path: "/v2/dns-domain/d1/record",
    body,
    expires: 1767226200,
  });

  assert.equal(signature, "xwKtY8kd+r31ZM9/FMXvlwNlwQrnHFQoQXsfHknuXjU=");
});

// ---------------------------------------------------------------------------
// present
// ---------------------------------------------------------------------------

test("exoscale: present resolves the domain id then POSTs the TXT record", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return { status: 200, body: DOMAIN_LIST_BODY };
    }
    return { status: 200, body: '{"id":"op-1","state":"pending"}' };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 2);
  assert.equal(fetchStub.calls[0].url, `${DEFAULT_API_ENDPOINT}/dns-domain`);

  const create = fetchStub.calls[1];
  assert.equal(create.url, `${DEFAULT_API_ENDPOINT}/dns-domain/d1/record`);
  assert.equal(create.options.method, "POST");
  assert.deepEqual(JSON.parse(create.options.body), {
    name: "_acme-challenge",
    type: "TXT",
    content: CHALLENGE.txtValue,
    ttl: 60,
  });
});

test("exoscale: the Authorization header is a verifiable EXO2-HMAC-SHA256 signature", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: DOMAIN_LIST_BODY }));
  const solver = solverWith(fetchStub);

  await solver.presentChallenge(CHALLENGE);

  const header = fetchStub.calls[0].options.headers.Authorization;
  const match = /^EXO2-HMAC-SHA256 credential=EXOexample,expires=(\d+),signature=(.+)$/.exec(header);
  assert.ok(match, `unexpected Authorization header: ${header}`);

  // Recompute the signature from the sent request parts.
  const { signature } = signExoscaleRequest({
    apiKey: "EXOexample",
    apiSecret: "exo-secret",
    method: "GET",
    path: "/v2/dns-domain",
    body: "",
    expires: Number(match[1]),
  });
  assert.equal(match[2], signature);
});

test("exoscale: a domain lookup with no matching zone maps to ok:false", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 200,
    body: '{"dns-domains":[{"id":"d0","unicode-name":"other.org"}]}',
  }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.match(result.detail, /no domain named/);
});

test("exoscale: HTTP error on create maps to ok:false with statusCode", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return { status: 200, body: DOMAIN_LIST_BODY };
    }
    return { status: 403, body: '{"message":"forbidden"}' };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 403);
  assert.match(result.detail, /HTTP 403/);
});

test("exoscale: a custom apiEndpoint override is used for every call", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: DOMAIN_LIST_BODY }));
  const solver = solverWith(fetchStub, {
    ...CREDENTIALS,
    apiEndpoint: "https://api-de-fra-1.exoscale.com/v2",
  });

  await solver.presentChallenge(CHALLENGE);

  assert.match(fetchStub.calls[0].url, /^https:\/\/api-de-fra-1\.exoscale\.com\/v2\//);
});

// ---------------------------------------------------------------------------
// cleanup
// ---------------------------------------------------------------------------

test("exoscale: cleanup lists records and DELETEs the exact match only", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET" && url.endsWith("/dns-domain")) {
      return { status: 200, body: DOMAIN_LIST_BODY };
    }
    if (options.method === "GET") {
      return {
        status: 200,
        body: JSON.stringify({
          "dns-domain-records": [
            { id: "keep-1", type: "TXT", name: "_acme-challenge", content: '"other-value"' },
            { id: "keep-2", type: "A", name: "_acme-challenge", content: "1.2.3.4" },
            { id: "del-1", type: "TXT", name: "_acme-challenge", content: '"token-value"' },
          ],
        }),
      };
    }
    return { status: 200, body: '{"id":"op-2","state":"pending"}' };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  const deletes = fetchStub.calls.filter((call) => call.options.method === "DELETE");
  assert.equal(deletes.length, 1);
  assert.equal(deletes[0].url, `${DEFAULT_API_ENDPOINT}/dns-domain/d1/record/del-1`);
});

test("exoscale: cleanup of an already-absent record is idempotent success", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET" && url.endsWith("/dns-domain")) {
      return { status: 200, body: DOMAIN_LIST_BODY };
    }
    return { status: 200, body: '{"dns-domain-records":[]}' };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.filter((c) => c.options.method === "DELETE").length, 0);
});

test("exoscale: a 404 on record delete is idempotent success", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET" && url.endsWith("/dns-domain")) {
      return { status: 200, body: DOMAIN_LIST_BODY };
    }
    if (options.method === "GET") {
      return {
        status: 200,
        body: '{"dns-domain-records":[{"id":"gone","type":"TXT","name":"_acme-challenge","content":"token-value"}]}',
      };
    }
    return { status: 404, body: '{"message":"record not found"}' };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
});

test("exoscale: failing DELETE maps to ok:false", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET" && url.endsWith("/dns-domain")) {
      return { status: 200, body: DOMAIN_LIST_BODY };
    }
    if (options.method === "GET") {
      return {
        status: 200,
        body: '{"dns-domain-records":[{"id":"del-1","type":"TXT","name":"_acme-challenge","content":"token-value"}]}',
      };
    }
    return { status: 500, body: "server error" };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 500);
});

// ---------------------------------------------------------------------------
// redaction
// ---------------------------------------------------------------------------

test("exoscale: error body echoing the apiSecret is redacted wholesale", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 403,
    body: 'signature mismatch for secret "exo-secret"',
  }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.detail, "[redacted]");
});
