"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createDnsSolver } = require("../index.js");
const {
  validateCredentials,
  signOvhRequest,
  DEFAULT_ENDPOINT,
} = require("./ovhcloud.js");

const CREDENTIALS = {
  applicationKey: "app-key",
  applicationSecret: "app-secret",
  consumerKey: "consumer-key",
};

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

function solverWith(fetchImpl, credentials = CREDENTIALS) {
  return createDnsSolver({ provider: "ovhcloud", credentials, fetchImpl });
}

// ---------------------------------------------------------------------------
// credential validation
// ---------------------------------------------------------------------------

test("ovhcloud: applicationKey, applicationSecret and consumerKey are required", () => {
  assert.throws(
    () => validateCredentials({ applicationSecret: "s", consumerKey: "c" }),
    /applicationKey/,
  );
  assert.throws(
    () => validateCredentials({ applicationKey: "a", consumerKey: "c" }),
    /applicationSecret/,
  );
  assert.throws(
    () => validateCredentials({ applicationKey: "a", applicationSecret: "s" }),
    /consumerKey/,
  );
});

test("ovhcloud: endpoint defaults to the EU API and trailing slashes are stripped", () => {
  assert.equal(validateCredentials(CREDENTIALS).endpoint, DEFAULT_ENDPOINT);
  assert.equal(
    validateCredentials({ ...CREDENTIALS, endpoint: "https://ca.api.ovh.com/1.0/" }).endpoint,
    "https://ca.api.ovh.com/1.0",
  );
});

// ---------------------------------------------------------------------------
// signature fixed vector (deterministic given timestamp)
// ---------------------------------------------------------------------------

test("ovhcloud: request signature matches the fixed vector", () => {
  const signature = signOvhRequest({
    applicationSecret: "app-secret",
    consumerKey: "consumer-key",
    method: "POST",
    url: "https://eu.api.ovh.com/1.0/domain/zone/example.com/record",
    body: '{"fieldType":"TXT"}',
    timestamp: 1767225600,
  });
  // SHA1 of "app-secret+consumer-key+POST+https://eu.api.ovh.com/1.0/domain/zone/example.com/record+{\"fieldType\":\"TXT\"}+1767225600"
  assert.equal(signature, "$1$eee7898dc253b3f58e1efd88f0ae537fc7144fd7");
});

// ---------------------------------------------------------------------------
// present
// ---------------------------------------------------------------------------

test("ovhcloud: present POSTs the TXT record then refreshes the zone", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: '{"id":42}' }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 2);

  const create = fetchStub.calls[0];
  assert.equal(create.url, `${DEFAULT_ENDPOINT}/domain/zone/example.com/record`);
  assert.equal(create.options.method, "POST");
  assert.deepEqual(JSON.parse(create.options.body), {
    fieldType: "TXT",
    subDomain: "_acme-challenge",
    target: CHALLENGE.txtValue,
    ttl: 60,
  });

  const refresh = fetchStub.calls[1];
  assert.equal(refresh.url, `${DEFAULT_ENDPOINT}/domain/zone/example.com/refresh`);
  assert.equal(refresh.options.method, "POST");
});

test("ovhcloud: signed headers carry application, consumer, timestamp and signature", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200 }));
  const solver = solverWith(fetchStub);

  await solver.presentChallenge(CHALLENGE);

  const headers = fetchStub.calls[0].options.headers;
  assert.equal(headers["X-Ovh-Application"], "app-key");
  assert.equal(headers["X-Ovh-Consumer"], "consumer-key");
  assert.match(headers["X-Ovh-Timestamp"], /^\d+$/);
  assert.match(headers["X-Ovh-Signature"], /^\$1\$[0-9a-f]{40}$/);

  // The signature must be reproducible from the sent request parts.
  const call = fetchStub.calls[0];
  assert.equal(
    headers["X-Ovh-Signature"],
    signOvhRequest({
      applicationSecret: "app-secret",
      consumerKey: "consumer-key",
      method: "POST",
      url: call.url,
      body: call.options.body,
      timestamp: Number(headers["X-Ovh-Timestamp"]),
    }),
  );
});

test("ovhcloud: a custom endpoint override is used for every call", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200 }));
  const solver = solverWith(fetchStub, {
    ...CREDENTIALS,
    endpoint: "https://us.api.ovhcloud.com/1.0",
  });

  await solver.presentChallenge(CHALLENGE);

  assert.match(fetchStub.calls[0].url, /^https:\/\/us\.api\.ovhcloud\.com\/1\.0\//);
});

test("ovhcloud: HTTP error on create maps to ok:false with statusCode", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 403,
    body: '{"message":"This credential is not valid"}',
  }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 403);
  assert.match(result.detail, /HTTP 403/);
});

test("ovhcloud: a failing zone refresh after create maps to ok:false", async () => {
  const fetchStub = makeFetchStub((url) => {
    if (url.endsWith("/refresh")) {
      return { status: 500, body: '{"message":"refresh failed"}' };
    }
    return { status: 200, body: '{"id":42}' };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 500);
  assert.match(result.detail, /zone refresh/);
});

// ---------------------------------------------------------------------------
// cleanup
// ---------------------------------------------------------------------------

test("ovhcloud: cleanup deletes only the record whose target matches, then refreshes", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET" && url.includes("?fieldType=TXT")) {
      return { status: 200, body: "[11,22]" };
    }
    if (options.method === "GET" && url.endsWith("/record/11")) {
      return { status: 200, body: '{"id":11,"target":"other-value"}' };
    }
    if (options.method === "GET" && url.endsWith("/record/22")) {
      return { status: 200, body: '{"id":22,"target":"token-value"}' };
    }
    return { status: 200, body: "null" };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  const listUrl = fetchStub.calls[0].url;
  assert.match(listUrl, /\/domain\/zone\/example\.com\/record\?fieldType=TXT&subDomain=_acme-challenge$/);

  const deletes = fetchStub.calls.filter((call) => call.options.method === "DELETE");
  assert.equal(deletes.length, 1);
  assert.match(deletes[0].url, /\/record\/22$/);

  const last = fetchStub.calls[fetchStub.calls.length - 1];
  assert.match(last.url, /\/refresh$/);
});

test("ovhcloud: cleanup of an already-absent record is idempotent success (no refresh)", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: "[]" }));
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 1);
});

test("ovhcloud: a 404 on record delete is idempotent success", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET" && url.includes("?fieldType=TXT")) {
      return { status: 200, body: "[11]" };
    }
    if (options.method === "GET") {
      return { status: 200, body: '{"id":11,"target":"token-value"}' };
    }
    if (options.method === "DELETE") {
      return { status: 404, body: '{"message":"not found"}' };
    }
    return { status: 200, body: "null" };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
});

test("ovhcloud: failing DELETE maps to ok:false", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET" && url.includes("?fieldType=TXT")) {
      return { status: 200, body: "[11]" };
    }
    if (options.method === "GET") {
      return { status: 200, body: '{"id":11,"target":"token-value"}' };
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

test("ovhcloud: error body echoing the applicationSecret is redacted wholesale", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 400,
    body: 'invalid signature computed from secret "app-secret"',
  }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.detail, "[redacted]");
});

test("ovhcloud: error body echoing the consumerKey is redacted wholesale", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 403,
    body: "consumer-key is not allowed on this route",
  }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.detail, "[redacted]");
});
