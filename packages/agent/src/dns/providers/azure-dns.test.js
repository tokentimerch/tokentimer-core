"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createDnsSolver } = require("../index.js");
const { validateCredentials, LOGIN_BASE_URL, MANAGEMENT_BASE_URL } = require("./azure-dns.js");

const CREDENTIALS = {
  tenantId: "tenant-1",
  clientId: "client-1",
  clientSecret: "client-secret-SECRET",
  subscriptionId: "sub-1",
  resourceGroup: "rg-dns",
};

const CHALLENGE = {
  zone: "example.com",
  recordName: "_acme-challenge.www.example.com",
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

function tokenResponder(rest) {
  return (url, options) => {
    if (url.startsWith(LOGIN_BASE_URL)) {
      return { status: 200, body: '{"access_token":"azure-access-token"}' };
    }
    return rest(url, options);
  };
}

function solverWith(fetchImpl) {
  return createDnsSolver({
    provider: "azure-dns",
    credentials: CREDENTIALS,
    fetchImpl,
  });
}

// ---------------------------------------------------------------------------
// credential validation
// ---------------------------------------------------------------------------

test("azure-dns: every credential field is required", () => {
  for (const field of ["tenantId", "clientId", "clientSecret", "subscriptionId", "resourceGroup"]) {
    const broken = { ...CREDENTIALS };
    delete broken[field];
    assert.throws(() => validateCredentials(broken), new RegExp(field));
  }
});

// ---------------------------------------------------------------------------
// present
// ---------------------------------------------------------------------------

test("azure-dns: present fetches a token then PUTs the relative TXT record", async () => {
  const fetchStub = makeFetchStub(tokenResponder(() => ({ status: 201, body: "{}" })));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 2);

  const tokenCall = fetchStub.calls[0];
  assert.equal(tokenCall.url, `${LOGIN_BASE_URL}/tenant-1/oauth2/v2.0/token`);
  assert.match(tokenCall.options.body, /grant_type=client_credentials/);
  assert.match(tokenCall.options.body, /client_id=client-1/);

  const putCall = fetchStub.calls[1];
  assert.equal(
    putCall.url,
    `${MANAGEMENT_BASE_URL}/subscriptions/sub-1/resourceGroups/rg-dns` +
      "/providers/Microsoft.Network/dnsZones/example.com" +
      "/TXT/_acme-challenge.www?api-version=2018-05-01",
  );
  assert.equal(putCall.options.method, "PUT");
  assert.equal(putCall.options.headers.Authorization, "Bearer azure-access-token");
  assert.deepEqual(JSON.parse(putCall.options.body), {
    properties: { TTL: 60, TXTRecords: [{ value: ["token-value"] }] },
  });
});

test("azure-dns: a record at the zone apex uses the @ relative name", async () => {
  const fetchStub = makeFetchStub(tokenResponder(() => ({ status: 200, body: "{}" })));
  const solver = solverWith(fetchStub);

  await solver.presentChallenge({
    zone: "_acme-challenge.example.com",
    recordName: "_acme-challenge.example.com",
    txtValue: "v",
  });

  assert.match(fetchStub.calls[1].url, /\/TXT\/%40\?api-version/);
});

test("azure-dns: token failure maps to ok:false and skips the record call", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 401,
    body: '{"error":"invalid_client"}',
  }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 401);
  assert.equal(fetchStub.calls.length, 1);
});

test("azure-dns: a token response with no access_token maps to ok:false", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: '{"nope":true}' }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.match(result.detail, /no access_token/);
});

test("azure-dns: HTTP error on PUT maps to ok:false with statusCode", async () => {
  const fetchStub = makeFetchStub(
    tokenResponder(() => ({ status: 403, body: '{"error":"authorization failed"}' })),
  );
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 403);
  assert.match(result.detail, /HTTP 403/);
});

// ---------------------------------------------------------------------------
// cleanup
// ---------------------------------------------------------------------------

test("azure-dns: cleanup DELETEs the record set", async () => {
  const fetchStub = makeFetchStub(tokenResponder(() => ({ status: 200, body: "" })));
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls[1].options.method, "DELETE");
});

test("azure-dns: a 404 on delete is idempotent success", async () => {
  const fetchStub = makeFetchStub(tokenResponder(() => ({ status: 404, body: "" })));
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
});

// ---------------------------------------------------------------------------
// redaction
// ---------------------------------------------------------------------------

test("azure-dns: error body echoing the clientSecret is redacted wholesale", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 400,
    body: 'bad secret client-secret-SECRET rejected',
  }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);
  assert.equal(result.detail, "[redacted]");
});
