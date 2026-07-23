"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  createDnsSolver,
  listSupportedDnsProviders,
  OUTPUT_EXCERPT_MAX_CHARS,
} = require("./index.js");

const CLOUDFLARE_CREDENTIALS = { apiToken: "cf-token-SECRET", zoneId: "zone123" };

/**
 * fetch stub factory: records calls and answers each one from `respond`
 * (a function of (url, options) returning { status, body }).
 */
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

function cloudflareSolver(fetchImpl, credentials = CLOUDFLARE_CREDENTIALS) {
  return createDnsSolver({ provider: "cloudflare", credentials, fetchImpl });
}

const CHALLENGE = {
  zone: "example.com",
  recordName: "_acme-challenge.www.example.com",
  txtValue: "token-value",
};

// ---------------------------------------------------------------------------
// listSupportedDnsProviders
// ---------------------------------------------------------------------------

test("listSupportedDnsProviders returns the six wave-1 provider ids", () => {
  assert.deepEqual(listSupportedDnsProviders(), [
    "cloudflare",
    "route53",
    "azure-dns",
    "google-cloud-dns",
    "rfc2136",
    "acme-dns",
  ]);
});

test("listSupportedDnsProviders returns a fresh copy each call", () => {
  const first = listSupportedDnsProviders();
  first.push("mutated");
  assert.equal(listSupportedDnsProviders().includes("mutated"), false);
});

// ---------------------------------------------------------------------------
// createDnsSolver construction validation (fail loud)
// ---------------------------------------------------------------------------

test("createDnsSolver throws on an unsupported provider", () => {
  assert.throws(
    () => createDnsSolver({ provider: "namecheap", credentials: {} }),
    /unsupported provider/,
  );
});

test("createDnsSolver throws on a missing provider", () => {
  assert.throws(() => createDnsSolver({ credentials: {} }), /non-empty provider/);
});

test("createDnsSolver throws on non-object credentials", () => {
  assert.throws(
    () => createDnsSolver({ provider: "cloudflare", credentials: "token" }),
    /credentials must be an object/,
  );
  assert.throws(
    () => createDnsSolver({ provider: "cloudflare", credentials: null }),
    /credentials must be an object/,
  );
});

test("createDnsSolver throws on malformed credentials (fail loud at construction)", () => {
  assert.throws(
    () => createDnsSolver({ provider: "cloudflare", credentials: {} }),
    /apiToken/,
  );
});

test("createDnsSolver throws on a non-positive timeoutMs", () => {
  assert.throws(
    () =>
      createDnsSolver({
        provider: "cloudflare",
        credentials: CLOUDFLARE_CREDENTIALS,
        timeoutMs: 0,
      }),
    /timeoutMs/,
  );
});

test("createDnsSolver throws on a non-function dnsUpdateImpl", () => {
  assert.throws(
    () =>
      createDnsSolver({
        provider: "cloudflare",
        credentials: CLOUDFLARE_CREDENTIALS,
        dnsUpdateImpl: "not-a-function",
      }),
    /dnsUpdateImpl/,
  );
});

// ---------------------------------------------------------------------------
// challenge input validation (programmer error => throws)
// ---------------------------------------------------------------------------

test("presentChallenge throws on missing zone/recordName/txtValue", async () => {
  const solver = cloudflareSolver(makeFetchStub(() => ({})));
  await assert.rejects(
    solver.presentChallenge({ recordName: "_acme-challenge.example.com", txtValue: "v" }),
    /zone must be a non-empty string/,
  );
  await assert.rejects(
    solver.presentChallenge({ zone: "example.com", txtValue: "v" }),
    /recordName must be a non-empty string/,
  );
  await assert.rejects(
    solver.presentChallenge({ zone: "example.com", recordName: "_acme-challenge.example.com" }),
    /txtValue must be a non-empty string/,
  );
});

test("recordName outside the zone throws (dot-boundary rule)", async () => {
  const fetchStub = makeFetchStub(() => ({}));
  const solver = cloudflareSolver(fetchStub);

  // evilexample.com must NOT match zone example.com (naive endsWith would).
  await assert.rejects(
    solver.presentChallenge({
      zone: "example.com",
      recordName: "_acme-challenge.evilexample.com",
      txtValue: "v",
    }),
    /is not within zone/,
  );
  assert.equal(fetchStub.calls.length, 0);
});

test("recordName equal to the zone is accepted", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: "{}" }));
  const solver = cloudflareSolver(fetchStub);
  const result = await solver.presentChallenge({
    zone: "_acme-challenge.example.com",
    recordName: "_acme-challenge.example.com",
    txtValue: "v",
  });
  assert.equal(result.ok, true);
});

test("cleanupChallenge validates inputs the same way as presentChallenge", async () => {
  const solver = cloudflareSolver(makeFetchStub(() => ({})));
  await assert.rejects(
    solver.cleanupChallenge({
      zone: "example.com",
      recordName: "_acme-challenge.other.org",
      txtValue: "v",
    }),
    /is not within zone/,
  );
});

// ---------------------------------------------------------------------------
// operational failure contract: never throw, always { ok:false }
// ---------------------------------------------------------------------------

test("a throwing fetch maps to ok:false with the provider id, never a throw", async () => {
  const solver = createDnsSolver({
    provider: "cloudflare",
    credentials: CLOUDFLARE_CREDENTIALS,
    fetchImpl: async () => {
      throw new Error("ECONNREFUSED 1.2.3.4:443");
    },
  });

  const result = await solver.presentChallenge(CHALLENGE);
  assert.equal(result.ok, false);
  assert.equal(result.provider, "cloudflare");
  assert.match(result.detail, /ECONNREFUSED/);
});

test("results carry the provider id on success too", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: "{}" }));
  const solver = cloudflareSolver(fetchStub);
  const result = await solver.presentChallenge(CHALLENGE);
  assert.deepEqual(result, { provider: "cloudflare", ok: true });
});

// ---------------------------------------------------------------------------
// excerpt bounding and credential redaction
// ---------------------------------------------------------------------------

test("HTTP error details are bounded to the documented maximum", async () => {
  const longBody = "x".repeat(OUTPUT_EXCERPT_MAX_CHARS + 500);
  const fetchStub = makeFetchStub(() => ({ status: 500, body: longBody }));
  const solver = cloudflareSolver(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);
  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 500);
  assert.ok(result.detail.length <= OUTPUT_EXCERPT_MAX_CHARS);
});

test("a response echoing the credential is redacted wholesale", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 403,
    body: `{"error":"invalid token cf-token-SECRET supplied"}`,
  }));
  const solver = cloudflareSolver(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);
  assert.equal(result.ok, false);
  assert.equal(result.detail, "[redacted]");
});

test("a response containing a PRIVATE KEY marker is redacted wholesale", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 500,
    body: "-----BEGIN RSA PRIVATE KEY-----\nnot-real\n",
  }));
  const solver = cloudflareSolver(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);
  assert.equal(result.detail, "[redacted]");
});

test("a credential echoed past the excerpt window still triggers redaction", async () => {
  const body = "y".repeat(OUTPUT_EXCERPT_MAX_CHARS + 10) + " cf-token-SECRET";
  const fetchStub = makeFetchStub(() => ({ status: 500, body }));
  const solver = cloudflareSolver(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);
  assert.equal(result.detail, "[redacted]");
});
