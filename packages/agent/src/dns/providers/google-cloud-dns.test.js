"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const { createDnsSolver } = require("../index.js");
const {
  validateCredentials,
  buildServiceAccountJwt,
  TOKEN_URL,
  API_BASE_URL,
} = require("./google-cloud-dns.js");

// One real (throwaway) RSA keypair for the whole file: the JWT must be
// RS256-signed with an actual key for the signature-verification test.
const { publicKey: TEST_PUBLIC_KEY, privateKey: TEST_PRIVATE_KEY } =
  crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const TEST_PRIVATE_KEY_PEM = TEST_PRIVATE_KEY.export({
  type: "pkcs8",
  format: "pem",
});

const CREDENTIALS = {
  client_email: "sa@project-1.iam.gserviceaccount.com",
  private_key: TEST_PRIVATE_KEY_PEM,
  project_id: "project-1",
  managedZone: "example-zone",
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

function tokenResponder(rest) {
  return (url, options) => {
    if (url === TOKEN_URL) {
      return { status: 200, body: '{"access_token":"gcp-access-token"}' };
    }
    return rest(url, options);
  };
}

// ---------------------------------------------------------------------------
// credential validation
// ---------------------------------------------------------------------------

test("google-cloud-dns: client_email, private_key, project_id are required", () => {
  for (const field of ["client_email", "private_key", "project_id"]) {
    const broken = { ...CREDENTIALS };
    delete broken[field];
    assert.throws(() => validateCredentials(broken), new RegExp(field));
  }
});

test("google-cloud-dns: a private_key that is not PEM key material throws", () => {
  assert.throws(
    () => validateCredentials({ ...CREDENTIALS, private_key: "not-a-key" }),
    /PEM private key/,
  );
});

// ---------------------------------------------------------------------------
// service-account JWT
// ---------------------------------------------------------------------------

test("google-cloud-dns: the assertion JWT is RS256-signed and carries the SA claims", () => {
  const nowEpochSeconds = 1700000000;
  const jwt = buildServiceAccountJwt(
    { client_email: CREDENTIALS.client_email, private_key: TEST_PRIVATE_KEY_PEM },
    nowEpochSeconds,
  );

  const [headerB64, claimsB64, signatureB64] = jwt.split(".");
  assert.deepEqual(JSON.parse(Buffer.from(headerB64, "base64url").toString()), {
    alg: "RS256",
    typ: "JWT",
  });
  const claims = JSON.parse(Buffer.from(claimsB64, "base64url").toString());
  assert.equal(claims.iss, CREDENTIALS.client_email);
  assert.equal(claims.aud, TOKEN_URL);
  assert.equal(claims.iat, nowEpochSeconds);
  assert.equal(claims.exp, nowEpochSeconds + 300);
  assert.match(claims.scope, /ndev\.clouddns\.readwrite/);

  // Signature must verify against the matching public key: the key is used
  // locally to sign and never leaves the host.
  const verified = crypto.verify(
    "RSA-SHA256",
    Buffer.from(`${headerB64}.${claimsB64}`),
    TEST_PUBLIC_KEY,
    Buffer.from(signatureB64, "base64url"),
  );
  assert.equal(verified, true);
});

// ---------------------------------------------------------------------------
// present / cleanup
// ---------------------------------------------------------------------------

test("google-cloud-dns: present exchanges the JWT then POSTs an additions change", async () => {
  const fetchStub = makeFetchStub(
    tokenResponder((url, options) => {
      if (options.method === "GET") {
        return { status: 200, body: '{"rrsets":[]}' };
      }
      return { status: 200, body: "{}" };
    }),
  );
  const solver = createDnsSolver({
    provider: "google-cloud-dns",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 3);

  const tokenCall = fetchStub.calls[0];
  assert.equal(tokenCall.url, TOKEN_URL);
  assert.match(tokenCall.options.body, /grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer/);
  assert.match(tokenCall.options.body, /assertion=/);

  const rrsetCall = fetchStub.calls[1];
  assert.match(
    rrsetCall.url,
    /\/managedZones\/example-zone\/rrsets\?name=_acme-challenge\.example\.com\.&type=TXT$/,
  );
  assert.equal(rrsetCall.options.method, "GET");

  const changeCall = fetchStub.calls[2];
  assert.equal(
    changeCall.url,
    `${API_BASE_URL}/projects/project-1/managedZones/example-zone/changes`,
  );
  assert.equal(changeCall.options.headers.Authorization, "Bearer gcp-access-token");
  assert.deepEqual(JSON.parse(changeCall.options.body), {
    additions: [
      {
        name: "_acme-challenge.example.com.",
        type: "TXT",
        ttl: 60,
        rrdatas: ['"token-value"'],
      },
    ],
  });
});

test("google-cloud-dns: present merges with pre-existing rrdatas (deletions + additions)", async () => {
  const existingRrset = {
    name: "_acme-challenge.example.com.",
    type: "TXT",
    ttl: 120,
    rrdatas: ['"sibling-value"'],
  };
  const fetchStub = makeFetchStub(
    tokenResponder((url, options) => {
      if (options.method === "GET") {
        return { status: 200, body: JSON.stringify({ rrsets: [existingRrset] }) };
      }
      return { status: 200, body: "{}" };
    }),
  );
  const solver = createDnsSolver({
    provider: "google-cloud-dns",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.deepEqual(JSON.parse(fetchStub.calls[2].options.body), {
    deletions: [existingRrset],
    additions: [
      {
        name: "_acme-challenge.example.com.",
        type: "TXT",
        ttl: 120,
        rrdatas: ['"sibling-value"', '"token-value"'],
      },
    ],
  });
});

test("google-cloud-dns: cleanup removes only the challenge value and keeps siblings", async () => {
  const existingRrset = {
    name: "_acme-challenge.example.com.",
    type: "TXT",
    ttl: 60,
    rrdatas: ['"sibling-value"', '"token-value"'],
  };
  const fetchStub = makeFetchStub(
    tokenResponder((url, options) => {
      if (options.method === "GET") {
        return { status: 200, body: JSON.stringify({ rrsets: [existingRrset] }) };
      }
      return { status: 200, body: "{}" };
    }),
  );
  const solver = createDnsSolver({
    provider: "google-cloud-dns",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.deepEqual(JSON.parse(fetchStub.calls[2].options.body), {
    deletions: [existingRrset],
    additions: [
      {
        name: "_acme-challenge.example.com.",
        type: "TXT",
        ttl: 60,
        rrdatas: ['"sibling-value"'],
      },
    ],
  });
});

test("google-cloud-dns: cleanup of the last value deletes the rrset outright", async () => {
  const existingRrset = {
    name: "_acme-challenge.example.com.",
    type: "TXT",
    ttl: 60,
    rrdatas: ['"token-value"'],
  };
  const fetchStub = makeFetchStub(
    tokenResponder((url, options) => {
      if (options.method === "GET") {
        return { status: 200, body: JSON.stringify({ rrsets: [existingRrset] }) };
      }
      return { status: 200, body: "{}" };
    }),
  );
  const solver = createDnsSolver({
    provider: "google-cloud-dns",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  const body = JSON.parse(fetchStub.calls[2].options.body);
  assert.deepEqual(body, { deletions: [existingRrset] });
});

test("google-cloud-dns: cleanup of an already-absent value is idempotent success", async () => {
  const fetchStub = makeFetchStub(
    tokenResponder((url, options) => {
      if (options.method === "GET") {
        return { status: 200, body: '{"rrsets":[]}' };
      }
      return { status: 500, body: "should never be called" };
    }),
  );
  const solver = createDnsSolver({
    provider: "google-cloud-dns",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 2);
});

test("google-cloud-dns: the managed zone is looked up by dnsName when absent", async () => {
  const fetchStub = makeFetchStub(
    tokenResponder((url, options) => {
      if (url.includes("/managedZones?dnsName=")) {
        return { status: 200, body: '{"managedZones":[{"name":"looked-up-zone"}]}' };
      }
      if (options.method === "GET") {
        return { status: 200, body: '{"rrsets":[]}' };
      }
      return { status: 200, body: "{}" };
    }),
  );
  const solver = createDnsSolver({
    provider: "google-cloud-dns",
    credentials: { ...CREDENTIALS, managedZone: undefined },
    fetchImpl: fetchStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 4);
  assert.match(fetchStub.calls[1].url, /managedZones\?dnsName=example\.com\.$/);
  assert.match(fetchStub.calls[2].url, /\/managedZones\/looked-up-zone\/rrsets\?/);
  assert.match(fetchStub.calls[3].url, /\/managedZones\/looked-up-zone\/changes$/);
});

test("google-cloud-dns: an empty managed zone lookup maps to ok:false", async () => {
  const fetchStub = makeFetchStub(
    tokenResponder(() => ({ status: 200, body: '{"managedZones":[]}' })),
  );
  const solver = createDnsSolver({
    provider: "google-cloud-dns",
    credentials: { ...CREDENTIALS, managedZone: undefined },
    fetchImpl: fetchStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.match(result.detail, /found no zone/);
});

test("google-cloud-dns: token failure maps to ok:false and stops the flow", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 401, body: '{"error":"invalid_grant"}' }));
  const solver = createDnsSolver({
    provider: "google-cloud-dns",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 401);
  assert.equal(fetchStub.calls.length, 1);
});

test("google-cloud-dns: an error body echoing key material is redacted wholesale", async () => {
  // Any PRIVATE KEY marker in a response body redacts the whole excerpt.
  const fetchStub = makeFetchStub(() => ({
    status: 400,
    body: "error near -----BEGIN PRIVATE KEY----- input",
  }));
  const solver = createDnsSolver({
    provider: "google-cloud-dns",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);
  assert.equal(result.detail, "[redacted]");
});
