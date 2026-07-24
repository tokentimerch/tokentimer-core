"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createDnsSolver } = require("../index.js");
const {
  validateCredentials,
  quoteTxtValue,
  toCanonicalFqdn,
} = require("./powerdns.js");

const CREDENTIALS = {
  apiUrl: "http://127.0.0.1:8081",
  apiKey: "pdns-key",
  allowInsecureLocalHttp: true,
};

const CHALLENGE = {
  zone: "example.com",
  recordName: "_acme-challenge.example.com",
  txtValue: "token-value",
};

const ZONE_URL = "http://127.0.0.1:8081/api/v1/servers/localhost/zones/example.com.";

function zoneBody(rrsets) {
  return JSON.stringify({ name: "example.com.", rrsets });
}

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
  return createDnsSolver({ provider: "powerdns", credentials, fetchImpl });
}

// ---------------------------------------------------------------------------
// credential validation and helpers
// ---------------------------------------------------------------------------

test("powerdns: apiUrl and apiKey are required", () => {
  assert.throws(() => validateCredentials({ apiKey: "k" }), /apiUrl/);
  assert.throws(() => validateCredentials({ apiUrl: "http://x" }), /apiKey/);
});

test("powerdns: apiUrl is validated (https only, no creds/fragments, loopback http opt-in)", () => {
  assert.throws(
    () => validateCredentials({ apiUrl: "https://u:p@pdns.example:8081", apiKey: "k" }),
    /embed credentials/,
  );
  assert.throws(
    () => validateCredentials({ apiUrl: "https://pdns.example:8081#frag", apiKey: "k" }),
    /hash fragment/,
  );
  // Plain http without the loopback escape hatch is rejected...
  assert.throws(
    () => validateCredentials({ apiUrl: "http://127.0.0.1:8081", apiKey: "k" }),
    /https/,
  );
  // ...and even with it, only loopback hosts qualify.
  assert.throws(
    () =>
      validateCredentials({
        apiUrl: "http://pdns.example:8081",
        apiKey: "k",
        allowInsecureLocalHttp: true,
      }),
    /loopback/,
  );
  // https always works; loopback http works with the flag.
  assert.equal(
    validateCredentials({ apiUrl: "https://pdns.example:8081", apiKey: "k" }).apiUrl,
    "https://pdns.example:8081",
  );
  assert.equal(validateCredentials(CREDENTIALS).apiUrl, "http://127.0.0.1:8081");
});

test("powerdns: serverId defaults to localhost and trailing slashes are stripped", () => {
  const normalized = validateCredentials({
    apiUrl: "http://127.0.0.1:8081/",
    apiKey: "k",
    allowInsecureLocalHttp: true,
  });
  assert.equal(normalized.serverId, "localhost");
  assert.equal(normalized.apiUrl, "http://127.0.0.1:8081");
});

test("powerdns: TXT values are double-quoted with backslash/quote escaping", () => {
  assert.equal(quoteTxtValue("plain"), '"plain"');
  assert.equal(quoteTxtValue('has"quote'), '"has\\"quote"');
  assert.equal(quoteTxtValue("has\\backslash"), '"has\\\\backslash"');
});

test("powerdns: canonical FQDNs are lowercased with exactly one trailing dot", () => {
  assert.equal(toCanonicalFqdn("Example.COM"), "example.com.");
  assert.equal(toCanonicalFqdn("example.com."), "example.com.");
});

// ---------------------------------------------------------------------------
// present
// ---------------------------------------------------------------------------

test("powerdns: present on an empty name REPLACEs with the single quoted value", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return { status: 200, body: zoneBody([]) };
    }
    return { status: 204, body: "" };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 2);
  assert.equal(fetchStub.calls[0].url, ZONE_URL);
  assert.equal(fetchStub.calls[0].options.headers["X-API-Key"], "pdns-key");

  const patch = fetchStub.calls[1];
  assert.equal(patch.url, ZONE_URL);
  assert.equal(patch.options.method, "PATCH");
  assert.deepEqual(JSON.parse(patch.options.body), {
    rrsets: [
      {
        name: "_acme-challenge.example.com.",
        type: "TXT",
        ttl: 60,
        changetype: "REPLACE",
        records: [{ content: '"token-value"', disabled: false }],
      },
    ],
  });
});

test("powerdns: present merges with existing TXT records at the same name", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return {
        status: 200,
        body: zoneBody([
          {
            name: "_acme-challenge.example.com.",
            type: "TXT",
            ttl: 60,
            records: [{ content: '"sibling-value"', disabled: false }],
          },
          {
            name: "example.com.",
            type: "SOA",
            ttl: 3600,
            records: [{ content: "ns1.example.com. hostmaster.example.com. 1 2 3 4 5", disabled: false }],
          },
        ]),
      };
    }
    return { status: 204, body: "" };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  const rrset = JSON.parse(fetchStub.calls[1].options.body).rrsets[0];
  assert.equal(rrset.changetype, "REPLACE");
  assert.deepEqual(rrset.records, [
    { content: '"sibling-value"', disabled: false },
    { content: '"token-value"', disabled: false },
  ]);
});

test("powerdns: present is idempotent when the value is already in the rrset", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return {
        status: 200,
        body: zoneBody([
          {
            name: "_acme-challenge.example.com.",
            type: "TXT",
            ttl: 60,
            records: [{ content: '"token-value"', disabled: false }],
          },
        ]),
      };
    }
    return { status: 204, body: "" };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  const rrset = JSON.parse(fetchStub.calls[1].options.body).rrsets[0];
  assert.deepEqual(rrset.records, [{ content: '"token-value"', disabled: false }]);
});

test("powerdns: a custom serverId is used in the zone URL", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return { status: 200, body: zoneBody([]) };
    }
    return { status: 204, body: "" };
  });
  const solver = solverWith(fetchStub, { ...CREDENTIALS, serverId: "pdns-2" });

  await solver.presentChallenge(CHALLENGE);

  assert.match(fetchStub.calls[0].url, /\/api\/v1\/servers\/pdns-2\/zones\/example\.com\.$/);
});

test("powerdns: HTTP error on zone read maps to ok:false with statusCode", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 404,
    body: '{"error":"Not Found"}',
  }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 404);
  assert.match(result.detail, /zone read/);
});

test("powerdns: HTTP error on PATCH maps to ok:false with statusCode", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return { status: 200, body: zoneBody([]) };
    }
    return { status: 422, body: '{"error":"RRset content invalid"}' };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 422);
  assert.match(result.detail, /HTTP 422/);
});

// ---------------------------------------------------------------------------
// cleanup
// ---------------------------------------------------------------------------

test("powerdns: cleanup with remaining siblings REPLACEs with the leftovers", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return {
        status: 200,
        body: zoneBody([
          {
            name: "_acme-challenge.example.com.",
            type: "TXT",
            ttl: 60,
            records: [
              { content: '"sibling-value"', disabled: false },
              { content: '"token-value"', disabled: false },
            ],
          },
        ]),
      };
    }
    return { status: 204, body: "" };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  const rrset = JSON.parse(fetchStub.calls[1].options.body).rrsets[0];
  assert.equal(rrset.changetype, "REPLACE");
  assert.deepEqual(rrset.records, [{ content: '"sibling-value"', disabled: false }]);
});

test("powerdns: cleanup of the last value sends changetype DELETE", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return {
        status: 200,
        body: zoneBody([
          {
            name: "_acme-challenge.example.com.",
            type: "TXT",
            ttl: 60,
            records: [{ content: '"token-value"', disabled: false }],
          },
        ]),
      };
    }
    return { status: 204, body: "" };
  });
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  const rrset = JSON.parse(fetchStub.calls[1].options.body).rrsets[0];
  assert.deepEqual(rrset, {
    name: "_acme-challenge.example.com.",
    type: "TXT",
    changetype: "DELETE",
    records: [],
  });
});

test("powerdns: cleanup of an already-absent value is idempotent success", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200, body: zoneBody([]) }));
  const solver = solverWith(fetchStub);

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 1);
});

test("powerdns: failing PATCH on cleanup maps to ok:false", async () => {
  const fetchStub = makeFetchStub((url, options) => {
    if (options.method === "GET") {
      return {
        status: 200,
        body: zoneBody([
          {
            name: "_acme-challenge.example.com.",
            type: "TXT",
            ttl: 60,
            records: [{ content: '"token-value"', disabled: false }],
          },
        ]),
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

test("powerdns: error body echoing the apiKey is redacted wholesale", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 401,
    body: 'wrong key "pdns-key" supplied',
  }));
  const solver = solverWith(fetchStub);

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.detail, "[redacted]");
});
