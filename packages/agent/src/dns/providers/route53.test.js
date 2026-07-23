"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createDnsSolver } = require("../index.js");
const {
  validateCredentials,
  signRequest,
  buildChangeBatchXml,
  quoteTxtValue,
  API_HOST,
} = require("./route53.js");

const CREDENTIALS = {
  accessKeyId: "AKIDEXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
  hostedZoneId: "Z123EXAMPLE",
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
    const { status = 200, body = "<ok/>" } = respond(url, options) || {};
    return { status, text: async () => body };
  }
  fetchStub.calls = calls;
  return fetchStub;
}

// ---------------------------------------------------------------------------
// credential validation
// ---------------------------------------------------------------------------

test("route53: accessKeyId and secretAccessKey are required", () => {
  assert.throws(() => validateCredentials({ secretAccessKey: "s" }), /accessKeyId/);
  assert.throws(() => validateCredentials({ accessKeyId: "a" }), /secretAccessKey/);
});

test("route53: region defaults to us-east-1 and /hostedzone/ prefix is stripped", () => {
  const normalized = validateCredentials({
    accessKeyId: "a",
    secretAccessKey: "s",
    hostedZoneId: "/hostedzone/Z42",
  });
  assert.equal(normalized.region, "us-east-1");
  assert.equal(normalized.hostedZoneId, "Z42");
});

// ---------------------------------------------------------------------------
// SigV4 fixed vector (deterministic given amzDate)
// ---------------------------------------------------------------------------

test("route53: SigV4 canonical request and signature match the fixed vector", () => {
  const { canonicalRequest, signature, headers } = signRequest({
    method: "POST",
    path: "/2013-04-01/hostedzone/Z123EXAMPLE/rrset",
    query: [],
    body: "<xml/>",
    amzDate: "20260101T000000Z",
    accessKeyId: "AKIDEXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    sessionToken: null,
    region: "us-east-1",
  });

  assert.equal(
    canonicalRequest,
    [
      "POST",
      "/2013-04-01/hostedzone/Z123EXAMPLE/rrset",
      "",
      "host:route53.amazonaws.com",
      "x-amz-date:20260101T000000Z",
      "",
      "host;x-amz-date",
      // sha256 of "<xml/>"
      "6eb820e0f9762c611c2a77189f686afeca64dfb212e023017e0346e7ab826c39",
    ].join("\n"),
  );
  assert.equal(
    signature,
    "4c722057e42432b0d0bd9e18d1572f7bb597f1ec5d385aa4d9f53a41b117aef0",
  );
  assert.equal(
    headers.Authorization,
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/us-east-1/route53/aws4_request, " +
      "SignedHeaders=host;x-amz-date, " +
      "Signature=4c722057e42432b0d0bd9e18d1572f7bb597f1ec5d385aa4d9f53a41b117aef0",
  );
});

test("route53: a sessionToken joins the signed headers", () => {
  const { canonicalRequest, headers } = signRequest({
    method: "GET",
    path: "/2013-04-01/hostedzonebyname",
    query: [["dnsname", "example.com"]],
    body: "",
    amzDate: "20260101T000000Z",
    accessKeyId: "AKIDEXAMPLE",
    secretAccessKey: "secret",
    sessionToken: "the-session-token",
    region: "us-east-1",
  });

  assert.match(canonicalRequest, /x-amz-security-token:the-session-token\n/);
  assert.match(canonicalRequest, /host;x-amz-date;x-amz-security-token/);
  assert.equal(headers["X-Amz-Security-Token"], "the-session-token");
});

// ---------------------------------------------------------------------------
// TXT quoting and change batch XML
// ---------------------------------------------------------------------------

test("route53: TXT values are double-quoted with backslash/quote escaping", () => {
  assert.equal(quoteTxtValue("plain"), '"plain"');
  assert.equal(quoteTxtValue('has"quote'), '"has\\"quote"');
  assert.equal(quoteTxtValue("has\\backslash"), '"has\\\\backslash"');
});

test("route53: change batch XML carries action, FQDN name, and quoted value", () => {
  const xml = buildChangeBatchXml("UPSERT", "_acme-challenge.example.com", "abc");
  assert.match(xml, /<Action>UPSERT<\/Action>/);
  assert.match(xml, /<Name>_acme-challenge\.example\.com\.<\/Name>/);
  assert.match(xml, /<Type>TXT<\/Type>/);
  assert.match(xml, /<Value>&quot;abc&quot;<\/Value>/);
});

// ---------------------------------------------------------------------------
// present / cleanup dispatch
// ---------------------------------------------------------------------------

test("route53: present UPSERTs via ChangeResourceRecordSets on the configured zone", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200 }));
  const solver = createDnsSolver({
    provider: "route53",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 1);
  const call = fetchStub.calls[0];
  assert.equal(call.url, `https://${API_HOST}/2013-04-01/hostedzone/Z123EXAMPLE/rrset`);
  assert.equal(call.options.method, "POST");
  assert.match(call.options.headers.Authorization, /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//);
  assert.match(call.options.body, /<Action>UPSERT<\/Action>/);
  assert.match(call.options.body, /&quot;token-value&quot;/);
});

test("route53: cleanup sends a DELETE change for the same rrset", async () => {
  const fetchStub = makeFetchStub(() => ({ status: 200 }));
  const solver = createDnsSolver({
    provider: "route53",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.match(fetchStub.calls[0].options.body, /<Action>DELETE<\/Action>/);
});

test("route53: hosted zone is looked up by name when hostedZoneId is absent", async () => {
  const fetchStub = makeFetchStub((url) => {
    if (url.includes("/hostedzonebyname")) {
      return {
        status: 200,
        body:
          "<ListHostedZonesByNameResponse><HostedZones><HostedZone>" +
          "<Id>/hostedzone/ZLOOKEDUP</Id><Name>example.com.</Name>" +
          "</HostedZone></HostedZones></ListHostedZonesByNameResponse>",
      };
    }
    return { status: 200 };
  });
  const solver = createDnsSolver({
    provider: "route53",
    credentials: { accessKeyId: "AKIDLOOKUP", secretAccessKey: "lookup-secret-key" },
    fetchImpl: fetchStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(fetchStub.calls.length, 2);
  assert.match(fetchStub.calls[0].url, /hostedzonebyname\?dnsname=example\.com&maxitems=1$/);
  assert.match(fetchStub.calls[1].url, /\/hostedzone\/ZLOOKEDUP\/rrset$/);
});

test("route53: a lookup returning a non-matching zone maps to ok:false", async () => {
  // ListHostedZonesByName returns the lexicographically NEXT zone when no
  // exact match exists; that must not be treated as a hit.
  const fetchStub = makeFetchStub(() => ({
    status: 200,
    body:
      "<ListHostedZonesByNameResponse><HostedZones><HostedZone>" +
      "<Id>/hostedzone/ZOTHER</Id><Name>example.org.</Name>" +
      "</HostedZone></HostedZones></ListHostedZonesByNameResponse>",
  }));
  const solver = createDnsSolver({
    provider: "route53",
    credentials: { accessKeyId: "AKIDLOOKUP", secretAccessKey: "lookup-secret-key" },
    fetchImpl: fetchStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.match(result.detail, /found no zone named/);
});

test("route53: HTTP error maps to ok:false with statusCode", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 400,
    body: "<ErrorResponse><Error><Code>InvalidChangeBatch</Code></Error></ErrorResponse>",
  }));
  const solver = createDnsSolver({
    provider: "route53",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.equal(result.statusCode, 400);
  assert.match(result.detail, /InvalidChangeBatch/);
});

test("route53: error body echoing the secret key is redacted wholesale", async () => {
  const fetchStub = makeFetchStub(() => ({
    status: 403,
    body: `SignatureDoesNotMatch for key wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`,
  }));
  const solver = createDnsSolver({
    provider: "route53",
    credentials: CREDENTIALS,
    fetchImpl: fetchStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);
  assert.equal(result.detail, "[redacted]");
});
