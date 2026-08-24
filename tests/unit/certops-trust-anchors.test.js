"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_TRUST_ANCHOR_INVALID,
  CERTOPS_TRUST_ANCHOR_PEM_INVALID,
  CERTOPS_TRUST_JOB_IDEMPOTENCY_KEY_REQUIRED,
  ANCHOR_TYPES,
  parseAndValidateAnchorPem,
  normalizeStore,
  normalizeOwner,
  normalizeAgentId,
  normalizeIdempotencyKey,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/trustAnchors.js"),
);

// Both certs below carry an explicit Basic Constraints extension (unlike
// tests/unit/certops-parser.test.js's own fixtures, which do not set
// basicConstraints CA at all and therefore both parse as ca:true under
// Node's X509Certificate -- unsuitable for testing the CA=true/false split
// this validator actually enforces). Generated once via
// `openssl req -x509 -newkey rsa:2048 -nodes ... -addext basicConstraints=critical,CA:{TRUE,FALSE}`;
// PUBLIC_CA_CERT has CA:TRUE, PUBLIC_LEAF_CERT has CA:FALSE.
const PUBLIC_CA_CERT = `-----BEGIN CERTIFICATE-----
MIIDWzCCAkOgAwIBAgIUO4M9RDQQe4qvDSkq7b3BRphLb2YwDQYJKoZIhvcNAQEL
BQAwPTEhMB8GA1UEAwwYVG9rZW5UaW1lciBUZXN0IFRydXN0IENBMRgwFgYDVQQK
DA9Ub2tlblRpbWVyIFRlc3QwHhcNMjYwODI0MTEzMjA5WhcNMzYwODIxMTEzMjA5
WjA9MSEwHwYDVQQDDBhUb2tlblRpbWVyIFRlc3QgVHJ1c3QgQ0ExGDAWBgNVBAoM
D1Rva2VuVGltZXIgVGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AMKlo0teFGLPsvWNXs0U1mNys9WcIexHMCaLnS2Gx9j3G29/O8QqGrYWEgWjMyKt
aqBihILFUAtbLXbR6X4ZdX1A4HFzCRs9UrN/oWxcGzG1XiDZrsM9fefE5d1ZFzaj
YwLfX6sumkamZ2tcNoLw2JW/DR/oRLPHWvp6cP4MSk35RtYkn50q8ol6Yh6iKK9D
zAFbtiOtACDcgeFfr9JBVIM0RpMvHET31IRBTq2ra0UX2fcO9NaZc4r0UrwwmYzb
daGqi6Yqe/+mwARWkxJN70q2lfWLXIfrcGD+5pgnd+efAaQfzfgWSMFim2jVMGSp
1gXMcKVa5EZ7zUo0INz4RMUCAwEAAaNTMFEwHQYDVR0OBBYEFFmb4AiBTXj71cEt
YnmZwRocw5XdMB8GA1UdIwQYMBaAFFmb4AiBTXj71cEtYnmZwRocw5XdMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFXBmIQB3cypnViSL/8AoWld
PtBqceWuBear3TVjjg0vjph1ivC874MVk0p/a3iN1bCmwVQrCXSnnFaiKTrd2INf
DlAJRX06NM8R3c11KETld/U1frRZv/zLQAu3JgIUoClMHNUu9PS76XPQvnTOUhPB
gRV33NAuVSAvzJizCLzQ1j/RqXbtWme4HWg0nQFWBfAWUmMwkF6GLhk6ek2G8Mig
zKBXymZ0vAdbn3b9wULEKZIf9+fZkkU3lYBDFItyFqZRd9V9PYWA2mh+ySkFbiNP
ph5U4OER9tvWPEpqFMV6T30VTrO4J1ZF0UpWwpWCtxv6txFvoNpbVJ0rmCT3hCk=
-----END CERTIFICATE-----`;

const PUBLIC_LEAF_CERT = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIUCp2exGnK0lPiRgk/vESii6CJ+KcwDQYJKoZIhvcNAQEL
BQAwOTEdMBsGA1UEAwwUbGVhZi5jZXJ0b3BzLmV4YW1wbGUxGDAWBgNVBAoMD1Rv
a2VuVGltZXIgVGVzdDAeFw0yNjA4MjQxMTMyMDlaFw0zNjA4MjExMTMyMDlaMDkx
HTAbBgNVBAMMFGxlYWYuY2VydG9wcy5leGFtcGxlMRgwFgYDVQQKDA9Ub2tlblRp
bWVyIFRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCWyJ8E39sH
6IDO/TPGihYS+Rrt9UwwH6Vy39AnDzq5YZ3iXZ8FAFP+e7CGdtlyUzRCpDd7NztT
pTtQB6Ce1tuGSXo8MUgXAnWE0vx9zvxivNCNiMqk6jpBTG+CDwIDmTecgi/lmRJv
OMDLs03O6vbLKpiAygJvIAejy3gjvrfkIpTBG6YtO0X7VvwM0xq/iHg0mng9D3Ad
DQyFY/Z09kaiDsgng1e/kvP1GFU+cHaiB3l7fo1L0dAYKOqFR4mxPWH8/vFyPTN5
58eiJFLDQT0pdXTfOaTI0QzX2a6uDlcBehTotyyUdceb4IiM8OT1Mm+DaLRotcRU
9jj2gplUw401AgMBAAGjXTBbMB0GA1UdDgQWBBToB4yVNU+rp+wt9ZYoMJB5dCoz
GzAfBgNVHSMEGDAWgBToB4yVNU+rp+wt9ZYoMJB5dCozGzAMBgNVHRMBAf8EAjAA
MAsGA1UdDwQEAwIFoDANBgkqhkiG9w0BAQsFAAOCAQEAFQif8RSwfrz2MZo3NBRW
A2eVwGw11X5CIr3rzMgzGpO7zTKIOAmqd37DqciG5eWRHOPVI9sli4xuOoRfonmo
CajTCGWWzZw2rJ9e65T0jf7l/oqBsGCOP87MZFgGLT3zVgKMkWP2RWLQf05rZN+q
lH2KuqBdZ3xm3FoD4Q21t/m4xcFjR5hNESpB03hideA6wznklSTue4KffzbU/4xV
GYjaK39N+zVx4kY6ewdHV1zYWJAivrGVrFlSD0NG2abiUKLBmJ/ymcQfaDv0T87k
1QQ8Lmm/FthmSvPt40mJ+2t4xUoMxNPZklQWT+NbcV/ZD52GJRxcAAuj60abw2RC
aQ==
-----END CERTIFICATE-----`;

function assertCode(fn, code) {
  assert.throws(fn, (error) => error?.code === code);
}

describe("trust anchor PEM validation (ADR-0012 decision 6)", () => {
  it("accepts exactly one CA certificate and computes the fingerprint server-side", () => {
    const result = parseAndValidateAnchorPem(PUBLIC_CA_CERT);
    assert.equal(typeof result.fingerprintSha256, "string");
    assert.match(result.fingerprintSha256, /^[a-f0-9]{64}$/);
    assert.equal(result.subjectCommonName, "TokenTimer Test Trust CA");
    assert.ok(result.pem.startsWith("-----BEGIN CERTIFICATE-----"));
  });

  it("rejects a leaf certificate (Basic Constraints CA=false)", () => {
    assertCode(
      () => parseAndValidateAnchorPem(PUBLIC_LEAF_CERT),
      CERTOPS_TRUST_ANCHOR_PEM_INVALID,
    );
  });

  it("rejects a bundle/multi-certificate PEM", () => {
    const bundle = `${PUBLIC_LEAF_CERT}\n${PUBLIC_CA_CERT}`;
    assertCode(
      () => parseAndValidateAnchorPem(bundle),
      CERTOPS_TRUST_ANCHOR_PEM_INVALID,
    );
  });

  it("rejects an empty or non-string pem", () => {
    assertCode(() => parseAndValidateAnchorPem(""), CERTOPS_TRUST_ANCHOR_PEM_INVALID);
    assertCode(() => parseAndValidateAnchorPem(null), CERTOPS_TRUST_ANCHOR_PEM_INVALID);
    assertCode(() => parseAndValidateAnchorPem(undefined), CERTOPS_TRUST_ANCHOR_PEM_INVALID);
  });

  it("rejects unparseable garbage", () => {
    assertCode(
      () => parseAndValidateAnchorPem("-----BEGIN CERTIFICATE-----\nnot-a-cert\n-----END CERTIFICATE-----"),
      CERTOPS_TRUST_ANCHOR_PEM_INVALID,
    );
  });

  it("never trusts a client-supplied fingerprint (always recomputed server-side)", () => {
    const first = parseAndValidateAnchorPem(PUBLIC_CA_CERT);
    const second = parseAndValidateAnchorPem(PUBLIC_CA_CERT);
    assert.equal(first.fingerprintSha256, second.fingerprintSha256);
  });

  it("exposes root/intermediate as the only valid anchorType values", () => {
    assert.deepEqual(ANCHOR_TYPES, ["root", "intermediate"]);
  });
});

describe("trust job field normalization (ADR-0012 decision 20a/20c)", () => {
  it("requires idempotencyKey and rejects blank/whitespace-only values", () => {
    assertCode(
      () => normalizeIdempotencyKey(""),
      CERTOPS_TRUST_JOB_IDEMPOTENCY_KEY_REQUIRED,
    );
    assertCode(
      () => normalizeIdempotencyKey("   "),
      CERTOPS_TRUST_JOB_IDEMPOTENCY_KEY_REQUIRED,
    );
    assertCode(
      () => normalizeIdempotencyKey(undefined),
      CERTOPS_TRUST_JOB_IDEMPOTENCY_KEY_REQUIRED,
    );
    assert.equal(normalizeIdempotencyKey(" key-1 "), "key-1");
  });

  it("requires agentId: distribute-trust/revoke-trust always target one agent", () => {
    assertCode(() => normalizeAgentId(""), CERTOPS_TRUST_ANCHOR_INVALID);
    assertCode(() => normalizeAgentId(null), CERTOPS_TRUST_ANCHOR_INVALID);
    assert.equal(normalizeAgentId(" agent-1 "), "agent-1");
  });

  it("validates store against the machine-trust-store name pattern", () => {
    assertCode(() => normalizeStore(""), CERTOPS_TRUST_ANCHOR_INVALID);
    assertCode(() => normalizeStore("bad$store"), CERTOPS_TRUST_ANCHOR_INVALID);
    assert.equal(normalizeStore("Root"), "Root");
  });

  it("requires a non-empty owner (reference-counting key, decision 6)", () => {
    assertCode(() => normalizeOwner(""), CERTOPS_TRUST_ANCHOR_INVALID);
    assertCode(() => normalizeOwner("   "), CERTOPS_TRUST_ANCHOR_INVALID);
    assert.equal(normalizeOwner(" workspace-policy "), "workspace-policy");
  });
});

describe("trust result wire carriage", () => {
  const agentProtocolSchema = require(
    path.resolve(
      __dirname,
      "../../packages/contracts/certops/agent-protocol.schema.json",
    ),
  );
  const {
    validateTrustResult,
  } = require(
    path.resolve(
      __dirname,
      "../../packages/contracts/certops/validate-trust-result.cjs",
    ),
  );

  // Regression guard: resultBody is additionalProperties:false, so without a
  // dedicated carrier property the agent's typed trust result is silently
  // dropped on the wire and every real trust job fails result ingestion.
  it("gives resultBody a trustResult property to carry the typed result", () => {
    const properties = agentProtocolSchema.definitions.resultBody.properties;
    assert.ok(
      Object.prototype.hasOwnProperty.call(properties, "trustResult"),
      "resultBody must expose a trustResult property",
    );
    assert.equal(agentProtocolSchema.definitions.resultBody.additionalProperties, false);
  });

  it("accepts a full trust result and rejects a missing one", () => {
    const result = {
      schemaVersion: 1,
      jobId: "job-1",
      workspaceId: "11111111-1111-4111-8111-111111111111",
      agentId: "22222222-2222-4222-8222-222222222222",
      trustAnchorId: "anchor-1",
      action: "distribute-trust",
      transitionGeneration: 2,
      store: "Root",
      outcome: "installed",
      mutationAttempted: true,
      mutationPerformed: true,
      receipt: { id: "receipt-1", state: "finalized" },
      observedAt: "2026-01-01T00:00:00.000Z",
    };
    assert.equal(
      validateTrustResult(result).valid,
      true,
      JSON.stringify(validateTrustResult(result).errors),
    );
    // A result body that omitted trustResult must fail closed rather than
    // being treated as a valid empty result.
    assert.equal(validateTrustResult(undefined).valid, false);
  });
});
