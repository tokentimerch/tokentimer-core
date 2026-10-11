"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { X509Certificate } = require("node:crypto");

const {
  validateIssuedCertificate,
  dnsNameAuthorized,
  parseSubjectCn,
  spkiSha256Hex,
  extractSpkiFromCertificate,
} = require("./issued-certificate-validation");
const {
  readCertificateTemplateOid,
  readExtKeyUsageOids,
  readKeyUsageNames,
  OID_SERVER_AUTH,
  decodeOid,
  encodeOid,
} = require("./der-extensions");

const ISSUED_CER = path.join(
  __dirname,
  "..",
  "..",
  "reference",
  "adcs-cmc",
  "testdata",
  "issued.cer",
);

describe("dnsNameAuthorized", () => {
  it("matches exact and single-label wildcards", () => {
    assert.equal(dnsNameAuthorized("app.example.com", ["app.example.com"]), true);
    assert.equal(dnsNameAuthorized("APP.example.com", ["app.example.com"]), true);
    assert.equal(dnsNameAuthorized("a.example.com", ["*.example.com"]), true);
    assert.equal(dnsNameAuthorized("a.b.example.com", ["*.example.com"]), false);
    assert.equal(dnsNameAuthorized("other.com", ["app.example.com"]), false);
  });
});

describe("der-extensions against AD CS issued.cer fixture", () => {
  it("reads EKU, key usage, and template OID", () => {
    const der = fs.readFileSync(ISSUED_CER);
    assert.deepEqual(readExtKeyUsageOids(der), [OID_SERVER_AUTH]);
    const ku = readKeyUsageNames(der);
    assert.ok(ku.includes("digitalSignature"));
    assert.ok(ku.includes("keyEncipherment"));
    const templateOid = readCertificateTemplateOid(der);
    assert.ok(typeof templateOid === "string" && templateOid.startsWith("1.3.6.1.4.1.311.21.8."));
  });
});

describe("OID base-128 BigInt arcs", () => {
  it("round-trips arcs above 2^31 without 32-bit truncation", () => {
    const oid = "1.2.840.113556.1.8000000000";
    const encoded = encodeOid(oid);
    assert.equal(decodeOid(encoded), oid);
  });

  it("rejects truncated and non-minimal base-128 encodings", () => {
    assert.throws(() => decodeOid(Buffer.from([0x2a, 0x80, 0x01])), /leading/);
    assert.throws(() => decodeOid(Buffer.from([0x2a, 0x81])), /truncated/);
  });
});

describe("validateIssuedCertificate", () => {
  const certificatePem = fs.readFileSync(ISSUED_CER, "utf8");
  const cert = new X509Certificate(certificatePem);
  const templateOid = readCertificateTemplateOid(certificatePem);
  const csrSpkiSha256 = spkiSha256Hex(extractSpkiFromCertificate(certificatePem));
  const hostname = "iis10-interrupted.tokentimer-verify.local";

  const base = {
    certificatePem,
    csrSpkiSha256,
    authorizedDnsNames: [hostname],
    requiredDnsName: hostname,
    templateOid,
    caKeySha256: "a".repeat(64),
    minimumRemainingValidity: 0,
    requireLaterNotAfter: false,
    keyAlgorithm: "rsa",
    now: new Date("2026-10-10T00:00:00Z"),
    chainValidateImpl: async () => ({ verdict: "valid" }),
  };

  it("accepts a fixture leaf when chain helper reports valid", async () => {
    const result = await validateIssuedCertificate(base);
    assert.equal(result.ok, true);
    assert.equal(result.state, "validated");
  });

  it("rejects SPKI mismatch", async () => {
    const result = await validateIssuedCertificate({
      ...base,
      csrSpkiSha256: "b".repeat(64),
    });
    assert.equal(result.ok, false);
    assert.equal(result.errorCode, "ADCS_CERTIFICATE_INVALID");
    assert.match(result.detail, /SubjectPublicKeyInfo/);
  });

  it("rejects SAN outside authorizedDnsNames", async () => {
    const result = await validateIssuedCertificate({
      ...base,
      authorizedDnsNames: ["other.example.com"],
      requiredDnsName: "other.example.com",
    });
    assert.equal(result.ok, false);
    assert.match(result.detail, /SAN|CN|required DNS/i);
  });

  it("requires the binding hostname in DNS SAN when SAN is present (CN alone is not enough)", async () => {
    // Fixture has CN == SAN == hostname. Simulate a required name that matches
    // only if CN were consulted while SAN carries a different authorized name.
    const result = await validateIssuedCertificate({
      ...base,
      authorizedDnsNames: [hostname, "other.example.com"],
      requiredDnsName: "other.example.com",
    });
    assert.equal(result.ok, false);
    assert.match(result.detail, /not present in DNS SAN/);
  });

  it("skips requireLaterNotAfter when no installed certificate was observed", async () => {
    const result = await validateIssuedCertificate({
      ...base,
      requireLaterNotAfter: true,
      existingNotAfter: null,
    });
    assert.equal(result.ok, true);
  });

  it("rejects wrong template OID", async () => {
    const result = await validateIssuedCertificate({
      ...base,
      templateOid: "1.2.3.4.5.6.7.8.9",
    });
    assert.equal(result.ok, false);
    assert.match(result.detail, /template OID/);
  });

  it("maps revocation_unknown to validation_deferred under require", async () => {
    const result = await validateIssuedCertificate({
      ...base,
      chainValidateImpl: async () => ({
        verdict: "revocation_unknown",
        detail: "offline",
      }),
    });
    assert.equal(result.ok, false);
    assert.equal(result.state, "validation_deferred");
  });

  it("accepts revocation_unknown under best-effort", async () => {
    const result = await validateIssuedCertificate({
      ...base,
      revocationCheck: "best-effort",
      chainValidateImpl: async () => ({
        verdict: "revocation_unknown",
        detail: "offline",
      }),
    });
    assert.equal(result.ok, true);
    assert.equal(result.revocationBestEffort, true);
  });

  it("maps ca_key_changed", async () => {
    const result = await validateIssuedCertificate({
      ...base,
      chainValidateImpl: async () => ({
        verdict: "ca_key_changed",
        detail: "pin miss",
      }),
    });
    assert.equal(result.ok, false);
    assert.equal(result.errorCode, "ADCS_CA_KEY_CHANGED");
  });

  it("rejects notAfter inside minimumRemainingValidity", async () => {
    const result = await validateIssuedCertificate({
      ...base,
      // Fixture notAfter is 2028-10-08; force a huge remaining-validity floor.
      minimumRemainingValidity: 60 * 60 * 24 * 365 * 50,
      now: new Date("2026-10-10T00:00:00Z"),
    });
    assert.equal(result.ok, false);
    assert.match(result.detail, /minimumRemainingValidity/);
  });

  it("rejects equal serial when existingSerialHex is set", async () => {
    const result = await validateIssuedCertificate({
      ...base,
      existingSerialHex: cert.serialNumber,
    });
    assert.equal(result.ok, false);
    assert.match(result.detail, /serial/);
  });

  it("parses subject CN from Node DN formatting", () => {
    assert.equal(parseSubjectCn(cert.subject), hostname);
  });
});
