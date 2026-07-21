"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_CERTIFICATE_PARSE_FAILED,
  CERTOPS_CERTIFICATE_TOO_LARGE,
  MAX_PUBLIC_CERTIFICATE_INPUT_BYTES,
  PRIVATE_KEY_MATERIAL_REJECTED,
  parsePublicCertificateMaterial,
  parseTypedSubjectAltNames,
  parseSubjectAltNames,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/parser.js"),
);

const PUBLIC_LEAF_CERT = `
-----BEGIN CERTIFICATE-----
MIIDgjCCAmqgAwIBAgIUKJShixxx/7TH81hKwHE3UsvIFMkwDQYJKoZIhvcNAQEL
BQAwNDEYMBYGA1UEAwwPY2VydG9wcy5leGFtcGxlMRgwFgYDVQQKDA9Ub2tlblRp
bWVyIFRlc3QwHhcNMjYwNjI2MDA0MDU5WhcNMjcwNjI2MDA0MDU5WjA0MRgwFgYD
VQQDDA9jZXJ0b3BzLmV4YW1wbGUxGDAWBgNVBAoMD1Rva2VuVGltZXIgVGVzdDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANoaAIgElNelqNg6TsY++HnK
rFeOgn7csJYu9AbFfQRAoFO592aVI9QdyejoGesSy+tDN06vJl411Ntz6caB2+fd
+qkllZ+c39IZEbp++PDp7dD+4aEC68tGoZ9F/9dOGRaZ4xSFp0W0+5hd8E5q4E9U
MSdc4cUjQKuZX+jwBQqy+SRxhhNh6GPVWg3Cr6W0F53yFxWlb8q+4cwOZg0AP7sK
2u8UvordGO3o4eiPsVtmRh87YeRnUDRuzPb4Mi/Fo9Cr+1Fq3Q3xdWH9LhP0DSmD
89Ho84nvn+DfM+Dbnb7PsmNgqOVictn/LxHMOrl1F04BkvY9rNuBkh7wHC7TOR8C
AwEAAaOBizCBiDAdBgNVHQ4EFgQUoOXgW3/xFso+3GDIpFqimZ2K2TUwHwYDVR0j
BBgwFoAUoOXgW3/xFso+3GDIpFqimZ2K2TUwDwYDVR0TAQH/BAUwAwEB/zA1BgNV
HREELjAsgg9jZXJ0b3BzLmV4YW1wbGWCE2FwaS5jZXJ0b3BzLmV4YW1wbGWHBH8A
AAEwDQYJKoZIhvcNAQELBQADggEBAGi4XAScskH5bdxNbXwtEqlep2eDyseUyulF
g2yILrkiA22+WveOZrmReuxHx+umHVAO4O6JtHwD1figZyKgCrMzrREqmRwGj6pb
jgaW6Eeck+zFh1cKTH6ZUYlN6yOHOhKR0nBnseSuoh/gEangQVLRug3SqCCi6GQI
aOAUKMHYsxTyfjtE2k7URQYy7fbfLW/k+68l+xI/ktwFlS+MncmrS+Lx+dWwxVCn
EucPyYnACaKyw2oY6kCVaW9OReglxzoFzLxZvqxyrA1LpWjzgJiR7nIpZCappsi9
gB1JS6DPep8dhLORucnHS/Opy2xOB0lB3kmNoh5bierJUVeReSc=
-----END CERTIFICATE-----
`;

const PUBLIC_CA_CERT = `
-----BEGIN CERTIFICATE-----
MIIDaDCCAlCgAwIBAgIUdCT2l9wFjDoFlfsF97QP3v7uq5IwDQYJKoZIhvcNAQEL
BQAwNDEYMBYGA1UEAwwPQ2VydE9wcyBUZXN0IENBMRgwFgYDVQQKDA9Ub2tlblRp
bWVyIFRlc3QwHhcNMjYwNjI2MDA0MTA3WhcNMjgwNjI1MDA0MTA3WjA0MRgwFgYD
VQQDDA9DZXJ0T3BzIFRlc3QgQ0ExGDAWBgNVBAoMD1Rva2VuVGltZXIgVGVzdDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANupE0mTV+O2+WJOXL/nj/Cw
JzVE6KVygV/W8MZWg3yN+FFzO/o+AcCxJlRgnDdkF9P8CWmhsDZ4GfVZtTfjuQeT
lu2Y5LG3fDGN3cxJovrbGjA1TbIRIODE7C5jAPJMvwmXE9PJO0nJnuhE15xKU7IZ
2zk6fO/TwG7FfCqS9NBccbtHKB9sV/4dBf2GZ1eT8VMWLeUPrKFbAitQ7tgFb6h2
MLKfMjfqbW+IYchp53YSPS8k/alXJRi84Ev6tDASrZoaYTjRO0Ps1QFa9tVBAQLg
fa/4IpcXZmItiTYZlVAHN90WhbxZOiY5GiirZWWLkcUv9pSOHv07awzDolek/MkC
AwEAAaNyMHAwHQYDVR0OBBYEFMET4X2O2V7eGtpu6k8TjKLtf6AxMB8GA1UdIwQY
MBaAFMET4X2O2V7eGtpu6k8TjKLtf6AxMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0R
BBYwFIISY2EuY2VydG9wcy5leGFtcGxlMA0GCSqGSIb3DQEBCwUAA4IBAQBUjILj
UB9s79qPbzSVE4uZ+zMatfiOxG4PnF46iNJg1iRJJ1w3FOcjlj1FxO19RsRlqyOf
2rICSmyiSGundtu7u7cFVK0OFhNr8Da9ugm0tqiHh5ZtwGCfbDirLDIwPuL2nelR
8bk/cUepTFC1NAmRRa8cX3HgaEzY8YFThZ/JR1ps0/iWOMxC1MWdSNPgSrgX2DQ1
Wyd4gytVWmsBFmV4Xvc2wshwjy56jm60KaaNAWN/N6xSL5ay5+ImaBm1g2rapCMU
WXYC1Jw/NQfgLOwRIlX/AmpCib6udusu0XruVpYvBu9E2RxbaRto34iLQdUtrNN/
o9wtTp83p6p21Okl
-----END CERTIFICATE-----
`;

const FAKE_PRIVATE_BODY = "RkFLRS1OT1QtQS1SRUFMLUtFWQ==";
const fakePem = (label) =>
  `-----BEGIN ${label}-----\n${FAKE_PRIVATE_BODY}\n-----END ${label}-----`;

function pemToDer(pem) {
  return Buffer.from(
    pem
      .replace(/-----BEGIN CERTIFICATE-----/g, "")
      .replace(/-----END CERTIFICATE-----/g, "")
      .replace(/\s+/g, ""),
    "base64",
  );
}

function fakePrivateKeyDer() {
  return Buffer.from([
    0x30, 0x08, 0x02, 0x01, 0x00, 0x30, 0x03, 0x06, 0x01, 0x2a,
  ]);
}

function fakePfxDer() {
  return Buffer.from([0x30, 0x05, 0x02, 0x01, 0x03, 0x30, 0x00]);
}

function fakeJks() {
  return Buffer.from([0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, 2, 0, 0, 0, 0]);
}

function assertParserCode(input, code) {
  assert.throws(
    () => parsePublicCertificateMaterial(input),
    (error) => error?.code === code,
  );
}

function walkKeys(value, visit) {
  if (Array.isArray(value)) {
    for (const item of value) walkKeys(item, visit);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value)) {
    visit(key);
    walkKeys(item, visit);
  }
}

describe("CertOps public certificate parser", () => {
  it("parses a valid single certificate PEM", () => {
    const certificates = parsePublicCertificateMaterial(PUBLIC_LEAF_CERT);

    assert.equal(certificates.length, 1);
    assert.equal(certificates[0].commonName, "certops.example");
    assert.match(certificates[0].subject, /CN=certops\.example/);
    assert.match(certificates[0].issuer, /CN=certops\.example/);
    assert.ok(certificates[0].certificatePem.startsWith("-----BEGIN CERTIFICATE-----"));
    assert.ok(certificates[0].certificatePem.endsWith("-----END CERTIFICATE-----"));
  });

  it("keeps PEM behavior when Kubernetes supplies decoded PEM bytes", () => {
    assert.deepEqual(
      parsePublicCertificateMaterial(Buffer.from(PUBLIC_LEAF_CERT)),
      parsePublicCertificateMaterial(PUBLIC_LEAF_CERT),
    );
  });

  it("parses a certificate chain with multiple certificates", () => {
    const chain = `\n\n${PUBLIC_LEAF_CERT}\n\n${PUBLIC_CA_CERT}\n`;
    const certificates = parsePublicCertificateMaterial(chain);

    assert.equal(certificates.length, 2);
    assert.equal(certificates[0].commonName, "certops.example");
    assert.equal(certificates[1].commonName, "CertOps Test CA");
  });

  it("parses one exact public DER certificate with the same normalized metadata as PEM", () => {
    const der = pemToDer(PUBLIC_LEAF_CERT);
    const [fromPem] = parsePublicCertificateMaterial(PUBLIC_LEAF_CERT);
    const [fromDer] = parsePublicCertificateMaterial(der);

    assert.deepEqual(fromDer, fromPem);
    assert.equal(parsePublicCertificateMaterial(new Uint8Array(der)).length, 1);
  });

  it("extracts SAN values", () => {
    const [certificate] = parsePublicCertificateMaterial(PUBLIC_LEAF_CERT);

    assert.equal(certificate.subjectAltName.includes("DNS:certops.example"), true);
    assert.deepEqual(certificate.subjectAltNames, [
      "certops.example",
      "api.certops.example",
      "127.0.0.1",
    ]);
  });

  it("extracts typed SAN entries and keeps IP SANs distinct from DNS", () => {
    const [certificate] = parsePublicCertificateMaterial(PUBLIC_LEAF_CERT);

    assert.deepEqual(certificate.subjectAltNameEntries, [
      { type: "dns", value: "certops.example", prefix: "DNS" },
      { type: "dns", value: "api.certops.example", prefix: "DNS" },
      { type: "ip", value: "127.0.0.1", prefix: "IP Address" },
    ]);
    assert.deepEqual(
      certificate.subjectAltNameEntries.map((entry) => entry.value),
      certificate.subjectAltNames,
    );
  });

  it("rejects unsafe DNS SAN values as a closed parse failure", () => {
    const mixedDns = `DNS:p\u0430ypal.com, IP Address:127.0.0.1`;
    assert.throws(
      () => parseTypedSubjectAltNames(mixedDns),
      (error) =>
        error?.code === CERTOPS_CERTIFICATE_PARSE_FAILED &&
        /homograph/i.test(error.message),
    );
  });

  it("rejects bidirectional override in DNS SAN values", () => {
    assert.throws(
      () => parseTypedSubjectAltNames("DNS:evil.com\u202Egoogle.com"),
      (error) =>
        error?.code === CERTOPS_CERTIFICATE_PARSE_FAILED &&
        /bidirectional/i.test(error.message),
    );
  });

  it("accepts IP SANs without applying DNS mixed-script rules", () => {
    assert.deepEqual(parseSubjectAltNames("IP Address:127.0.0.1, IP Address:::1"), [
      "127.0.0.1",
      "::1",
    ]);
    assert.deepEqual(parseTypedSubjectAltNames("IP Address:2001:db8::1"), [
      { type: "ip", value: "2001:db8::1", prefix: "IP Address" },
    ]);
  });

  it("accepts well-formed punycode DNS SANs", () => {
    assert.deepEqual(parseTypedSubjectAltNames("DNS:xn--fsq.example"), [
      { type: "dns", value: "xn--fsq.example", prefix: "DNS" },
    ]);
  });

  it("extracts validity dates", () => {
    const [certificate] = parsePublicCertificateMaterial(PUBLIC_LEAF_CERT);

    assert.match(certificate.validFrom, /^\d{4}-\d{2}-\d{2}T/);
    assert.match(certificate.validTo, /^\d{4}-\d{2}-\d{2}T/);
    assert.equal(certificate.notBefore, certificate.validFrom);
    assert.equal(certificate.notAfter, certificate.validTo);
    assert.ok(Date.parse(certificate.validTo) > Date.parse(certificate.validFrom));
  });

  it("extracts certificate and public-key fingerprints", () => {
    const [certificate] = parsePublicCertificateMaterial(PUBLIC_LEAF_CERT);

    assert.match(certificate.fingerprint256, /^[a-f0-9]{64}$/);
    assert.match(certificate.fingerprint512, /^[a-f0-9]{128}$/);
    assert.equal(certificate.fingerprintSha256, certificate.fingerprint256);
    assert.match(certificate.spkiFingerprintSha256, /^[a-f0-9]{64}$/);
    assert.equal(certificate.publicKeyAlgorithm, "rsa");
    assert.equal(certificate.publicKeySize, 2048);
    assert.equal(certificate.publicKeyMetadata.asymmetricKeyType, "rsa");
  });

  it("rejects RSA private key PEM", () => {
    assertParserCode(fakePem("RSA PRIVATE KEY"), PRIVATE_KEY_MATERIAL_REJECTED);
  });

  it("rejects EC private key PEM", () => {
    assertParserCode(fakePem("EC PRIVATE KEY"), PRIVATE_KEY_MATERIAL_REJECTED);
  });

  it("rejects PKCS#8 private key PEM", () => {
    assertParserCode(fakePem("PRIVATE KEY"), PRIVATE_KEY_MATERIAL_REJECTED);
  });

  it("rejects base64-wrapped private key PEM", () => {
    const wrapped = Buffer.from(fakePem("RSA PRIVATE KEY")).toString("base64");
    assertParserCode(wrapped, PRIVATE_KEY_MATERIAL_REJECTED);
  });

  it("rejects malformed certificate input with a stable code", () => {
    const malformed = "not a public certificate";

    assert.throws(
      () => parsePublicCertificateMaterial(malformed),
      (error) =>
        error?.code === CERTOPS_CERTIFICATE_PARSE_FAILED &&
        !error.message.includes(malformed),
    );
  });

  it("rejects PKCS#12/PFX-like binary input as key material", () => {
    const pfxLike = Buffer.from([0x30, 0x82, 0x01, 0x0a, 0x02, 0x01, 0x03]);

    assertParserCode(pfxLike, PRIVATE_KEY_MATERIAL_REJECTED);
  });

  it("rejects malformed, empty, trailing, and oversized DER input", () => {
    assertParserCode(Buffer.alloc(0), CERTOPS_CERTIFICATE_PARSE_FAILED);
    assertParserCode(Buffer.from([0x30, 0x03, 0x01]), CERTOPS_CERTIFICATE_PARSE_FAILED);
    assertParserCode(
      Buffer.concat([pemToDer(PUBLIC_LEAF_CERT), Buffer.from([0x00])]),
      CERTOPS_CERTIFICATE_PARSE_FAILED,
    );
    assertParserCode(
      Buffer.alloc(MAX_PUBLIC_CERTIFICATE_INPUT_BYTES + 1),
      CERTOPS_CERTIFICATE_TOO_LARGE,
    );
  });

  it("rejects DER private-key and key-container material before certificate parsing", () => {
    for (const input of [fakePrivateKeyDer(), fakePfxDer(), fakeJks()]) {
      assertParserCode(input, PRIVATE_KEY_MATERIAL_REJECTED);
    }
  });

  it("allows a public certificate but rejects the same payload when a private key is present", () => {
    assert.doesNotThrow(() => parsePublicCertificateMaterial(PUBLIC_LEAF_CERT));
    assertParserCode(
      `${PUBLIC_LEAF_CERT}\n${fakePem("RSA PRIVATE KEY")}`,
      PRIVATE_KEY_MATERIAL_REJECTED,
    );
  });

  it("does not emit private-key-looking fields or values", () => {
    const output = parsePublicCertificateMaterial(PUBLIC_LEAF_CERT);
    const forbiddenFragments = [
      "private",
      "pkcs12",
      "pfx",
      "key_material",
      "key_pem",
      "key_der",
      "raw_key",
      "backup",
      "secret",
      "credential",
      "password",
    ];

    walkKeys(output, (key) => {
      for (const fragment of forbiddenFragments) {
        assert.equal(
          key.toLowerCase().includes(fragment),
          false,
          `${key} looks like a private-key custody field`,
        );
      }
    });
    assert.equal(JSON.stringify(output).includes("PRIVATE KEY"), false);
  });
});
