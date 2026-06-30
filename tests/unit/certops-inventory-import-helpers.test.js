"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  fingerprintsFromCertificates,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/inventory.js"),
);
const { parsePublicCertificateMaterial } = require(
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

describe("CertOps inventory import helpers", () => {
  it("fingerprintsFromCertificates extracts normalized unique fingerprints", () => {
    const certificates = parsePublicCertificateMaterial(
      `${PUBLIC_LEAF_CERT}\n${PUBLIC_CA_CERT}`,
    );
    const fingerprints = fingerprintsFromCertificates(certificates);

    assert.equal(fingerprints.length, 2);
    for (const fingerprint of fingerprints) {
      assert.match(fingerprint, /^[a-f0-9]{64}$/);
    }
    assert.equal(fingerprintsFromCertificates(certificates).length, 2);
  });

  it("fingerprintsFromCertificates normalizes colon-separated fingerprints", () => {
    const [certificate] = parsePublicCertificateMaterial(PUBLIC_LEAF_CERT);
    const colonSeparated = {
      ...certificate,
      fingerprintSha256: certificate.fingerprintSha256
        .match(/.{1,2}/g)
        .join(":"),
    };

    const [fingerprint] = fingerprintsFromCertificates([colonSeparated]);
    assert.equal(fingerprint, certificate.fingerprintSha256);
  });

  it("fingerprintsFromCertificates deduplicates repeated certificates", () => {
    const [certificate] = parsePublicCertificateMaterial(PUBLIC_LEAF_CERT);
    const fingerprints = fingerprintsFromCertificates([
      certificate,
      certificate,
    ]);

    assert.equal(fingerprints.length, 1);
    assert.equal(fingerprints[0], certificate.fingerprintSha256);
  });

  it("fingerprintsFromCertificates returns an empty list for invalid input", () => {
    assert.deepEqual(fingerprintsFromCertificates(null), []);
    assert.deepEqual(fingerprintsFromCertificates([]), []);
    assert.deepEqual(
      fingerprintsFromCertificates([{ commonName: "missing fingerprint" }]),
      [],
    );
  });

  it("exports overlay import quota helpers", () => {
    const inventory = require(
      path.resolve(__dirname, "../../apps/api/services/certops/inventory.js"),
    );
    for (const name of [
      "fingerprintsFromCertificates",
      "acquireManagedCertificateImportLock",
      "countActiveManagedCertificates",
      "countActiveManagedCertificatesWithClient",
      "countQuotaConsumingNewFingerprints",
    ]) {
      assert.equal(typeof inventory[name], "function", `missing export ${name}`);
    }
  });

  it("importPublicCertificates invokes validateImport before token creation", () => {
    const inventorySource = require("node:fs").readFileSync(
      path.resolve(__dirname, "../../apps/api/services/certops/inventory.js"),
      "utf8",
    );
    const importStart = inventorySource.indexOf("async function importPublicCertificates");
    assert.notEqual(importStart, -1);
    const importBody = inventorySource.slice(importStart);
    const validateIndex = importBody.indexOf(
      'typeof normalizedOptions.validateImport === "function"',
    );
    const tokenCreateIndex = importBody.indexOf("await ensureManagedCertificateToken(");

    assert.notEqual(validateIndex, -1);
    assert.notEqual(tokenCreateIndex, -1);
    assert.ok(
      validateIndex < tokenCreateIndex,
      "validateImport must run before managed certificate upsert",
    );
  });
});
