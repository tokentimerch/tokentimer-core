"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  PRIVATE_KEY_MATERIAL_REJECTED,
  rejectKeyMaterial,
} = require(
  path.resolve(__dirname, "../../apps/api/middleware/reject-key-material.js"),
);

const FAKE_PRIVATE_BODY = "RkFLRS1OT1QtQS1SRUFMLUtFWQ==";
const fakePem = (label) =>
  `-----BEGIN ${label}-----\n${FAKE_PRIVATE_BODY}\n-----END ${label}-----`;

const PUBLIC_CERTIFICATE_PEM = fakePem("CERTIFICATE");
const PUBLIC_KEY_PEM = fakePem("PUBLIC KEY");

function fakePkcs12Buffer() {
  return Buffer.concat([
    Buffer.from([0x30, 0x5c, 0x02, 0x01, 0x03]),
    Buffer.alloc(89, 0),
  ]);
}

function runMiddleware(body) {
  let statusCode = null;
  let responseBody = null;
  let nextCalled = false;
  const req = { body };
  const res = {
    status(code) {
      statusCode = code;
      return this;
    },
    json(payload) {
      responseBody = payload;
      return this;
    },
  };

  rejectKeyMaterial(req, res, () => {
    nextCalled = true;
  });

  return { nextCalled, responseBody, statusCode };
}

function assertRejected(body) {
  const result = runMiddleware(body);

  assert.equal(result.nextCalled, false);
  assert.equal(result.statusCode, 422);
  assert.deepEqual(result.responseBody, {
    error: "Private key material is not accepted in CertOps requests",
    code: PRIVATE_KEY_MATERIAL_REJECTED,
  });
  return result;
}

function assertAllowed(body) {
  const result = runMiddleware(body);

  assert.equal(result.nextCalled, true);
  assert.equal(result.statusCode, null);
  assert.equal(result.responseBody, null);
}

describe("rejectKeyMaterial middleware", () => {
  it("rejects a direct private key field", () => {
    assertRejected({ certificate: fakePem("RSA PRIVATE KEY") });
  });

  it("rejects nested private key material", () => {
    assertRejected({
      import: {
        notes: "nested payload",
        certificate: { pem: fakePem("EC PRIVATE KEY") },
      },
    });
  });

  it("rejects array-contained private key material", () => {
    assertRejected({
      certificates: [PUBLIC_CERTIFICATE_PEM, fakePem("PRIVATE KEY")],
    });
  });

  it("rejects base64-wrapped private key PEM", () => {
    const wrapped = Buffer.from(fakePem("ENCRYPTED PRIVATE KEY")).toString(
      "base64",
    );

    assertRejected({ attachment: wrapped });
  });

  it("rejects PKCS#12/PFX-like binary request bodies", () => {
    assertRejected(fakePkcs12Buffer());
  });

  it("rejects base64-wrapped PKCS#12/PFX-like payloads", () => {
    assertRejected({ bundle: fakePkcs12Buffer().toString("base64") });
  });

  it("allows public certificate PEM input", () => {
    assertAllowed({ certificatePem: PUBLIC_CERTIFICATE_PEM });
  });

  it("allows public key PEM input", () => {
    assertAllowed({ publicKeyPem: PUBLIC_KEY_PEM });
  });

  it("allows malformed non-key input", () => {
    assertAllowed({
      certificatePem: "not a certificate and not private key material",
    });
  });

  it("does not echo private key material in the response", () => {
    const privateKey = fakePem("RSA PRIVATE KEY");
    const result = assertRejected({ payload: privateKey });
    const serialized = JSON.stringify(result.responseBody);

    assert.equal(serialized.includes(privateKey), false);
    assert.equal(serialized.includes(FAKE_PRIVATE_BODY), false);
  });

  it("does not introduce private-key-looking response fields", () => {
    const result = assertRejected({ payload: fakePem("PRIVATE KEY") });
    const responseKeys = Object.keys(result.responseBody);

    assert.deepEqual(responseKeys.sort(), ["code", "error"]);
  });
});
