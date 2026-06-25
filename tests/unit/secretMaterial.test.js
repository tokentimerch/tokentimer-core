"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("path");

const {
  PRIVATE_KEY_REDACTION_PLACEHOLDER,
  containsPrivateKeyMaterial,
  redactPrivateKeyMaterial,
  redactGenericSecrets,
} = require(
  path.resolve(__dirname, "../../apps/api/utils/secretMaterial.js"),
);

// Synthetic header/footer fixtures with fake bodies. No real key material is
// committed: zero private-key custody applies to the test suite too.
const FAKE_BODY = "RkFLRS1OT1QtQS1SRUFMLUtFWQ==";
const pem = (label) =>
  `-----BEGIN ${label}-----\n${FAKE_BODY}\n-----END ${label}-----`;

const PRIVATE_KEY_LABELS = [
  "PRIVATE KEY", // PKCS#8
  "RSA PRIVATE KEY", // PKCS#1
  "EC PRIVATE KEY", // SEC1
  "DSA PRIVATE KEY",
  "OPENSSH PRIVATE KEY",
  "ENCRYPTED PRIVATE KEY",
  "RSA ENCRYPTED PRIVATE KEY",
];

const NON_KEY_VALUES = [
  pem("CERTIFICATE"),
  pem("CERTIFICATE REQUEST"),
  pem("PUBLIC KEY"),
  "just a normal log line with no secrets",
  "fingerprint: AA:BB:CC:DD",
  "",
  null,
  undefined,
  42,
  true,
];

describe("secretMaterial.containsPrivateKeyMaterial", () => {
  for (const label of PRIVATE_KEY_LABELS) {
    it(`detects a ${label} PEM block`, () => {
      assert.strictEqual(containsPrivateKeyMaterial(pem(label)), true);
    });
  }

  it("detects base64-wrapped private key PEM", () => {
    const wrapped = Buffer.from(pem("RSA PRIVATE KEY")).toString("base64");
    assert.strictEqual(containsPrivateKeyMaterial(wrapped), true);
  });

  it("detects key material under an innocent field name", () => {
    const payload = { note: "harmless", attachment: pem("EC PRIVATE KEY") };
    assert.strictEqual(containsPrivateKeyMaterial(payload), true);
  });

  it("detects key material nested in arrays and objects", () => {
    const payload = {
      evidence: [{ output: ["line1", pem("PRIVATE KEY")] }],
    };
    assert.strictEqual(containsPrivateKeyMaterial(payload), true);
  });

  it("detects key material inside a Buffer", () => {
    assert.strictEqual(
      containsPrivateKeyMaterial(Buffer.from(pem("PRIVATE KEY"))),
      true,
    );
  });

  for (const value of NON_KEY_VALUES) {
    it(`does not flag non-key value: ${JSON.stringify(value)?.slice(0, 32)}`, () => {
      assert.strictEqual(containsPrivateKeyMaterial(value), false);
    });
  }

  it("does not flag a certificate nested in an object", () => {
    const payload = { cert: pem("CERTIFICATE"), meta: { issuer: "Test CA" } };
    assert.strictEqual(containsPrivateKeyMaterial(payload), false);
  });

  it("does not infinitely recurse on cyclic objects", () => {
    const a = {};
    a.self = a;
    assert.strictEqual(containsPrivateKeyMaterial(a), false);
  });
});

describe("secretMaterial.redactPrivateKeyMaterial", () => {
  it("replaces a private key block with the placeholder", () => {
    const input = `before\n${pem("RSA PRIVATE KEY")}\nafter`;
    const out = redactPrivateKeyMaterial(input);
    assert.ok(out.includes(PRIVATE_KEY_REDACTION_PLACEHOLDER));
    assert.ok(!out.includes(FAKE_BODY));
    assert.ok(out.startsWith("before"));
    assert.ok(out.endsWith("after"));
  });

  it("leaves non-key strings unchanged", () => {
    assert.strictEqual(redactPrivateKeyMaterial("plain text"), "plain text");
  });

  it("returns non-strings unchanged", () => {
    assert.strictEqual(redactPrivateKeyMaterial(123), 123);
  });
});

describe("secretMaterial.redactGenericSecrets", () => {
  it("redacts private key blocks in nested structures without mutating input", () => {
    const input = { logs: [pem("PRIVATE KEY")] };
    const out = redactGenericSecrets(input);
    assert.ok(out.logs[0].includes(PRIVATE_KEY_REDACTION_PLACEHOLDER));
    assert.ok(input.logs[0].includes(FAKE_BODY), "input must not be mutated");
  });

  it("redacts Authorization bearer header values", () => {
    const out = redactGenericSecrets("Authorization: Bearer abc123tokenvalue");
    assert.ok(!out.includes("abc123tokenvalue"));
    assert.ok(/Bearer \[REDACTED\]/.test(out));
  });

  it("leaves ordinary content intact", () => {
    assert.strictEqual(
      redactGenericSecrets("renewal succeeded for example.com"),
      "renewal succeeded for example.com",
    );
  });
});
