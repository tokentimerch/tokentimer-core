"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("path");

const {
  PRIVATE_KEY_MATERIAL_REJECTED,
  PRIVATE_KEY_REDACTION_PLACEHOLDER,
  assertNoPrivateKeyMaterial,
  containsPrivateKeyMaterial,
  looksPrivateKeyDer,
  fieldNameLooksGenericSecret,
  fieldNameLooksPrivateKeyMaterial,
  looksPkcs12Bundle,
  redactPrivateKeyMaterial,
  redactGenericSecrets,
  redactGenericSecretsWithReport,
} = require(
  path.resolve(__dirname, "../../apps/api/utils/secretMaterial.js"),
);

// Synthetic header/footer fixtures with fake bodies. No real key material is
// committed: zero private-key custody applies to the test suite too.
const FAKE_BODY = "RkFLRS1OT1QtQS1SRUFMLUtFWQ==";
const pem = (label) =>
  `-----BEGIN ${label}-----\n${FAKE_BODY}\n-----END ${label}-----`;

function fakePkcs12Buffer() {
  return Buffer.concat([
    Buffer.from([0x30, 0x5c, 0x02, 0x01, 0x03]),
    Buffer.alloc(89, 0),
  ]);
}

function fakePkcs8PrivateKeyBuffer() {
  const value = Buffer.alloc(96);
  value[0] = 0x30;
  value[1] = 0x5e;
  value[2] = 0x02;
  value[3] = 0x01;
  value[4] = 0x00;
  value[5] = 0x30;
  return value;
}

function fakeCertificateDerBuffer() {
  return Buffer.from([
    0x30, 0x0a, 0x30, 0x08, 0x02, 0x01, 0x01, 0x30, 0x03, 0x06, 0x01,
    0x2a,
  ]);
}

function deeplyNested(value, depth = 14) {
  let node = value;
  for (let index = 0; index < depth; index += 1) {
    node = { child: node };
  }
  return node;
}

const PRIVATE_KEY_LABELS = [
  "PRIVATE KEY", // PKCS#8
  "RSA PRIVATE KEY", // PKCS#1
  "EC PRIVATE KEY", // SEC1
  "DSA PRIVATE KEY",
  "OPENSSH PRIVATE KEY",
  "ENCRYPTED PRIVATE KEY",
  "RSA ENCRYPTED PRIVATE KEY",
];

const NONCANONICAL_PRIVATE_KEY_PEMS = [
  {
    name: "lowercase PEM armor",
    value: `-----begin rsa private key-----\n${FAKE_BODY}\n-----end rsa private key-----`,
  },
  {
    name: "extra PEM armor whitespace",
    value: `-----BEGIN  RSA   PRIVATE   KEY-----\n${FAKE_BODY}\n-----END  RSA   PRIVATE   KEY-----`,
  },
  {
    name: "mixed-case PEM armor",
    value: `-----BeGiN EnCrYpTeD PrIvAtE KeY-----\n${FAKE_BODY}\n-----eNd EnCrYpTeD PrIvAtE KeY-----`,
  },
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

  for (const fixture of NONCANONICAL_PRIVATE_KEY_PEMS) {
    it(`detects ${fixture.name}`, () => {
      assert.strictEqual(containsPrivateKeyMaterial(fixture.value), true);
    });
  }

  it("detects noncanonical private key PEM in objects, arrays, and buffers", () => {
    const privateKey = NONCANONICAL_PRIVATE_KEY_PEMS[1].value;

    assert.strictEqual(
      containsPrivateKeyMaterial({ certificate: { pem: privateKey } }),
      true,
    );
    assert.strictEqual(
      containsPrivateKeyMaterial(["public metadata", privateKey]),
      true,
    );
    assert.strictEqual(containsPrivateKeyMaterial(Buffer.from(privateKey)), true);
  });

  it("detects base64-wrapped private key PEM", () => {
    const wrapped = Buffer.from(pem("RSA PRIVATE KEY")).toString("base64");
    assert.strictEqual(containsPrivateKeyMaterial(wrapped), true);
  });

  it("detects base64-wrapped noncanonical private key PEM", () => {
    const wrapped = Buffer.from(
      NONCANONICAL_PRIVATE_KEY_PEMS[2].value,
    ).toString("base64");
    assert.strictEqual(containsPrivateKeyMaterial(wrapped), true);
  });

  it("detects PKCS#12/PFX-like DER bundles", () => {
    const pfxLike = fakePkcs12Buffer();

    assert.strictEqual(looksPkcs12Bundle(pfxLike), true);
    assert.strictEqual(containsPrivateKeyMaterial(pfxLike), true);
  });

  it("detects base64-wrapped PKCS#12/PFX-like DER bundles", () => {
    const wrapped = fakePkcs12Buffer().toString("base64");

    assert.strictEqual(containsPrivateKeyMaterial(wrapped), true);
  });

  it("detects base64-wrapped PKCS#8 DER private keys without PEM armor", () => {
    const privateKeyDer = fakePkcs8PrivateKeyBuffer();
    assert.strictEqual(looksPrivateKeyDer(privateKeyDer), true);
    assert.strictEqual(
      containsPrivateKeyMaterial(privateKeyDer.toString("base64")),
      true,
    );
  });

  it("detects hex-encoded private-key PEM blobs", () => {
    const hexEncoded = Buffer.from(pem("EC PRIVATE KEY"), "utf8").toString(
      "hex",
    );
    assert.strictEqual(containsPrivateKeyMaterial(hexEncoded), true);
  });

  it("does not confuse a DER certificate envelope with a private key", () => {
    const certificateDer = fakeCertificateDerBuffer();
    assert.strictEqual(looksPrivateKeyDer(certificateDer), false);
    assert.strictEqual(containsPrivateKeyMaterial(certificateDer), false);
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

  it("fails closed for harmless values nested beyond the scan depth", () => {
    assert.strictEqual(
      containsPrivateKeyMaterial(deeplyNested("harmless public metadata")),
      true,
    );
  });

  it("does not infinitely recurse on cyclic objects and fails closed", () => {
    const a = {};
    a.self = a;
    assert.strictEqual(containsPrivateKeyMaterial(a), true);
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

  for (const fixture of NONCANONICAL_PRIVATE_KEY_PEMS) {
    it(`redacts ${fixture.name}`, () => {
      const input = `before\n${fixture.value}\nafter`;
      const out = redactPrivateKeyMaterial(input);

      assert.ok(out.includes(PRIVATE_KEY_REDACTION_PLACEHOLDER));
      assert.ok(!out.includes(FAKE_BODY));
      assert.ok(!/private\s+key/i.test(out));
      assert.ok(out.startsWith("before"));
      assert.ok(out.endsWith("after"));
    });
  }

  it("redacts a base64-wrapped private key to the placeholder", () => {
    const wrapped = Buffer.from(pem("RSA PRIVATE KEY")).toString("base64");
    const out = redactPrivateKeyMaterial(wrapped);
    assert.strictEqual(out, PRIVATE_KEY_REDACTION_PLACEHOLDER);
    assert.ok(!out.includes(wrapped));
  });

  it("redacts a base64-wrapped noncanonical private key to the placeholder", () => {
    const wrapped = Buffer.from(
      NONCANONICAL_PRIVATE_KEY_PEMS[0].value,
    ).toString("base64");
    const out = redactPrivateKeyMaterial(wrapped);
    assert.strictEqual(out, PRIVATE_KEY_REDACTION_PLACEHOLDER);
    assert.ok(!out.includes(wrapped));
  });

  it("redacts a base64-wrapped PKCS#12/PFX-like bundle to the placeholder", () => {
    const wrapped = fakePkcs12Buffer().toString("base64");
    const out = redactPrivateKeyMaterial(wrapped);
    assert.strictEqual(out, PRIVATE_KEY_REDACTION_PLACEHOLDER);
  });

  it("redacts base64-wrapped DER private keys and hex-encoded PEM blobs", () => {
    const der = fakePkcs8PrivateKeyBuffer().toString("base64");
    const hex = Buffer.from(pem("RSA PRIVATE KEY"), "utf8").toString("hex");
    assert.strictEqual(
      redactPrivateKeyMaterial(der),
      PRIVATE_KEY_REDACTION_PLACEHOLDER,
    );
    assert.strictEqual(
      redactPrivateKeyMaterial(hex),
      PRIVATE_KEY_REDACTION_PLACEHOLDER,
    );
  });

  it("leaves non-key strings unchanged", () => {
    assert.strictEqual(redactPrivateKeyMaterial("plain text"), "plain text");
  });

  it("returns non-strings unchanged", () => {
    assert.strictEqual(redactPrivateKeyMaterial(123), 123);
  });
});

describe("secretMaterial.redactGenericSecrets", () => {
  it("hard-rejects private key blocks instead of accepting redacted key material", () => {
    const input = { logs: [pem("PRIVATE KEY")] };
    assert.throws(
      () => redactGenericSecrets(input),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
    assert.ok(input.logs[0].includes(FAKE_BODY), "input must not be mutated");
  });

  it("redacts Authorization bearer header values", () => {
    const out = redactGenericSecrets("Authorization: Bearer abc123tokenvalue");
    assert.ok(!out.includes("abc123tokenvalue"));
    assert.strictEqual(out, "[REDACTED]");
  });

  it("redacts generic secret assignment values", () => {
    const out = redactGenericSecrets("password=swordfish");
    assert.strictEqual(out, "[REDACTED]");
  });

  it("returns safe redaction metadata without echoing field names", () => {
    const out = redactGenericSecretsWithReport({
      note: "credential=abc",
      authorization: "Authorization: Bearer abc123tokenvalue",
      cookie: "session-value",
    });
    assert.deepStrictEqual(out.value, {
      note: "[REDACTED]",
      authorization: "[REDACTED]",
      cookie: "[REDACTED]",
    });
    assert.strictEqual(out.redactionApplied, true);
    assert.ok(out.redactionCount >= 2);
    assert.ok(out.redactedFields.includes("generic-secret"));
    assert.ok(out.redactedFields.includes("authorization"));
    assert.ok(out.redactedFields.includes("cookie"));
  });

  it("redacts values under generic secret-looking field names", () => {
    const out = redactGenericSecrets({
      password: "swordfish",
      publicStatus: "succeeded",
    });
    assert.deepStrictEqual(out, {
      password: "[REDACTED]",
      publicStatus: "succeeded",
    });
  });

  it("hard-rejects a base64-wrapped private key nested in a structure", () => {
    const wrapped = Buffer.from(pem("RSA PRIVATE KEY")).toString("base64");
    assert.throws(
      () => redactGenericSecrets({ evidence: { blob: wrapped } }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
  });

  it("hard-rejects a Buffer carrying private key material", () => {
    assert.throws(
      () => redactGenericSecrets({ raw: Buffer.from(pem("PRIVATE KEY")) }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
  });

  it("hard-rejects a Buffer carrying PKCS#12/PFX-like material", () => {
    assert.throws(
      () => redactGenericSecrets({ raw: fakePkcs12Buffer() }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
  });

  it("hard-rejects incomplete PEM headers and private-key-shaped fields", () => {
    for (const value of [
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\nincomplete",
      { publicNote: { privateKeyPem: "not-accepted" } },
    ]) {
      assert.throws(
        () => redactGenericSecretsWithReport(value),
        (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
      );
      assert.throws(
        () => assertNoPrivateKeyMaterial(value),
        (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
      );
    }
  });

  it("leaves ordinary content intact", () => {
    assert.strictEqual(
      redactGenericSecrets("renewal succeeded for example.com"),
      "renewal succeeded for example.com",
    );
  });

  it("fails closed on cyclic objects", () => {
    const node = { label: "evidence" };
    node.self = node;
    assert.throws(
      () => redactGenericSecrets(node),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
  });

  it("rejects a key reachable before a cycle closes", () => {
    const node = { secret: pem("RSA PRIVATE KEY") };
    node.self = node;
    assert.throws(
      () => redactGenericSecrets(node),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
  });

  it("classifies private-key and generic secret field names separately", () => {
    assert.strictEqual(fieldNameLooksPrivateKeyMaterial("privateKeyPem"), true);
    assert.strictEqual(fieldNameLooksPrivateKeyMaterial("credential"), false);
    assert.strictEqual(fieldNameLooksGenericSecret("credential"), true);
    assert.strictEqual(fieldNameLooksGenericSecret("publicMetadata"), false);
  });
});
