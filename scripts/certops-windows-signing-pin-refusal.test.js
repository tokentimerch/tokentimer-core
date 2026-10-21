"use strict";
/** Actual public-pin reader plus closed proof controls; no native state changes. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path"),
  crypto = require("node:crypto");
const h = require("../tests/e2e/helpers/certops-windows-signing-pin-refusal"),
  { readSigningKeyPin } = require("../packages/agent/src/config");
test("actual pin reader refuses both public malformed copies then accepts exact original repair", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "owned-public-pin-")),
    file = path.join(root, "signing-key-pin.json");
  const original = Buffer.from(
    JSON.stringify({
      signingKeyId: "owned-public-control",
      publicKeyPem: crypto
        .generateKeyPairSync("ed25519")
        .publicKey.export({ type: "spki", format: "pem" }),
    }),
  );
  try {
    fs.writeFileSync(file, original, { flag: "wx", mode: 0o600 });
    const expected = readSigningKeyPin(root);
    for (const row of h.pinCases(original)) {
      fs.writeFileSync(file, row.content);
      assert.throws(
        () => readSigningKeyPin(root),
        (error) => error.message.includes(row.expectedError),
      );
      assert.ok(fs.readFileSync(file).equals(row.content));
    }
    fs.writeFileSync(file, original);
    assert.deepEqual(readSigningKeyPin(root), expected);
    assert.ok(fs.readFileSync(file).equals(original));
    assert.throws(() => h.pinCases(Buffer.from("{}")));
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});
test("pin startup proof cannot qualify missing-pin enrollment or active mutation", () => {
  const p = {
    scope: h.SCOPE,
    pins: [...h.CASES],
    startupFailureCount: 2,
    missingPinQualified: false,
    inFlightMutationQualified: false,
    ...Object.fromEntries(h.FLAGS.map((k) => [k, true])),
  };
  h.verifyProof(p);
  for (const k of Object.keys(p)) {
    const bad = { ...p };
    delete bad[k];
    assert.throws(() => h.verifyProof(bad));
  }
  for (const k of h.FLAGS)
    assert.throws(() => h.verifyProof({ ...p, [k]: false }));
  for (const patch of [
    { missingPinQualified: true },
    { inFlightMutationQualified: true },
    { rawOriginalPin: "private" },
    { pins: [h.CASES[0]] },
  ])
    assert.throws(() => h.verifyProof({ ...p, ...patch }));
});

test("unresolved signing-pin guard blocks cleanup independently of unchanged original public bytes", () => {
  const engine = require("../tests/e2e/helpers/certops-windows-config-encoding"),
    root = fs.mkdtempSync(path.join(os.tmpdir(), "owned-pin-guard-")),
    marker = path.join(root, ".installed-signing-pin-refusal-active.json"),
    pin = path.join(root, "signing-key-pin.json");
  try {
    fs.writeFileSync(pin, "original public pin");
    fs.writeFileSync(marker, "owned pending");
    assert.throws(() => engine.assertCleanupSafe(root));
    assert.equal(fs.readFileSync(pin, "utf8"), "original public pin");
    fs.unlinkSync(marker);
    engine.assertCleanupSafe(root);
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

test("actual pin sidecar reporter requires complete bounded proof for every Windows key profile", () => {
  const {
      fixture,
    } = require("./fixtures/certops-windows-signing-pin-refusal.cjs"),
    { signingPinRefusalProof: read } = require("./certops-stack-reporter"),
    root = fs.mkdtempSync(path.join(os.tmpdir(), "owned-pin-report-")),
    name =
      "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence";
  try {
    fs.mkdirSync(path.join(root, "qualification-results"));
    for (const profile of [
      "rsa-2048",
      "rsa-3072",
      "rsa-4096",
      "ec-p256",
      "ec-p384",
    ]) {
      const scope = "real-agent-windows-acme-iis/" + profile,
        file = path.join(
          root,
          "qualification-results",
          `windows-signing-pin-refusal-${profile}.json`,
        );
      assert.throws(() => read(scope, name, root));
      fs.writeFileSync(file, JSON.stringify(fixture()));
      assert.deepEqual(read(scope, name, root), fixture());
      for (const patch of [
        { twoActualSystemPinFailures: false },
        { missingPinQualified: true },
        { inFlightMutationQualified: true },
        { rawPin: "private" },
      ]) {
        fs.writeFileSync(file, JSON.stringify({ ...fixture(), ...patch }));
        assert.throws(() => read(scope, name, root));
      }
      fs.unlinkSync(file);
    }
    assert.equal(read("real-agent-acme-filesystem", name, root), undefined);
    assert.throws(() =>
      read("real-agent-windows-acme-iis/unknown", name, root),
    );
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});
