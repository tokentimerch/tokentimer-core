"use strict";
/** Offline public-byte generation and proof controls. No service, credential
 * store, native certificate/key, network or actual agent identity is changed. */
const test = require("node:test"),
  assert = require("node:assert/strict");
const h = require("../tests/e2e/helpers/certops-windows-credential-refusal");
test("credential fault copies contain no original secret and select distinct actual-reader errors", () => {
  const original = Buffer.from(
      "private-fixture-original-not-a-real-credential",
    ),
    rows = h.credentialCases(original);
  assert.deepEqual(
    rows.map((x) => x.id),
    h.CASES,
  );
  assert.equal(rows[0].content.length, 0);
  assert.equal(rows[1].content.toString(), "owned-public-invalid-credential");
  assert.ok(rows.every((x) => !x.content.includes(original)));
  assert.ok(!original.equals(rows[1].content));
  assert.throws(() => h.credentialCases(Buffer.alloc(0)));
  assert.throws(() => h.credentialCases("secret"));
});
test("credential startup proof cannot omit native observations or qualify in-flight certificate operations", () => {
  const p = {
    scope: h.SCOPE,
    credentials: [...h.CASES],
    startupFailureCount: 2,
    inFlightMutationQualified: false,
    ...Object.fromEntries(h.FLAGS.map((x) => [x, true])),
  };
  h.verifyProof(p);
  for (const key of Object.keys(p)) {
    const q = { ...p };
    delete q[key];
    assert.throws(() => h.verifyProof(q));
  }
  for (const flag of h.FLAGS)
    assert.throws(() => h.verifyProof({ ...p, [flag]: false }));
  assert.throws(() => h.verifyProof({ ...p, inFlightMutationQualified: true }));
  assert.throws(() => h.verifyProof({ ...p, rawCredential: "secret" }));
});
test("actual protected credential reader refuses empty and malformed owned files then accepts exact repair", () => {
  const fs = require("node:fs"),
    path = require("node:path"),
    os = require("node:os");
  const {
    applyRestrictivePermissions,
  } = require("../packages/agent/src/platform");
  const { readCredential } = require("../packages/agent/src/config");
  const root = fs.mkdtempSync(
      path.join(os.tmpdir(), "owned-credential-reader-"),
    ),
    file = path.join(root, "credential");
  const original = Buffer.from("ttagent_ownedid_publicfixturevalue123");
  try {
    fs.writeFileSync(file, original, { mode: 0o600 });
    applyRestrictivePermissions(file, { kind: "file" });
    assert.ok(
      readCredential(root) === original.toString(),
      "Owned public control credential must be readable",
    );
    for (const row of h.credentialCases(original)) {
      fs.writeFileSync(file, row.content);
      assert.throws(
        () => readCredential(root),
        (error) =>
          error instanceof Error && error.message.includes(row.expectedError),
      );
      assert.ok(fs.readFileSync(file).equals(row.content));
    }
    fs.writeFileSync(file, original);
    assert.ok(
      readCredential(root) === original.toString(),
      "Exact owned public credential repair must succeed",
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
test("actual bounded credential reporter requires complete sidecar for each Windows profile", () => {
  const fs = require("node:fs"),
    path = require("node:path"),
    os = require("node:os"),
    reporter = require("./certops-stack-reporter");
  const root = fs.mkdtempSync(
      path.join(os.tmpdir(), "credential-refusal-report-"),
    ),
    main =
      "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence",
    proof = {
      scope: h.SCOPE,
      credentials: [...h.CASES],
      startupFailureCount: 2,
      inFlightMutationQualified: false,
      ...Object.fromEntries(h.FLAGS.map((x) => [x, true])),
    };
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
          `windows-credential-refusal-${profile}.json`,
        );
      assert.throws(() => reporter.credentialRefusalProof(scope, main, root));
      fs.writeFileSync(file, JSON.stringify(proof));
      assert.deepEqual(
        reporter.credentialRefusalProof(scope, main, root),
        proof,
      );
      fs.writeFileSync(
        file,
        JSON.stringify({ ...proof, inFlightMutationQualified: true }),
      );
      assert.throws(() => reporter.credentialRefusalProof(scope, main, root));
      fs.writeFileSync(
        file,
        JSON.stringify({ ...proof, rawCredential: "secret" }),
      );
      assert.throws(() => reporter.credentialRefusalProof(scope, main, root));
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
test("unresolved credential guard refuses parent cleanup even when original public bytes remain intact", () => {
  const fs = require("node:fs"),
    path = require("node:path"),
    os = require("node:os"),
    engine = require("../tests/e2e/helpers/certops-windows-config-encoding");
  const root = fs.mkdtempSync(
      path.join(os.tmpdir(), "credential-cleanup-guard-"),
    ),
    credential = path.join(root, "credential"),
    bytes = Buffer.from("owned-public-control");
  try {
    fs.writeFileSync(credential, bytes);
    fs.writeFileSync(
      path.join(root, ".installed-credential-refusal-active.json"),
      "owned-guard",
    );
    assert.throws(() => engine.assertCleanupSafe(root));
    assert.ok(fs.readFileSync(credential).equals(bytes));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
