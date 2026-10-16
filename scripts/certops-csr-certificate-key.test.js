"use strict";
/** Real OpenSSL RSA/EC public-key comparison regressions for the Windows ACME
 * preaccept boundary. Keys remain ephemeral local fixture files and never enter
 * reports. This portable proof does not execute Windows CNG or acceptance. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  certificateMatchesCsr,
} = require("../packages/agent/src/issuers/csr-certificate-key");
test("actual RSA and EC issued public keys must match their own CSR only", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "certops-spki-"));
  const run = (args) => {
    const result = spawnSync("openssl", args, {
      cwd: directory,
      timeout: 20000,
      stdio: "ignore",
    });
    assert.equal(result.status, 0, "OpenSSL fixture command failed");
  };
  try {
    for (const [name, key] of [
      ["rsa", ["rsa:2048"]],
      ["rsa-other", ["rsa:2048"]],
      ["ec", ["ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"]],
      ["ec-other", ["ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"]],
    ]) {
      run([
        "req",
        "-new",
        "-newkey",
        ...key,
        "-nodes",
        "-keyout",
        `${name}.key`,
        "-out",
        `${name}.csr`,
        "-subj",
        "/CN=owned.example.test",
      ]);
      run([
        "x509",
        "-req",
        "-in",
        `${name}.csr`,
        "-signkey",
        `${name}.key`,
        "-out",
        `${name}.crt`,
        "-days",
        "1",
      ]);
    }
    const read = (name) => fs.readFileSync(path.join(directory, name), "utf8");
    for (const name of ["rsa", "ec"]) {
      assert.equal(
        certificateMatchesCsr(read(`${name}.csr`), read(`${name}.crt`)),
        true,
      );
      assert.equal(
        certificateMatchesCsr(
          read(`${name}.csr`),
          read(`${name === "rsa" ? "ec" : "rsa"}.crt`),
        ),
        false,
      );
      assert.equal(
        certificateMatchesCsr(read(`${name}.csr`), read(`${name}-other.crt`)),
        false,
      );
      assert.equal(
        certificateMatchesCsr("malformed", read(`${name}.crt`)),
        false,
      );
      assert.equal(
        certificateMatchesCsr(read(`${name}.csr`), "malformed"),
        false,
      );
      assert.equal(
        certificateMatchesCsr(
          read(`${name}.csr`),
          read(`${name}.crt`).slice(0, 100),
        ),
        false,
      );
      assert.equal(
        certificateMatchesCsr(
          read(`${name}.csr`),
          read(`${name}.csr`).replaceAll("CERTIFICATE REQUEST", "CERTIFICATE"),
        ),
        false,
        "A DER-shaped CSR is not an X.509 leaf",
      );
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("native wrong-key evidence refuses missing custody or restoration facts", () => {
  const {
    verifyProof,
  } = require("../tests/e2e/helpers/certops-windows-wrong-leaf");
  const proof = Object.fromEntries(
    [
      "actualSignedRenewalFailed",
      "actualCsrDiffersFromReturnedLeaf",
      "genuineCaIssuedLeafReused",
      "rejectedUnacceptedKeyRemoved",
      "predecessorCustodyUnchanged",
      "bindingAndTrustedTlsUnchanged",
      "storedProfileUnchanged",
      "configurationRestored",
    ].map((field) => [field, true]),
  );
  assert.equal(verifyProof(proof), true);
  for (const field of Object.keys(proof))
    assert.throws(() => verifyProof({ ...proof, [field]: false }));
});
