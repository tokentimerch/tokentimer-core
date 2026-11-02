"use strict";
// Supporting report validation only; native preservation must be observed by
// the disposable installed Windows journey before these flags can be emitted.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const helper = require("../tests/e2e/helpers/certops-windows-key-reuse-refusal");
test("Windows public reuse refusal requires every bounded independent observation", () => {
  const proof = { scope: "public-windows-acme-profile-reuse-refusal", ...Object.fromEntries(helper.fields.map(field => [field, true])) };
  assert.equal(helper.verifyProof(proof), true);
  for (const field of helper.fields) {
    assert.throws(() => helper.verifyProof({ ...proof, [field]: false }));
    const missing = { ...proof }; delete missing[field];
    assert.throws(() => helper.verifyProof(missing));
  }
  assert.throws(() => helper.verifyProof({ ...proof, scope: "installed-agent-invalid-signed-job" }));
  assert.throws(() => helper.verifyProof({ ...proof, privateKey: "forbidden" }));
});

test("Windows reporter reads only the successful main journey's exact profile refusal receipt", () => {
  const fs = require("node:fs"), path = require("node:path");
  const base = path.resolve(__dirname, "../.build"); fs.mkdirSync(base, { recursive: true });
  const root = fs.mkdtempSync(path.join(base, "windows-reuse-reporter-"));
  const read = require("./certops-stack-reporter").windowsKeyReuseRefusalProof;
  const name = "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence";
  try {
    assert.equal(read("agent-protocol-api-worker", name, root), undefined);
    assert.equal(read("real-agent-windows-acme-iis/rsa-2048", helper.scenarioName, root), undefined);
    assert.throws(() => read("real-agent-windows-acme-iis/../../foreign", name, root));
    assert.throws(() => read("real-agent-windows-acme-iis/rsa-2048", name, root));
    fs.mkdirSync(path.join(root, "qualification-results"));
    const proof = { scope: "public-windows-acme-profile-reuse-refusal", ...Object.fromEntries(helper.fields.map(field => [field, true])) };
    const receipt = path.join(root, "qualification-results/windows-key-reuse-refusal-rsa-2048.json");
    fs.writeFileSync(receipt, JSON.stringify(proof), { flag: "wx" });
    assert.deepEqual(read("real-agent-windows-acme-iis/rsa-2048", name, root), proof);
    fs.writeFileSync(receipt, JSON.stringify({ ...proof, noJobAllocated: false }));
    assert.throws(() => read("real-agent-windows-acme-iis/rsa-2048", name, root));
  } finally { fs.rmSync(root, { recursive: true }); }
});
