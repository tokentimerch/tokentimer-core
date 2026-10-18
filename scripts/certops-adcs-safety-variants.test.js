"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const subject = require("../tests/e2e/helpers/certops-adcs-safety-variants");
const revoked = require("../tests/e2e/helpers/certops-adcs-ocsp-revoked");

const root = path.resolve(__dirname, "..");

test("each safety variant fails closed", () => {
  const cases = [
    ["template-mismatch", { requestedTemplate: "TTQualificationRSAShort", confirmedTemplate: "TTQualificationRSA3072" }],
    ["allowlist-miss", { template: "ForeignTemplate" }],
    ["disallowed-algorithm", { algorithm: "md5" }],
    ["foreign-request", { owner: "foreign-run", ownedOwner: "owned-run" }],
    ["revocation-ocsp-disagreement", { crlStatus: "revoked", ocspStatus: "good", authoritativeRevokedStatusQualified: true }],
  ];
  assert.deepEqual(cases.map((item) => item[0]), [...subject.VARIANTS]);
  for (const [variant, input] of cases) {
    const result = subject.refuseSafety(variant, input);
    subject.verifyProof(result.proof);
    assert.equal(result.ok, false);
    assert.equal(result.proof.closed, true);
    assert.equal(result.proof.variant, variant);
    assert.equal(result.proof.authoritativeRevokedStatusQualified, false);
    assert.equal(result.proof.nativeExecutionQualified, false);
    assert.equal(result.proof.hostCapabilityAbsentIsPass, false);
    assert.equal(result.proof.disposableForestRan, false);
  }
  assert.throws(() => subject.refuseSafety("template-mismatch", { requestedTemplate: "TTQualificationRSAShort", confirmedTemplate: "TTQualificationRSAShort" }));
  assert.throws(() => subject.refuseSafety("allowlist-miss", { template: "TTQualificationRSAShort" }));
  assert.throws(() => subject.refuseSafety("disallowed-algorithm", { algorithm: "rsa-2048" }));
  assert.throws(() => subject.refuseSafety("foreign-request", { owner: "owned-run", ownedOwner: "owned-run" }));
  assert.throws(() => subject.refuseSafety("revocation-ocsp-disagreement", { crlStatus: "revoked", ocspStatus: "revoked" }));
  assert.throws(() => subject.verifyProof({
    ...subject.refuseSafety("foreign-request", { owner: "foreign-run", ownedOwner: "owned-run" }).proof,
    authoritativeRevokedStatusQualified: true,
  }));
});

test("the authoritative OCSP revoked proof stays closed", () => {
  const fixture = require("./fixtures/certops-adcs-ocsp-revoked.cjs").proof;
  const proof = fixture();
  assert.equal(proof.authoritativeRevokedStatusQualified, true);
  assert.equal(subject.assertAuthoritativeRevokedIntact(proof, revoked.verifyProof), true);
  assert.throws(() => revoked.verifyProof({ ...proof, authoritativeRevokedStatusQualified: false }));
  assert.throws(() => subject.verifyProof(proof));
  assert.equal(subject.assessLab({}, "win32").passed, false);
  assert.throws(() => subject.qualifySafetyVariants({ env: {}, platform: "win32" }), /Disposable AD CS forest is required/);
});

test("command entry writes a failed report", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "adcs-safety-"));
  const reportPath = path.join(dir, "report.json");
  try {
    const env = { ...process.env, CERTOPS_ADCS_SAFETY_VARIANTS_REPORT: reportPath };
    delete env.CERTOPS_ADCS_DISPOSABLE_LAB;
    const result = spawnSync(process.execPath, [path.join(root, "scripts/certops-adcs-safety-variants.js")], { encoding: "utf8", env });
    assert.equal(result.status, 1);
    const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    assert.equal(report.status, "failed");
    assert.equal(report.authoritativeRevokedStatusQualified, false);
    assert.equal(report.nativeExecutionQualified, false);
    assert.equal(report.hostCapabilityAbsentIsPass, false);
    assert.equal(report.disposableForestRan, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  for (const rel of subject.REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
});
