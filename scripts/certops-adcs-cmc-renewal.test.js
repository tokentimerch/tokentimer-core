"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const subject = require("../tests/e2e/helpers/certops-adcs-cmc-renewal");

const root = path.resolve(__dirname, "..");
const keys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const foreignKeys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const owner = "owned-run";

function renewal(requestId, extra = {}) {
  return subject.signOwnedRenewal({
    owner,
    template: "TTQualificationRSAShort",
    requestId,
    ...extra,
  }, keys.privateKey);
}

test("a signature over the owned renewal is required", () => {
  const signed = renewal("11");
  const proof = subject.acceptSignedRenewal(signed, keys.publicKey, owner);
  subject.verifyProof(proof);
  assert.equal(proof.case, "signed-renewal");
  assert.equal(proof.signatureVerified, true);
  assert.equal(proof.ownerMatched, true);
  assert.equal(proof.nativeExecutionQualified, false);
  assert.equal(proof.hostCapabilityAbsentIsPass, false);
  assert.equal(proof.disposableForestRan, false);
  assert.throws(() => subject.acceptSignedRenewal({ ...signed, signature: "" }, keys.publicKey, owner), /Unsigned CMC renewal/);
  const foreign = subject.signOwnedRenewal({
    owner: "foreign-run",
    template: "TTQualificationRSAShort",
    requestId: "11",
  }, foreignKeys.privateKey);
  assert.throws(() => subject.acceptSignedRenewal(foreign, foreignKeys.publicKey, owner), /Foreign CMC renewal/);
  const bytes = Buffer.from(signed.signature, "base64");
  bytes[bytes.length - 1] ^= 0xff;
  assert.throws(() => subject.acceptSignedRenewal({ ...signed, signature: bytes.toString("base64") }, keys.publicKey, owner), /signature rejected/);
  assert.throws(() => subject.verifyProof({ ...proof, nativeExecutionQualified: true }));
});

test("a repeated unattended renewal keeps the template and consumes a new request id", () => {
  const first = renewal("11", { consumed: true });
  const second = renewal("12", { consumed: true });
  const repeated = subject.acceptRepeatedRenewal(first, second, keys.publicKey, owner);
  subject.verifyProof(repeated.proof);
  assert.equal(repeated.proof.case, "repeated-unattended");
  assert.equal(repeated.proof.template, "TTQualificationRSAShort");
  assert.equal(repeated.proof.priorRequestId, "11");
  assert.equal(repeated.proof.requestId, "12");
  assert.equal(repeated.proof.consumedRequestReused, false);
  assert.equal(repeated.proof.nativeExecutionQualified, false);
  assert.throws(() => subject.acceptRepeatedRenewal(first, renewal("11", { consumed: true }), keys.publicKey, owner), /Consumed request id reused/);
  const other = subject.signOwnedRenewal({
    owner,
    template: "TTQualificationRSA3072",
    requestId: "13",
    consumed: true,
  }, keys.privateKey);
  assert.throws(() => subject.acceptRepeatedRenewal(first, other, keys.publicKey, owner), /template changed/);
  assert.throws(() => subject.acceptRepeatedRenewal(renewal("11"), second, keys.publicKey, owner), /consumed request/);
});

test("a missing lab fails closed", () => {
  assert.equal(subject.assessLab({}, "win32").hostCapabilityAbsentIsPass, false);
  assert.throws(() => subject.qualifyCmcRenewal({ env: {}, platform: "win32" }), /Disposable AD CS forest is required/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "adcs-cmc-"));
  const reportPath = path.join(dir, "report.json");
  try {
    const env = { ...process.env, CERTOPS_ADCS_CMC_RENEWAL_REPORT: reportPath };
    delete env.CERTOPS_ADCS_DISPOSABLE_LAB;
    const result = spawnSync(process.execPath, [path.join(root, "scripts/certops-adcs-cmc-renewal.js")], { encoding: "utf8", env });
    assert.equal(result.status, 1);
    const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    assert.equal(report.status, "failed");
    assert.equal(report.evidenceLevel, "integration");
    assert.equal(report.nativeExecutionQualified, false);
    assert.equal(report.hostCapabilityAbsentIsPass, false);
    assert.equal(report.disposableForestRan, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  for (const rel of subject.REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
});
