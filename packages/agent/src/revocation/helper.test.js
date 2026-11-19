"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { X509Certificate } = require("node:crypto");
const { checkObservedCertificate, resolveHelperPath } = require("./helper");

const pem = fs.readFileSync(path.join(__dirname, "../verify/fixtures/chain-leaf.crt.pem"), "utf8");
const fp = new X509Certificate(pem).fingerprint256.replace(/:/g, "").toLowerCase();
function fakeHelper(result) {
  return () => spawn(process.execPath, ["-e", `process.stdin.resume(); process.stdin.on('end',()=>console.log(${JSON.stringify(JSON.stringify(result))}));`], { stdio: ["pipe", "pipe", "ignore"] });
}

test("rejects mismatched fingerprints and non-public material before executing helper", async () => {
  let called = false;
  const spawnImpl = () => { called = true; throw new Error("must not spawn"); };
  assert.equal((await checkObservedCertificate({ certificatePem: pem, fingerprintSha256: "0".repeat(64), roots: [pem], spawnImpl })).verdict, "unknown");
  assert.equal((await checkObservedCertificate({ certificatePem: pem, fingerprintSha256: fp, roots: [pem + "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----"], spawnImpl })).verdict, "unknown");
  assert.equal(called, false);
});

test("accepts a valid helper verdict and rejects an untrusted or malformed result", async () => {
  const checkedAt = "2026-01-01T00:00:00Z", validUntil = "2026-01-01T01:00:00Z";
  const args = { certificatePem: pem, fingerprintSha256: fp, roots: [pem] };
  const good = await checkObservedCertificate({ ...args, spawnImpl: fakeHelper({ verdict: "good", chainStatus: "valid", checkedAt, validUntil }) });
  assert.equal(good.verdict, "good");
  const forged = await checkObservedCertificate({ ...args, spawnImpl: fakeHelper({ verdict: "good", chainStatus: "invalid", checkedAt, validUntil }) });
  assert.equal(forged.verdict, "unknown");
  const invalidDate = await checkObservedCertificate({ ...args, spawnImpl: fakeHelper({ verdict: "good", chainStatus: "valid", checkedAt, validUntil: checkedAt }) });
  assert.equal(invalidDate.verdict, "unknown");
});

test("unsupported platforms have no helper and a missing binary reports unknown", async () => {
  assert.equal(resolveHelperPath({ platform: "darwin", arch: "x64" }), null);
  assert.equal((await checkObservedCertificate({ helperPath: path.join(__dirname, "missing-helper"), certificatePem: pem, fingerprintSha256: fp, roots: [pem] })).verdict, "unknown");
});

test("accepts only a revoked issuer fingerprint from supplied intermediate certificates", async () => {
  const checkedAt = "2026-01-01T00:00:00Z", validUntil = "2026-01-01T01:00:00Z";
  const issuer = fs.readFileSync(path.join(__dirname, "../verify/fixtures/intermediate.crt.pem"), "utf8");
  const issuerFp = new X509Certificate(issuer).fingerprint256.replace(/:/g, "").toLowerCase();
  const args = { certificatePem: pem, fingerprintSha256: fp, roots: [pem], intermediates: [issuer] };
  const result = { verdict: "issuer_revoked", chainStatus: "valid", checkedAt, validUntil, revokedIssuerFingerprintSha256: issuerFp };
  assert.equal((await checkObservedCertificate({ ...args, spawnImpl: fakeHelper(result) })).revokedIssuerFingerprintSha256, issuerFp);
  assert.equal((await checkObservedCertificate({ ...args, spawnImpl: fakeHelper({ ...result, revokedIssuerFingerprintSha256: "a".repeat(64) }) })).verdict, "unknown");
  assert.equal((await checkObservedCertificate({ ...args, spawnImpl: fakeHelper({ ...result, verdict: "good" }) })).verdict, "unknown");
});

test("separates operating-system trust and fails closed when an older helper rejects the protocol", async () => {
  const args = { certificatePem: pem, fingerprintSha256: fp, roots: [], systemRoots: [pem], systemIntermediates: [pem] };
  const spawnImpl = () => spawn(process.execPath, ["-e", `let s=''; process.stdin.on('data',x=>s+=x); process.stdin.on('end',()=>{const v=JSON.parse(s);if(v.roots.length!==0||v.systemRoots.length!==1||v.systemIntermediates.length!==1)process.exit(2);console.log(JSON.stringify({verdict:'good',chainStatus:'valid',checkedAt:'2026-01-01T00:00:00Z',validUntil:'2026-01-01T01:00:00Z'}));});`], { stdio: ["pipe", "pipe", "ignore"] });
  assert.equal((await checkObservedCertificate({ ...args, spawnImpl })).verdict, "good");
  const oldHelper = () => spawn(process.execPath, ["-e", "process.stdin.resume();process.stdin.on('end',()=>process.exit(1));"], { stdio: ["pipe", "pipe", "ignore"] });
  assert.equal((await checkObservedCertificate({ ...args, spawnImpl: oldHelper })).verdict, "unknown");
});
