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
