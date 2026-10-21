/**
 * Regression: a genuine failed-reload dispatch produced a public nonce whose decoded
 * prefix resembled a zlib private container. The result POST was rejected, leaving
 * the job running. Resampling is bounded and retains 24-byte randomness, signing,
 * ownership and replay checks; the private-material detector is unchanged.
 * Run: node --test tests/unit/certops-distribution-nonce.test.js
 */
"use strict";
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const {
  containsPrivateKeyMaterial,
} = require("../../packages/log-scrub/secret-material");
const signing = require("../../apps/api/services/certops/jobSigning");
test("dispatch nonce from real failed distribution outbox is resampled without weakening custody rejection", () => {
  const bad = Buffer.from("OMuMIxYIpFYikkNjwQ-eEldCLnuFEPc_", "base64url");
  assert.equal(bad.length, 24);
  assert.equal(containsPrivateKeyMaterial(bad.toString("base64url")), true);
  const good = Buffer.alloc(24, 0x61);
  let calls = 0;
  const nonce = signing._test.generateNonce((size) => {
    assert.equal(size, 24);
    return calls++ === 0 ? bad : good;
  });
  assert.equal(calls, 2);
  assert.equal(nonce, good.toString("base64url"));
  assert.equal(containsPrivateKeyMaterial({ nonce }), false);
  assert.equal(
    containsPrivateKeyMaterial({ nonce: bad.toString("base64url") }),
    true,
  );
});
test("unsafe RNG candidates cannot loop forever or publish an unreportable nonce", () => {
  let calls = 0;
  assert.throws(
    () =>
      signing._test.generateNonce(() => {
        calls++;
        return Buffer.from("OMuMIxYIpFYikkNjwQ-eEldCLnuFEPc_", "base64url");
      }),
    { code: "CERTOPS_SIGNING_PAYLOAD_INVALID" },
  );
  assert.equal(calls, 16);
});
