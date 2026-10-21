"use strict";
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const {
  containsPrivateKeyMaterial,
} = require("../../packages/log-scrub/secret-material");
const signing = require("../../apps/api/services/certops/jobSigning");
// 24 bytes shaped like a DER private key (SEQUENCE, INTEGER 0, SEQUENCE): still rejected by the custody detector.
const BAD_NONCE = () => Buffer.concat([Buffer.from([0x30, 0x16, 0x02, 0x01, 0x00, 0x30]), Buffer.alloc(18, 0x41)]);
test("dispatch nonce from real failed distribution outbox is resampled without weakening custody rejection", () => {
  const bad = BAD_NONCE();
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
        return BAD_NONCE();
      }),
    { code: "CERTOPS_SIGNING_PAYLOAD_INVALID" },
  );
  assert.equal(calls, 16);
});
