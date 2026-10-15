"use strict";
/** Pure observation controls; no native signing rotation/agent/CA execution. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  crypto = require("node:crypto"),
  h = require("../tests/e2e/helpers/certops-acme-signing-observer");
const id = crypto.randomUUID();
function envelope(key = "certops-test-old", job = id) {
  return {
    envelopeVersion: 2,
    payloadB64: Buffer.from(
      JSON.stringify({ jobId: job, privatePrerequisite: "must-not-persist" }),
    ).toString("base64"),
    signatureB64: "original-signed-bytes",
    signingKeyId: key,
  };
}
const bytes = (jobs) => Buffer.from(JSON.stringify({ jobs }));
test("original signed response observation retains only public job/key identities and leaves bytes unchanged", () => {
  const original = bytes([envelope()]),
    copy = Buffer.from(original),
    observer = h.createClaimObserver();
  observer.observe(original);
  assert.ok(original.equals(copy));
  assert.equal(observer.signingKeyFor(id), "certops-test-old");
  assert.deepEqual(observer.snapshot(), { responseCount: 1, jobCount: 1 });
  assert.deepEqual(h.observeClaimResponse(original), [
    { jobId: id, signingKeyId: "certops-test-old" },
  ]);
  assert.ok(!JSON.stringify(observer.snapshot()).includes("must-not-persist"));
  const fresh = crypto.randomUUID();
  observer.observe(bytes([envelope("certops-test-new", fresh)]));
  assert.equal(observer.signingKeyFor(fresh), "certops-test-new");
  assert.throws(() => observer.observe(bytes([envelope("certops-test-new")])));
});
test("bounded read-only observer refuses ambiguous, malformed and foreign protocol identities", () => {
  for (const value of [
    Buffer.alloc(0),
    Buffer.alloc(1048577),
    Buffer.from("private-parse-sentinel"),
    bytes([envelope(), envelope()]),
    bytes([{ ...envelope(), envelopeVersion: 1 }]),
    bytes([{ ...envelope(), signingKeyId: "bad/key" }]),
    bytes([{ ...envelope(), payloadB64: "not-base64" }]),
    bytes([envelope("safe", "not-a-job")]),
  ])
    assert.throws(() => h.observeClaimResponse(value));
  assert.deepEqual(h.observeClaimResponse(bytes([])), []);
});
