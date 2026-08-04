"use strict";

// Property-based fuzzing of the envelope-v2 decoding path in
// packages/agent/src/signing/index.js.
//
// verifyV2Envelope hand-rolls three strict decoders in sequence (base64
// shape check + canonical decode, strict UTF-8 decode, single-JSON-value
// scan/parse) directly on untrusted network input, before ever touching
// the Ed25519 verification result. Hand-written decoders are exactly the
// kind of surface where an edge case (an off-by-one in the JSON scanner, an
// unhandled Buffer allocation on a hostile length, an uncaught exception
// from TextDecoder) can crash the whole process instead of producing a
// clean rejection. This suite throws structured malformed input at
// verifyV2Envelope and asserts, for every input, exactly one of two
// outcomes: a clean { allowed: false, rejectionReason, detail } object, or
// (for a rare validly-signed random construction) { allowed: true, job }.
// Never an uncaught throw, never a hang, never a crash.
//
// fast-check is used here as a lightweight, well-maintained property-based
// testing library (no jsfuzz/jazzer or similar fuzzing tool exists yet in
// this repo's devDependencies).

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");
const crypto = require("node:crypto");
const fc = require("fast-check");

const { ENVELOPE_VERSION_2, verifyV2Envelope } = require("./index.js");

const FUZZ_RUNS = 2000;

const { publicKeyPem, signingKeyId } = (() => {
  const keys = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKey: keys.privateKey,
    signingKeyId: "fuzz-pinned-signing-key",
  };
})();

/**
 * Runs a candidate envelope through verifyV2Envelope and asserts the call
 * never throws and always returns a well-shaped verdict. Returns the
 * verdict so callers can add further assertions.
 *
 * @param {unknown} envelope
 * @returns {{ allowed: boolean }}
 */
function assertNeverThrowsAlwaysWellShaped(envelope) {
  let verdict;
  assert.doesNotThrow(() => {
    verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
  }, `verifyV2Envelope threw on envelope: ${safeDescribe(envelope)}`);

  assert.ok(
    verdict && typeof verdict === "object",
    `verdict must be an object for envelope: ${safeDescribe(envelope)}`,
  );
  assert.ok(
    typeof verdict.allowed === "boolean",
    `verdict.allowed must be a boolean for envelope: ${safeDescribe(envelope)}`,
  );
  if (verdict.allowed) {
    assert.ok(
      verdict.job && typeof verdict.job === "object",
      "an allowed verdict must carry a decoded job object",
    );
  } else {
    assert.equal(typeof verdict.rejectionReason, "string");
    assert.equal(typeof verdict.detail, "string");
  }
  return verdict;
}

function safeDescribe(value) {
  try {
    return JSON.stringify(value);
  } catch (_err) {
    return String(value);
  }
}

// Arbitrary raw byte buffers of varied, sometimes-large lengths, so both
// short and boundary-length inputs get exercised as base64 strings.
const arbitraryBytes = fc
  .uint8Array({ minLength: 0, maxLength: 4096 })
  .map((arr) => Buffer.from(arr));

// Fuzzes payloadB64 with structurally hostile base64 strings: truncated
// base64, embedded nulls (as bytes before encoding), non-canonical padding,
// completely random text, and base64url variants.
const arbitraryPayloadB64Candidate = fc.oneof(
  arbitraryBytes.map((buf) => buf.toString("base64")),
  arbitraryBytes.map((buf) => buf.toString("base64url")),
  fc.string({ maxLength: 4096 }),
  arbitraryBytes.map((buf) => {
    const b64 = buf.toString("base64");
    // Truncate at a random point, which frequently produces non-canonical
    // padding or an incomplete final group.
    return b64.slice(0, Math.max(0, b64.length - 1));
  }),
  arbitraryBytes.map((buf) => `${buf.toString("base64")}\n`),
  arbitraryBytes.map((buf) => buf.toString("base64").replace(/=+$/, "")),
  fc.constant(""),
);

const arbitrarySignatureB64Candidate = fc.oneof(
  arbitraryBytes.map((buf) => buf.toString("base64")),
  fc.string({ maxLength: 256 }),
  fc.constant(""),
);

describe("verifyV2Envelope fuzzing (envelope-v2 decoder)", () => {
  it("never throws and always returns a well-shaped verdict for random envelope shapes", () => {
    fc.assert(
      fc.property(
        fc.record(
          {
            envelopeVersion: fc.constantFrom(
              ENVELOPE_VERSION_2,
              1,
              2,
              "2",
              null,
              undefined,
              3,
              -1,
            ),
            payloadB64: fc.oneof(
              arbitraryPayloadB64Candidate,
              fc.constant(undefined),
              fc.integer(),
              fc.constant(null),
            ),
            signatureB64: fc.oneof(
              arbitrarySignatureB64Candidate,
              fc.constant(undefined),
              fc.integer(),
              fc.constant(null),
            ),
            signingKeyId: fc.oneof(
              fc.constant(signingKeyId),
              fc.string({ maxLength: 200 }),
              fc.constant(undefined),
              fc.integer(),
            ),
          },
          { requiredKeys: [] },
        ),
        (envelope) => {
          assertNeverThrowsAlwaysWellShaped(envelope);
        },
      ),
      { numRuns: FUZZ_RUNS },
    );
  });

  it("never throws on non-object / primitive top-level envelope values", () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.constant(null),
          fc.constant(undefined),
          fc.string(),
          fc.integer(),
          fc.boolean(),
          fc.array(fc.anything()),
          fc.constant(Symbol("fuzz")),
        ),
        (envelope) => {
          assertNeverThrowsAlwaysWellShaped(envelope);
        },
      ),
      { numRuns: 500 },
    );
  });

  it("never throws on payloadB64 that decodes to random bytes fed straight through UTF-8 + JSON parsing", () => {
    // Builds a STRUCTURALLY VALID base64/signature pair (so the decoder
    // reaches the UTF-8 + JSON parsing stages, not just the earlier shape
    // checks) around genuinely random decoded bytes, which are almost never
    // valid UTF-8 or valid JSON.
    fc.assert(
      fc.property(arbitraryBytes, (payloadBytes) => {
        const signatureBytes = crypto.sign(
          null,
          payloadBytes,
          crypto.createPrivateKey(
            crypto
              .generateKeyPairSync("ed25519")
              .privateKey.export({ type: "pkcs8", format: "pem" }),
          ),
        );
        const envelope = {
          envelopeVersion: ENVELOPE_VERSION_2,
          payloadB64: payloadBytes.toString("base64"),
          signatureB64: signatureBytes.toString("base64"),
          signingKeyId,
        };
        assertNeverThrowsAlwaysWellShaped(envelope);
      }),
      { numRuns: 500 },
    );
  });

  it("never throws on truncated / embedded-null / non-canonically-padded base64 payloads specifically", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 1, maxLength: 512 }),
        fc.integer({ min: 0, max: 3 }),
        (rawBytes, paddingVariant) => {
          const buf = Buffer.from(rawBytes);
          let b64 = buf.toString("base64");
          if (paddingVariant === 1) b64 = b64.slice(0, -1); // truncated
          if (paddingVariant === 2) b64 = `${b64}==`; // over-padded
          if (paddingVariant === 3 && b64.length > 0) {
            b64 = `${b64.slice(0, -1)}${b64.at(-1) === "A" ? "B" : "A"}`; // last-char flip
          }
          const envelope = {
            envelopeVersion: ENVELOPE_VERSION_2,
            payloadB64: b64,
            signatureB64: Buffer.alloc(64, 0).toString("base64"),
            signingKeyId,
          };
          assertNeverThrowsAlwaysWellShaped(envelope);
        },
      ),
      { numRuns: 500 },
    );
  });
});
