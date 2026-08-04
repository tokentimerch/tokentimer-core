"use strict";

// Inverse must-fail tests, named individually.
//
// The negative/fail-closed guarantees for the signed-dispatch envelope
// protocol (ADR-0012 decision 2's normative verification order, steps 1-8
// and 13, implemented by verifyV2Envelope / verifyJobEnvelope in
// ./index.js) were previously only prose in the ADR and manual
// verification. This file gives each guarantee below its own name and its
// own assertion, so a regression that silently reopens one of them shows
// up as a single named test failure instead of nothing at all.
//
// This file adds ONLY the cases not already covered by an individually
// named test elsewhere, to avoid duplicate assertions. Cases already
// covered, and where to find them:
//
//   - base64url alphabet in payloadB64                 signing.test.js: "rejects base64url-encoded payloadB64 (- and _ are not standard base64)"
//   - embedded whitespace in payloadB64                signing.test.js: "rejects payloadB64 with embedded whitespace (not standard base64)"
//   - non-canonical base64 (bit-flip) in payloadB64    signing.test.js: "rejects non-canonical base64 (decode-then-re-encode does not round-trip)"
//   - invalid UTF-8 after decoding                     signing.test.js: "rejects malformed UTF-8 in the payload bytes, though the signature verifies"
//   - UTF-8 BOM at the start of the decoded payload     signing.test.js: "rejects a payload with a leading UTF-8 BOM even though the signature verifies"
//   - trailing whitespace after the JSON value          signing.test.js: "rejects trailing content after the JSON value, even whitespace-only, though the signature verifies"
//   - signatureB64 too short (not 64 decoded bytes)      signing.test.js: "rejects a signature that is not exactly 64 decoded bytes"
//   - payload signingKeyId disagrees with wrapper's     signing.test.js: "rejects a v2 payload whose own signingKeyId disagrees with the wrapper's, even though the signature verifies (ADR-0012 decision 2 step 13 / decision 3)"
//     (this was a real bug, fixed in commit e7999a9 "Enforce step 13
//     signingKeyId equality in the v2 payload, not just the wrapper")
//   - payload omits signingKeyId entirely                signing.test.js: "rejects a v2 payload that omits signingKeyId entirely, even though the signature verifies"
//   - wrapper signingKeyId mismatch vs pinned key        signing.test.js: "rejects a signingKeyId mismatch before touching payload bytes"
//   - whole-payload substitution (signature stale)       signing.test.js: "rejects a tampered payload (signature no longer matches)"
//   - payloadB64 exceeding the max ENCODED length         signing.test.js: "rejects payloadB64 exceeding the maximum encoded length"
//   - unrecognized numeric envelopeVersion                signing.test.js: "rejects an unrecognized envelopeVersion with a clear reason, never silently falling back to v1"
//   - v1 path: malformed/missing signed fields, key-id
//     mismatch, cross-key forgery, hostile inputs          signing.test.js describe("verifyJobSignature")
//   - time-window / clock-drift handling (step 14)         signing.test.js describe("checkJobTimeWindow")
//
// Cases considered but deliberately NOT added here, and why:
//
//   - "agentId present in the payload but not matching the identity the job
//     was dispatched to." ADR-0012 decision 2's normative order names this
//     step 11, "validate agentId against the client's own bound identity",
//     but that step is NOT implemented anywhere client-side yet (in this
//     file, in packages/agent/src/index.js's handleSignedJob, or elsewhere
//     in this package). Faking a test against verifyV2Envelope itself would
//     test a control that function does not own, and does not exist. The
//     agentId-binding gate is expected to land on certops/reference-clients
//     (agent-id-binding-v1), which should add the real must-fail test for
//     this case once the check itself exists.
//
//   - "Oversized decoded payload exceeding whatever max-size bound the code
//     enforces." V2_MAX_ENCODED_PAYLOAD_CHARS (65536) and
//     V2_MAX_DECODED_PAYLOAD_BYTES (49152) are pinned so that
//     floor(65536/4)*3 == 49152 exactly (see the comment above their
//     definitions in index.js): any base64 string within the encoded bound
//     decodes to at most 49152 bytes, so the encoded-length check (already
//     covered by "rejects payloadB64 exceeding the maximum encoded length")
//     always rejects first. No input exists that passes the encoded check
//     and still exceeds the decoded check, so a distinct test for the
//     decoded bound cannot be constructed; it is not dead code, it is an
//     unreachable-by-construction second gate on the identical ceiling.
//
//   - "If the code enforces a decompression/expansion bound." It does not:
//     there is no decompression anywhere in this module (payloadB64 is
//     base64-decoded straight to the signed bytes, no gzip/deflate layer
//     exists). Adding a test for a control that is not implemented would be
//     fabricating coverage for something that does not exist.

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const {
  SIGNING_REJECTION_REASONS,
  ENVELOPE_VERSION_2,
  verifyV2Envelope,
  verifyJobEnvelope,
  generateSigningKeyPair,
} = require("./index.js");

/**
 * Builds a well-formed v2 envelope by signing the raw JSON bytes of `job`
 * (mirrors buildV2Envelope in signing.test.js; redefined locally because
 * that file does not export it).
 */
function buildV2Envelope({ job, privateKeyPem, signingKeyId, overrides = {} }) {
  const payloadBytes = Buffer.from(JSON.stringify(job), "utf8");
  const signatureBytes = crypto.sign(
    null,
    payloadBytes,
    crypto.createPrivateKey(privateKeyPem),
  );
  return {
    envelopeVersion: ENVELOPE_VERSION_2,
    payloadB64: payloadBytes.toString("base64"),
    signatureB64: signatureBytes.toString("base64"),
    signingKeyId,
    ...overrides,
  };
}

function assertRejectedIntegrityFailure(verdict) {
  assert.equal(verdict.allowed, false);
  assert.equal(
    verdict.rejectionReason,
    SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
  );
  assert.equal(typeof verdict.detail, "string");
  assert.ok(verdict.detail.length > 0);
}

describe("verifyV2Envelope: non-canonical base64 padding on payloadB64 (ADR-0012 decision 2 steps 2-4)", () => {
  // Each case below is pattern-valid (V2_BASE64_PATTERN allows 0-2 trailing
  // '=' characters) but fails the decode-then-re-encode canonical check,
  // which is a distinct failure mode from the alphabet/whitespace cases
  // already covered in signing.test.js. Raw byte buffers (not JSON) are
  // used, same as the base64url test in signing.test.js, because rejection
  // happens at the canonical-base64 check, before any JSON parsing.
  const { publicKeyPem, privateKeyPem, signingKeyId } = generateSigningKeyPair();

  function sigFor(bytes) {
    return crypto
      .sign(null, bytes, crypto.createPrivateKey(privateKeyPem))
      .toString("base64");
  }

  it("fails closed on payloadB64 with padding appended where none is required", () => {
    // 3 bytes -> base64 length is a multiple of 4, no padding needed.
    const bytes = Buffer.from([0x41, 0x42, 0x43]);
    const payloadB64 = `${bytes.toString("base64")}==`;
    const verdict = verifyV2Envelope({
      envelope: {
        envelopeVersion: ENVELOPE_VERSION_2,
        payloadB64,
        signatureB64: sigFor(bytes),
        signingKeyId,
      },
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assertRejectedIntegrityFailure(verdict);
    assert.match(verdict.detail, /not canonical base64/);
  });

  it("fails closed on payloadB64 with one extra padding character beyond canonical", () => {
    // 2 bytes -> canonical encoding needs exactly one trailing '='.
    const bytes = Buffer.from([0x41, 0x42]);
    const payloadB64 = `${bytes.toString("base64")}=`; // canonical has 1 '=', this has 2
    const verdict = verifyV2Envelope({
      envelope: {
        envelopeVersion: ENVELOPE_VERSION_2,
        payloadB64,
        signatureB64: sigFor(bytes),
        signingKeyId,
      },
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assertRejectedIntegrityFailure(verdict);
    assert.match(verdict.detail, /not canonical base64/);
  });

  it("fails closed on payloadB64 with insufficient padding characters (missing padding)", () => {
    // 1 byte -> canonical encoding needs exactly two trailing '=' characters.
    const bytes = Buffer.from([0x41]);
    const canonical = bytes.toString("base64");
    const payloadB64 = canonical.slice(0, -1); // drop one required '='
    const verdict = verifyV2Envelope({
      envelope: {
        envelopeVersion: ENVELOPE_VERSION_2,
        payloadB64,
        signatureB64: sigFor(bytes),
        signingKeyId,
      },
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assertRejectedIntegrityFailure(verdict);
    assert.match(verdict.detail, /not canonical base64/);
  });
});

describe("verifyV2Envelope: base64 alphabet and whitespace on signatureB64 (ADR-0012 decision 2 step 2)", () => {
  // signing.test.js exercises these exact malformations against payloadB64;
  // ADR-0012 pins the identical alphabet/whitespace/padding rule for
  // signatureB64, and that field has no equivalent coverage yet.
  const { publicKeyPem, privateKeyPem, signingKeyId } = generateSigningKeyPair();

  it("fails closed on a signatureB64 containing base64url alphabet characters (- and _)", () => {
    // A signature over a fixed jobId is a deterministic function of the
    // (freshly generated) keypair, so roughly 6.5% of keypairs would sign
    // "job-1" to a base64 string with neither '+' nor '/' -- not silently
    // wrong, but flaky, since the base64url substitution below would be a
    // no-op against that particular signature. Looping the jobId suffix
    // (which changes the signed bytes, and therefore the signature) until
    // one produces a base64 encoding containing '+' or '/' makes this
    // deterministic without pinning a fixture keypair, for the same reason
    // signing.test.js picks a fixed byte sequence for the payloadB64
    // version of this case.
    let payloadBytes;
    let signatureB64;
    for (let attempt = 0; attempt < 200; attempt += 1) {
      const job = { jobId: `job-1-${attempt}`, signingKeyId };
      const candidatePayloadBytes = Buffer.from(JSON.stringify(job), "utf8");
      const candidateSignatureB64 = crypto
        .sign(null, candidatePayloadBytes, crypto.createPrivateKey(privateKeyPem))
        .toString("base64");
      if (candidateSignatureB64.includes("+") || candidateSignatureB64.includes("/")) {
        payloadBytes = candidatePayloadBytes;
        signatureB64 = candidateSignatureB64;
        break;
      }
    }
    if (!signatureB64) {
      // Astronomically unlikely (roughly 0.065^200): fail loudly rather
      // than silently passing a test that tested nothing.
      throw new Error(
        "could not find a jobId suffix producing a signature with '+' or '/' " +
          "after 200 attempts; cannot exercise the base64url substitution",
      );
    }
    const envelope = {
      envelopeVersion: ENVELOPE_VERSION_2,
      payloadB64: payloadBytes.toString("base64"),
      signatureB64: signatureB64.replace(/\+/g, "-").replace(/\//g, "_"),
      signingKeyId,
    };
    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assertRejectedIntegrityFailure(verdict);
    assert.match(verdict.detail, /signatureB64/);
  });

  it("fails closed on a signatureB64 with embedded whitespace", () => {
    const job = { jobId: "job-1", signingKeyId };
    const payloadBytes = Buffer.from(JSON.stringify(job), "utf8");
    const signatureBytes = crypto.sign(
      null,
      payloadBytes,
      crypto.createPrivateKey(privateKeyPem),
    );
    const signatureB64 = signatureBytes.toString("base64");
    const withWhitespace = `${signatureB64.slice(0, 4)} ${signatureB64.slice(4)}`;
    const envelope = {
      envelopeVersion: ENVELOPE_VERSION_2,
      payloadB64: payloadBytes.toString("base64"),
      signatureB64: withWhitespace,
      signingKeyId,
    };
    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assertRejectedIntegrityFailure(verdict);
    assert.match(verdict.detail, /signatureB64/);
  });
});

describe("verifyV2Envelope: Ed25519 signature length and key-type bounds (ADR-0012 decision 2 step 5)", () => {
  it("fails closed on a signatureB64 that decodes to more than 64 bytes (too long)", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } = generateSigningKeyPair();
    const job = { jobId: "job-1", signingKeyId };
    const payloadBytes = Buffer.from(JSON.stringify(job), "utf8");
    const realSignature = crypto.sign(
      null,
      payloadBytes,
      crypto.createPrivateKey(privateKeyPem),
    );
    const tooLong = Buffer.concat([realSignature, Buffer.from([0x00])]);
    const verdict = verifyV2Envelope({
      envelope: {
        envelopeVersion: ENVELOPE_VERSION_2,
        payloadB64: payloadBytes.toString("base64"),
        signatureB64: tooLong.toString("base64"),
        signingKeyId,
      },
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assertRejectedIntegrityFailure(verdict);
    assert.match(verdict.detail, /decodes to 65 bytes/);
  });

  it("fails closed, does not throw, when the pinned public key is not Ed25519 (RSA)", () => {
    // Defense in depth: config/index.js is the primary enforcement point
    // (it rejects a non-Ed25519 signingPublicKeyPem at config-write time,
    // per ADR-0003), but verifyV2Envelope must not crash the process if it
    // is ever handed one anyway; crypto.verify(null, ...) against a
    // non-Ed25519 key returns false rather than throwing, which this test
    // pins so a future refactor cannot turn that into an uncaught throw.
    const { privateKeyPem, signingKeyId } = generateSigningKeyPair();
    const { publicKey: rsaPublicKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    const rsaPublicKeyPem = rsaPublicKey
      .export({ type: "spki", format: "pem" })
      .toString();

    const job = { jobId: "job-1", signingKeyId };
    const envelope = buildV2Envelope({ job, privateKeyPem, signingKeyId });

    let verdict;
    assert.doesNotThrow(() => {
      verdict = verifyV2Envelope({
        envelope,
        publicKeyPem: rsaPublicKeyPem,
        pinnedSigningKeyId: signingKeyId,
      });
    });
    assertRejectedIntegrityFailure(verdict);
  });
});

describe("verifyV2Envelope: byte-level tamper detection on the signed bytes (ADR-0012 decision 2 step 5)", () => {
  // Distinct from signing.test.js's "rejects a tampered payload" case,
  // which substitutes an entirely different re-serialized payload. These
  // cases flip exactly one bit, which is the minimal possible tamper and
  // the strongest evidence that verification operates on exact bytes, not
  // on some looser structural comparison.
  const { publicKeyPem, privateKeyPem, signingKeyId } = generateSigningKeyPair();

  it("rejects a payload with a single bit flipped, leaving the signature untouched", () => {
    const job = { jobId: "job-1", signingKeyId };
    const payloadBytes = Buffer.from(JSON.stringify(job), "utf8");
    const signatureBytes = crypto.sign(
      null,
      payloadBytes,
      crypto.createPrivateKey(privateKeyPem),
    );
    const flippedPayload = Buffer.from(payloadBytes);
    flippedPayload[0] ^= 0x01;

    const verdict = verifyV2Envelope({
      envelope: {
        envelopeVersion: ENVELOPE_VERSION_2,
        payloadB64: flippedPayload.toString("base64"),
        signatureB64: signatureBytes.toString("base64"),
        signingKeyId,
      },
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assertRejectedIntegrityFailure(verdict);
    assert.match(verdict.detail, /signature verification failed/);
  });

  it("rejects a signature with a single bit flipped, leaving the payload untouched", () => {
    const job = { jobId: "job-1", signingKeyId };
    const payloadBytes = Buffer.from(JSON.stringify(job), "utf8");
    const signatureBytes = crypto.sign(
      null,
      payloadBytes,
      crypto.createPrivateKey(privateKeyPem),
    );
    const flippedSignature = Buffer.from(signatureBytes);
    flippedSignature[0] ^= 0x01;

    const verdict = verifyV2Envelope({
      envelope: {
        envelopeVersion: ENVELOPE_VERSION_2,
        payloadB64: payloadBytes.toString("base64"),
        signatureB64: flippedSignature.toString("base64"),
        signingKeyId,
      },
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assertRejectedIntegrityFailure(verdict);
    assert.match(verdict.detail, /signature verification failed/);
  });
});

describe("verifyV2Envelope: single JSON value framing (ADR-0012 decision 2 steps 7-8)", () => {
  it("rejects a second JSON value concatenated after the first", () => {
    // signing.test.js already covers whitespace-only trailing content; this
    // covers the other framing violation considered above: a second,
    // structurally valid JSON document appended right after the first one,
    // with no separator at all.
    const { publicKeyPem, privateKeyPem, signingKeyId } = generateSigningKeyPair();
    const firstValue = Buffer.from(
      JSON.stringify({ jobId: "job-1", signingKeyId }),
      "utf8",
    );
    const secondValue = Buffer.from(JSON.stringify({ jobId: "job-2" }), "utf8");
    const concatenated = Buffer.concat([firstValue, secondValue]);
    const signatureBytes = crypto.sign(
      null,
      concatenated,
      crypto.createPrivateKey(privateKeyPem),
    );

    const verdict = verifyV2Envelope({
      envelope: {
        envelopeVersion: ENVELOPE_VERSION_2,
        payloadB64: concatenated.toString("base64"),
        signatureB64: signatureBytes.toString("base64"),
        signingKeyId,
      },
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assertRejectedIntegrityFailure(verdict);
    assert.match(verdict.detail, /not exactly one/);
  });
});

describe("verifyJobEnvelope: envelopeVersion type validation", () => {
  it("rejects envelopeVersion given as a string instead of a number, never falling back to v1", () => {
    // signing.test.js covers an unrecognized NUMERIC envelopeVersion (99);
    // this covers the wrong-type case, which the strict `=== 2` /
    // `!== ENVELOPE_VERSION_1` checks in verifyJobEnvelope must also catch,
    // rather than coercing "2" into the v2 path or silently treating it as
    // legacy v1.
    const { publicKeyPem, privateKeyPem, signingKeyId } = generateSigningKeyPair();
    const job = { jobId: "job-1", signingKeyId };
    const envelope = buildV2Envelope({
      job,
      privateKeyPem,
      signingKeyId,
      overrides: { envelopeVersion: "2" },
    });

    const verdict = verifyJobEnvelope({
      claimed: envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assertRejectedIntegrityFailure(verdict);
    assert.match(verdict.detail, /Unrecognized envelopeVersion/);
  });
});
