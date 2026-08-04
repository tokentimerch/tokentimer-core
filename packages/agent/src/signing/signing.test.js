"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const {
  SIGNING_REJECTION_REASONS,
  DEFAULT_TIME_WINDOW_TOLERANCE_MS,
  ENVELOPE_VERSION_2,
  V2_MAX_ENCODED_PAYLOAD_CHARS,
  V2_MAX_DECODED_PAYLOAD_BYTES,
  canonicalizeJobPayload,
  verifyJobSignature,
  verifyV2Envelope,
  verifyJobEnvelope,
  checkJobTimeWindow,
  generateSigningKeyPair,
  signJobPayload,
} = require("./index.js");

const NOW_MS = Date.parse("2026-07-22T12:00:00.000Z");

function buildSignedJob({ privateKeyPem, signingKeyId, overrides = {} }) {
  const job = {
    schemaVersion: 1,
    jobId: `job-${crypto.randomUUID()}`,
    workspaceId: "11111111-1111-4111-8111-111111111111",
    certificateId: "cert-1",
    action: "renew",
    target: { type: "domain", reference: "example.com" },
    keyMode: "agent-local",
    requestedAt: new Date(NOW_MS).toISOString(),
    nonce: crypto.randomUUID(),
    signingKeyId,
    issuedAt: new Date(NOW_MS).toISOString(),
    expiresAt: new Date(NOW_MS + 5 * 60 * 1000).toISOString(),
    ...overrides,
  };
  job.signature = signJobPayload({ job, privateKeyPem });
  return job;
}

describe("canonicalizeJobPayload", () => {
  it("sorts object keys lexicographically at every level, no whitespace", () => {
    const canonical = canonicalizeJobPayload({
      b: 1,
      a: { z: true, m: null, a: "x" },
    });
    assert.equal(canonical, '{"a":{"a":"x","m":null,"z":true},"b":1}');
  });

  it("excludes only the TOP-LEVEL signature property", () => {
    const canonical = canonicalizeJobPayload({
      signature: "should-be-dropped",
      nested: { signature: "kept" },
    });
    assert.equal(canonical, '{"nested":{"signature":"kept"}}');
  });

  it("keeps array element order", () => {
    assert.equal(
      canonicalizeJobPayload({ list: [3, 1, 2, ["b", "a"]] }),
      '{"list":[3,1,2,["b","a"]]}',
    );
  });

  it("is insensitive to property insertion order", () => {
    const one = canonicalizeJobPayload({ a: 1, b: { d: 4, c: 3 } });
    const two = canonicalizeJobPayload({ b: { c: 3, d: 4 }, a: 1 });
    assert.equal(one, two);
  });

  it("escapes strings using standard JSON escaping", () => {
    assert.equal(
      canonicalizeJobPayload({ s: 'quote " and \n newline and ünïcödé' }),
      '{"s":"quote \\" and \\n newline and ünïcödé"}',
    );
  });

  it("throws on non-plain-object input", () => {
    for (const bad of [null, undefined, "str", 42, [], new Map(), new Date()]) {
      assert.throws(() => canonicalizeJobPayload(bad), /plain object/);
    }
  });

  it("throws on undefined values anywhere in the tree", () => {
    assert.throws(
      () => canonicalizeJobPayload({ a: { b: undefined } }),
      /undefined value at \$\.a\.b/,
    );
    assert.throws(
      () => canonicalizeJobPayload({ list: [1, undefined] }),
      /undefined value at \$\.list\[1\]/,
    );
  });

  it("throws on non-finite numbers and non-JSON values", () => {
    assert.throws(() => canonicalizeJobPayload({ n: NaN }), /non-finite/);
    assert.throws(() => canonicalizeJobPayload({ n: Infinity }), /non-finite/);
    assert.throws(
      () => canonicalizeJobPayload({ d: new Date() }),
      /cannot serialize/,
    );
  });
});

describe("verifyJobSignature", () => {
  const keys = generateSigningKeyPair();

  it("accepts a validly signed job (sign/verify interop via shared canonicalization)", () => {
    const job = buildSignedJob({
      privateKeyPem: keys.privateKeyPem,
      signingKeyId: keys.signingKeyId,
    });
    const result = verifyJobSignature({
      job,
      publicKeyPem: keys.publicKeyPem,
      pinnedSigningKeyId: keys.signingKeyId,
    });
    assert.deepEqual(result, { allowed: true });
  });

  it("accepts a job whose properties arrive in a different order", () => {
    const job = buildSignedJob({
      privateKeyPem: keys.privateKeyPem,
      signingKeyId: keys.signingKeyId,
    });
    const reordered = {};
    for (const key of Object.keys(job).reverse()) reordered[key] = job[key];
    const result = verifyJobSignature({
      job: reordered,
      publicKeyPem: keys.publicKeyPem,
      pinnedSigningKeyId: keys.signingKeyId,
    });
    assert.deepEqual(result, { allowed: true });
  });

  it("rejects a tampered payload with job_integrity_failed", () => {
    const job = buildSignedJob({
      privateKeyPem: keys.privateKeyPem,
      signingKeyId: keys.signingKeyId,
    });
    job.action = "revoke";
    const result = verifyJobSignature({
      job,
      publicKeyPem: keys.publicKeyPem,
      pinnedSigningKeyId: keys.signingKeyId,
    });
    assert.equal(result.allowed, false);
    assert.equal(
      result.rejectionReason,
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
    );
    assert.ok(typeof result.detail === "string" && result.detail.length > 0);
  });

  it("rejects a signingKeyId mismatch with a detail mentioning the key id mismatch", () => {
    const job = buildSignedJob({
      privateKeyPem: keys.privateKeyPem,
      signingKeyId: "signing-key-other",
    });
    const result = verifyJobSignature({
      job,
      publicKeyPem: keys.publicKeyPem,
      pinnedSigningKeyId: keys.signingKeyId,
    });
    assert.equal(result.allowed, false);
    assert.equal(
      result.rejectionReason,
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
    );
    assert.match(result.detail, /key id mismatch/i);
  });

  it("rejects a job signed with a different keypair but the pinned signingKeyId", () => {
    const otherKeys = generateSigningKeyPair();
    const job = buildSignedJob({
      privateKeyPem: otherKeys.privateKeyPem,
      signingKeyId: keys.signingKeyId,
    });
    const result = verifyJobSignature({
      job,
      publicKeyPem: keys.publicKeyPem,
      pinnedSigningKeyId: keys.signingKeyId,
    });
    assert.equal(result.allowed, false);
    assert.equal(
      result.rejectionReason,
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
    );
  });

  it("rejects missing or malformed signed fields without throwing", () => {
    const base = () =>
      buildSignedJob({
        privateKeyPem: keys.privateKeyPem,
        signingKeyId: keys.signingKeyId,
      });

    const cases = [
      (job) => delete job.signature,
      (job) => (job.signature = "too-short"),
      (job) => (job.signature = "!!!not-base64###".repeat(8)),
      (job) => delete job.signingKeyId,
      (job) => delete job.nonce,
      (job) => (job.nonce = "short"),
      (job) => delete job.issuedAt,
      (job) => (job.issuedAt = "not-a-date"),
      (job) => delete job.expiresAt,
    ];

    for (const mutate of cases) {
      const job = base();
      mutate(job);
      const result = verifyJobSignature({
        job,
        publicKeyPem: keys.publicKeyPem,
        pinnedSigningKeyId: keys.signingKeyId,
      });
      assert.equal(result.allowed, false);
      assert.equal(
        result.rejectionReason,
        SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      );
    }
  });

  it("never throws on hostile untrusted job inputs", () => {
    for (const hostile of [null, undefined, "job", 7, [], { nested: [] }]) {
      const result = verifyJobSignature({
        job: hostile,
        publicKeyPem: keys.publicKeyPem,
        pinnedSigningKeyId: keys.signingKeyId,
      });
      assert.equal(result.allowed, false);
    }
  });

  it("throws on programmer error: missing publicKeyPem or pinnedSigningKeyId", () => {
    const job = buildSignedJob({
      privateKeyPem: keys.privateKeyPem,
      signingKeyId: keys.signingKeyId,
    });
    assert.throws(
      () => verifyJobSignature({ job, pinnedSigningKeyId: keys.signingKeyId }),
      /publicKeyPem/,
    );
    assert.throws(
      () => verifyJobSignature({ job, publicKeyPem: keys.publicKeyPem }),
      /pinnedSigningKeyId/,
    );
    assert.throws(
      () =>
        verifyJobSignature({
          job,
          publicKeyPem: "garbage-not-pem",
          pinnedSigningKeyId: keys.signingKeyId,
        }),
      /unparseable publicKeyPem/,
    );
  });

  it("never leaks private key material into rejection details", () => {
    const job = buildSignedJob({
      privateKeyPem: keys.privateKeyPem,
      signingKeyId: keys.signingKeyId,
    });
    job.certificateId = "tampered";
    const result = verifyJobSignature({
      job,
      publicKeyPem: keys.publicKeyPem,
      pinnedSigningKeyId: keys.signingKeyId,
    });
    const serialized = JSON.stringify(result);
    assert.ok(!serialized.includes("PRIVATE KEY"));
    assert.ok(!serialized.includes(keys.privateKeyPem.slice(30, 60)));
  });
});

describe("checkJobTimeWindow", () => {
  const window = {
    issuedAt: new Date(NOW_MS).toISOString(),
    expiresAt: new Date(NOW_MS + 5 * 60 * 1000).toISOString(),
  };

  it("allows a job whose window contains now", () => {
    assert.deepEqual(
      checkJobTimeWindow({ job: { ...window }, nowMs: NOW_MS + 1000 }),
      { allowed: true },
    );
  });

  it("allows edge times within the default tolerance", () => {
    assert.deepEqual(
      checkJobTimeWindow({
        job: { ...window },
        nowMs: NOW_MS - DEFAULT_TIME_WINDOW_TOLERANCE_MS,
      }),
      { allowed: true },
    );
    assert.deepEqual(
      checkJobTimeWindow({
        job: { ...window },
        nowMs: NOW_MS + 5 * 60 * 1000 + DEFAULT_TIME_WINDOW_TOLERANCE_MS,
      }),
      { allowed: true },
    );
  });

  it("rejects a future-issued job with clock_drift_suspected", () => {
    const result = checkJobTimeWindow({
      job: { ...window },
      nowMs: NOW_MS - DEFAULT_TIME_WINDOW_TOLERANCE_MS - 1,
    });
    assert.equal(result.allowed, false);
    assert.equal(
      result.rejectionReason,
      SIGNING_REJECTION_REASONS.CLOCK_DRIFT_SUSPECTED,
    );
    assert.match(result.detail, /future/);
  });

  it("rejects an expired job with clock_drift_suspected", () => {
    const result = checkJobTimeWindow({
      job: { ...window },
      nowMs: NOW_MS + 10 * 60 * 1000,
    });
    assert.equal(result.allowed, false);
    assert.equal(
      result.rejectionReason,
      SIGNING_REJECTION_REASONS.CLOCK_DRIFT_SUSPECTED,
    );
    assert.match(result.detail, /expired/i);
  });

  it("rejects expiresAt < issuedAt as job_integrity_failed (malformed, not drift)", () => {
    const result = checkJobTimeWindow({
      job: {
        issuedAt: new Date(NOW_MS).toISOString(),
        expiresAt: new Date(NOW_MS - 1000).toISOString(),
      },
      nowMs: NOW_MS,
    });
    assert.equal(result.allowed, false);
    assert.equal(
      result.rejectionReason,
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
    );
  });

  it("applies a finite integer clockOffsetMs (serverTime - localTime) to now", () => {
    // Local clock 2 minutes behind the server: without the offset the job
    // (issued "now" in server time) would look future-dated beyond tolerance.
    const skewMs = 2 * 60 * 1000;
    const localNowMs = NOW_MS - skewMs;

    const withoutOffset = checkJobTimeWindow({
      job: { ...window },
      nowMs: localNowMs,
    });
    assert.equal(withoutOffset.allowed, false);

    const withOffset = checkJobTimeWindow({
      job: { ...window },
      nowMs: localNowMs,
      clockOffsetMs: skewMs,
    });
    assert.deepEqual(withOffset, { allowed: true });
  });

  it("ignores null/undefined/non-finite clockOffsetMs", () => {
    for (const offset of [null, undefined, NaN, Infinity, 0.5]) {
      assert.deepEqual(
        checkJobTimeWindow({
          job: { ...window },
          nowMs: NOW_MS + 1000,
          clockOffsetMs: offset,
        }),
        { allowed: true },
      );
    }
  });

  it("rejects missing/unparseable window fields as job_integrity_failed", () => {
    for (const job of [
      {},
      { issuedAt: "bad", expiresAt: window.expiresAt },
      { issuedAt: window.issuedAt },
      null,
    ]) {
      const result = checkJobTimeWindow({ job, nowMs: NOW_MS });
      assert.equal(result.allowed, false);
      assert.equal(
        result.rejectionReason,
        SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      );
    }
  });

  it("throws on programmer error: non-finite nowMs or negative tolerance", () => {
    assert.throws(
      () => checkJobTimeWindow({ job: { ...window }, nowMs: NaN }),
      /finite nowMs/,
    );
    assert.throws(
      () =>
        checkJobTimeWindow({
          job: { ...window },
          nowMs: NOW_MS,
          toleranceMs: -1,
        }),
      /toleranceMs/,
    );
  });
});

describe("generateSigningKeyPair / signJobPayload (test-side utilities)", () => {
  it("generates a usable Ed25519 keypair with PEM material and a key id", () => {
    const keys = generateSigningKeyPair();
    assert.match(keys.publicKeyPem, /-----BEGIN PUBLIC KEY-----/);
    assert.match(keys.privateKeyPem, /-----BEGIN PRIVATE KEY-----/);
    assert.match(keys.signingKeyId, /^signing-key-/);
  });

  it("produces base64 signatures within the schema's 64-1024 char bounds", () => {
    const keys = generateSigningKeyPair();
    const signature = signJobPayload({
      job: { jobId: "job-1", nonce: crypto.randomUUID() },
      privateKeyPem: keys.privateKeyPem,
    });
    assert.ok(signature.length >= 64 && signature.length <= 1024);
    assert.match(signature, /^[A-Za-z0-9+/]+={0,2}$/);
  });

  it("signJobPayload throws on programmer error (missing privateKeyPem)", () => {
    assert.throws(
      () => signJobPayload({ job: { jobId: "job-1" } }),
      /privateKeyPem/,
    );
  });
});

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

describe("verifyV2Envelope", () => {
  it("verifies a well-formed v2 envelope and returns the decoded job", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    const job = {
      jobId: "job-1",
      workspaceId: "ws-1",
      agentId: "agent-1",
      signingKeyId,
    };
    const envelope = buildV2Envelope({ job, privateKeyPem, signingKeyId });

    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.deepEqual(verdict, { allowed: true, job });
  });

  it("rejects a v2 payload whose own signingKeyId disagrees with the wrapper's, even though the signature verifies (ADR-0012 decision 2 step 13 / decision 3)", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    // The payload is genuinely signed by the pinned key (verification
    // succeeds), but its OWN signingKeyId field -- part of the signed
    // bytes -- names a different key id than the wrapper's hint. Decision
    // 3: "the wrapper's copy is the pre-verification selection hint, the
    // payload's copy is the authenticated value, and step 13 requires them
    // to agree."
    const job = {
      jobId: "job-1",
      signingKeyId: "signing-key-different-from-wrapper",
    };
    const envelope = buildV2Envelope({ job, privateKeyPem, signingKeyId });

    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.equal(verdict.allowed, false);
    assert.equal(
      verdict.rejectionReason,
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
    );
    assert.match(verdict.detail, /Signing key id mismatch/);
  });

  it("rejects a v2 payload that omits signingKeyId entirely, even though the signature verifies", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    const job = { jobId: "job-1" }; // no signingKeyId field at all
    const envelope = buildV2Envelope({ job, privateKeyPem, signingKeyId });

    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.equal(verdict.allowed, false);
    assert.equal(
      verdict.rejectionReason,
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
    );
    assert.match(verdict.detail, /signingKeyId is missing or malformed/);
  });

  it("rejects a tampered payload (signature no longer matches)", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    const envelope = buildV2Envelope({
      job: { jobId: "job-1" },
      privateKeyPem,
      signingKeyId,
    });
    envelope.payloadB64 = Buffer.from(
      JSON.stringify({ jobId: "job-EVIL" }),
      "utf8",
    ).toString("base64");

    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.equal(verdict.allowed, false);
    assert.equal(
      verdict.rejectionReason,
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
    );
  });

  it("rejects a signingKeyId mismatch before touching payload bytes", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    const envelope = buildV2Envelope({
      job: { jobId: "job-1" },
      privateKeyPem,
      signingKeyId,
    });

    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: "some-other-key-id",
    });
    assert.equal(verdict.allowed, false);
    assert.match(verdict.detail, /Signing key id mismatch/);
  });

  it("rejects payloadB64 with embedded whitespace (not standard base64)", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    const envelope = buildV2Envelope({
      job: { jobId: "job-1" },
      privateKeyPem,
      signingKeyId,
    });
    envelope.payloadB64 = envelope.payloadB64.slice(0, 4) + " " + envelope.payloadB64.slice(4);

    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.equal(verdict.allowed, false);
  });

  it("rejects base64url-encoded payloadB64 (- and _ are not standard base64)", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    // These specific bytes provably base64-encode to "++++////" (every
    // group forces the top two 6-bit values, 62 and 63), so both '+' and
    // '/' are guaranteed present and the base64url substitution below is
    // guaranteed to actually change the string. Ascending byte sequences do
    // NOT reliably produce both characters (verified: bytes 0..47, 0..63,
    // and 0..95 all encode without a single '/'), so this fixed sequence is
    // used instead of a derived one. This buffer's content is not meant to
    // be valid JSON; the test only exercises the base64-alphabet check,
    // which runs before any JSON parsing is attempted.
    const rawBytes = Buffer.from([0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff]);
    const signatureBytes = crypto.sign(
      null,
      rawBytes,
      crypto.createPrivateKey(privateKeyPem),
    );
    const payloadB64 = rawBytes.toString("base64");
    assert.match(payloadB64, /\+/);
    assert.match(payloadB64, /\//);
    const envelope = {
      envelopeVersion: ENVELOPE_VERSION_2,
      payloadB64: payloadB64.replace(/\+/g, "-").replace(/\//g, "_"),
      signatureB64: signatureBytes.toString("base64"),
      signingKeyId,
    };

    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.equal(verdict.allowed, false);
  });

  it("rejects non-canonical base64 (decode-then-re-encode does not round-trip)", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    const envelope = buildV2Envelope({
      job: { jobId: "job-1" },
      privateKeyPem,
      signingKeyId,
    });
    // Flipping the last significant base64 char before padding often
    // produces a non-canonical-but-same-length string (extra padding bits
    // set); if this particular flip happens to still be canonical the
    // signature check below still catches it, so the test only asserts the
    // overall rejection outcome, not which specific check caught it.
    const chars = envelope.payloadB64.split("");
    const idx = chars.findIndex((c) => c !== "=");
    chars[idx] = chars[idx] === "A" ? "B" : "A";
    envelope.payloadB64 = chars.join("");

    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.equal(verdict.allowed, false);
  });

  it("rejects payloadB64 exceeding the maximum encoded length", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    const hugeJob = { jobId: "job-1", filler: "x".repeat(200000) };
    const envelope = buildV2Envelope({
      job: hugeJob,
      privateKeyPem,
      signingKeyId,
    });
    assert.ok(envelope.payloadB64.length > V2_MAX_ENCODED_PAYLOAD_CHARS);

    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.equal(verdict.allowed, false);
    assert.equal(
      verdict.rejectionReason,
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
    );
  });

  it("actually reaches and enforces the decoded-byte limit for a payload within the encoded-char bound (reachability, not just equivalence)", () => {
    // Regression for a bug where V2_MAX_ENCODED_PAYLOAD_CHARS was set to the
    // exact floor(chars/4)*3 equivalent of V2_MAX_DECODED_PAYLOAD_BYTES
    // (65536 encoded chars, decoding to exactly 49152 bytes): with that
    // pairing, no payload could ever pass the encoded-length check and then
    // fail the decoded-byte check, so the decoded check was unreachable dead
    // code. This constructs a job whose encoded form is comfortably under
    // V2_MAX_ENCODED_PAYLOAD_CHARS but whose decoded form exceeds
    // V2_MAX_DECODED_PAYLOAD_BYTES, and asserts the rejection is specifically
    // the decoded-size one, not the encoded-length one.
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    // A raw filler string this long, once JSON-escaped and base64-encoded,
    // comfortably clears V2_MAX_DECODED_PAYLOAD_BYTES while staying well
    // under V2_MAX_ENCODED_PAYLOAD_CHARS -- the gap the two bounds must
    // leave open for this test to be meaningful.
    const fillerLength = V2_MAX_DECODED_PAYLOAD_BYTES + 5000;
    const oversizedDecodedJob = {
      jobId: "job-1",
      filler: "x".repeat(fillerLength),
    };
    const envelope = buildV2Envelope({
      job: oversizedDecodedJob,
      privateKeyPem,
      signingKeyId,
    });
    assert.ok(
      envelope.payloadB64.length <= V2_MAX_ENCODED_PAYLOAD_CHARS,
      "test fixture must pass the encoded-length gate to prove the decoded gate is reachable",
    );
    const decodedByteLength = Buffer.from(
      envelope.payloadB64,
      "base64",
    ).length;
    assert.ok(decodedByteLength > V2_MAX_DECODED_PAYLOAD_BYTES);

    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.equal(verdict.allowed, false);
    assert.equal(
      verdict.rejectionReason,
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
    );
    assert.match(verdict.detail, /decodes to \d+ bytes/);
  });

  it("rejects a signature that is not exactly 64 decoded bytes", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    const envelope = buildV2Envelope({
      job: { jobId: "job-1" },
      privateKeyPem,
      signingKeyId,
    });
    envelope.signatureB64 = Buffer.from("too-short").toString("base64");

    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.equal(verdict.allowed, false);
  });

  it("rejects a payload with a leading UTF-8 BOM even though the signature verifies", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    const bomBytes = Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      Buffer.from(JSON.stringify({ jobId: "job-1" }), "utf8"),
    ]);
    const signatureBytes = crypto.sign(
      null,
      bomBytes,
      crypto.createPrivateKey(privateKeyPem),
    );
    const envelope = {
      envelopeVersion: ENVELOPE_VERSION_2,
      payloadB64: bomBytes.toString("base64"),
      signatureB64: signatureBytes.toString("base64"),
      signingKeyId,
    };

    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.equal(verdict.allowed, false);
    assert.match(verdict.detail, /BOM/);
  });

  it("rejects trailing content after the JSON value, even whitespace-only, though the signature verifies", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    const withTrailingWs = Buffer.concat([
      Buffer.from(JSON.stringify({ jobId: "job-1" }), "utf8"),
      Buffer.from("\n"),
    ]);
    const signatureBytes = crypto.sign(
      null,
      withTrailingWs,
      crypto.createPrivateKey(privateKeyPem),
    );
    const envelope = {
      envelopeVersion: ENVELOPE_VERSION_2,
      payloadB64: withTrailingWs.toString("base64"),
      signatureB64: signatureBytes.toString("base64"),
      signingKeyId,
    };

    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.equal(verdict.allowed, false);
  });

  it("rejects malformed UTF-8 in the payload bytes, though the signature verifies", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    // 0xff is not valid UTF-8 in any position.
    const invalidUtf8 = Buffer.from([0x7b, 0xff, 0x7d]);
    const signatureBytes = crypto.sign(
      null,
      invalidUtf8,
      crypto.createPrivateKey(privateKeyPem),
    );
    const envelope = {
      envelopeVersion: ENVELOPE_VERSION_2,
      payloadB64: invalidUtf8.toString("base64"),
      signatureB64: signatureBytes.toString("base64"),
      signingKeyId,
    };

    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.equal(verdict.allowed, false);
  });

  it("rejects a verified payload that is valid JSON but not a JSON object (e.g. an array)", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    const arrayBytes = Buffer.from(JSON.stringify([1, 2, 3]), "utf8");
    const signatureBytes = crypto.sign(
      null,
      arrayBytes,
      crypto.createPrivateKey(privateKeyPem),
    );
    const envelope = {
      envelopeVersion: ENVELOPE_VERSION_2,
      payloadB64: arrayBytes.toString("base64"),
      signatureB64: signatureBytes.toString("base64"),
      signingKeyId,
    };

    const verdict = verifyV2Envelope({
      envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.equal(verdict.allowed, false);
  });

  it("throws on programmer error (missing publicKeyPem or pinnedSigningKeyId)", () => {
    const envelope = { envelopeVersion: ENVELOPE_VERSION_2 };
    assert.throws(
      () => verifyV2Envelope({ envelope, pinnedSigningKeyId: "k" }),
      /publicKeyPem/,
    );
    assert.throws(
      () => verifyV2Envelope({ envelope, publicKeyPem: "pem" }),
      /pinnedSigningKeyId/,
    );
  });
});

describe("verifyJobEnvelope (dual-format dispatcher)", () => {
  it("routes an envelopeVersion:2 object to the v2 path", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    const job = { jobId: "job-1", signingKeyId };
    const envelope = buildV2Envelope({ job, privateKeyPem, signingKeyId });

    const verdict = verifyJobEnvelope({
      claimed: envelope,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.deepEqual(verdict, { allowed: true, job });
  });

  it("routes a legacy job object with no envelopeVersion to the v1 path", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    const job = buildSignedJob({ privateKeyPem, signingKeyId });

    const verdict = verifyJobEnvelope({
      claimed: job,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.equal(verdict.allowed, true);
    assert.deepEqual(verdict.job, job);
  });

  it("routes an explicit envelopeVersion:1 job object to the v1 path", () => {
    const { publicKeyPem, privateKeyPem, signingKeyId } =
      generateSigningKeyPair();
    const job = buildSignedJob({
      privateKeyPem,
      signingKeyId,
      overrides: { envelopeVersion: 1 },
    });

    const verdict = verifyJobEnvelope({
      claimed: job,
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.equal(verdict.allowed, true);
  });

  it("rejects an unrecognized envelopeVersion with a clear reason, never silently falling back to v1", () => {
    const { publicKeyPem, signingKeyId } = generateSigningKeyPair();
    const verdict = verifyJobEnvelope({
      claimed: { envelopeVersion: 99, jobId: "job-1" },
      publicKeyPem,
      pinnedSigningKeyId: signingKeyId,
    });
    assert.equal(verdict.allowed, false);
    assert.equal(
      verdict.rejectionReason,
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
    );
    assert.match(verdict.detail, /Unrecognized envelopeVersion/);
  });
});
