"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const {
  SIGNING_REJECTION_REASONS,
  DEFAULT_TIME_WINDOW_TOLERANCE_MS,
  canonicalizeJobPayload,
  verifyJobSignature,
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
