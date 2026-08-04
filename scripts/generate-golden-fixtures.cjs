#!/usr/bin/env node
"use strict";

// Deterministic golden fixtures for the envelope-v2 decoder
// (packages/agent/src/signing/index.js -> verifyV2Envelope).
//
// Everything here is derived from a single fixed seed string and a single
// pinned clock value, through a sha256-based deterministic byte stream, so
// re-running this generator on any machine, at any time, reproduces the
// exact same fixture file byte-for-byte. There is no OS randomness anywhere
// in this file: even the Ed25519 keypairs are derived from the seeded byte
// stream (via a raw PKCS8 seed import), not crypto.generateKeyPairSync,
// which cannot be seeded.
//
// Usage:
//   node scripts/generate-golden-fixtures.cjs                 print JSON to stdout
//   node scripts/generate-golden-fixtures.cjs --update-golden  write the committed fixture file
//
// The committed fixture consumer is
// packages/agent/src/signing/fixtures/envelope-v2-golden.test.js, which
// re-derives the fixtures from this module at test time and asserts they
// are byte-identical to the checked-in JSON, so the fixture file can never
// silently drift from what this generator actually produces.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");
const OUTPUT_PATH = path.join(
  repoRoot,
  "packages",
  "agent",
  "src",
  "signing",
  "fixtures",
  "envelope-v2-golden.json",
);

// Changing this seed changes every derived byte in the fixture file. It is
// a fixture-identity constant, not a secret: these keys sign nothing in
// production and exist only so the decoder's test suite has real, byte-
// stable Ed25519 material to exercise.
const FIXTURE_SEED = "tokentimer-certops-envelope-v2-golden-fixtures-v1";
// Pinned clock: golden fixtures must never depend on Date.now(), so every
// timestamp embedded in a fixture job payload uses this fixed instant.
const PINNED_CLOCK_ISO = "2025-01-01T00:00:00.000Z";
const PINNED_SIGNING_KEY_ID = "signing-key-golden-v2-fixture-a";

/**
 * A deterministic byte stream seeded from a string: sha256(`${seed}:${n}`)
 * for n = 0, 1, 2, ... concatenated and sliced to the requested length.
 * Same seed -> same bytes, forever, on any machine or Node version (sha256
 * itself is the only primitive relied on).
 *
 * @param {string} seed
 * @returns {(byteLength: number) => Buffer} nextBytes
 */
function makeSha256Prng(seed) {
  let counter = 0;
  let pool = Buffer.alloc(0);

  function refill() {
    const chunk = crypto
      .createHash("sha256")
      .update(`${seed}:${counter}`, "utf8")
      .digest();
    counter += 1;
    pool = Buffer.concat([pool, chunk]);
  }

  return function nextBytes(byteLength) {
    while (pool.length < byteLength) refill();
    const out = pool.subarray(0, byteLength);
    pool = pool.subarray(byteLength);
    return Buffer.from(out);
  };
}

// RFC 8410 PKCS8 wrapper for a raw 32-byte Ed25519 private key seed. Fixed
// for all Ed25519 keys; only the trailing 32 bytes vary. This lets a
// deterministic 32-byte seed become a real, importable Ed25519 private key
// without calling crypto.generateKeyPairSync (which draws from OS entropy
// and cannot be seeded).
const ED25519_PKCS8_PREFIX = Buffer.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

/**
 * @param {(n: number) => Buffer} nextBytes
 * @returns {{ publicKeyPem: string, privateKeyPem: string }}
 */
function deriveEd25519KeyPair(nextBytes) {
  const seed = nextBytes(32);
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  const privateKey = crypto.createPrivateKey({
    key: der,
    format: "der",
    type: "pkcs8",
  });
  const publicKey = crypto.createPublicKey(privateKey);
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

/**
 * Tamper-vector construction: flips the last byte of a signature buffer.
 * Byte-identical signing input, corrupted signature -- the exact transform
 * this milestone's other signed-vector fixtures use for tampered-signature
 * cases. XOR with 0xff guarantees a change regardless of the original
 * byte's value (unlike +1, which can wrap without visibly "flipping"
 * anything meaningful for byte 0xff itself... XOR has no such edge case).
 *
 * @param {Buffer} buffer
 * @returns {Buffer}
 */
function flipLastByte(buffer) {
  const copy = Buffer.from(buffer);
  copy[copy.length - 1] ^= 0xff;
  return copy;
}

function buildV2Envelope({ job, privateKeyPem, signingKeyId }) {
  const payloadBytes = Buffer.from(JSON.stringify(job), "utf8");
  const signatureBytes = crypto.sign(
    null,
    payloadBytes,
    crypto.createPrivateKey(privateKeyPem),
  );
  return {
    envelopeVersion: 2,
    payloadB64: payloadBytes.toString("base64"),
    signatureB64: signatureBytes.toString("base64"),
    signingKeyId,
  };
}

/**
 * Builds the full deterministic fixture object: a pinned keypair (plus a
 * second "wrong" keypair used only for the wrong-key vector), and four
 * envelope-v2 vectors (valid, tampered-payload, tampered-signature,
 * wrong-key) with their expected verifyV2Envelope verdicts.
 *
 * @returns {object}
 */
function buildFixtures() {
  const nextBytes = makeSha256Prng(FIXTURE_SEED);

  const pinnedKeyPair = deriveEd25519KeyPair(nextBytes);
  const wrongKeyPair = deriveEd25519KeyPair(nextBytes);

  const job = {
    jobId: "golden-fixture-job-1",
    workspaceId: "golden-fixture-workspace-1",
    agentId: "golden-fixture-agent-1",
    issuedAt: PINNED_CLOCK_ISO,
    // Step 13 (ADR-0012 decision 3) requires the signed payload to carry
    // its own signingKeyId, checked against the wrapper's after signature
    // verification. Must equal PINNED_SIGNING_KEY_ID for the "valid" vector
    // to actually verify.
    signingKeyId: PINNED_SIGNING_KEY_ID,
  };

  const validEnvelope = buildV2Envelope({
    job,
    privateKeyPem: pinnedKeyPair.privateKeyPem,
    signingKeyId: PINNED_SIGNING_KEY_ID,
  });

  const tamperedPayloadEnvelope = {
    ...validEnvelope,
    payloadB64: Buffer.from(
      JSON.stringify({ ...job, jobId: "golden-fixture-job-TAMPERED" }),
      "utf8",
    ).toString("base64"),
  };

  const tamperedSignatureEnvelope = {
    ...validEnvelope,
    signatureB64: flipLastByte(
      Buffer.from(validEnvelope.signatureB64, "base64"),
    ).toString("base64"),
  };

  // Signed with the WRONG private key but claiming the pinned signingKeyId,
  // exactly the shape of an attacker who knows the key id string but does
  // not hold the pinned private key.
  const wrongKeyEnvelope = buildV2Envelope({
    job,
    privateKeyPem: wrongKeyPair.privateKeyPem,
    signingKeyId: PINNED_SIGNING_KEY_ID,
  });

  return {
    generatedBy: "scripts/generate-golden-fixtures.cjs",
    note:
      "Do not hand-edit. Regenerate with " +
      "`node scripts/generate-golden-fixtures.cjs --update-golden`. Every " +
      "byte in this file is deterministically derived from seed and " +
      "pinnedClockIso below; the consumer test re-derives and byte-compares.",
    seed: FIXTURE_SEED,
    pinnedClockIso: PINNED_CLOCK_ISO,
    pinnedSigningKeyId: PINNED_SIGNING_KEY_ID,
    publicKeyPem: pinnedKeyPair.publicKeyPem,
    job,
    vectors: [
      {
        name: "valid",
        description: "well-formed v2 envelope signed by the pinned key",
        envelope: validEnvelope,
        expected: { allowed: true, job },
      },
      {
        name: "tampered-payload",
        description:
          "payloadB64 replaced after signing; signature no longer matches",
        envelope: tamperedPayloadEnvelope,
        expected: {
          allowed: false,
          rejectionReason: "job_integrity_failed",
        },
      },
      {
        name: "tampered-signature",
        description:
          "valid payload, signatureB64 corrupted by flipping its last byte",
        envelope: tamperedSignatureEnvelope,
        expected: {
          allowed: false,
          rejectionReason: "job_integrity_failed",
        },
      },
      {
        name: "wrong-key",
        description:
          "signed by a different Ed25519 key than the one pinned under " +
          "this signingKeyId",
        envelope: wrongKeyEnvelope,
        expected: {
          allowed: false,
          rejectionReason: "job_integrity_failed",
        },
      },
    ],
  };
}

function render(fixtures) {
  return `${JSON.stringify(fixtures, null, 2)}\n`;
}

function main() {
  const args = process.argv.slice(2);
  const shouldWrite = args.includes("--update-golden");

  const fixtures = buildFixtures();
  const json = render(fixtures);

  if (shouldWrite) {
    fs.mkdirSync(path.dirname(OUTPUT_PATH), { recursive: true });
    fs.writeFileSync(OUTPUT_PATH, json, "utf8");
    console.log(
      `generate-golden-fixtures: wrote ${fixtures.vectors.length} vector(s) to ` +
        `${path.relative(repoRoot, OUTPUT_PATH).replace(/\\/g, "/")}`,
    );
  } else {
    process.stdout.write(json);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  OUTPUT_PATH,
  FIXTURE_SEED,
  PINNED_CLOCK_ISO,
  PINNED_SIGNING_KEY_ID,
  makeSha256Prng,
  deriveEd25519KeyPair,
  flipLastByte,
  buildFixtures,
  render,
};
