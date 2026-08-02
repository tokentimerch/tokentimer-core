"use strict";

/**
 * Dev-only fixture generator for the reference-client test suite.
 * NOT shipped (excluded from packages/agent/package.json's "files" array
 * via "!reference/generate-fixtures.js"): it is only run by a maintainer
 * (or CI, for reproducibility checks) to (re)produce the committed
 * fixtures under reference/fixtures/.
 *
 * Deliberately generates a FRESH throwaway Ed25519 keypair every run and
 * discards the private key immediately after signing -- only the public
 * key ever touches disk. This is what lets reference/fixtures/ ship a
 * valid signed-job fixture without ever committing private-key material
 * (see packages/agent/scripts/pack-release.js's private-key content scan,
 * which the tarball-content test in reference-client.test.js also
 * exercises against this package's real release tarball).
 *
 *   node reference/generate-fixtures.js
 */

const fs = require("node:fs");
const path = require("node:path");
const {
  canonicalizeJobPayload,
  generateSigningKeyPair,
  signJobPayload,
} = require("../src/signing/index.js");

const fixturesDir = path.join(__dirname, "fixtures");

const BASE_JOB = {
  schemaVersion: 1,
  jobId: "job-ref-0001",
  workspaceId: "00000000-0000-4000-8000-000000000000",
  certificateId: "cert-ref-0001",
  action: "renew",
  target: { type: "domain", reference: "example.test" },
  keyMode: "agent-local",
  requestedAt: "2026-08-01T00:00:00.000Z",
  // Deliberately wide so this fixture never expires under any realistic
  // clock (this repo's own test suite runs for many decades, hopefully
  // not literally, but far longer than a signed dispatch's real 5-minute
  // validity window would ever be) -- see checkJobTimeWindow in
  // src/signing/index.js. A narrow window here would make the reference
  // test suite flaky purely from the passage of time.
  issuedAt: "2020-01-01T00:00:00.000Z",
  expiresAt: "2099-12-31T23:59:59.000Z",
  nonce: "reference0000000000000000000001",
};

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function main() {
  fs.mkdirSync(fixturesDir, { recursive: true });

  const { publicKeyPem, privateKeyPem, signingKeyId } = generateSigningKeyPair();

  const validJob = { ...BASE_JOB, signingKeyId };
  const signature = signJobPayload({ job: validJob, privateKeyPem });
  const signedJob = { ...validJob, signature };

  // Tampered fixture: same signature, one field changed after signing --
  // the canonical bytes it now serializes to no longer match what was
  // signed, so verification must reject it (job_integrity_failed).
  const tamperedJob = { ...signedJob, action: "revoke" };

  // Wrong-key fixture: a syntactically valid signature (over the tampered
  // job's own canonical bytes, signed by a SECOND throwaway key), but its
  // signingKeyId does not match the pinned key either script is given --
  // exercises the "signingKeyId mismatch" rejection path independent of
  // the raw Ed25519 math.
  const otherKeyPair = generateSigningKeyPair();
  const wrongKeyJob = { ...BASE_JOB, signingKeyId: otherKeyPair.signingKeyId };
  const wrongKeySignature = signJobPayload({
    job: wrongKeyJob,
    privateKeyPem: otherKeyPair.privateKeyPem,
  });

  writeJson(path.join(fixturesDir, "job-signed-valid.json"), signedJob);
  writeJson(path.join(fixturesDir, "job-signed-tampered.json"), tamperedJob);
  writeJson(path.join(fixturesDir, "job-signed-wrong-key.json"), {
    ...wrongKeyJob,
    signature: wrongKeySignature,
  });
  fs.writeFileSync(
    path.join(fixturesDir, "signing-public-key.pem"),
    publicKeyPem,
    "utf8",
  );
  fs.writeFileSync(
    path.join(fixturesDir, "signing-key-id.txt"),
    `${signingKeyId}\n`,
    "utf8",
  );
  // The exact canonical byte sequence both reference scripts' canonicalize
  // step must reproduce (see reference-client.test.js).
  fs.writeFileSync(
    path.join(fixturesDir, "canonical-job-payload.txt"),
    canonicalizeJobPayload(signedJob),
    "utf8",
  );

  process.stdout.write(
    `Generated reference fixtures with signingKeyId=${signingKeyId} ` +
      `(private key discarded, not written to disk).\n`,
  );
}

main();
