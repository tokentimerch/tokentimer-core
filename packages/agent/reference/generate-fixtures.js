"use strict";

/**
 * Dev-only fixture generator for the reference-client test suite.
 * NOT shipped. Uses Node crypto + the reference-local canonicalize helper
 * (no production agent runtime imports).
 *
 *   node reference/generate-fixtures.js
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { canonicalizeJobPayload } = require("./lib/canonicalize.cjs");

const fixturesDir = path.join(__dirname, "fixtures");

// Shaped like a real claimed dispatch: the claim-time fields (claimId,
// attemptId, leaseExpiresAt, attemptCount) and the immutable execution mode
// are part of the signed payload, so the reference tests exercise the same
// envelope an agent actually receives.
const BASE_JOB = {
  schemaVersion: 1,
  jobId: "job-ref-0001",
  workspaceId: "00000000-0000-4000-8000-000000000000",
  certificateId: "cert-ref-0001",
  action: "renew",
  mode: "dry_run",
  target: { type: "domain", reference: "example.test" },
  keyMode: "agent-local",
  requestedAt: "2020-01-01T00:00:00.000Z",
  issuedAt: "2020-01-01T00:00:00.000Z",
  expiresAt: "2099-12-31T23:59:59.000Z",
  nonce: "reference0000000000000000000001",
  claimId: "claim-ref-0001",
  attemptId: "claim-ref-0001",
  leaseExpiresAt: "2099-12-31T23:59:59.000Z",
  attemptCount: 1,
};

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function generateSigningKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    signingKeyId: "signing-key-reference-001",
  };
}

function signJobPayload({ job, privateKeyPem }) {
  const canonical = canonicalizeJobPayload(job);
  const key = crypto.createPrivateKey(privateKeyPem);
  return crypto.sign(null, Buffer.from(canonical, "utf8"), key).toString("base64");
}

function main() {
  fs.mkdirSync(fixturesDir, { recursive: true });
  const { publicKeyPem, privateKeyPem, signingKeyId } = generateSigningKeyPair();

  const validJob = { ...BASE_JOB, signingKeyId };
  const signature = signJobPayload({ job: validJob, privateKeyPem });
  const signedJob = { ...validJob, signature };

  const tamperedJob = { ...signedJob, action: "revoke" };

  const otherKeyPair = generateSigningKeyPair();
  const wrongKeyJob = { ...BASE_JOB, signingKeyId: otherKeyPair.signingKeyId };
  const wrongKeySignature = signJobPayload({
    job: wrongKeyJob,
    privateKeyPem: otherKeyPair.privateKeyPem,
  });

  const realModeJob = { ...validJob, mode: "real", jobId: "job-ref-0002" };
  const realModeSignature = signJobPayload({ job: realModeJob, privateKeyPem });

  writeJson(path.join(fixturesDir, "job-signed-valid.json"), signedJob);
  writeJson(path.join(fixturesDir, "job-signed-real-mode.json"), {
    ...realModeJob,
    signature: realModeSignature,
  });
  writeJson(path.join(fixturesDir, "job-signed-tampered.json"), tamperedJob);
  writeJson(path.join(fixturesDir, "job-signed-wrong-key.json"), {
    ...wrongKeyJob,
    signature: wrongKeySignature,
  });
  fs.writeFileSync(path.join(fixturesDir, "signing-public-key.pem"), publicKeyPem, "utf8");
  fs.writeFileSync(
    path.join(fixturesDir, "signing-key-id.txt"),
    `${signingKeyId}\n`,
    "utf8",
  );
  fs.writeFileSync(
    path.join(fixturesDir, "canonical-job-payload.txt"),
    canonicalizeJobPayload(signedJob),
    "utf8",
  );

  process.stdout.write(
    `Generated reference fixtures with signingKeyId=${signingKeyId} (private key discarded, not written to disk).\n`,
  );
}

main();