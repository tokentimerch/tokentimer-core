"use strict";

/**
 * tokentimer-protocol reference client helper.
 *
 * Thin CLI wrapper around the agent's own signing module
 * (packages/agent/src/signing/index.js), which is the single source of
 * truth for canonical-JSON serialization and Ed25519 dispatch-signature
 * verification (ADR-0003). This file adds zero cryptographic logic of its
 * own: it only reads argv/files and formats output, so the reference
 * client can never drift from the production verifier.
 *
 * The PowerShell reference script (tokentimer-protocol.ps1) shells out to
 * this file's "verify" subcommand for BOTH canonicalization and the actual
 * Ed25519 signature check (native Ed25519 is not reliably available across
 * supported Windows PowerShell runtimes yet) -- this is the pinned
 * Node 22 helper used for Ed25519 verification.
 *
 * The bash reference script (tokentimer-protocol.sh) shells out to this
 * file only for the "canonicalize" and "extract-field" subcommands (plain
 * JSON data handling); the actual Ed25519 signature math for the bash
 * script runs entirely in OpenSSL 3 (`openssl pkeyutl -verify -rawin`), not
 * here. That split is intentional: "OpenSSL 3 for the Bash script, a
 * pinned Node 22 helper for the PowerShell script."
 *
 * Usage:
 *   node canonicalize.cjs canonicalize <job.json>
 *   node canonicalize.cjs extract-field <job.json> <fieldName>
 *   node canonicalize.cjs verify <job.json> <pubkey.pem> <pinnedSigningKeyId> [--skip-time-window]
 *
 * Exit codes (verify): 0 = signature (and, unless --skip-time-window, time
 * window) valid; 1 = untrusted job soft-rejected (job_integrity_failed /
 * clock_drift_suspected -- printed as JSON on stdout); 2 = usage or
 * programmer error (bad args, unreadable/unparseable files).
 */

const fs = require("node:fs");
const path = require("node:path");
const {
  canonicalizeJobPayload,
  verifyJobSignature,
  checkJobTimeWindow,
} = require("../../src/signing/index.js");

// Only plain scalar (string) top-level fields a shell script has a
// legitimate reason to pull out of an untrusted job payload without
// parsing JSON itself. Deliberately not "signature" -- callers extract
// that as raw text too, but list it explicitly so this stays an
// allowlist, not "any field the caller asks for".
const EXTRACTABLE_FIELDS = new Set([
  "jobId",
  "action",
  "mode",
  "keyMode",
  "nonce",
  "issuedAt",
  "expiresAt",
  "signingKeyId",
  "signature",
  "claimId",
  "attemptId",
]);

function fail(message) {
  process.stderr.write(`canonicalize: ${message}\n`);
  process.exit(2);
}

function readJobFile(jobFilePath) {
  let raw;
  try {
    raw = fs.readFileSync(jobFilePath, "utf8");
  } catch (err) {
    fail(`could not read job file "${jobFilePath}": ${err.message}`);
  }
  try {
    return JSON.parse(raw);
  } catch (err) {
    fail(`job file "${jobFilePath}" is not valid JSON: ${err.message}`);
  }
  return undefined;
}

function readPublicKeyPem(pemPath) {
  try {
    return fs.readFileSync(pemPath, "utf8");
  } catch (err) {
    fail(`could not read public key file "${pemPath}": ${err.message}`);
  }
  return undefined;
}

function cmdCanonicalize(argv) {
  const [jobFilePath] = argv;
  if (!jobFilePath) fail("canonicalize requires <job.json>");
  const job = readJobFile(jobFilePath);
  let canonical;
  try {
    canonical = canonicalizeJobPayload(job);
  } catch (err) {
    fail(`could not canonicalize job payload: ${err.message}`);
  }
  // Raw write (no trailing newline): callers pipe this directly into a
  // signature verifier or hash function, where a stray trailing byte would
  // silently produce the wrong digest.
  process.stdout.write(canonical);
}

function cmdExtractField(argv) {
  const [jobFilePath, fieldName] = argv;
  if (!jobFilePath || !fieldName) {
    fail("extract-field requires <job.json> <fieldName>");
  }
  if (!EXTRACTABLE_FIELDS.has(fieldName)) {
    fail(
      `field "${fieldName}" is not extractable (allowed: ${[...EXTRACTABLE_FIELDS].join(", ")})`,
    );
  }
  const job = readJobFile(jobFilePath);
  const value = job?.[fieldName];
  if (typeof value !== "string") {
    fail(`job field "${fieldName}" is missing or not a string`);
  }
  process.stdout.write(value);
}

function cmdVerify(argv) {
  const [jobFilePath, pubKeyPath, pinnedSigningKeyId, ...rest] = argv;
  if (!jobFilePath || !pubKeyPath || !pinnedSigningKeyId) {
    fail(
      "verify requires <job.json> <pubkey.pem> <pinnedSigningKeyId> [--skip-time-window]",
    );
  }
  const skipTimeWindow = rest.includes("--skip-time-window");

  const job = readJobFile(jobFilePath);
  const publicKeyPem = readPublicKeyPem(pubKeyPath);

  let signatureResult;
  try {
    signatureResult = verifyJobSignature({ job, publicKeyPem, pinnedSigningKeyId });
  } catch (err) {
    // Programmer/operator error (unparseable pinned key etc.), not an
    // untrusted-job soft rejection -- mirrors verifyJobSignature's own
    // fail-loud contract.
    fail(err.message);
  }

  if (signatureResult.allowed && !skipTimeWindow) {
    const timeWindowResult = checkJobTimeWindow({ job, nowMs: Date.now() });
    if (!timeWindowResult.allowed) {
      process.stdout.write(`${JSON.stringify(timeWindowResult)}\n`);
      process.exit(1);
    }
  }

  process.stdout.write(`${JSON.stringify(signatureResult)}\n`);
  process.exit(signatureResult.allowed ? 0 : 1);
}

function main() {
  const [subcommand, ...rest] = process.argv.slice(2);
  switch (subcommand) {
    case "canonicalize":
      return cmdCanonicalize(rest);
    case "extract-field":
      return cmdExtractField(rest);
    case "verify":
      return cmdVerify(rest);
    default:
      return fail(
        `unknown subcommand "${subcommand ?? ""}" (expected canonicalize | extract-field | verify)`,
      );
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  EXTRACTABLE_FIELDS,
  cmdCanonicalize,
  cmdExtractField,
  cmdVerify,
};

void path;
