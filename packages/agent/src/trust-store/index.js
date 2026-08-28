"use strict";

/**
 * Cross-platform trust-anchor store executor: agent-side implementation of
 * `distribute-trust` and `revoke-trust` signed jobs across Windows
 * (LocalMachine\Root / LocalMachine\CA), Debian-family
 * (/usr/local/share/ca-certificates + update-ca-certificates), and
 * RHEL-family (/etc/pki/ca-trust/source/anchors + update-ca-trust extract)
 * machine trust stores. See docs/adr/0012-certops-windows-execution-surface-and-trust-anchors.md.
 *
 * CommonJS, node builtins only, exec via child_process.execFile without a
 * shell, argv re-validated against a shell-metacharacter pattern.
 *
 * Each fingerprintSha256 is an independent anchor with its own ownership
 * receipt (./receipt.js keys by (store, fingerprintSha256)) - a cross-signed
 * CA under two roots is two unrelated pairs. No desired-state pruning: every
 * function acts on exactly the one (store, fingerprint) pair its caller named.
 */

const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { X509Certificate } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const receipt = require("./receipt.js");
const {
  fetchRawCertificateDerByThumbprint,
  computeFingerprintSha256: computeFingerprintSha256FromDerBase64,
} = require("../discovery/windows.js");
const { isWindows } = require("../platform/index.js");
const { fsyncDirectorySync } = require("../platform/durability.js");

/** Defense in depth: every exec runs without a shell, but argv is still
 * checked against this pattern. */
const SHELL_METACHARACTER_PATTERN = /[;|&$`><\r\n]/;

const DEFAULT_TIMEOUT_MS = 2 * 60 * 1000;
const OUTPUT_EXCERPT_MAX_CHARS = 1024;
const REDACTED_EXCERPT_PLACEHOLDER = "[redacted]";
const PRIVATE_KEY_MARKER = "PRIVATE KEY";

/** Mirrors trust-job-payload.schema.json's fingerprintSha256 pattern. */
const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;

/** Mirrors trust-result-contract.schema.json's `store` field pattern. */
const STORE_PATTERN = /^[A-Za-z0-9 _.-]{1,64}$/;

/** Mirrors trust-job-payload.schema.json's trustAnchorId/jobId pattern. */
const ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;

/**
 * Root anchors target LocalMachine\Root, intermediates target LocalMachine\CA.
 * The signed job's anchorType is the routing decision, never re-derived from
 * the certificate's basicConstraints/issuer at run time.
 */
const WINDOWS_STORE_BY_ANCHOR_TYPE = Object.freeze({
  root: "Root",
  intermediate: "CA",
});

const DEBIAN_ANCHORS_DIR = "/usr/local/share/ca-certificates";
const DEBIAN_UPDATE_COMMAND = "update-ca-certificates";
const DEBIAN_STORE_NAME = "debian-ca-certificates";

/** `update-ca-trust extract`, not bare `update-ca-trust`, is what actually
 * regenerates the consolidated bundle after a source anchor file changes. */
const RHEL_ANCHORS_DIR = "/etc/pki/ca-trust/source/anchors";
const RHEL_UPDATE_COMMAND = "update-ca-trust";
const RHEL_UPDATE_ARGS = Object.freeze(["extract"]);
const RHEL_STORE_NAME = "rhel-ca-trust";

/** Grep-able marker of agent-owned artifacts on a shared filesystem. */
const ANCHOR_FILENAME_PREFIX = "tokentimer-";

/**
 * Policy allowlist (../policy) command-ref names, one per platform-native
 * trust-store executable. ../index.js resolves these via
 * `policyEngine.checkCommandRef` before any store mutation on every
 * platform, so a renew-only agent's policy (no trust-store refs configured)
 * grants no trust-store command execution anywhere, Windows included. The
 * Debian/RHEL refs gate a full update-command argv (executable plus fixed
 * args); the Windows ref gates the `certutil` executable itself, since the
 * rest of that platform's argv (`-addstore`/`-delstore`, store name, staging
 * path) is built from validated agent-local inputs rather than an
 * operator-supplied template.
 */
const TRUST_STORE_COMMAND_REFS = Object.freeze({
  DEBIAN_UPDATE_CA_CERTIFICATES: "trust-store:update-ca-certificates",
  RHEL_UPDATE_CA_TRUST: "trust-store:update-ca-trust",
  WINDOWS_CERTUTIL: "trust-store:certutil",
});

/**
 * Command-ref name for a family.
 * @param {"debian"|"rhel"|"windows"} family
 * @returns {string}
 */
function trustStoreCommandRefForFamily(family) {
  if (family === "debian") return TRUST_STORE_COMMAND_REFS.DEBIAN_UPDATE_CA_CERTIFICATES;
  if (family === "rhel") return TRUST_STORE_COMMAND_REFS.RHEL_UPDATE_CA_TRUST;
  if (family === "windows") return TRUST_STORE_COMMAND_REFS.WINDOWS_CERTUTIL;
  throw buildError(`trustStoreCommandRefForFamily: unsupported family ${JSON.stringify(family)}`);
}

function buildError(message, code) {
  const error = new Error(`tokentimer-agent trust-store: ${message}`);
  if (code) error.code = code;
  return error;
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function assertSafeArgvElements(label, argv) {
  argv.forEach((element, index) => {
    if (!isNonEmptyString(element)) {
      throw buildError(`${label}[${index}] must be a non-empty string (got ${typeof element})`);
    }
    if (SHELL_METACHARACTER_PATTERN.test(element)) {
      throw buildError(`${label}[${index}] contains a disallowed shell metacharacter: ${JSON.stringify(element)}`);
    }
  });
}

function boundAndRedactExcerpt(output) {
  const text =
    typeof output === "string" ? output : Buffer.isBuffer(output) ? output.toString("utf8") : "";
  if (text.includes(PRIVATE_KEY_MARKER)) return REDACTED_EXCERPT_PLACEHOLDER;
  return text.slice(0, OUTPUT_EXCERPT_MAX_CHARS);
}

/**
 * Promise wrapper around an execFile-shaped implementation. Never rejects on
 * a nonzero exit/timeout (an operational outcome), only surfaces a genuine
 * spawn/programmer error via the resolved execError field.
 * @param {Function} execFileImpl
 * @param {string[]} argv argv[0] is the executable
 * @param {number} timeoutMs
 * @returns {Promise<{exitCode: number|null, stdout: unknown, stderr: unknown, execError: Error|null}>}
 */
function execWithoutShell(execFileImpl, argv, timeoutMs) {
  const [file, ...args] = argv;
  return new Promise((resolve) => {
    execFileImpl(
      file,
      args,
      { timeout: timeoutMs, windowsHide: true, maxBuffer: 10 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) {
          const exitCode = typeof error.code === "number" ? error.code : null;
          resolve({ exitCode, stdout, stderr, execError: error });
          return;
        }
        resolve({ exitCode: 0, stdout, stderr, execError: null });
      },
    );
  });
}

/**
 * Whether a PEM string contains exactly one certificate block. The schema's
 * `pem` pattern only requires the text to START with a cert header, so a
 * concatenated bundle isn't ruled out; a bundle is never installed as a
 * single anchor.
 * @param {string} pem
 * @returns {boolean}
 */
function isSingleCertificatePem(pem) {
  const matches = pem.match(/-----BEGIN CERTIFICATE-----/g);
  return Array.isArray(matches) && matches.length === 1;
}

/**
 * Re-validates a signed distribute-trust job's PEM against its claimed
 * fingerprintSha256 and re-checks the Basic Constraints CA flag, rather than
 * trusting the (already-signed) payload. Never throws; a malformed or
 * mismatched PEM returns a tagged failure instead.
 * @param {string} pem
 * @param {string} expectedFingerprintSha256 lowercase 64-hex-char SHA-256.
 * @returns {
 *   { ok: true, der: Buffer, actualFingerprintSha256: string }
 *   | { ok: false, failureCategory: string }
 * }
 */
function verifyAnchorPem(pem, expectedFingerprintSha256) {
  if (!isNonEmptyString(pem)) {
    return { ok: false, failureCategory: "invalid_payload" };
  }
  if (!isNonEmptyString(expectedFingerprintSha256) || !FINGERPRINT_PATTERN.test(expectedFingerprintSha256)) {
    return { ok: false, failureCategory: "invalid_payload" };
  }
  if (!isSingleCertificatePem(pem)) {
    return { ok: false, failureCategory: "multiple_certificates_in_pem" };
  }

  let cert;
  try {
    cert = new X509Certificate(pem);
  } catch {
    return { ok: false, failureCategory: "unparseable_certificate" };
  }

  const actualFingerprintSha256 = String(cert.fingerprint256 || "").replace(/:/g, "").toLowerCase();
  if (!FINGERPRINT_PATTERN.test(actualFingerprintSha256)) {
    return { ok: false, failureCategory: "unparseable_certificate" };
  }
  if (actualFingerprintSha256 !== expectedFingerprintSha256) {
    return { ok: false, failureCategory: "fingerprint_mismatch" };
  }
  // Refused agent-side too: defense in depth against a buggy control plane.
  if (cert.ca !== true) {
    return { ok: false, failureCategory: "not_a_ca_certificate" };
  }

  return { ok: true, der: cert.raw, actualFingerprintSha256 };
}

/**
 * Deterministic anchor filename derived purely from the fingerprint, never
 * from control-plane-supplied names (not validated against a filesystem-safe
 * alphabet). Used for both the permanent Linux anchor file and the transient
 * Windows staging file, so a leftover staging file after a crash stays
 * attributable.
 * @param {string} fingerprintSha256 lowercase 64-hex-char SHA-256.
 * @param {string} extension without a leading dot, e.g. "crt", "pem", "cer".
 * @returns {string}
 */
function deterministicAnchorFilename(fingerprintSha256, extension) {
  if (!isNonEmptyString(fingerprintSha256) || !FINGERPRINT_PATTERN.test(fingerprintSha256)) {
    throw buildError(`fingerprintSha256 must be a 64-hex-char lowercase SHA-256 string (got ${JSON.stringify(fingerprintSha256)})`);
  }
  if (!isNonEmptyString(extension) || !/^[a-z0-9]{1,8}$/.test(extension)) {
    throw buildError(`extension must be a short lowercase alphanumeric string (got ${JSON.stringify(extension)})`);
  }
  return `${ANCHOR_FILENAME_PREFIX}${fingerprintSha256}.${extension}`;
}

/**
 * Whether an executable resolves on PATH, without spawning it.
 * @param {string} command
 * @param {object} [options]
 * @param {(p: string) => boolean} [options.existsSyncImpl]
 * @param {string} [options.pathEnv]
 * @returns {boolean}
 */
function commandExistsOnPath(command, { existsSyncImpl = fs.existsSync, pathEnv = process.env.PATH || "" } = {}) {
  if (!isNonEmptyString(command)) return false;
  return pathEnv
    .split(path.delimiter)
    .filter((dir) => dir.length > 0)
    .some((dir) => {
      try {
        return existsSyncImpl(path.join(dir, command));
      } catch {
        return false;
      }
    });
}

/**
 * Debian-family detection: requires BOTH the anchor directory and the update
 * command, rather than sniffing `/etc/os-release`.
 * @param {object} [options]
 * @param {(p: string) => boolean} [options.existsSyncImpl]
 * @param {string} [options.pathEnv]
 * @param {string} [options.anchorsDir]
 * @returns {boolean}
 */
function detectDebianFamily({
  existsSyncImpl = fs.existsSync,
  pathEnv = process.env.PATH || "",
  anchorsDir = DEBIAN_ANCHORS_DIR,
} = {}) {
  return (
    existsSyncImpl(anchorsDir) &&
    commandExistsOnPath(DEBIAN_UPDATE_COMMAND, { existsSyncImpl, pathEnv })
  );
}

/**
 * RHEL-family detection, symmetric to detectDebianFamily.
 * @param {object} [options]
 * @param {(p: string) => boolean} [options.existsSyncImpl]
 * @param {string} [options.pathEnv]
 * @param {string} [options.anchorsDir]
 * @returns {boolean}
 */
function detectRhelFamily({
  existsSyncImpl = fs.existsSync,
  pathEnv = process.env.PATH || "",
  anchorsDir = RHEL_ANCHORS_DIR,
} = {}) {
  return (
    existsSyncImpl(anchorsDir) &&
    commandExistsOnPath(RHEL_UPDATE_COMMAND, { existsSyncImpl, pathEnv })
  );
}

/**
 * Resolves whether this executor can run on the current host and under which
 * family, without executing anything. ../index.js's AGENT_CANDIDATE_CAPABILITIES
 * uses this to decide whether `trust-anchor-deploy-v1` is a candidate capability.
 * @param {object} [options]
 * @param {string} [options.platform] defaults to process.platform.
 * @param {(p: string) => boolean} [options.existsSyncImpl]
 * @param {string} [options.pathEnv]
 * @returns {{ candidate: boolean, family: "windows"|"debian"|"rhel"|null }}
 */
function resolveTrustStorePrerequisites({
  platform = process.platform,
  existsSyncImpl = fs.existsSync,
  pathEnv = process.env.PATH || "",
} = {}) {
  if (isWindows(platform)) {
    return { candidate: true, family: "windows" };
  }
  if (detectDebianFamily({ existsSyncImpl, pathEnv })) {
    return { candidate: true, family: "debian" };
  }
  if (detectRhelFamily({ existsSyncImpl, pathEnv })) {
    return { candidate: true, family: "rhel" };
  }
  return { candidate: false, family: null };
}

/**
 * Enumerates a Windows machine store and resolves which entry (if any)
 * matches a target SHA-256 fingerprint. certutil's `-store` listing only
 * reports SHA-1 thumbprints, so this recomputes the SHA-256 for every entry
 * via ../discovery/windows.js and matches against the target.
 * @param {object} input
 * @param {string} input.store Windows machine store name (e.g. "Root", "CA").
 * @param {string} input.fingerprintSha256 lowercase 64-hex-char SHA-256.
 * @param {Function} [input.spawnImpl] injection point for
 *   fetchRawCertificateDerByThumbprint's underlying spawnSync-shaped call.
 * @param {(m: string) => void} [input.onWarning]
 * @returns {{ found: true, thumbprint: string }|{ found: false }}
 */
function findWindowsStoreEntryByFingerprint({ store, fingerprintSha256, spawnImpl = spawnSync, onWarning = () => {} }) {
  const byThumbprint = fetchRawCertificateDerByThumbprint({
    storeLocation: "LocalMachine",
    storeName: store,
    spawn: spawnImpl,
    onWarning,
  });
  for (const [thumbprint, rawCertificateBase64] of byThumbprint.entries()) {
    const actual = computeFingerprintSha256FromDerBase64(rawCertificateBase64, onWarning);
    if (actual === fingerprintSha256) {
      return { found: true, thumbprint: thumbprint.toUpperCase() };
    }
  }
  return { found: false };
}

/**
 * `certutil -addstore <store> <file>` against a deterministically-named
 * staging file, best-effort-deleted in a `finally` (public cert bytes only,
 * so a failed unlink is litter, not a security issue).
 * @param {object} input
 * @param {string} input.store
 * @param {string} input.pem
 * @param {string} input.fingerprintSha256
 * @param {string} input.workDir
 * @param {Function} [input.execFileImpl]
 * @param {string} [input.certutilPath]
 * @param {number} [input.timeoutMs]
 * @returns {Promise<{ ok: true }|{ ok: false, exitCode: number|null, stdoutExcerpt: string, stderrExcerpt: string }>}
 */
async function addWindowsStoreEntry({
  store,
  pem,
  fingerprintSha256,
  workDir,
  execFileImpl = childProcess.execFile,
  certutilPath = "certutil.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
}) {
  fs.mkdirSync(workDir, { recursive: true });
  const stagingPath = path.join(workDir, deterministicAnchorFilename(fingerprintSha256, "cer"));
  fs.writeFileSync(stagingPath, pem, { encoding: "utf8", flag: "w" });
  try {
    const argv = [certutilPath, "-addstore", store, stagingPath];
    assertSafeArgvElements("argv", argv);
    const { exitCode, stdout, stderr } = await execWithoutShell(execFileImpl, argv, timeoutMs);
    if (exitCode !== 0) {
      return {
        ok: false,
        exitCode,
        stdoutExcerpt: boundAndRedactExcerpt(stdout),
        stderrExcerpt: boundAndRedactExcerpt(stderr),
      };
    }
    return { ok: true };
  } finally {
    try {
      fs.unlinkSync(stagingPath);
    } catch {
      // best-effort; see doc comment above.
    }
  }
}

/**
 * `certutil -delstore <store> <thumbprint>`. Delete is thumbprint-keyed, not
 * fingerprint-keyed, so the caller must resolve the thumbprint first via
 * findWindowsStoreEntryByFingerprint.
 * @param {object} input
 * @param {string} input.store
 * @param {string} input.thumbprint SHA-1, 40 hex chars.
 * @param {Function} [input.execFileImpl]
 * @param {string} [input.certutilPath]
 * @param {number} [input.timeoutMs]
 * @returns {Promise<{ ok: true }|{ ok: false, exitCode: number|null, stdoutExcerpt: string, stderrExcerpt: string }>}
 */
async function removeWindowsStoreEntry({
  store,
  thumbprint,
  execFileImpl = childProcess.execFile,
  certutilPath = "certutil.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
}) {
  const argv = [certutilPath, "-delstore", store, thumbprint];
  assertSafeArgvElements("argv", argv);
  const { exitCode, stdout, stderr } = await execWithoutShell(execFileImpl, argv, timeoutMs);
  if (exitCode !== 0) {
    return {
      ok: false,
      exitCode,
      stdoutExcerpt: boundAndRedactExcerpt(stdout),
      stderrExcerpt: boundAndRedactExcerpt(stderr),
    };
  }
  return { ok: true };
}

/**
 * Linux anchor file path for one fingerprint. Debian-family uses `.crt`
 * because `update-ca-certificates` only scans `*.crt`; RHEL-family uses
 * `.pem` by convention.
 * @param {"debian"|"rhel"} family
 * @param {string} fingerprintSha256
 * @param {string} [anchorsDir] override for tests.
 * @returns {string}
 */
function linuxAnchorFilePath(family, fingerprintSha256, anchorsDir) {
  if (family === "debian") {
    const dir = anchorsDir || DEBIAN_ANCHORS_DIR;
    return path.join(dir, deterministicAnchorFilename(fingerprintSha256, "crt"));
  }
  if (family === "rhel") {
    const dir = anchorsDir || RHEL_ANCHORS_DIR;
    return path.join(dir, deterministicAnchorFilename(fingerprintSha256, "pem"));
  }
  throw buildError(`unsupported Linux family: ${JSON.stringify(family)}`);
}

/**
 * Whether the anchor file for (family, fingerprintSha256) is present AND its
 * content actually hashes to that fingerprint (catches a file at this
 * deterministic path whose content doesn't match its own name).
 * @param {object} input
 * @param {"debian"|"rhel"} input.family
 * @param {string} input.fingerprintSha256
 * @param {string} [input.anchorsDir]
 * @param {typeof fs} [input.fsImpl]
 * @returns {{ present: true }|{ present: false }|{ present: "conflict", actualFingerprintSha256: string|null }}
 */
function probeLinuxAnchorFile({ family, fingerprintSha256, anchorsDir, fsImpl = fs }) {
  const filePath = linuxAnchorFilePath(family, fingerprintSha256, anchorsDir);
  let pem;
  try {
    pem = fsImpl.readFileSync(filePath, "utf8");
  } catch (err) {
    if (err && err.code === "ENOENT") return { present: false };
    return { present: "conflict", actualFingerprintSha256: null };
  }
  let cert;
  try {
    cert = new X509Certificate(pem);
  } catch {
    return { present: "conflict", actualFingerprintSha256: null };
  }
  const actualFingerprintSha256 = String(cert.fingerprint256 || "").replace(/:/g, "").toLowerCase();
  if (actualFingerprintSha256 !== fingerprintSha256) {
    return { present: "conflict", actualFingerprintSha256 };
  }
  return { present: true };
}

/**
 * Writes the anchor PEM to its deterministic path and runs the family's
 * update command. Uses plain fs, not receipt.js's writeFileAtomically: a
 * partial write here just gets re-written identically next attempt, since
 * filename and content are both pure functions of the fingerprint (a receipt
 * row, by contrast, must never be torn).
 * @param {object} input
 * @param {"debian"|"rhel"} input.family
 * @param {string} input.pem
 * @param {string} input.fingerprintSha256
 * @param {string} [input.anchorsDir]
 * @param {typeof fs} [input.fsImpl]
 * @param {Function} [input.execFileImpl]
 * @param {string[]} [input.updateCommandArgv] policy-resolved argv override;
 *   falls back to the hardcoded command literals for tests/bypass callers.
 * @param {number} [input.timeoutMs]
 * @returns {Promise<{ ok: true }|{ ok: false, exitCode: number|null, stdoutExcerpt: string, stderrExcerpt: string }>}
 */
async function installLinuxAnchorFile({
  family,
  pem,
  fingerprintSha256,
  anchorsDir,
  fsImpl = fs,
  execFileImpl = childProcess.execFile,
  updateCommandArgv,
  timeoutMs = DEFAULT_TIMEOUT_MS,
}) {
  const filePath = linuxAnchorFilePath(family, fingerprintSha256, anchorsDir);
  fsImpl.mkdirSync(path.dirname(filePath), { recursive: true });
  fsImpl.writeFileSync(filePath, pem, { encoding: "utf8", mode: 0o644 });

  const argv =
    updateCommandArgv || (family === "debian" ? [DEBIAN_UPDATE_COMMAND] : [RHEL_UPDATE_COMMAND, ...RHEL_UPDATE_ARGS]);
  assertSafeArgvElements("argv", argv);
  const { exitCode, stdout, stderr } = await execWithoutShell(execFileImpl, argv, timeoutMs);
  if (exitCode !== 0) {
    return {
      ok: false,
      exitCode,
      stdoutExcerpt: boundAndRedactExcerpt(stdout),
      stderrExcerpt: boundAndRedactExcerpt(stderr),
    };
  }
  return { ok: true };
}

/**
 * Deletes the deterministic anchor file and re-runs the family's update
 * command: leaving the source file deleted but the derived bundle stale
 * would mean the anchor is still effectively trusted.
 * @param {object} input
 * @param {"debian"|"rhel"} input.family
 * @param {string} input.fingerprintSha256
 * @param {string} [input.anchorsDir]
 * @param {typeof fs} [input.fsImpl]
 * @param {Function} [input.execFileImpl]
 * @param {string[]} [input.updateCommandArgv] policy-resolved argv override;
 *   falls back to the hardcoded command literals for tests/bypass callers.
 * @param {number} [input.timeoutMs]
 * @returns {Promise<{ ok: true }|{ ok: false, exitCode: number|null, stdoutExcerpt: string, stderrExcerpt: string }>}
 */
async function removeLinuxAnchorFile({
  family,
  fingerprintSha256,
  anchorsDir,
  fsImpl = fs,
  execFileImpl = childProcess.execFile,
  updateCommandArgv,
  timeoutMs = DEFAULT_TIMEOUT_MS,
}) {
  const filePath = linuxAnchorFilePath(family, fingerprintSha256, anchorsDir);

  try {
    fsImpl.unlinkSync(filePath);
  } catch (err) {
    if (!err || err.code !== "ENOENT") {
      return { ok: false, exitCode: null, stdoutExcerpt: "", stderrExcerpt: String(err && err.message ? err.message : err) };
    }
  }

  const argv =
    updateCommandArgv || (family === "debian" ? [DEBIAN_UPDATE_COMMAND] : [RHEL_UPDATE_COMMAND, ...RHEL_UPDATE_ARGS]);
  assertSafeArgvElements("argv", argv);
  const { exitCode, stdout, stderr } = await execWithoutShell(execFileImpl, argv, timeoutMs);
  if (exitCode !== 0) {
    return {
      ok: false,
      exitCode,
      stdoutExcerpt: boundAndRedactExcerpt(stdout),
      stderrExcerpt: boundAndRedactExcerpt(stderr),
    };
  }
  return { ok: true };
}

/**
 * Resolves the concrete, family-specific store destination for the real OS
 * mutation and this agent's local receipt key. NOT reported on the wire -
 * see resolveWireStore for the platform-neutral label a result actually
 * carries in its `store` field. Kept distinct so a Debian/RHEL family value
 * (e.g. "debian-ca-certificates") never leaks into the wire contract, where
 * only Windows-shaped names ("Root"/"CA") are meaningful across platforms.
 * @param {"windows"|"debian"|"rhel"} family
 * @param {"root"|"intermediate"} anchorType
 * @returns {string}
 */
function resolveConcreteStore(family, anchorType) {
  if (family === "windows") {
    const store = WINDOWS_STORE_BY_ANCHOR_TYPE[anchorType];
    if (!store) throw buildError(`unsupported anchorType for windows: ${JSON.stringify(anchorType)}`);
    return store;
  }
  if (family === "debian") return DEBIAN_STORE_NAME;
  if (family === "rhel") return RHEL_STORE_NAME;
  throw buildError(`unsupported family: ${JSON.stringify(family)}`);
}

/**
 * The wire-visible `store` label reported on every result (trust-result-
 * contract.schema.json). Unlike resolveConcreteStore's family-specific
 * value (used only locally, for the real OS mutation and receipt keys),
 * this is anchorType-only and therefore identical across every platform:
 * ADR-0012 decision 4 keeps anchorType platform-neutral in the contract
 * and confines platform-specific naming to the executor. The control
 * plane derives this exact same label from anchor_type alone when it
 * creates the job, with no need to know this agent's platform/family, so
 * a correct result can never be rejected as a store mismatch.
 * @param {"root"|"intermediate"} anchorType
 * @returns {string}
 */
function resolveWireStore(anchorType) {
  const store = WINDOWS_STORE_BY_ANCHOR_TYPE[anchorType];
  if (!store) throw buildError(`unsupported anchorType: ${JSON.stringify(anchorType)}`);
  return store;
}

/**
 * The generation the control plane resolved for this dispatch. The server
 * rejects any result that doesn't echo the row's current generation, so
 * refusing here (rather than defaulting) avoids producing unsyncable work.
 */
function requireTransitionGeneration(job) {
  if (!Number.isInteger(job.transitionGeneration) || job.transitionGeneration < 1) {
    throw buildError(
      `transitionGeneration must be an integer >= 1 (got ${JSON.stringify(job.transitionGeneration)})`,
    );
  }
  return job.transitionGeneration;
}

/**
 * Maps internal result shapes to the wire `receipt.state` enum. Deliberately
 * a different vocabulary from receipt.js's on-disk `RECEIPT_STATES`: wire
 * states describe how far THIS result's operation got, on-disk states
 * describe what the persisted row currently says.
 * @param {"intent_written"|"finalized"|"missing"|"corrupt"} state
 * @returns {string}
 */
function receiptWireState(state) {
  if (!["intent_written", "finalized", "missing", "corrupt"].includes(state)) {
    throw buildError(`invalid receipt wire state: ${JSON.stringify(state)}`);
  }
  return state;
}

/**
 * failureCategory values for a receipt bookkeeping conflict, distinct from
 * an OS-mutation failure: the OS-level state described by `outcome` is
 * accurate, but the on-disk receipt itself could not be written/finalized to
 * match it. Only reachable if this executor's single-job-at-a-time
 * sequencing assumption is violated (see receipt.js's reclaimStalePending).
 */
const RECEIPT_WRITE_CONFLICT = "receipt_write_conflict";
const RECEIPT_FINALIZE_CONFLICT = "receipt_finalize_conflict";

/**
 * Runs a receipt.js write step (writeIntentReceipt/finalizeReceipt) that is
 * documented to throw on a guard violation, and converts that into a tagged
 * failure instead of propagating - distributeTrust/revokeTrust must never
 * throw for an operational outcome.
 * @param {() => object} fn
 * @returns {{ ok: true, value: object }|{ ok: false, error: Error }}
 */
function tryReceiptStep(fn) {
  try {
    return { ok: true, value: fn() };
  } catch (error) {
    return { ok: false, error };
  }
}

/**
 * Builds one trust-result-contract.schema.json-shaped result object.
 * @param {object} input see call sites for the exact fields threaded through.
 * @returns {object}
 */
function buildResult({
  jobId,
  workspaceId,
  agentId,
  trustAnchorId,
  action,
  transitionGeneration,
  store,
  observedFingerprintBefore,
  observedFingerprintAfter,
  outcome,
  mutationAttempted,
  mutationPerformed,
  receiptId: builtReceiptId,
  receiptState,
  failureCategory = null,
  now = () => new Date(),
}) {
  return {
    schemaVersion: 1,
    jobId,
    workspaceId,
    agentId,
    trustAnchorId,
    action,
    transitionGeneration,
    store,
    observedFingerprintBefore,
    observedFingerprintAfter,
    outcome,
    mutationAttempted,
    mutationPerformed,
    receipt: { id: builtReceiptId, state: receiptWireState(receiptState) },
    failureCategory,
    observedAt: now().toISOString(),
  };
}

/**
 * Executes a signed `distribute-trust` job. Never throws for an operational
 * outcome; every refusal is reported via `outcome`/`failureCategory`, and the
 * store is never touched on a mismatch.
 *
 * Sequencing: fingerprint/CA re-validation and the preexisting-in-store probe
 * run BEFORE any receipt write; the intent receipt is written and fsynced
 * before the install mutation is attempted; the receipt is finalized only
 * after the mutation completes.
 *
 * @param {object} input
 * @param {object} input.job the verified trust-job-payload.schema.json
 *   payload (already signature-verified by the caller; this function
 *   re-validates the PEM/fingerprint pairing itself regardless).
 * @param {"windows"|"debian"|"rhel"} input.family resolveTrustStorePrerequisites' own family value.
 * @param {string} input.receiptDir agent-local receipt storage directory.
 * @param {string} [input.workDir] scratch directory for Windows staging files.
 * @param {object} [input.seams] injectable exec/fs/spawn seams, threaded
 *   through to the platform-specific install functions.
 * @param {() => Date} [input.now]
 * @returns {Promise<object>} a trust-result-contract.schema.json-shaped result.
 */
async function distributeTrust({ job, family, receiptDir, workDir, seams = {}, now = () => new Date() }) {
  const { jobId, workspaceId, agentId, trustAnchorId, anchorType, fingerprintSha256, pem } = job;
  // osStore: the real OS-level destination (mutation + receipt key). store:
  // the wire-visible label echoed on the result (see resolveWireStore).
  const osStore = resolveConcreteStore(family, anchorType);
  const store = resolveWireStore(anchorType);
  const transitionGeneration = requireTransitionGeneration(job);

  const verification = verifyAnchorPem(pem, fingerprintSha256);
  if (!verification.ok) {
    // No wire `outcome` value exists for "refused before probing the store",
    // so this reports `already_absent` with the real reason in failureCategory.
    return buildResult({
      jobId,
      workspaceId,
      agentId,
      trustAnchorId,
      action: "distribute-trust",
      transitionGeneration,
      store,
      observedFingerprintBefore: null,
      observedFingerprintAfter: null,
      outcome: "already_absent",
      mutationAttempted: false,
      mutationPerformed: false,
      receiptId: receipt.receiptId(osStore, fingerprintSha256),
      receiptState: "missing",
      failureCategory: verification.failureCategory,
      now,
    });
  }

  const presence =
    family === "windows"
      ? findWindowsStoreEntryByFingerprint({
          store: osStore,
          fingerprintSha256,
          spawnImpl: seams.spawnImpl,
          onWarning: seams.onWarning,
        })
      : probeLinuxAnchorFile({
          family,
          fingerprintSha256,
          anchorsDir: seams.anchorsDir,
          fsImpl: seams.fsImpl,
        });
  const isPresent = family === "windows" ? presence.found : presence.present === true;

  if (isPresent) {
    // Idempotent install: no mutation, outcome `preexisting`, no receipt
    // write (an anchor this agent didn't install has no ownership to record).
    return buildResult({
      jobId,
      workspaceId,
      agentId,
      trustAnchorId,
      action: "distribute-trust",
      transitionGeneration,
      store,
      observedFingerprintBefore: fingerprintSha256,
      observedFingerprintAfter: fingerprintSha256,
      outcome: "preexisting",
      mutationAttempted: false,
      mutationPerformed: false,
      receiptId: receipt.receiptId(osStore, fingerprintSha256),
      receiptState: "missing",
      now,
    });
  }

  const intentAttempt = tryReceiptStep(() =>
    receipt.writeIntentReceipt({
      receiptDir,
      store: osStore,
      fingerprintSha256,
      jobId,
      transitionGeneration,
      intentState: "pending_install",
      // isPresent just proved this fingerprint is NOT in the OS store, so any
      // stale pending_install receipt from a different, dead job on this exact
      // (store, fingerprint) never reached the OS either - safe to reclaim.
      // Without this, a crash between intent-write and OS mutation would
      // permanently block later distribute-trust jobs for that fingerprint.
      reclaimStalePending: true,
      now,
    }),
  );
  if (!intentAttempt.ok) {
    // No OS mutation was attempted. Only reachable if another process is
    // genuinely still working this same (store, fingerprint) right now.
    return buildResult({
      jobId,
      workspaceId,
      agentId,
      trustAnchorId,
      action: "distribute-trust",
      transitionGeneration,
      store,
      observedFingerprintBefore: null,
      observedFingerprintAfter: null,
      outcome: "already_absent",
      mutationAttempted: false,
      mutationPerformed: false,
      receiptId: receipt.receiptId(osStore, fingerprintSha256),
      receiptState: "missing",
      failureCategory: RECEIPT_WRITE_CONFLICT,
      now,
    });
  }
  const intentRow = intentAttempt.value;

  const mutationResult =
    family === "windows"
      ? await addWindowsStoreEntry({
          store: osStore,
          pem,
          fingerprintSha256,
          workDir,
          execFileImpl: seams.execFileImpl,
          certutilPath: seams.certutilPath,
          timeoutMs: seams.timeoutMs,
        })
      : await installLinuxAnchorFile({
          family,
          pem,
          fingerprintSha256,
          anchorsDir: seams.anchorsDir,
          fsImpl: seams.fsImpl,
          execFileImpl: seams.execFileImpl,
          updateCommandArgv: seams.updateCommandArgv,
          timeoutMs: seams.timeoutMs,
        });

  if (!mutationResult.ok) {
    return buildResult({
      jobId,
      workspaceId,
      agentId,
      trustAnchorId,
      action: "distribute-trust",
      transitionGeneration,
      store,
      observedFingerprintBefore: null,
      observedFingerprintAfter: null,
      outcome: "already_absent",
      mutationAttempted: true,
      mutationPerformed: false,
      receiptId: intentRow.id,
      receiptState: "intent_written",
      failureCategory: "os_mutation_failed",
      now,
    });
  }

  const finalizeAttempt = tryReceiptStep(() =>
    receipt.finalizeReceipt({ receiptDir, store: osStore, fingerprintSha256, jobId, transitionGeneration, now }),
  );
  if (!finalizeAttempt.ok) {
    // The OS mutation genuinely completed - outcome/mutationPerformed report
    // that truthfully - but the local receipt bookkeeping itself didn't
    // reach "finalized". Surface it via failureCategory rather than either
    // throwing or silently claiming a clean finalize.
    return buildResult({
      jobId,
      workspaceId,
      agentId,
      trustAnchorId,
      action: "distribute-trust",
      transitionGeneration,
      store,
      observedFingerprintBefore: null,
      observedFingerprintAfter: fingerprintSha256,
      outcome: "installed",
      mutationAttempted: true,
      mutationPerformed: true,
      receiptId: intentRow.id,
      receiptState: "intent_written",
      failureCategory: RECEIPT_FINALIZE_CONFLICT,
      now,
    });
  }

  return buildResult({
    jobId,
    workspaceId,
    agentId,
    trustAnchorId,
    action: "distribute-trust",
    transitionGeneration,
    store,
    observedFingerprintBefore: null,
    observedFingerprintAfter: fingerprintSha256,
    outcome: "installed",
    mutationAttempted: true,
    mutationPerformed: true,
    receiptId: intentRow.id,
    receiptState: "finalized",
    now,
  });
}

/**
 * Executes a signed `revoke-trust` job. Removal is ownership-proof-gated: a
 * missing or corrupt receipt refuses removal (never treated as
 * `already_absent`). Only once a receipt proves this agent installed the
 * material does this re-probe the actual store state immediately before
 * deleting; if already gone, that's `already_absent` (success, no error).
 *
 * @param {object} input
 * @param {object} input.job the verified trust-job-payload.schema.json
 *   payload for a revoke-trust action (no `pem` field; identified by
 *   trustAnchorId + fingerprintSha256 alone).
 * @param {"windows"|"debian"|"rhel"} input.family
 * @param {string} input.receiptDir
 * @param {object} [input.seams]
 * @param {() => Date} [input.now]
 * @returns {Promise<object>}
 */
async function revokeTrust({ job, family, receiptDir, seams = {}, now = () => new Date() }) {
  const { jobId, workspaceId, agentId, trustAnchorId, anchorType, fingerprintSha256 } = job;
  // osStore: the real OS-level destination (mutation + receipt key). store:
  // the wire-visible label echoed on the result (see resolveWireStore).
  const osStore = resolveConcreteStore(family, anchorType);
  const store = resolveWireStore(anchorType);
  const transitionGeneration = requireTransitionGeneration(job);

  if (!isNonEmptyString(fingerprintSha256) || !FINGERPRINT_PATTERN.test(fingerprintSha256)) {
    return buildResult({
      jobId,
      workspaceId,
      agentId,
      trustAnchorId,
      action: "revoke-trust",
      transitionGeneration,
      store,
      observedFingerprintBefore: null,
      observedFingerprintAfter: null,
      outcome: "already_absent",
      mutationAttempted: false,
      mutationPerformed: false,
      receiptId: "invalid-fingerprint",
      receiptState: "corrupt",
      failureCategory: "invalid_payload",
      now,
    });
  }

  const existingReceipt = receipt.readReceipt(receiptDir, osStore, fingerprintSha256);

  if (existingReceipt === null) {
    // No ownership proof at all: fail-safe refusal.
    return buildResult({
      jobId,
      workspaceId,
      agentId,
      trustAnchorId,
      action: "revoke-trust",
      transitionGeneration,
      store,
      observedFingerprintBefore: null,
      observedFingerprintAfter: null,
      outcome: "already_absent",
      mutationAttempted: false,
      mutationPerformed: false,
      receiptId: receipt.receiptId(osStore, fingerprintSha256),
      receiptState: "missing",
      failureCategory: "receipt_missing",
      now,
    });
  }
  if ("corrupt" in existingReceipt) {
    return buildResult({
      jobId,
      workspaceId,
      agentId,
      trustAnchorId,
      action: "revoke-trust",
      transitionGeneration,
      store,
      observedFingerprintBefore: null,
      observedFingerprintAfter: null,
      outcome: "already_absent",
      mutationAttempted: false,
      mutationPerformed: false,
      receiptId: receipt.receiptId(osStore, fingerprintSha256),
      receiptState: "corrupt",
      failureCategory: "receipt_corrupt",
      now,
    });
  }
  if (existingReceipt.row.state === "pending_install") {
    // Crash before the install mutation completed: no proof this agent's
    // material reached the store, so nothing is proven to remove. Refuse
    // rather than guess whether the earlier mutation silently succeeded.
    return buildResult({
      jobId,
      workspaceId,
      agentId,
      trustAnchorId,
      action: "revoke-trust",
      transitionGeneration,
      store,
      observedFingerprintBefore: null,
      observedFingerprintAfter: null,
      outcome: "already_absent",
      mutationAttempted: false,
      mutationPerformed: false,
      receiptId: existingReceipt.row.id,
      receiptState: "intent_written",
      failureCategory: "receipt_pending_install",
      now,
    });
  }
  if (existingReceipt.row.state === "removed") {
    // Already removed by a prior transition; nothing left to prove ownership
    // over. Success, no mutation.
    return buildResult({
      jobId,
      workspaceId,
      agentId,
      trustAnchorId,
      action: "revoke-trust",
      transitionGeneration,
      store,
      observedFingerprintBefore: null,
      observedFingerprintAfter: null,
      outcome: "already_absent",
      mutationAttempted: false,
      mutationPerformed: false,
      receiptId: existingReceipt.row.id,
      receiptState: "finalized",
      now,
    });
  }
  // else: state is "installed" (the normal case), a DIFFERENT job's stale
  // pending_remove (a crashed prior revoke attempt - reclaimed below exactly
  // like distributeTrust reclaims a stale pending_install, since the control
  // plane serializes revoke-trust per (agent, store, fingerprint, owner) and
  // a genuinely still-running sibling job is not something this agent can
  // observe any other way), or THIS SAME job's pending_remove (a resumed
  // attempt after a crash between intent and finalize).
  const resumingSameJob =
    existingReceipt.row.state === "pending_remove" && existingReceipt.row.jobId === jobId;

  // Re-probe the ACTUAL store state immediately before deleting: if already
  // gone, report already_absent rather than mutating against nothing.
  const presence =
    family === "windows"
      ? findWindowsStoreEntryByFingerprint({
          store: osStore,
          fingerprintSha256,
          spawnImpl: seams.spawnImpl,
          onWarning: seams.onWarning,
        })
      : probeLinuxAnchorFile({
          family,
          fingerprintSha256,
          anchorsDir: seams.anchorsDir,
          fsImpl: seams.fsImpl,
        });
  const isPresent = family === "windows" ? presence.found : presence.present === true;

  if (!isPresent) {
    // Ownership proven but material already gone: success, no mutation. The
    // receipt still transitions pending_remove -> removed rather than
    // finalizing directly from `installed`; reuses the existing pending_remove
    // row only when resuming this exact job, otherwise writes a fresh intent
    // (reclaiming a different job's stale row, same as the isPresent branch
    // below).
    const intentAttempt = tryReceiptStep(() =>
      resumingSameJob
        ? existingReceipt.row
        : receipt.writeIntentReceipt({
            receiptDir,
            store: osStore,
            fingerprintSha256,
            jobId,
            transitionGeneration,
            intentState: "pending_remove",
            reclaimStalePending: true,
            now,
          }),
    );
    if (!intentAttempt.ok) {
      return buildResult({
        jobId,
        workspaceId,
        agentId,
        trustAnchorId,
        action: "revoke-trust",
        transitionGeneration,
        store,
        observedFingerprintBefore: null,
        observedFingerprintAfter: null,
        outcome: "already_absent",
        mutationAttempted: false,
        mutationPerformed: false,
        receiptId: existingReceipt.row.id,
        receiptState: "intent_written",
        failureCategory: RECEIPT_WRITE_CONFLICT,
        now,
      });
    }
    const intentRow = intentAttempt.value;
    const finalizeAttempt = tryReceiptStep(() =>
      receipt.finalizeReceipt({
        receiptDir,
        store: osStore,
        fingerprintSha256,
        jobId: intentRow.jobId,
        transitionGeneration: intentRow.transitionGeneration,
        now,
      }),
    );
    if (!finalizeAttempt.ok) {
      return buildResult({
        jobId,
        workspaceId,
        agentId,
        trustAnchorId,
        action: "revoke-trust",
        transitionGeneration,
        store,
        observedFingerprintBefore: null,
        observedFingerprintAfter: null,
        outcome: "already_absent",
        mutationAttempted: false,
        mutationPerformed: false,
        receiptId: intentRow.id,
        receiptState: "intent_written",
        failureCategory: RECEIPT_FINALIZE_CONFLICT,
        now,
      });
    }
    const finalized = finalizeAttempt.value;
    return buildResult({
      jobId,
      workspaceId,
      agentId,
      trustAnchorId,
      action: "revoke-trust",
      transitionGeneration,
      store,
      observedFingerprintBefore: null,
      observedFingerprintAfter: null,
      outcome: "already_absent",
      mutationAttempted: false,
      mutationPerformed: false,
      receiptId: finalized.id,
      receiptState: "finalized",
      now,
    });
  }

  const intentAttempt = tryReceiptStep(() =>
    receipt.writeIntentReceipt({
      receiptDir,
      store: osStore,
      fingerprintSha256,
      jobId,
      transitionGeneration,
      intentState: "pending_remove",
      // Symmetric to distributeTrust's reclaim: the isPresent probe just ran
      // above, and a different job's pending_remove row here can only be a
      // crashed prior attempt (per the comment on resumingSameJob above), so
      // reclaiming it here rather than refusing the job matches TRU-10's fix
      // on the distribute side.
      reclaimStalePending: true,
      now,
    }),
  );
  if (!intentAttempt.ok) {
    return buildResult({
      jobId,
      workspaceId,
      agentId,
      trustAnchorId,
      action: "revoke-trust",
      transitionGeneration,
      store,
      observedFingerprintBefore: fingerprintSha256,
      observedFingerprintAfter: fingerprintSha256,
      outcome: "installed",
      mutationAttempted: false,
      mutationPerformed: false,
      receiptId: existingReceipt.row.id,
      receiptState: "intent_written",
      failureCategory: RECEIPT_WRITE_CONFLICT,
      now,
    });
  }
  const intentRow = intentAttempt.value;

  const mutationResult =
    family === "windows"
      ? await removeWindowsStoreEntry({
          store: osStore,
          thumbprint: presence.thumbprint,
          execFileImpl: seams.execFileImpl,
          certutilPath: seams.certutilPath,
          timeoutMs: seams.timeoutMs,
        })
      : await removeLinuxAnchorFile({
          family,
          fingerprintSha256,
          anchorsDir: seams.anchorsDir,
          fsImpl: seams.fsImpl,
          execFileImpl: seams.execFileImpl,
          updateCommandArgv: seams.updateCommandArgv,
          timeoutMs: seams.timeoutMs,
        });

  if (!mutationResult.ok) {
    // `outcome` names the store's TRUE post-attempt state (still installed,
    // since removal didn't complete), not the attempted action - reporting
    // `removed` here would false-positive any consumer checking `outcome`
    // before `mutationPerformed`.
    return buildResult({
      jobId,
      workspaceId,
      agentId,
      trustAnchorId,
      action: "revoke-trust",
      transitionGeneration,
      store,
      observedFingerprintBefore: fingerprintSha256,
      observedFingerprintAfter: fingerprintSha256,
      outcome: "installed",
      mutationAttempted: true,
      mutationPerformed: false,
      receiptId: intentRow.id,
      receiptState: "intent_written",
      failureCategory: "os_mutation_failed",
      now,
    });
  }

  const finalizeAttempt = tryReceiptStep(() =>
    receipt.finalizeReceipt({ receiptDir, store: osStore, fingerprintSha256, jobId, transitionGeneration, now }),
  );
  if (!finalizeAttempt.ok) {
    // The OS mutation genuinely completed - report it truthfully - but the
    // local receipt didn't reach "finalized"; see distributeTrust's mirror
    // of this same handling.
    return buildResult({
      jobId,
      workspaceId,
      agentId,
      trustAnchorId,
      action: "revoke-trust",
      transitionGeneration,
      store,
      observedFingerprintBefore: fingerprintSha256,
      observedFingerprintAfter: null,
      outcome: "removed",
      mutationAttempted: true,
      mutationPerformed: true,
      receiptId: intentRow.id,
      receiptState: "intent_written",
      failureCategory: RECEIPT_FINALIZE_CONFLICT,
      now,
    });
  }

  return buildResult({
    jobId,
    workspaceId,
    agentId,
    trustAnchorId,
    action: "revoke-trust",
    transitionGeneration,
    store,
    observedFingerprintBefore: fingerprintSha256,
    observedFingerprintAfter: null,
    outcome: "removed",
    mutationAttempted: true,
    mutationPerformed: true,
    receiptId: intentRow.id,
    receiptState: "finalized",
    now,
  });
}

module.exports = {
  SHELL_METACHARACTER_PATTERN,
  DEFAULT_TIMEOUT_MS,
  OUTPUT_EXCERPT_MAX_CHARS,
  FINGERPRINT_PATTERN,
  STORE_PATTERN,
  ID_PATTERN,
  WINDOWS_STORE_BY_ANCHOR_TYPE,
  DEBIAN_ANCHORS_DIR,
  DEBIAN_UPDATE_COMMAND,
  DEBIAN_STORE_NAME,
  RHEL_ANCHORS_DIR,
  RHEL_UPDATE_COMMAND,
  RHEL_UPDATE_ARGS,
  RHEL_STORE_NAME,
  ANCHOR_FILENAME_PREFIX,
  TRUST_STORE_COMMAND_REFS,
  trustStoreCommandRefForFamily,
  isSingleCertificatePem,
  verifyAnchorPem,
  deterministicAnchorFilename,
  commandExistsOnPath,
  detectDebianFamily,
  detectRhelFamily,
  resolveTrustStorePrerequisites,
  findWindowsStoreEntryByFingerprint,
  addWindowsStoreEntry,
  removeWindowsStoreEntry,
  linuxAnchorFilePath,
  probeLinuxAnchorFile,
  installLinuxAnchorFile,
  removeLinuxAnchorFile,
  resolveConcreteStore,
  resolveWireStore,
  buildResult,
  distributeTrust,
  revokeTrust,
  assertSafeArgvElements,
  boundAndRedactExcerpt,
  execWithoutShell,
};
