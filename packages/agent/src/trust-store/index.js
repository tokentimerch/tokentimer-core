"use strict";

/**
 * Cross-platform trust-anchor store executor: the agent-side implementation
 * of `distribute-trust` and `revoke-trust` signed jobs
 * (packages/contracts/certops/trust-job-payload.schema.json) across Windows
 * (LocalMachine\Root / LocalMachine\CA), Debian-family
 * (/usr/local/share/ca-certificates + update-ca-certificates), and
 * RHEL-family (/etc/pki/ca-trust/source/anchors + update-ca-trust extract)
 * machine trust stores. Implements the trust-anchor execution surface
 * described in
 * docs/adr/0012-certops-windows-execution-surface-and-trust-anchors.md.
 *
 * Module style follows ../windows-cert-store and ../windows-discovery:
 * CommonJS, node builtins only, injectable exec/fs seams, exec via
 * child_process.execFile WITHOUT a shell, every dynamic argv element
 * re-validated against a shell-metacharacter pattern as defense in depth.
 *
 * Cross-signed-root independence: each fingerprintSha256 is an independent
 * anchor with its own ownership receipt (./receipt.js keys receipts by
 * (store, fingerprintSha256)). A CA cross-signing under two roots is just two
 * unrelated pairs; installing or revoking one implies nothing about the other.
 *
 * No desired-state pruning: every function acts on exactly the one (store,
 * fingerprintSha256) pair named by its caller. Enumeration only ever ANSWERS
 * "is this exact fingerprint present", never decides what else to touch.
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

/** Every exec runs without a shell; this pattern is defense in depth against
 * a malformed caller-supplied value ending up in argv. */
const SHELL_METACHARACTER_PATTERN = /[;|&$`><\r\n]/;

const DEFAULT_TIMEOUT_MS = 2 * 60 * 1000;
const OUTPUT_EXCERPT_MAX_CHARS = 1024;
const REDACTED_EXCERPT_PLACEHOLDER = "[redacted]";
const PRIVATE_KEY_MARKER = "PRIVATE KEY";

/** Mirrors trust-job-payload.schema.json's fingerprintSha256 pattern
 * (lowercase, 64 hex chars). */
const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;

/** Mirrors trust-result-contract.schema.json's `store` field pattern: the
 * concrete store this module resolved anchorType/family into. */
const STORE_PATTERN = /^[A-Za-z0-9 _.-]{1,64}$/;

/** Mirrors trust-job-payload.schema.json's trustAnchorId/jobId pattern. */
const ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;

/**
 * A root anchor targets LocalMachine\Root, an intermediate targets
 * LocalMachine\CA. The ONLY place anchorType turns into a concrete Windows
 * store name: the signed job's anchorType is the routing decision, never
 * re-derived from the certificate's basicConstraints/issuer at run time.
 */
const WINDOWS_STORE_BY_ANCHOR_TYPE = Object.freeze({
  root: "Root",
  intermediate: "CA",
});

/** Debian-family anchor directory + update command: every PEM installed on a
 * Debian-family host lives here, named from its own fingerprint. */
const DEBIAN_ANCHORS_DIR = "/usr/local/share/ca-certificates";
const DEBIAN_UPDATE_COMMAND = "update-ca-certificates";
const DEBIAN_STORE_NAME = "debian-ca-certificates";

/** RHEL-family anchor directory + update command. `update-ca-trust extract`
 * (not bare `update-ca-trust`) is the invocation that actually regenerates
 * the consolidated bundle after a source anchor file changes. */
const RHEL_ANCHORS_DIR = "/etc/pki/ca-trust/source/anchors";
const RHEL_UPDATE_COMMAND = "update-ca-trust";
const RHEL_UPDATE_ARGS = Object.freeze(["extract"]);
const RHEL_STORE_NAME = "rhel-ca-trust";

/** Every file this module creates starts with this literal prefix: a
 * grep-able marker of agent-owned artifacts on a shared filesystem. */
const ANCHOR_FILENAME_PREFIX = "tokentimer-";

/**
 * Command-reference names the agent-local policy allowlist (../policy) must
 * carry, one per platform-native update command. ../index.js resolves these
 * via `policyEngine.checkCommandRef(...)` into
 * distributeTrust/revokeTrust's `seams.updateCommandArgv`, so a renew-only
 * agent's policy grants no trust-store command execution, and vice versa.
 */
const TRUST_STORE_COMMAND_REFS = Object.freeze({
  DEBIAN_UPDATE_CA_CERTIFICATES: "trust-store:update-ca-certificates",
  RHEL_UPDATE_CA_TRUST: "trust-store:update-ca-trust",
});

/**
 * Resolves the command-ref name for a given family. Windows has no
 * command-ref-mediated step (certutil is invoked directly, with argv built
 * from validated agent-local inputs), so this is Linux-only.
 * @param {"debian"|"rhel"} family
 * @returns {string}
 */
function trustStoreCommandRefForFamily(family) {
  if (family === "debian") return TRUST_STORE_COMMAND_REFS.DEBIAN_UPDATE_CA_CERTIFICATES;
  if (family === "rhel") return TRUST_STORE_COMMAND_REFS.RHEL_UPDATE_CA_TRUST;
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
 * Promise wrapper around an execFile-shaped implementation, mirroring
 * ../windows-cert-store's execWithoutShell: never rejects on a nonzero
 * exit/timeout (an operational outcome), only surfaces a genuine
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
 * Whether a PEM string contains exactly one certificate block.
 * trust-job-payload.schema.json's `pem` pattern only requires the text to
 * START with a certificate header, so it does not rule out a concatenated
 * bundle. A bundle is never installed as a single anchor: each anchor is one
 * certificate with its own fingerprint and receipt.
 * @param {string} pem
 * @returns {boolean}
 */
function isSingleCertificatePem(pem) {
  const matches = pem.match(/-----BEGIN CERTIFICATE-----/g);
  return Array.isArray(matches) && matches.length === 1;
}

/**
 * Re-validates a signed distribute-trust job's PEM against its claimed
 * fingerprintSha256 and re-checks the Basic Constraints CA flag. The payload
 * is signed, but both values are recomputed here rather than trusted, via
 * node:crypto's X509Certificate.
 *
 * Never throws: a malformed or mismatched PEM must refuse and report a
 * failure category, not crash the executor, so this returns a tagged result.
 *
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
  // Refused agent-side even though the control plane is expected to have
  // checked already: defense in depth against a buggy control plane.
  if (cert.ca !== true) {
    return { ok: false, failureCategory: "not_a_ca_certificate" };
  }

  return { ok: true, der: cert.raw, actualFingerprintSha256 };
}

/**
 * Deterministic anchor filename derived purely from the anchor's fingerprint,
 * never from control-plane-supplied names or subjects (which are not
 * validated against a filesystem-safe alphabet). Used for both the permanent
 * Linux anchor file and the transient Windows `certutil -addstore` staging
 * file, so a leftover staging file after a crash stays attributable.
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
 * Whether an executable name resolves somewhere on PATH, without spawning it,
 * so capability detection never forks a process.
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
 * command, rather than sniffing `/etc/os-release`. A host missing either
 * cannot run the Debian-family path whatever its os-release ID claims.
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
 * family, WITHOUT executing anything. ../index.js's
 * AGENT_CANDIDATE_CAPABILITIES calls this to decide whether
 * `trust-anchor-deploy-v1` is a candidate capability, rather than duplicating
 * platform-sniffing inline.
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
 * Enumerates a Windows machine store and resolves which entry (if any) matches
 * a target SHA-256 fingerprint. certutil's `-store` listing only reports SHA-1
 * thumbprints, so no single-shot "delete by SHA-256" selector exists. This
 * closes the gap by reusing ../discovery/windows.js's
 * `fetchRawCertificateDerByThumbprint` plus `computeFingerprintSha256` to
 * compute the real SHA-256 for every entry and match against the target.
 *
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
 * staging file, best-effort-deleted in a `finally`: it carries only public
 * certificate bytes, so a failed unlink is litter, not a security issue.
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
 * `certutil -delstore <store> <thumbprint>`. certutil's delete path is
 * thumbprint-keyed, never fingerprint-keyed, so the caller must have already
 * resolved the thumbprint via findWindowsStoreEntryByFingerprint.
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
 * Linux anchor file path for one fingerprint, under the family's canonical
 * source directory. Debian-family uses `.crt` because `update-ca-certificates`
 * only scans `*.crt`; RHEL-family uses `.pem` by convention.
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
 * content actually hashes to that fingerprint. Re-hashing before reporting
 * `preexisting`/`already_absent` catches a file at this deterministic path
 * whose content does not match its own name.
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
 * Writes the anchor PEM to its deterministic path and runs the family's update
 * command, so the new source file takes effect in the consolidated bundle.
 * Uses plain fs, not receipt.js's writeFileAtomically: a partially-written
 * anchor file is simply re-written identically next attempt, since filename
 * and content are both pure functions of the fingerprint. A receipt row, by
 * contrast, must never be torn.
 * @param {object} input
 * @param {"debian"|"rhel"} input.family
 * @param {string} input.pem
 * @param {string} input.fingerprintSha256
 * @param {string} [input.anchorsDir]
 * @param {typeof fs} [input.fsImpl]
 * @param {Function} [input.execFileImpl]
 * @param {string[]} [input.updateCommandArgv] policy-resolved argv override
 *   (see ../policy's checkCommandRef); falls back to the hardcoded command
 *   literals only for tests and callers that bypass the policy engine.
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
 * Deletes the deterministic anchor file and re-runs the family's own update
 * command: leaving the source file deleted but the derived bundle stale would
 * mean the anchor is still effectively trusted.
 * @param {object} input
 * @param {"debian"|"rhel"} input.family
 * @param {string} input.fingerprintSha256
 * @param {string} [input.anchorsDir]
 * @param {typeof fs} [input.fsImpl]
 * @param {Function} [input.execFileImpl]
 * @param {string[]} [input.updateCommandArgv] policy-resolved argv override
 *   (see ../policy's checkCommandRef); falls back to the hardcoded command
 *   literals only for tests and callers that bypass the policy engine.
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
 * Resolves the concrete store name reported back in a result's `store` field.
 * Reported back rather than only signed forward, so a routing disagreement
 * between control plane and agent is detectable.
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
 * The generation the control plane resolved for this dispatch. The server
 * rejects any result that does not echo the row's current generation, so
 * refusing here rather than defaulting keeps a malformed dispatch from
 * producing work whose result can only be discarded as stale.
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
 * Maps internal result shapes to the wire `receipt.state` enum. Deliberately a
 * DIFFERENT vocabulary from receipt.js's on-disk `RECEIPT_STATES`: the wire
 * states describe how far THIS result's own operation got, while the on-disk
 * states describe what the persisted row currently says.
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
 * outcome: every refusal is reported via `outcome`/`failureCategory`, and the
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
  const store = resolveConcreteStore(family, anchorType);
  const transitionGeneration = requireTransitionGeneration(job);

  const verification = verifyAnchorPem(pem, fingerprintSha256);
  if (!verification.ok) {
    // The wire `outcome` enum has no value for "refused before ever probing
    // the store", so this reports `already_absent` plus the specific
    // `failureCategory` carrying the real reason. mutationAttempted and
    // mutationPerformed both stay false, so this can never read as a removal.
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
      receiptId: receipt.receiptId(store, fingerprintSha256),
      receiptState: "missing",
      failureCategory: verification.failureCategory,
      now,
    });
  }

  const presence =
    family === "windows"
      ? findWindowsStoreEntryByFingerprint({
          store,
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
    // Install idempotency: success, no mutation, outcome `preexisting`. No
    // receipt write, because an already-present anchor this agent did not
    // install has no ownership event to record.
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
      receiptId: receipt.receiptId(store, fingerprintSha256),
      receiptState: "missing",
      now,
    });
  }

  const intentRow = receipt.writeIntentReceipt({
    receiptDir,
    store,
    fingerprintSha256,
    jobId,
    transitionGeneration,
    intentState: "pending_install",
    // The isPresent probe just above proved the fingerprint is NOT in the
    // OS store right now. If a stale pending_install receipt from a
    // DIFFERENT, now-dead job is sitting on this exact (store, fingerprint),
    // that same probe result proves ITS intent never reached the OS either
    // -- there is nothing for this fresh attempt to race against. Without
    // this, an agent crash between intent-write and OS mutation permanently
    // blocks every later distribute-trust job for that fingerprint, with no
    // automatic recovery (found on real-host QA: TRU-10 retry).
    reclaimStalePending: true,
    now,
  });

  const mutationResult =
    family === "windows"
      ? await addWindowsStoreEntry({
          store,
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

  receipt.finalizeReceipt({ receiptDir, store, fingerprintSha256, jobId, transitionGeneration, now });

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
 * missing or corrupt receipt refuses removal and reports a failure category,
 * and is never treated as `already_absent`. Only once a receipt PROVES this
 * agent installed the material does this re-probe the ACTUAL store state
 * immediately before deleting; if it is already gone by then, that is
 * `already_absent` (success, no error), the same idempotent-delete posture as
 * ../windows-cert-store's NTE_BAD_KEYSET handling.
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
  const store = resolveConcreteStore(family, anchorType);
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

  const existingReceipt = receipt.readReceipt(receiptDir, store, fingerprintSha256);

  if (existingReceipt === null) {
    // Fail-safe: no ownership proof at all. Refuse.
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
      receiptId: receipt.receiptId(store, fingerprintSha256),
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
      receiptId: receipt.receiptId(store, fingerprintSha256),
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
  if (existingReceipt.row.state === "pending_remove" && existingReceipt.row.jobId !== jobId) {
    // A DIFFERENT, still-pending remove attempt owns this row; refuse
    // rather than racing a second mutation against the same material.
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
      failureCategory: "receipt_remove_in_progress",
      now,
    });
  }
  // else: state is "installed" (the normal case), or "pending_remove" for THIS
  // SAME jobId (a resumed attempt after a crash between intent and finalize)
  // -- both are valid ownership proof to proceed past here.

  // Re-probe the ACTUAL store state immediately before deleting: if already
  // gone, report already_absent rather than mutating against nothing.
  const presence =
    family === "windows"
      ? findWindowsStoreEntryByFingerprint({
          store,
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
    // Ownership proven, but the material is already gone: success, no
    // mutation. The receipt must still be driven through its own
    // pending_remove -> removed transition rather than finalized directly
    // from `installed`. A row already `pending_remove` for THIS job (a
    // resumed attempt) reuses that intent; otherwise a fresh intent is
    // written first, so finalizeReceipt always has the pending row it needs.
    const intentRow =
      existingReceipt.row.state === "pending_remove"
        ? existingReceipt.row
        : receipt.writeIntentReceipt({
            receiptDir,
            store,
            fingerprintSha256,
            jobId,
            transitionGeneration,
            intentState: "pending_remove",
            now,
          });
    const finalized = receipt.finalizeReceipt({
      receiptDir,
      store,
      fingerprintSha256,
      jobId: intentRow.jobId,
      transitionGeneration: intentRow.transitionGeneration,
      now,
    });
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

  const intentRow = receipt.writeIntentReceipt({
    receiptDir,
    store,
    fingerprintSha256,
    jobId,
    transitionGeneration,
    intentState: "pending_remove",
    now,
  });

  const mutationResult =
    family === "windows"
      ? await removeWindowsStoreEntry({
          store,
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
    // Mirrors distributeTrust's own OS-mutation-failure report: the outcome
    // names the store's TRUE post-attempt state (material is still present,
    // since the removal did not complete), not the action that was
    // attempted. Reporting `removed` here would be a false positive for any
    // consumer that checks `outcome` before `mutationPerformed`.
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

  receipt.finalizeReceipt({ receiptDir, store, fingerprintSha256, jobId, transitionGeneration, now });

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
  buildResult,
  distributeTrust,
  revokeTrust,
  assertSafeArgvElements,
  boundAndRedactExcerpt,
  execWithoutShell,
};
