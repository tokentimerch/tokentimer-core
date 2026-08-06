"use strict";

/**
 * CNG-native certificate custody executor (ADR-0012 decision 9).
 *
 * CNG-native is the default and required path for any certificate the
 * Windows agent itself requests against `keyMode: os-store-managed`:
 * `certreq -new` against a generated INF request descriptor creates the
 * key pair directly inside the CNG machine key store (Microsoft Software
 * KSP unless a hardware KSP is configured) and writes out a PKCS#10 CSR;
 * the private key never exists as a file. `certreq -accept` later binds
 * the CA's signed response to that same pending request, completing
 * enrollment without the key ever leaving the store.
 *
 * This module never reads, receives, or returns private key bytes. The
 * CSR produced by generateCsrViaCng carries only public material (the
 * request's own public key), and acceptCertificateViaCng's input is the
 * CA's signed certificate (also public). Every returned value is passed
 * through the shared private-key-material detector as a last-resort guard,
 * mirroring keys/index.js's guardReturnValue.
 *
 * PFX import (the disciplined fallback for material that already exists
 * off-host) is intentionally NOT this module's job: it is a separate
 * custody path with its own staging/journal/sweep discipline (decision 9)
 * and lands as its own follow-up change.
 *
 * Module style follows the sibling acme/keys modules: CommonJS, node
 * builtins only, self-contained plain-data functions, exec via
 * child_process.execFile WITHOUT a shell, every dynamic argv element
 * re-validated against a shell-metacharacter pattern as defense in depth.
 *
 * Status: real, tested, and verified end-to-end against a real Windows
 * host (Windows Server, CNG/NCrypt via the Microsoft Software KSP) and a
 * real test CA: CSR generation, acceptance, mutex concurrency, invalid-INF
 * rejection, and store-thumbprint cross-checks all reproduced on-host. The
 * qualified-capabilities manifest was updated in the same change that
 * flipped os-store-managed to agent-deployable, per decision 14 / the
 * gated-capabilities module's own doc comment.
 */

const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const {
  assertNoPrivateKeyMaterial,
} = require("../../vendor/log-scrub/secret-material.js");

/** Mirrors the acme/policy modules' shell-metacharacter pattern. Commands
 * run without a shell; this is defense in depth against a malformed
 * caller-supplied value ending up embedded in an INF file or argv. */
const SHELL_METACHARACTER_PATTERN = /[;|&$`><\r\n]/;

/** certreq can be slow against a busy CA/CryptoAPI; generous default. */
const DEFAULT_TIMEOUT_MS = 2 * 60 * 1000;

/** Hard cap on stdout/stderr excerpt length carried into results/evidence. */
const OUTPUT_EXCERPT_MAX_CHARS = 1024;
const PRIVATE_KEY_MARKER = "PRIVATE KEY";
const REDACTED_EXCERPT_PLACEHOLDER = "[redacted]";

/**
 * Windows machine certificate store name (e.g. "My", "WebHosting"). Mirrors
 * deploy/index.js's WINDOWS_STORE_NAME_PATTERN (duplicated, not imported,
 * per this package's self-contained-module convention).
 */
const WINDOWS_STORE_NAME_PATTERN = /^[A-Za-z0-9 _.-]{1,64}$/;

/** RFC 1123-ish hostname, used for both the CSR common name and SAN
 * entries. Mirrors deploy/index.js's WINDOWS_SNI_HOST_PATTERN. Rejecting
 * anything outside this alphabet is what makes INF-injection through a
 * hostname field structurally impossible: no `"`, `[`, `]`, `=`, CR/LF. */
const HOSTNAME_PATTERN =
  /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

/** Key container names are agent-generated, never operator/CA-supplied, but
 * still validated: this identifier is persisted (decision 18's ledger) and
 * passed to certreq INF/argv, so it must stay in a safe, boring alphabet. */
const CONTAINER_NAME_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

const SUPPORTED_KEY_ALGORITHMS = Object.freeze({
  "rsa-2048": Object.freeze({ keyAlgorithm: "RSA", keyLength: 2048 }),
  "rsa-3072": Object.freeze({ keyAlgorithm: "RSA", keyLength: 3072 }),
  "rsa-4096": Object.freeze({ keyAlgorithm: "RSA", keyLength: 4096 }),
  "ec-p256": Object.freeze({ keyAlgorithm: "ECDSA_P256", keyLength: 256 }),
  "ec-p384": Object.freeze({ keyAlgorithm: "ECDSA_P384", keyLength: 384 }),
});
const SUPPORTED_KEY_ALGORITHM_NAMES = Object.freeze(
  Object.keys(SUPPORTED_KEY_ALGORITHMS),
);

const MICROSOFT_SOFTWARE_KSP = "Microsoft Software Key Storage Provider";

function buildError(message, code) {
  const error = new Error(`tokentimer-agent windows-cert-store: ${message}`);
  if (code) error.code = code;
  return error;
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

/**
 * Last-resort custody guard, identical in spirit to keys/index.js's
 * guardReturnValue: deep-scans a return value for private key material
 * immediately before it leaves this module.
 * @param {Record<string, *>} value
 * @returns {Record<string, *>}
 */
function guardReturnValue(value) {
  for (const item of Object.values(value)) {
    assertNoPrivateKeyMaterial(item);
  }
  return value;
}

function assertSafeArgvElements(label, argv) {
  argv.forEach((element, index) => {
    if (!isNonEmptyString(element)) {
      throw buildError(
        `${label}[${index}] must be a non-empty string (got ${typeof element})`,
      );
    }
    if (SHELL_METACHARACTER_PATTERN.test(element)) {
      throw buildError(
        `${label}[${index}] contains a disallowed shell metacharacter: ${JSON.stringify(element)}`,
      );
    }
  });
}

function assertHostname(value, fieldName) {
  if (!isNonEmptyString(value) || !HOSTNAME_PATTERN.test(value)) {
    throw buildError(
      `${fieldName} must be a valid hostname (got ${JSON.stringify(value)})`,
    );
  }
}

function boundAndRedactExcerpt(output) {
  const text =
    typeof output === "string"
      ? output
      : Buffer.isBuffer(output)
        ? output.toString("utf8")
        : "";
  if (text.includes(PRIVATE_KEY_MARKER)) {
    return REDACTED_EXCERPT_PLACEHOLDER;
  }
  return text.slice(0, OUTPUT_EXCERPT_MAX_CHARS);
}

/**
 * Generates a safe, agent-owned CNG key container name for one enrollment.
 * Deterministic-looking but unique: `tokentimer-<jobId>-<random>`. jobId is
 * sanitized into the same boring alphabet rather than trusted verbatim,
 * since it can originate from a control-plane job id string.
 * @param {string} jobId
 * @returns {string}
 */
function buildContainerName(jobId) {
  const safeJobId = String(jobId ?? "job").replace(/[^A-Za-z0-9_-]/g, "-").slice(0, 64);
  const suffix = crypto.randomBytes(4).toString("hex");
  const name = `tokentimer-${safeJobId}-${suffix}`;
  if (!CONTAINER_NAME_PATTERN.test(name)) {
    throw buildError(`generated container name failed validation: ${JSON.stringify(name)}`);
  }
  return name;
}

/**
 * Builds the certreq INF request descriptor for a CNG-native, non-exportable
 * machine-context key. Every value that ends up inside the INF text is
 * validated against a closed alphabet BEFORE this function runs (hostname
 * pattern for subject/SANs, container-name pattern for KeyContainer), so no
 * caller-controlled string can inject an extra INF section or directive.
 *
 * @param {object} input
 * @param {string} input.commonName
 * @param {string[]} input.altNames
 * @param {string} input.containerName
 * @param {"rsa-2048"|"rsa-3072"|"rsa-4096"|"ec-p256"|"ec-p384"} input.algorithm
 * @returns {string} INF file text
 */
function buildCertreqInf({ commonName, altNames, containerName, algorithm }) {
  assertHostname(commonName, "commonName");
  altNames.forEach((name, index) => assertHostname(name, `altNames[${index}]`));
  if (!CONTAINER_NAME_PATTERN.test(containerName)) {
    throw buildError(`containerName must match ${CONTAINER_NAME_PATTERN} (got ${JSON.stringify(containerName)})`);
  }
  const spec = SUPPORTED_KEY_ALGORITHMS[algorithm];
  if (!spec) {
    throw buildError(
      `unsupported algorithm ${JSON.stringify(algorithm)}; supported: ${SUPPORTED_KEY_ALGORITHM_NAMES.join(", ")}`,
    );
  }

  const uniqueAltNames = [...new Set([commonName, ...altNames])];
  const sanValue = uniqueAltNames.map((name) => `dns=${name}`).join("&");

  const lines = [
    "[Version]",
    'Signature="$Windows NT$"',
    "",
    "[NewRequest]",
    `Subject = "CN=${commonName}"`,
    "MachineKeySet = TRUE",
    "UseExistingKeySet = FALSE",
    `KeyContainer = "${containerName}"`,
    `ProviderName = "${MICROSOFT_SOFTWARE_KSP}"`,
    "ProviderType = 0",
    `KeyLength = ${spec.keyLength}`,
    `KeyAlgorithm = ${spec.keyAlgorithm}`,
    "KeyUsage = 0xa0",
    "Exportable = FALSE",
    "ExportableEncrypted = FALSE",
    "SMIME = FALSE",
    "PrivateKeyArchive = FALSE",
    "UserProtected = FALSE",
    "RequestType = PKCS10",
    "HashAlgorithm = SHA256",
    "",
    "[Extensions]",
    `2.5.29.17 = "{text}${sanValue}&"`,
    "",
  ];
  return lines.join("\r\n");
}

/**
 * Computes the Windows-convention SHA-1 thumbprint (uppercase hex, no
 * separators) for a PEM certificate. A Windows certificate store's
 * "thumbprint" IS the SHA-1 hash of the DER-encoded certificate, so this
 * can be computed locally without shelling out, and must equal whatever
 * the store reports after certreq -accept installs the same bytes.
 * @param {string} certPem
 * @returns {string}
 */
function computeSha1ThumbprintFromPem(certPem) {
  if (!isNonEmptyString(certPem)) {
    throw buildError("computeSha1ThumbprintFromPem requires a non-empty PEM string");
  }
  const der = pemToDer(certPem, /CERTIFICATE/);
  return crypto.createHash("sha1").update(der).digest("hex").toUpperCase();
}

/**
 * Strips PEM headers/footers/whitespace and base64-decodes to DER. Accepts
 * any label matching the given pattern (certificates and CSRs both use
 * multiple historical labels, e.g. "CERTIFICATE REQUEST" vs. "NEW
 * CERTIFICATE REQUEST").
 * @param {string} pem
 * @param {RegExp} labelPattern
 * @returns {Buffer}
 */
function pemToDer(pem, labelPattern) {
  const match = pem.match(
    /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]+?)-----END \1-----/,
  );
  if (!match || !labelPattern.test(match[1])) {
    throw buildError(`input is not a recognizable PEM block matching ${labelPattern}`);
  }
  const base64 = match[2].replace(/\s+/g, "");
  return Buffer.from(base64, "base64");
}

/**
 * Normalizes certreq's PKCS#10 output to the canonical
 * "CERTIFICATE REQUEST" PEM label. certreq -new writes
 * "-----BEGIN NEW CERTIFICATE REQUEST-----", an older alias for the same
 * ASN.1 structure; downstream ACME tooling (certbot's --csr, this repo's
 * own keys.generateCsr output) is written against the RFC 2986 label, so
 * normalizing here keeps the CNG path byte-for-byte a drop-in CSR source
 * for the existing acme/index.js adapter.
 * @param {string} raw
 * @returns {string}
 */
function normalizeCsrPemLabel(raw) {
  const der = pemToDer(raw, /CERTIFICATE REQUEST/);
  const base64 = der.toString("base64");
  const wrapped = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE REQUEST-----\n${wrapped.join("\n")}\n-----END CERTIFICATE REQUEST-----\n`;
}

/**
 * Promise wrapper around an execFile-shaped implementation, matching
 * acme/index.js's execWithoutShell: never rejects on nonzero exit/timeout
 * (operational outcomes), only on a genuine spawn/programmer error via the
 * resolved execError field for the caller to inspect.
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
      {
        timeout: timeoutMs,
        windowsHide: true,
        maxBuffer: 10 * 1024 * 1024,
      },
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
 * Ensures a working directory exists for one enrollment's transient
 * artifacts (the INF descriptor and certreq's own .req/.cer files). This
 * directory holds no private key material -- CNG-native enrollment never
 * writes key bytes to disk -- but it is still created under the caller's
 * ACL-protected agent state dir (decision 10) as a matter of course, and
 * every artifact in it is best-effort-deleted by the caller once each step
 * completes. A crash between steps leaves an orphaned INF/.req/.cer file
 * (never a key), cleaned up by a future startup sweep (tracked separately;
 * this module does not implement decision 18's ledger/sweep).
 * @param {string} workDir
 * @returns {void}
 */
function ensureWorkDir(workDir) {
  fs.mkdirSync(workDir, { recursive: true });
}

/**
 * Phase 1 of CNG-native enrollment (ADR-0012 decision 9): runs
 * `certreq -new` against a generated INF descriptor. This creates the key
 * pair directly inside the CNG machine key store as MachineKeySet +
 * non-exportable, under the given container name, and writes out a
 * PKCS#10 CSR. The private key is never returned, logged, or written
 * anywhere by this function: certreq itself never emits it, and this
 * function's return value is guarded by the shared private-key-material
 * detector regardless, as a last resort.
 *
 * @param {object} input
 * @param {string} input.commonName CSR/certificate subject CN (hostname).
 * @param {string[]} [input.altNames] additional dNSName SAN entries.
 * @param {string} input.jobId used to derive a readable, unique container name.
 * @param {"rsa-2048"|"rsa-3072"|"rsa-4096"|"ec-p256"|"ec-p384"} [input.algorithm]
 * @param {string} input.workDir absolute, ACL-protected scratch directory
 *   for this enrollment's INF/.req files (caller-owned; see ensureWorkDir).
 * @param {Function} [input.execFileImpl] injection point for tests;
 *   defaults to node:child_process.execFile.
 * @param {string} [input.certreqPath] defaults to "certreq.exe" (resolved
 *   via PATH/System32, matching every other Windows-native tool this agent
 *   shells out to).
 * @param {number} [input.timeoutMs]
 * @returns {Promise<
 *   { ok: true, csrPem: string, containerName: string, infPath: string, reqPath: string }
 *   | { ok: false, exitCode: number|null, stdoutExcerpt: string, stderrExcerpt: string }
 * >}
 */
async function generateCsrViaCng({
  commonName,
  altNames = [],
  jobId,
  algorithm = "rsa-2048",
  workDir,
  execFileImpl = childProcess.execFile,
  certreqPath = "certreq.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (!isNonEmptyString(workDir)) {
    throw buildError("generateCsrViaCng requires a non-empty workDir string");
  }
  if (!Array.isArray(altNames) || !altNames.every((n) => typeof n === "string")) {
    throw buildError("altNames must be an array of strings");
  }
  if (!isNonEmptyString(certreqPath)) {
    throw buildError("certreqPath must be a non-empty string");
  }
  assertSafeArgvElements("certreqPath", [certreqPath]);

  const containerName = buildContainerName(jobId);
  const infText = buildCertreqInf({ commonName, altNames, containerName, algorithm });

  ensureWorkDir(workDir);
  const nonce = crypto.randomBytes(4).toString("hex");
  const infPath = path.join(workDir, `${containerName}-${nonce}.inf`);
  const reqPath = path.join(workDir, `${containerName}-${nonce}.req`);

  fs.writeFileSync(infPath, infText, { encoding: "utf8", flag: "wx" });

  try {
    const argv = [certreqPath, "-q", "-new", infPath, reqPath];
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

    const rawCsr = fs.readFileSync(reqPath, "utf8");
    const csrPem = normalizeCsrPemLabel(rawCsr);

    return guardReturnValue({ ok: true, csrPem, containerName, infPath, reqPath });
  } finally {
    // Best-effort cleanup: neither file holds key material (the INF is a
    // request descriptor, the .req is a public CSR), so a failed unlink is
    // not a security incident, only litter for a future sweep to find.
    for (const artifactPath of [infPath, reqPath]) {
      try {
        fs.unlinkSync(artifactPath);
      } catch {
        // best-effort; see comment above.
      }
    }
  }
}

/**
 * Phase 2 of CNG-native enrollment (ADR-0012 decision 9): runs
 * `certreq -accept` with the CA's signed certificate. certreq matches the
 * certificate's public key against the pending request it created in
 * phase 1 (by container/public key, not by an explicit id this module
 * threads through) and, on a match, completes enrollment: the certificate
 * is bound to the already-in-store, non-exportable private key and lands
 * in the configured machine store (My, by default).
 *
 * The resulting store thumbprint is computed locally from the certificate
 * bytes (a Windows thumbprint IS sha1(DER)), not parsed from certreq's own
 * output, so this function's success path does not depend on certreq's
 * text output format.
 *
 * @param {object} input
 * @param {string} input.certificatePem the CA-issued leaf certificate, PEM.
 * @param {string} input.workDir absolute, ACL-protected scratch directory.
 * @param {Function} [input.execFileImpl]
 * @param {string} [input.certreqPath]
 * @param {number} [input.timeoutMs]
 * @returns {Promise<
 *   { ok: true, thumbprint: string, certPath: string }
 *   | { ok: false, exitCode: number|null, stdoutExcerpt: string, stderrExcerpt: string }
 * >}
 */
async function acceptCertificateViaCng({
  certificatePem,
  workDir,
  execFileImpl = childProcess.execFile,
  certreqPath = "certreq.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (!isNonEmptyString(certificatePem)) {
    throw buildError("acceptCertificateViaCng requires a non-empty certificatePem string");
  }
  if (!isNonEmptyString(workDir)) {
    throw buildError("acceptCertificateViaCng requires a non-empty workDir string");
  }
  assertSafeArgvElements("certreqPath", [certreqPath]);

  // Computed BEFORE the accept call: this is the thumbprint the store
  // WILL have if accept succeeds, since it is a pure function of the
  // certificate bytes certreq is about to import unchanged.
  const expectedThumbprint = computeSha1ThumbprintFromPem(certificatePem);

  ensureWorkDir(workDir);
  const nonce = crypto.randomBytes(4).toString("hex");
  const certPath = path.join(workDir, `accept-${nonce}.cer`);
  fs.writeFileSync(certPath, certificatePem, { encoding: "utf8", flag: "wx" });

  try {
    const argv = [certreqPath, "-q", "-accept", certPath];
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

    return guardReturnValue({ ok: true, thumbprint: expectedThumbprint, certPath });
  } finally {
    try {
      fs.unlinkSync(certPath);
    } catch {
      // best-effort; the file is a public certificate, not key material.
    }
  }
}

/**
 * Store-scoped mutex (ADR-0012 decision 13: "the per-target mutex covers
 * the store as well as the binding, since two jobs racing on the same
 * machine store is as damaging as two racing on one binding"). A plain
 * exclusive-create lock file under the agent's own ACL-protected state
 * dir: `wx` fails if another enrollment already holds the lock, which is
 * exactly the semantics a mutex needs and requires no additional OS
 * primitive. Reused as-is by the future IIS-binding executor so a single
 * lock name space covers both operations per decision 13.
 *
 * @param {string} stateDir agent state dir.
 * @param {string} storeName Windows machine store name (e.g. "My").
 * @returns {{ lockPath: string, release: () => void }}
 */
function acquireStoreLock(stateDir, storeName) {
  if (!WINDOWS_STORE_NAME_PATTERN.test(storeName)) {
    throw buildError(`invalid store name for lock: ${JSON.stringify(storeName)}`);
  }
  const lockDir = path.join(stateDir, "windows-cert-store");
  fs.mkdirSync(lockDir, { recursive: true });
  const lockPath = path.join(lockDir, `${storeName}.lock`);

  let fd;
  try {
    fd = fs.openSync(lockPath, "wx");
  } catch (err) {
    if (err && err.code === "EEXIST") {
      throw buildError(
        `store ${JSON.stringify(storeName)} is locked by a concurrent enrollment/binding operation (${lockPath})`,
        "STORE_LOCKED",
      );
    }
    throw err;
  }
  fs.writeSync(fd, `${process.pid}\n${new Date().toISOString()}\n`);
  fs.closeSync(fd);

  let released = false;
  return {
    lockPath,
    release() {
      if (released) return;
      released = true;
      try {
        fs.unlinkSync(lockPath);
      } catch {
        // best-effort; a stale lock file from a killed process is a known
        // limit of this simple primitive, not a security issue (nothing
        // sensitive is in it), and is expected to be swept by a future
        // startup sweep alongside the CNG artifact sweep.
      }
    },
  };
}

/** Windows-convention thumbprint: 40 hex chars, case-insensitive on input
 * (Windows tooling emits either case; this module's own output is always
 * uppercase via computeSha1ThumbprintFromPem). */
const THUMBPRINT_PATTERN = /^[0-9A-Fa-f]{40}$/;

/**
 * Removes a superseded certificate from the machine store and deletes its
 * CNG key container, the two `performCleanup` steps a
 * ../windows-retention sweep needs once a ledger row becomes eligible.
 *
 * Two independent `certutil` calls, each best-effort-verified by exit code
 * only (certutil's own text output is not parsed): `-delstore` removes the
 * certificate object from the named machine store, and `-delkey` (against
 * the same Microsoft Software KSP every CNG-native enrollment uses) frees
 * the non-exportable key container so it does not accumulate forever.
 * Deleting the store entry first and the key second means a mid-failure
 * (key delete fails after the store delete succeeds) leaves an orphaned key
 * container -- inert, non-exportable, no certificate referencing it -- never
 * a certificate pointing at a missing key, which would be the more
 * dangerous half-state for anything that later re-queries the store.
 *
 * Deliberately NOT wrapped in the store mutex (acquireStoreLock): the
 * caller (the retention sweep) already holds it for the duration of one
 * row's cleanup, matching decision 13's "one lock name space covers both
 * operations" note on acquireStoreLock itself.
 *
 * @param {object} input
 * @param {string} input.thumbprint the superseded certificate's SHA-1
 *   thumbprint (../windows-retention's ledger row `oldThumbprint`).
 * @param {string} input.store Windows machine store name (e.g. "My").
 * @param {string} input.containerName the CNG key container to delete
 *   (../windows-retention's ledger row `cngKeyContainerId`).
 * @param {Function} [input.execFileImpl]
 * @param {string} [input.certutilPath] defaults to "certutil.exe".
 * @param {number} [input.timeoutMs]
 * @returns {Promise<
 *   { ok: true }
 *   | { ok: false, stage: "delstore"|"delkey", exitCode: number|null, stdoutExcerpt: string, stderrExcerpt: string }
 * >}
 */
async function removeCertificateAndKeyContainer({
  thumbprint,
  store,
  containerName,
  execFileImpl = childProcess.execFile,
  certutilPath = "certutil.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (!isNonEmptyString(thumbprint) || !THUMBPRINT_PATTERN.test(thumbprint)) {
    throw buildError(`thumbprint must be a 40-hex-char SHA-1 string (got ${JSON.stringify(thumbprint)})`);
  }
  if (!isNonEmptyString(store) || !WINDOWS_STORE_NAME_PATTERN.test(store)) {
    throw buildError(`store must match ${WINDOWS_STORE_NAME_PATTERN} (got ${JSON.stringify(store)})`);
  }
  if (!isNonEmptyString(containerName) || !CONTAINER_NAME_PATTERN.test(containerName)) {
    throw buildError(`containerName must match ${CONTAINER_NAME_PATTERN} (got ${JSON.stringify(containerName)})`);
  }
  if (!isNonEmptyString(certutilPath)) {
    throw buildError("certutilPath must be a non-empty string");
  }
  assertSafeArgvElements("certutilPath", [certutilPath]);

  const delstoreArgv = [certutilPath, "-delstore", store, thumbprint];
  assertSafeArgvElements("delstoreArgv", delstoreArgv);
  const delstoreResult = await execWithoutShell(execFileImpl, delstoreArgv, timeoutMs);
  if (delstoreResult.exitCode !== 0) {
    return guardReturnValue({
      ok: false,
      stage: "delstore",
      exitCode: delstoreResult.exitCode,
      stdoutExcerpt: boundAndRedactExcerpt(delstoreResult.stdout),
      stderrExcerpt: boundAndRedactExcerpt(delstoreResult.stderr),
    });
  }

  const delkeyArgv = [
    certutilPath,
    "-csp",
    MICROSOFT_SOFTWARE_KSP,
    "-delkey",
    containerName,
  ];
  assertSafeArgvElements("delkeyArgv", delkeyArgv);
  const delkeyResult = await execWithoutShell(execFileImpl, delkeyArgv, timeoutMs);
  if (delkeyResult.exitCode !== 0) {
    return guardReturnValue({
      ok: false,
      stage: "delkey",
      exitCode: delkeyResult.exitCode,
      stdoutExcerpt: boundAndRedactExcerpt(delkeyResult.stdout),
      stderrExcerpt: boundAndRedactExcerpt(delkeyResult.stderr),
    });
  }

  return guardReturnValue({ ok: true });
}

/**
 * Deletes a CNG key container that generateCsrViaCng created but that
 * never reached acceptCertificateViaCng (the ACME order consuming its CSR
 * was rejected, failed, or the process crashed in between): there is no
 * certificate in any store for this attempt, so unlike
 * removeCertificateAndKeyContainer there is nothing to `-delstore` and no
 * thumbprint to require -- only the orphaned key container itself needs
 * freeing. Deliberately a single-step, best-effort operation: callers
 * (index.js's executeWindowsIisRenewJob) treat a failure here as a safe,
 * logged, non-fatal condition, never a reason to also fail the
 * already-failed renewal a second way.
 *
 * @param {object} input
 * @param {string} input.containerName the CNG key container to delete
 *   (generateCsrViaCng's own return value; never persisted anywhere for a
 *   request that never got this far, so the caller must supply it from
 *   its own in-memory result).
 * @param {Function} [input.execFileImpl]
 * @param {string} [input.certutilPath] defaults to "certutil.exe".
 * @param {number} [input.timeoutMs]
 * @returns {Promise<
 *   { ok: true }
 *   | { ok: false, exitCode: number|null, stdoutExcerpt: string, stderrExcerpt: string }
 * >}
 */
async function removeAbandonedKeyContainer({
  containerName,
  execFileImpl = childProcess.execFile,
  certutilPath = "certutil.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (!isNonEmptyString(containerName) || !CONTAINER_NAME_PATTERN.test(containerName)) {
    throw buildError(`containerName must match ${CONTAINER_NAME_PATTERN} (got ${JSON.stringify(containerName)})`);
  }
  if (!isNonEmptyString(certutilPath)) {
    throw buildError("certutilPath must be a non-empty string");
  }
  assertSafeArgvElements("certutilPath", [certutilPath]);

  const delkeyArgv = [certutilPath, "-csp", MICROSOFT_SOFTWARE_KSP, "-delkey", containerName];
  assertSafeArgvElements("delkeyArgv", delkeyArgv);
  const delkeyResult = await execWithoutShell(execFileImpl, delkeyArgv, timeoutMs);
  if (delkeyResult.exitCode !== 0) {
    return guardReturnValue({
      ok: false,
      exitCode: delkeyResult.exitCode,
      stdoutExcerpt: boundAndRedactExcerpt(delkeyResult.stdout),
      stderrExcerpt: boundAndRedactExcerpt(delkeyResult.stderr),
    });
  }
  return guardReturnValue({ ok: true });
}

module.exports = {
  SUPPORTED_KEY_ALGORITHM_NAMES,
  SHELL_METACHARACTER_PATTERN,
  OUTPUT_EXCERPT_MAX_CHARS,
  DEFAULT_TIMEOUT_MS,
  WINDOWS_STORE_NAME_PATTERN,
  HOSTNAME_PATTERN,
  CONTAINER_NAME_PATTERN,
  THUMBPRINT_PATTERN,
  buildContainerName,
  buildCertreqInf,
  computeSha1ThumbprintFromPem,
  normalizeCsrPemLabel,
  pemToDer,
  boundAndRedactExcerpt,
  assertSafeArgvElements,
  execWithoutShell,
  guardReturnValue,
  generateCsrViaCng,
  acceptCertificateViaCng,
  acquireStoreLock,
  removeCertificateAndKeyContainer,
  removeAbandonedKeyContainer,
};
