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
 * enrollment without the key ever leaving the store. `certreq -accept`
 * itself only ever populates the default `My` store for a MachineKeySet
 * request; acceptCertificateViaCng mirrors the result into a different
 * caller-requested store (e.g. "WebHosting") via `certutil -addstore` +
 * `-repairstore` when one is given -- see that function's own doc comment.
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
 * gated-capabilities module's own doc comment. The addstore/repairstore
 * non-default-store mirror path is unit-tested only (not yet real-host
 * verified); every real-host pass so far targeted the default "My" store.
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

/** Every container buildContainerName produces starts with this literal
 * prefix. isAgentOwnedContainerName uses it to distinguish a container THIS
 * agent created from one a human operator or another tool created directly
 * in the CNG store: both are valid, non-exportable CNG key containers and
 * both make certutil's "Key Container =" line non-empty, so container
 * PRESENCE alone is not evidence of agent ownership. Retention (ADR-0012
 * decision 18) must never mark a certificate `tokentimer_installed` -- and
 * therefore automatically deletable -- on that weaker signal. */
const AGENT_CONTAINER_NAME_PREFIX = "tokentimer-";

/**
 * Whether a CNG key container name matches this agent's own naming
 * convention (see buildContainerName), as opposed to merely being SOME
 * non-exportable CNG container -- which could belong to a certificate a
 * human operator or a different tool enrolled directly on this host. Only
 * the former is safe evidence of agent ownership for decision 18's
 * retention ledger; the presence of a key container generally is not.
 * @param {*} name
 * @returns {boolean}
 */
function isAgentOwnedContainerName(name) {
  return (
    isNonEmptyString(name) &&
    CONTAINER_NAME_PATTERN.test(name) &&
    name.startsWith(AGENT_CONTAINER_NAME_PREFIX)
  );
}

/** Directory (under the caller's agent state dir) holding one persisted,
 * durable record per CNG container this agent has ever issued via
 * generateCsrViaCng, written at issuance time and outliving both the
 * job-journal entry (cleared on terminal outcome) and the eventual
 * enrollment/rotation. isAgentOwnedContainerName's naming-convention check
 * alone is a closed-alphabet pattern match, not evidence that THIS agent
 * process actually created a given container: a sufficiently motivated
 * operator or another tool could, in principle, create a container whose
 * name happens to satisfy CONTAINER_NAME_PATTERN and the "tokentimer-"
 * prefix. recordIssuedContainer / hasIssuedContainerRecord give
 * recordSupersededWindowsCertificate (index.js) a second, independent
 * source of evidence -- an actual persisted record this agent wrote at the
 * moment it generated that exact container -- so retention's ownership
 * gate (ADR-0012 decision 18) requires BOTH the naming convention AND this
 * durable issuance record before ever marking a certificate
 * `tokentimer_installed` (and therefore eligible for automated deletion).
 */
const ISSUED_CONTAINER_RECORD_DIR_NAME = "issued-containers";

/**
 * @param {string} stateDir
 * @returns {string}
 */
function issuedContainerRecordDir(stateDir) {
  return path.join(stateDir, "windows-cert-store", ISSUED_CONTAINER_RECORD_DIR_NAME);
}

/**
 * @param {string} stateDir
 * @param {string} containerName
 * @returns {string}
 */
function issuedContainerRecordPath(stateDir, containerName) {
  return path.join(issuedContainerRecordDir(stateDir), `${containerName}.json`);
}

/**
 * Persists a durable record that this agent process issued `containerName`
 * for `jobId`/`certificateId`, at the moment generateCsrViaCng creates it.
 * Best-effort by contract (callers treat a write failure as non-fatal,
 * matching this module's other crash-recovery-adjacent writes): a missing
 * record only ever makes hasIssuedContainerRecord's check fail closed
 * (never eligible for automated retention), it never makes anything less
 * safe.
 * @param {object} input
 * @param {string} input.stateDir
 * @param {string} input.containerName
 * @param {string} [input.jobId]
 * @param {string} [input.certificateId]
 * @param {() => Date} [input.now]
 * @returns {void}
 */
function recordIssuedContainer({ stateDir, containerName, jobId, certificateId, now = () => new Date() }) {
  if (!isNonEmptyString(stateDir)) {
    throw buildError("recordIssuedContainer requires a non-empty stateDir string");
  }
  if (!isNonEmptyString(containerName) || !CONTAINER_NAME_PATTERN.test(containerName)) {
    throw buildError(`containerName must match ${CONTAINER_NAME_PATTERN} (got ${JSON.stringify(containerName)})`);
  }
  const dir = issuedContainerRecordDir(stateDir);
  fs.mkdirSync(dir, { recursive: true });
  // `status: "generated"` at this point means only "this agent created the
  // CNG key container", NOT "this agent's certificate is what is enrolled
  // to it" -- markIssuedContainerAccepted below is what upgrades a record
  // to "enrolled_by_agent" once certreq -accept has actually succeeded, and
  // recordSupersededWindowsCertificate's ownership-provenance gate requires
  // that upgraded status (plus a matching acceptedThumbprint), not merely
  // this record's existence, before ever treating a predecessor certificate
  // as this agent's own to delete. See this file's module doc comment and
  // ADR-0012 decision 18 for the two-signal (naming + persisted record)
  // rationale this strengthens.
  const record = {
    containerName,
    jobId: isNonEmptyString(jobId) ? jobId : null,
    certificateId: isNonEmptyString(certificateId) ? certificateId : null,
    issuedAt: now().toISOString(),
    status: "generated",
    acceptedThumbprint: null,
    acceptedStore: null,
    acceptedAt: null,
  };
  const filePath = issuedContainerRecordPath(stateDir, containerName);
  const tmp = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  fs.renameSync(tmp, filePath);
}

/**
 * Upgrades a recordIssuedContainer record to `status: "enrolled_by_agent"`
 * once `certreq -accept` (see acceptCertificateViaCng) has actually
 * succeeded for this exact container, binding the certificate's own
 * thumbprint into the durable record -- the missing link a PR review found
 * (2026-08-07): without it, recordSupersededWindowsCertificate could only
 * prove "this agent created this key container", never "this agent's
 * certificate is what is currently enrolled to it", so an operator who
 * later enrolled a DIFFERENT certificate into an agent-created container
 * (e.g. after reconcileOrphanedWindowsCngContainers left it alone because
 * it found something enrolled) could have that certificate inherit
 * `tokentimer_installed` provenance and become eligible for automatic
 * retention cleanup.
 *
 * Best-effort by design (mirrors recordIssuedContainer): a caller must
 * treat a thrown/failed call here as non-fatal to an otherwise-succeeded
 * CNG acceptance, since the failure mode of NOT upgrading the record is
 * merely "this predecessor will be conservatively treated as `preexisting`
 * (not deletable) by a later retention decision", never data loss or an
 * unsafe deletion -- the fail-closed direction ADR-0012 decision 18
 * requires.
 *
 * No-op (returns false) if no `recordIssuedContainer` record exists yet
 * for this containerName (e.g. the original best-effort write failed, or
 * this container was never tracked): there is nothing to upgrade, and this
 * function never creates a fresh record from scratch, since doing so would
 * fabricate an `issuedAt`/`jobId` provenance this call site does not
 * actually have.
 *
 * @param {object} input
 * @param {string} input.stateDir
 * @param {string} input.containerName
 * @param {string} input.acceptedThumbprint the SHA-1 thumbprint
 *   `acceptCertificateViaCng` reported for the certificate just accepted
 *   into this container (any case; normalized to uppercase on write).
 * @param {string} [input.store] the store the certificate now lives in
 *   (post-mirror for a non-default store; `CERTREQ_ACCEPT_DEFAULT_STORE`
 *   otherwise).
 * @param {() => Date} [input.now]
 * @returns {boolean} true if a record existed and was upgraded.
 */
function markIssuedContainerAccepted({ stateDir, containerName, acceptedThumbprint, store, now = () => new Date() }) {
  if (!isNonEmptyString(stateDir) || !isNonEmptyString(containerName)) return false;
  if (!isNonEmptyString(acceptedThumbprint)) return false;
  const filePath = issuedContainerRecordPath(stateDir, containerName);
  let existing;
  try {
    existing = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return false;
  }
  const record = {
    ...existing,
    containerName,
    status: "enrolled_by_agent",
    acceptedThumbprint: acceptedThumbprint.toUpperCase(),
    acceptedStore: isNonEmptyString(store) ? store : existing.acceptedStore ?? null,
    acceptedAt: now().toISOString(),
  };
  const tmp = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  fs.renameSync(tmp, filePath);
  return true;
}

/**
 * Reads back a recordIssuedContainer/markIssuedContainerAccepted record in
 * full (not just its existence, unlike hasIssuedContainerRecord below), so
 * a caller can inspect `status`/`acceptedThumbprint` -- the fields
 * recordSupersededWindowsCertificate's ownership-provenance gate now
 * requires.
 * @param {object} input
 * @param {string} input.stateDir
 * @param {string} input.containerName
 * @returns {null | { containerName: string, jobId: string|null, certificateId: string|null, issuedAt: string, status: "generated"|"enrolled_by_agent", acceptedThumbprint: string|null, acceptedStore: string|null, acceptedAt: string|null }}
 */
function readIssuedContainerRecord({ stateDir, containerName }) {
  if (!isNonEmptyString(stateDir) || !isNonEmptyString(containerName)) return null;
  try {
    return JSON.parse(fs.readFileSync(issuedContainerRecordPath(stateDir, containerName), "utf8"));
  } catch {
    return null;
  }
}

/**
 * Whether a durable recordIssuedContainer record exists for `containerName`,
 * in ANY status ("generated" or "enrolled_by_agent"). Existence alone only
 * proves "this agent created this key container", NOT "this agent's
 * certificate is currently enrolled to it" -- callers deciding whether a
 * predecessor certificate is safe to delete must use
 * readIssuedContainerRecord and check `status === "enrolled_by_agent"` plus
 * a matching `acceptedThumbprint` instead (see
 * recordSupersededWindowsCertificate). This existence-only check remains
 * useful for callers that only care "is there a record to clean up at all"
 * (e.g. removeIssuedContainerRecord's own call sites).
 * @param {object} input
 * @param {string} input.stateDir
 * @param {string} input.containerName
 * @returns {boolean}
 */
function hasIssuedContainerRecord({ stateDir, containerName }) {
  if (!isNonEmptyString(stateDir) || !isNonEmptyString(containerName)) return false;
  try {
    return fs.existsSync(issuedContainerRecordPath(stateDir, containerName));
  } catch {
    return false;
  }
}

/**
 * Best-effort deletes a recordIssuedContainer record once the container
 * itself has been permanently removed from the CNG store (../windows-
 * retention's sweep, after removeCertificateAndKeyContainer succeeds), so
 * this directory does not accumulate one file per container forever.
 * Never throws: a leftover record for an already-deleted container is
 * harmless litter (hasIssuedContainerRecord would only ever be consulted
 * again for that exact container name, which no longer exists to enroll
 * anything to), not a correctness or security concern.
 * @param {object} input
 * @param {string} input.stateDir
 * @param {string} input.containerName
 * @returns {void}
 */
function removeIssuedContainerRecord({ stateDir, containerName }) {
  if (!isNonEmptyString(stateDir) || !isNonEmptyString(containerName)) return;
  try {
    fs.unlinkSync(issuedContainerRecordPath(stateDir, containerName));
  } catch {
    // best-effort; see doc comment above.
  }
}

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

/** The only store `certreq -accept` itself ever populates for a
 * MachineKeySet=TRUE request: there is no INF directive or -accept switch
 * that targets a different store directly (confirmed against Microsoft's
 * own certreq reference and the standard WebHosting-store community
 * workaround, which starts from a My-store enrollment). See
 * acceptCertificateViaCng's doc comment. */
const CERTREQ_ACCEPT_DEFAULT_STORE = "My";

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
 * is bound to the already-in-store, non-exportable private key.
 *
 * Store targeting: `certreq -accept` has no switch or INF directive that
 * targets a store other than CERTREQ_ACCEPT_DEFAULT_STORE ("My") for a
 * MachineKeySet=TRUE request -- confirmed against Microsoft's own certreq
 * reference; there is no hidden flag this was just missing. When the
 * caller's `store` differs, the certificate is mirrored into it via the
 * same two-step `certutil -addstore` + `-repairstore` sequence Microsoft's
 * own IIS troubleshooting docs describe for a certificate that needs to
 * live in a non-Personal store (e.g. the "WebHosting" convention many IIS
 * deployments use): `-addstore` copies the certificate object into the
 * target store (from a bare .cer file, so with NO key-provider-info
 * property yet), then `-repairstore` re-associates it with the matching
 * CNG key by public key -- key containers are not themselves store-scoped,
 * so this is a metadata repair, not a key export/copy. The My-store copy
 * is then removed (`-delstore`), and a final `-store <targetStore>
 * <thumbprint>` query independently confirms the certificate is actually
 * retrievable from targetStore afterward (see
 * mirrorAcceptedCertificateToStore's own doc comment, step 4) -- this
 * function's success therefore never rests on certutil's exit codes alone.
 * NOTE: only the default-store (`My`) path has been verified against a
 * real Windows host so far; the addstore/repairstore/verify sequence for a
 * non-default store is unit-tested against a stubbed certutil, not yet
 * real-host verified (tracked as a follow-up).
 *
 * The resulting store thumbprint is computed locally from the certificate
 * bytes (a Windows thumbprint IS sha1(DER)), not parsed from certreq's own
 * output, so this function's success path does not depend on certreq's
 * text output format.
 *
 * @param {object} input
 * @param {string} input.certificatePem the CA-issued leaf certificate, PEM.
 * @param {string} input.workDir absolute, ACL-protected scratch directory.
 * @param {string} [input.store] target Windows machine store name; defaults
 *   to CERTREQ_ACCEPT_DEFAULT_STORE ("My"), which needs no extra steps.
 * @param {Function} [input.execFileImpl]
 * @param {string} [input.certreqPath]
 * @param {string} [input.certutilPath] defaults to "certutil.exe"; only
 *   invoked when `store` differs from CERTREQ_ACCEPT_DEFAULT_STORE.
 * @param {number} [input.timeoutMs]
 * @returns {Promise<
 *   { ok: true, thumbprint: string, certPath: string, store: string }
 *   | { ok: false, exitCode: number|null, stdoutExcerpt: string, stderrExcerpt: string }
 *   | { ok: false, stage: "addstore"|"delstore"|"repairstore"|"verify", exitCode: number|null, stdoutExcerpt: string, stderrExcerpt: string }
 * >}
 */
async function acceptCertificateViaCng({
  certificatePem,
  workDir,
  store = CERTREQ_ACCEPT_DEFAULT_STORE,
  execFileImpl = childProcess.execFile,
  certreqPath = "certreq.exe",
  certutilPath = "certutil.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (!isNonEmptyString(certificatePem)) {
    throw buildError("acceptCertificateViaCng requires a non-empty certificatePem string");
  }
  if (!isNonEmptyString(workDir)) {
    throw buildError("acceptCertificateViaCng requires a non-empty workDir string");
  }
  if (!isNonEmptyString(store) || !WINDOWS_STORE_NAME_PATTERN.test(store)) {
    throw buildError(`store must match ${WINDOWS_STORE_NAME_PATTERN} (got ${JSON.stringify(store)})`);
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

    if (store !== CERTREQ_ACCEPT_DEFAULT_STORE) {
      const mirrored = await mirrorAcceptedCertificateToStore({
        certPath,
        thumbprint: expectedThumbprint,
        targetStore: store,
        execFileImpl,
        certutilPath,
        timeoutMs,
      });
      if (!mirrored.ok) return mirrored;
    }

    return guardReturnValue({ ok: true, thumbprint: expectedThumbprint, certPath, store });
  } finally {
    try {
      fs.unlinkSync(certPath);
    } catch {
      // best-effort; the file is a public certificate, not key material.
    }
  }
}

/**
 * Mirrors a just-`certreq -accept`ed certificate from the default `My`
 * store into `targetStore` (see acceptCertificateViaCng's doc comment for
 * why this three-step sequence, rather than a single certreq/certutil
 * call, is what actually moves a CNG-keyed certificate between stores):
 *
 *   1. `certutil -addstore <targetStore> <certPath>` -- copies the
 *      certificate object (from the plain .cer file already on disk, i.e.
 *      no key-provider-info property) into targetStore.
 *   2. `certutil -repairstore <targetStore> <thumbprint>` -- re-associates
 *      that copy with the matching CNG private key by public key. This is
 *      the same operation Microsoft's own IIS troubleshooting docs use to
 *      restore a "missing private key" certificate; here it is used
 *      proactively, since a certificate freshly copied by -addstore from a
 *      bare .cer file starts in exactly that "no key metadata yet" state.
 *   3. `certutil -delstore My <thumbprint>` -- removes the original
 *      My-store copy `certreq -accept` created, so the certificate does
 *      not end up live in two stores after a non-default-store deploy.
 *   4. `certutil -store <targetStore> <thumbprint>` -- an explicit,
 *      independent confirmation query: since steps 1-3 above only prove
 *      "certutil reported a zero exit code", not "the certificate is
 *      actually retrievable from targetStore afterward", this step closes
 *      that gap by asking the store directly for the exact thumbprint one
 *      more time before this function reports success. A store whose
 *      -addstore/-repairstore silently no-opped (e.g. a store name
 *      certutil accepts but does not persist to) is caught here rather
 *      than surfacing later as a binding failure with a confusing error.
 *
 * Each step is independently checked; a failure at any step returns
 * immediately rather than attempting the next one, so a caller never sees
 * `ok: true` for a partially-completed (or unconfirmed) mirror.
 *
 * @param {object} input
 * @param {string} input.certPath the .cer file acceptCertificateViaCng
 *   already staged (still on disk; not yet cleaned up by its finally).
 * @param {string} input.thumbprint
 * @param {string} input.targetStore
 * @param {Function} input.execFileImpl
 * @param {string} input.certutilPath
 * @param {number} input.timeoutMs
 * @returns {Promise<
 *   { ok: true }
 *   | { ok: false, stage: "addstore"|"repairstore"|"delstore"|"verify", exitCode: number|null, stdoutExcerpt: string, stderrExcerpt: string }
 * >}
 */
async function mirrorAcceptedCertificateToStore({
  certPath,
  thumbprint,
  targetStore,
  execFileImpl,
  certutilPath,
  timeoutMs,
}) {
  assertSafeArgvElements("certutilPath", [certutilPath]);

  const addstoreArgv = [certutilPath, "-addstore", targetStore, certPath];
  assertSafeArgvElements("addstoreArgv", addstoreArgv);
  const addstoreResult = await execWithoutShell(execFileImpl, addstoreArgv, timeoutMs);
  if (addstoreResult.exitCode !== 0) {
    return {
      ok: false,
      stage: "addstore",
      exitCode: addstoreResult.exitCode,
      stdoutExcerpt: boundAndRedactExcerpt(addstoreResult.stdout),
      stderrExcerpt: boundAndRedactExcerpt(addstoreResult.stderr),
    };
  }

  const repairstoreArgv = [certutilPath, "-repairstore", targetStore, thumbprint];
  assertSafeArgvElements("repairstoreArgv", repairstoreArgv);
  const repairstoreResult = await execWithoutShell(execFileImpl, repairstoreArgv, timeoutMs);
  if (repairstoreResult.exitCode !== 0) {
    return {
      ok: false,
      stage: "repairstore",
      exitCode: repairstoreResult.exitCode,
      stdoutExcerpt: boundAndRedactExcerpt(repairstoreResult.stdout),
      stderrExcerpt: boundAndRedactExcerpt(repairstoreResult.stderr),
    };
  }

  const delstoreArgv = [certutilPath, "-delstore", CERTREQ_ACCEPT_DEFAULT_STORE, thumbprint];
  assertSafeArgvElements("delstoreArgv", delstoreArgv);
  const delstoreResult = await execWithoutShell(execFileImpl, delstoreArgv, timeoutMs);
  if (delstoreResult.exitCode !== 0) {
    return {
      ok: false,
      stage: "delstore",
      exitCode: delstoreResult.exitCode,
      stdoutExcerpt: boundAndRedactExcerpt(delstoreResult.stdout),
      stderrExcerpt: boundAndRedactExcerpt(delstoreResult.stderr),
    };
  }

  // Independent confirmation: ask targetStore directly for this exact
  // thumbprint, rather than trusting the three prior exit codes alone (see
  // this function's doc comment, step 4).
  const verifyArgv = [certutilPath, "-store", targetStore, thumbprint];
  assertSafeArgvElements("verifyArgv", verifyArgv);
  const verifyResult = await execWithoutShell(execFileImpl, verifyArgv, timeoutMs);
  if (verifyResult.exitCode !== 0) {
    return {
      ok: false,
      stage: "verify",
      exitCode: verifyResult.exitCode,
      stdoutExcerpt: boundAndRedactExcerpt(verifyResult.stdout),
      stderrExcerpt: boundAndRedactExcerpt(verifyResult.stderr),
    };
  }

  return { ok: true };
}

/** A lock older than this, no matter whose PID recorded it, is treated as
 * stale outright, guarding against the (rare but real) case where the OS
 * has since reused the recorded PID for a completely unrelated process
 * that is very much still running -- liveness alone cannot rule that out,
 * only age can. Set well above any real enrollment/binding operation's
 * duration (seconds, not minutes) while staying well below "an operator
 * has to notice and intervene manually" territory. */
const MAX_STORE_LOCK_AGE_MS = 30 * 60 * 1000;

/**
 * Whether the process that created a lock file is still alive.
 * `process.kill(pid, 0)` sends no signal, only checks existence/permission
 * (works on both POSIX and win32, per Node's own child_process.kill docs).
 * ESRCH means the process is gone; anything else (including a permission
 * error, i.e. the PID exists but under a different account) means it is
 * still considered live, since this function's only job is to rule out
 * "this process definitely no longer exists", not to fully authenticate
 * ownership.
 * @param {number} pid
 * @returns {boolean}
 */
function isProcessAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err?.code !== "ESRCH";
  }
}

/**
 * Parses an acquireStoreLock lock file's contents (`"<pid>\n<isoDate>\n"`,
 * written by acquireStoreLock itself) back into `{ pid, createdAt }`.
 * Returns null on anything unparseable, so a corrupted/foreign lock file
 * is treated the same as "cannot prove this is stale" (fails closed,
 * still locked) rather than crashing the caller.
 * @param {string} contents
 * @returns {{ pid: number, createdAt: Date }|null}
 */
function parseStoreLockContents(contents) {
  const lines = String(contents).split("\n");
  const pid = Number(lines[0]);
  const createdAt = new Date(lines[1] ?? "");
  if (!Number.isInteger(pid) || pid < 0 || Number.isNaN(createdAt.getTime())) return null;
  return { pid, createdAt };
}

/**
 * Whether an existing lock file at `lockPath` is safe to steal: either its
 * recording process is no longer alive, or the lock has simply existed
 * longer than any real operation ever legitimately takes (see
 * MAX_STORE_LOCK_AGE_MS). An unparseable lock file is never considered
 * stale -- decision 13's mutex fails closed on anything it cannot
 * positively prove is dead, matching this module's fail-closed style
 * elsewhere (e.g. store-name/container-name validation).
 * @param {string} lockPath
 * @returns {boolean}
 */
function isStoreLockStale(lockPath) {
  let contents;
  try {
    contents = fs.readFileSync(lockPath, "utf8");
  } catch (err) {
    // Already gone (another racer cleaned it up first) -- not "stale",
    // just no longer an obstacle; the caller's retry will succeed via the
    // normal wx path.
    if (err && err.code === "ENOENT") return true;
    return false;
  }
  const parsed = parseStoreLockContents(contents);
  if (parsed === null) return false;
  if (Date.now() - parsed.createdAt.getTime() > MAX_STORE_LOCK_AGE_MS) return true;
  return !isProcessAlive(parsed.pid);
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
 * Stale-lock recovery: a process killed mid-enrollment (crash, OOM kill,
 * `taskkill /F`) leaves its lock file behind forever under the plain `wx`
 * scheme above -- with no other recovery path, EVERY future renewal
 * against that store fails permanently until an operator manually deletes
 * the file. On an initial EEXIST, this now checks isStoreLockStale (dead
 * PID, or simply too old) and, if stale, unlinks the abandoned file and
 * retries the acquisition exactly once (not in a loop: a genuinely busy,
 * live lock must still fail fast with STORE_LOCKED, not spin).
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

  function tryAcquire() {
    return fs.openSync(lockPath, "wx");
  }

  let fd;
  try {
    fd = tryAcquire();
  } catch (err) {
    if (err && err.code === "EEXIST" && isStoreLockStale(lockPath)) {
      try {
        fs.unlinkSync(lockPath);
      } catch {
        // Another racer may have already cleaned it up (or re-acquired
        // it); either way, fall through to the single retry below, which
        // is the actual source of truth.
      }
      try {
        fd = tryAcquire();
      } catch (retryErr) {
        if (retryErr && retryErr.code === "EEXIST") {
          throw buildError(
            `store ${JSON.stringify(storeName)} is locked by a concurrent enrollment/binding operation (${lockPath})`,
            "STORE_LOCKED",
          );
        }
        throw retryErr;
      }
    } else if (err && err.code === "EEXIST") {
      throw buildError(
        `store ${JSON.stringify(storeName)} is locked by a concurrent enrollment/binding operation (${lockPath})`,
        "STORE_LOCKED",
      );
    } else {
      throw err;
    }
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
        // best-effort; a lock file surviving past release (e.g. another
        // process already stole it as stale in a race with this exact
        // release call) is not a security issue -- nothing sensitive is
        // in it -- and is exactly the scenario isStoreLockStale above
        // exists to eventually recover from.
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
 *   { ok: true, keyContainerAlreadyAbsent?: true }
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
    // Real-host finding (interrupted-cleanup repro, 2026-08-09): unlike
    // `-delstore` (which silently no-ops with exit 0 for a thumbprint that is
    // already absent, confirmed on Windows Server 2025 build 26100.32860),
    // `-delkey` genuinely FAILS with NTE_BAD_KEYSET ("Keyset does not exist")
    // once the container is already gone. That asymmetry meant a caller
    // retrying this same call after a crash that landed between a first,
    // fully successful `-delstore`+`-delkey` pair and the caller persisting
    // that success (e.g. windows-retention's sweepLedger writing the ledger
    // row as "removed") would have its retry fail here forever: the delete
    // already fully succeeded, but the caller has no record of that, so it
    // keeps retrying an operation whose second half can never succeed again
    // -- an unrecoverable retry loop despite the real on-disk state already
    // being exactly the desired end state. NTE_BAD_KEYSET on `-delkey` is
    // therefore treated the same way `-delstore` already treats a missing
    // thumbprint: the container being absent IS success for a delete.
    const combinedOutput = `${delkeyResult.stdout || ""}\n${delkeyResult.stderr || ""}`;
    if (/NTE_BAD_KEYSET/i.test(combinedOutput)) {
      return guardReturnValue({ ok: true, keyContainerAlreadyAbsent: true });
    }
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
  AGENT_CONTAINER_NAME_PREFIX,
  ISSUED_CONTAINER_RECORD_DIR_NAME,
  CERTREQ_ACCEPT_DEFAULT_STORE,
  THUMBPRINT_PATTERN,
  buildContainerName,
  isAgentOwnedContainerName,
  issuedContainerRecordDir,
  issuedContainerRecordPath,
  recordIssuedContainer,
  markIssuedContainerAccepted,
  readIssuedContainerRecord,
  hasIssuedContainerRecord,
  removeIssuedContainerRecord,
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
  isProcessAlive,
  isStoreLockStale,
  parseStoreLockContents,
  MAX_STORE_LOCK_AGE_MS,
  removeCertificateAndKeyContainer,
  removeAbandonedKeyContainer,
};
