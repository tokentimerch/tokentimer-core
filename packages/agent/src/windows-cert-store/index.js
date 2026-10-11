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
 * non-default-store mirror path (e.g. WebHosting) is also real-host
 * verified via the nondefault-store-verify driver.
 */

const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { Worker } = require("node:worker_threads");

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

/** Windows-convention thumbprint: 40 hex chars, case-insensitive on input
 * (Windows tooling emits either case; this module's own output is always
 * uppercase via computeSha1ThumbprintFromPem). */
const THUMBPRINT_PATTERN = /^[0-9A-Fa-f]{40}$/;

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

// KeyUsage: digitalSignature + keyEncipherment for RSA. An ECDSA key cannot
// encipher, so EC requests ask for digitalSignature only.
const SUPPORTED_KEY_ALGORITHMS = Object.freeze({
  "rsa-2048": Object.freeze({ keyAlgorithm: "RSA", keyLength: 2048, keyUsage: "0xa0" }),
  "rsa-3072": Object.freeze({ keyAlgorithm: "RSA", keyLength: 3072, keyUsage: "0xa0" }),
  "rsa-4096": Object.freeze({ keyAlgorithm: "RSA", keyLength: 4096, keyUsage: "0xa0" }),
  "ec-p256": Object.freeze({ keyAlgorithm: "ECDSA_P256", keyLength: 256, keyUsage: "0x80" }),
  "ec-p384": Object.freeze({ keyAlgorithm: "ECDSA_P384", keyLength: 384, keyUsage: "0x80" }),
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

/** Lowercase UUID, as the job-payload contract defines enrollmentId. */
const ENROLLMENT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Container name for an AD CS enrollment (ADR-0014 decision 7): one
 * enrollment owns one key, so the name is deterministic and recovery can
 * find the key from the enrollment id alone. The id is validated, never
 * sanitized, so two enrollments can never map to the same container. It
 * cannot collide with buildContainerName either: those end in 8 hex
 * characters, a UUID ends in 12.
 * @param {string} enrollmentId
 * @returns {string}
 */
function buildEnrollmentContainerName(enrollmentId) {
  if (typeof enrollmentId !== "string" || !ENROLLMENT_ID_PATTERN.test(enrollmentId)) {
    throw buildError(`enrollmentId must be a lowercase UUID (got ${JSON.stringify(enrollmentId)})`);
  }
  return `${AGENT_CONTAINER_NAME_PREFIX}enr-${enrollmentId}`;
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

  // Never a [RequestAttributes] CertificateTemplate: with the Software KSP,
  // certreq -new fails NTE_PROV_TYPE_NOT_DEF on schema v1/v2 templates, so an
  // AD CS template travels at submit instead (ADR-0014 decision 7).
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
    `KeyUsage = ${spec.keyUsage}`,
    "Exportable = FALSE",
    "ExportableEncrypted = FALSE",
    "SMIME = FALSE",
    "PrivateKeyArchive = FALSE",
    "UserProtected = FALSE",
    // The service session has no desktop; certreq must never wait on UI.
    "Silent = TRUE",
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
  // Windows store thumbprints are SHA-1 of the DER. Read Node's own
  // X509Certificate fingerprint instead of hashing peer bytes again.
  let fingerprint;
  try {
    fingerprint = new crypto.X509Certificate(der).fingerprint;
  } catch {
    throw buildError("certificate PEM did not parse as X.509");
  }
  const thumbprint = String(fingerprint || "")
    .replace(/:/g, "")
    .toUpperCase();
  if (!THUMBPRINT_PATTERN.test(thumbprint)) {
    throw buildError("certificate fingerprint is not a Windows SHA-1 thumbprint");
  }
  return thumbprint;
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
  const beginPrefix = "-----BEGIN ";
  const dashRun = "-----";
  const start = pem.indexOf(beginPrefix);
  if (start === -1) {
    throw buildError(
      `input is not a recognizable PEM block matching ${labelPattern}`,
    );
  }
  const labelStart = start + beginPrefix.length;
  const labelEnd = pem.indexOf(dashRun, labelStart);
  if (labelEnd === -1 || labelEnd === labelStart) {
    throw buildError(
      `input is not a recognizable PEM block matching ${labelPattern}`,
    );
  }
  const label = pem.slice(labelStart, labelEnd);
  if (!labelPattern.test(label)) {
    throw buildError(
      `input is not a recognizable PEM block matching ${labelPattern}`,
    );
  }
  const headerEnd = labelEnd + dashRun.length;
  const endMarker = `-----END ${label}-----`;
  const endAt = pem.indexOf(endMarker, headerEnd);
  if (endAt === -1) {
    throw buildError(
      `input is not a recognizable PEM block matching ${labelPattern}`,
    );
  }
  const body = pem.slice(headerEnd, endAt);
  let base64 = "";
  for (let i = 0; i < body.length; i += 1) {
    const code = body.charCodeAt(i);
    // ASCII whitespace only (space, tab, LF, VT, FF, CR). Matches PEM `\s`.
    if (
      code !== 32 &&
      code !== 9 &&
      code !== 10 &&
      code !== 11 &&
      code !== 12 &&
      code !== 13
    ) {
      base64 += body[i];
    }
  }
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
 * When `signal` aborts, the child is killed (if the impl returned one) and
 * the promise resolves with execError.code === "ABORT_ERR".
 * @param {Function} execFileImpl
 * @param {string[]} argv argv[0] is the executable
 * @param {number} timeoutMs
 * @param {AbortSignal} [signal]
 * @returns {Promise<{exitCode: number|null, stdout: unknown, stderr: unknown, execError: Error|null}>}
 */
/**
 * CNG helpers key cancellation on `execError.code === "ABORT_ERR"`.
 * `lock.run` aborts with STORE_/ENROLLMENT_LOCK_LOST — normalize here and
 * keep the original reason as `cause`.
 * @param {AbortSignal|null|undefined} signal
 * @returns {Error & { code: string, cause?: Error }}
 */
function abortExecError(signal) {
  const cause =
    signal && signal.reason instanceof Error
      ? signal.reason
      : signal && signal.reason != null
        ? new Error(String(signal.reason))
        : undefined;
  const abortErr = new Error(cause ? cause.message : "aborted");
  abortErr.code = "ABORT_ERR";
  if (cause) abortErr.cause = cause;
  return abortErr;
}

/** Bound wait after kill() before resolving abort if exit never arrives. */
const EXEC_ABORT_DRAIN_MS = 5_000;

function execWithoutShell(execFileImpl, argv, timeoutMs, signal) {
  const [file, ...args] = argv;
  return new Promise((resolve) => {
    if (signal && signal.aborted) {
      resolve({
        exitCode: null,
        stdout: "",
        stderr: "",
        execError: abortExecError(signal),
      });
      return;
    }

    let settled = false;
    let aborted = false;
    /** @type {(() => void)|null} */
    let onAbort = null;
    /** @type {ReturnType<typeof setTimeout>|null} */
    let drainTimer = null;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (drainTimer != null) {
        clearTimeout(drainTimer);
        drainTimer = null;
      }
      if (signal && onAbort) {
        signal.removeEventListener("abort", onAbort);
      }
      // Prefer the abort shape so callers never see a kill() exit code as success.
      if (aborted) {
        resolve({
          exitCode: null,
          stdout: "",
          stderr: "",
          execError: abortExecError(signal),
        });
        return;
      }
      resolve(result);
    };

    const child = execFileImpl(
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
          finish({ exitCode, stdout, stderr, execError: error });
          return;
        }
        finish({ exitCode: 0, stdout, stderr, execError: null });
      },
    );

    if (signal && child && typeof child.kill === "function") {
      onAbort = () => {
        aborted = true;
        try {
          child.kill();
        } catch {
          // best-effort
        }
        // Do not resolve until the child has exited (or the drain bound).
        // Resolving immediately would let lock holders release while certreq /
        // certutil / netsh may still be mutating protected state.
        if (typeof child.once === "function") {
          child.once("exit", () => finish({
            exitCode: null,
            stdout: "",
            stderr: "",
            execError: abortExecError(signal),
          }));
        }
        const drainMs =
          typeof timeoutMs === "number" && timeoutMs > 0
            ? Math.min(timeoutMs, EXEC_ABORT_DRAIN_MS)
            : EXEC_ABORT_DRAIN_MS;
        drainTimer = setTimeout(() => {
          finish({
            exitCode: null,
            stdout: "",
            stderr: "",
            execError: abortExecError(signal),
          });
        }, drainMs);
        if (typeof drainTimer.unref === "function") drainTimer.unref();
      };
      signal.addEventListener("abort", onAbort, { once: true });
    }
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
 * @param {string} [input.enrollmentId] AD CS only: names the container after
 *   the enrollment instead (see buildEnrollmentContainerName). When set,
 *   a second generate for the same enrollment refuses if that container
 *   already exists in the Software KSP (does not replace the first key).
 * @param {"rsa-2048"|"rsa-3072"|"rsa-4096"|"ec-p256"|"ec-p384"} [input.algorithm]
 * @param {string} input.workDir absolute, ACL-protected scratch directory
 *   for this enrollment's INF/.req files (caller-owned; see ensureWorkDir).
 * @param {Function} [input.execFileImpl] injection point for tests;
 *   defaults to node:child_process.execFile.
 * @param {string} [input.certreqPath] defaults to "certreq.exe" (resolved
 *   via PATH/System32, matching every other Windows-native tool this agent
 *   shells out to).
 * @param {string} [input.certutilPath] defaults to "certutil.exe"; used only
 *   for the enrollment-container existence probe.
 * @param {number} [input.timeoutMs]
 * @returns {Promise<
 *   { ok: true, csrPem: string, containerName: string, infPath: string, reqPath: string }
 *   | { ok: false, exitCode: number|null, stdoutExcerpt: string, stderrExcerpt: string, reason?: string, containerName?: string }
 * >}
 */
async function generateCsrViaCng({
  commonName,
  altNames = [],
  jobId,
  enrollmentId,
  algorithm = "rsa-2048",
  workDir,
  execFileImpl = childProcess.execFile,
  certreqPath = "certreq.exe",
  certutilPath = "certutil.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
  signal = undefined,
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

  const containerName =
    enrollmentId === undefined ? buildContainerName(jobId) : buildEnrollmentContainerName(enrollmentId);

  // Enrollment names are deterministic. A second -new under the same name
  // can replace or strand the first key; refuse before certreq runs.
  if (enrollmentId !== undefined) {
    if (!isNonEmptyString(certutilPath)) {
      throw buildError("certutilPath must be a non-empty string");
    }
    assertSafeArgvElements("certutilPath", [certutilPath]);
    const listArgv = [certutilPath, "-csp", MICROSOFT_SOFTWARE_KSP, "-key"];
    assertSafeArgvElements("listArgv", listArgv);
    const listing = await execWithoutShell(execFileImpl, listArgv, timeoutMs, signal);
    if (listing.execError && listing.execError.code === "ABORT_ERR") {
      return {
        ok: false,
        exitCode: null,
        reason: "aborted",
        containerName,
        stdoutExcerpt: "",
        stderrExcerpt: "",
      };
    }
    if (listing.exitCode !== 0) {
      return {
        ok: false,
        exitCode: listing.exitCode,
        reason: "enrollment_container_probe_failed",
        containerName,
        stdoutExcerpt: boundAndRedactExcerpt(listing.stdout),
        stderrExcerpt: boundAndRedactExcerpt(listing.stderr),
      };
    }
    // `certutil -key <name>` exits 0 even when the key is gone; match the
    // full Software KSP listing line by line instead.
    const present = String(listing.stdout || "")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .includes(containerName);
    if (present) {
      return guardReturnValue({
        ok: false,
        exitCode: null,
        reason: "enrollment_container_exists",
        containerName,
        stdoutExcerpt: "",
        stderrExcerpt: boundAndRedactExcerpt(
          `enrollment container ${containerName} already exists; refusing a second certreq -new`,
        ),
      });
    }
  }

  const infText = buildCertreqInf({ commonName, altNames, containerName, algorithm });

  ensureWorkDir(workDir);
  const nonce = crypto.randomBytes(4).toString("hex");
  const infPath = path.join(workDir, `${containerName}-${nonce}.inf`);
  const reqPath = path.join(workDir, `${containerName}-${nonce}.req`);

  fs.writeFileSync(infPath, infText, { encoding: "utf8", flag: "wx" });

  try {
    // MachineKeySet already implies machine context; -machine states it for
    // certreq too, so -new and -accept can never disagree under LocalSystem.
    const argv = [certreqPath, "-q", "-machine", "-new", infPath, reqPath];
    assertSafeArgvElements("argv", argv);
    const { exitCode, stdout, stderr, execError } = await execWithoutShell(
      execFileImpl,
      argv,
      timeoutMs,
      signal,
    );

    if (execError && execError.code === "ABORT_ERR") {
      return {
        ok: false,
        exitCode: null,
        reason: "aborted",
        containerName,
        stdoutExcerpt: "",
        stderrExcerpt: "",
      };
    }

    if (exitCode !== 0) {
      return {
        ok: false,
        exitCode,
        containerName,
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
 * Both the default-store (`My`) path and the non-default-store mirror
 * (WebHosting via addstore/repairstore/verify) are real-host verified.
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
  signal = undefined,
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
    const argv = [certreqPath, "-q", "-machine", "-accept", certPath];
    assertSafeArgvElements("argv", argv);
    const { exitCode, stdout, stderr, execError } = await execWithoutShell(
      execFileImpl,
      argv,
      timeoutMs,
      signal,
    );

    if (execError && execError.code === "ABORT_ERR") {
      return {
        ok: false,
        exitCode: null,
        reason: "aborted",
        stdoutExcerpt: "",
        stderrExcerpt: "",
      };
    }

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
        signal,
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
  execFileImpl = childProcess.execFile,
  certutilPath = "certutil.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
  signal = undefined,
}) {
  assertSafeArgvElements("certutilPath", [certutilPath]);

  const addstoreArgv = [certutilPath, "-addstore", targetStore, certPath];
  assertSafeArgvElements("addstoreArgv", addstoreArgv);
  const addstoreResult = await execWithoutShell(execFileImpl, addstoreArgv, timeoutMs, signal);
  if (addstoreResult.execError && addstoreResult.execError.code === "ABORT_ERR") {
    return {
      ok: false,
      stage: "addstore",
      exitCode: null,
      reason: "aborted",
      stdoutExcerpt: "",
      stderrExcerpt: "",
    };
  }
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
  const repairstoreResult = await execWithoutShell(
    execFileImpl,
    repairstoreArgv,
    timeoutMs,
    signal,
  );
  if (repairstoreResult.execError && repairstoreResult.execError.code === "ABORT_ERR") {
    return {
      ok: false,
      stage: "repairstore",
      exitCode: null,
      reason: "aborted",
      stdoutExcerpt: "",
      stderrExcerpt: "",
    };
  }
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
  const delstoreResult = await execWithoutShell(execFileImpl, delstoreArgv, timeoutMs, signal);
  if (delstoreResult.execError && delstoreResult.execError.code === "ABORT_ERR") {
    return {
      ok: false,
      stage: "delstore",
      exitCode: null,
      reason: "aborted",
      stdoutExcerpt: "",
      stderrExcerpt: "",
    };
  }
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
  const verifyResult = await execWithoutShell(execFileImpl, verifyArgv, timeoutMs, signal);
  if (verifyResult.execError && verifyResult.execError.code === "ABORT_ERR") {
    return {
      ok: false,
      stage: "verify",
      exitCode: null,
      reason: "aborted",
      stdoutExcerpt: "",
      stderrExcerpt: "",
    };
  }
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

/** IPC lock worker state codes (see exclusive-lock-worker.js). */
const EXCLUSIVE_LOCK_STATE_PENDING = 0;
const EXCLUSIVE_LOCK_STATE_HELD = 1;
const EXCLUSIVE_LOCK_STATE_BUSY = 2;
const EXCLUSIVE_LOCK_ACQUIRE_TIMEOUT_MS = 10_000;
/** Graceful close wait; terminate() always follows and drops the listen. */
const EXCLUSIVE_LOCK_RELEASE_TIMEOUT_MS = 500;
/** Parent treats a quieter heartbeat as lock loss (worker ticks every 50ms). */
const EXCLUSIVE_LOCK_HEARTBEAT_STALE_MS = 500;
/** After lock loss, wait this long for cooperative cancel before dropping IPC. */
const EXCLUSIVE_LOCK_ABORT_DRAIN_MS = 5_000;

/**
 * Maps a filesystem lock key to a short, deterministic IPC name.
 * Never appends to an arbitrarily long lockPath on POSIX (unix-domain
 * socket pathnames truncate and can collide). Returns
 * `{ ipcPath, ipcKind }` where ipcKind is "pipe" | "abstract" | "file".
 * @param {string} lockPath
 * @returns {{ ipcPath: string, ipcKind: "pipe"|"abstract"|"file" }}
 */
function exclusiveLockIpcTarget(lockPath) {
  const digest = crypto.createHash("sha256").update(lockPath).digest("hex").slice(0, 40);
  if (process.platform === "win32") {
    return {
      ipcPath: "\\\\.\\pipe\\tokentimer-agent-" + digest,
      ipcKind: "pipe",
    };
  }
  if (process.platform === "linux") {
    // Abstract namespace: no filesystem node, so no stale-path reclaim.
    return {
      ipcPath: "\0tokentimer-agent-" + digest,
      ipcKind: "abstract",
    };
  }
  const dir = path.join(os.tmpdir(), "tokentimer-agent-ipc");
  return {
    ipcPath: path.join(dir, digest + ".sock"),
    ipcKind: "file",
  };
}

/** @deprecated use exclusiveLockIpcTarget; kept for tests that only need the path string */
function exclusiveLockIpcPath(lockPath) {
  return exclusiveLockIpcTarget(lockPath).ipcPath;
}

function lockLostCode(busyCode) {
  if (busyCode === "STORE_LOCKED") return "STORE_LOCK_LOST";
  if (busyCode === "ENROLLMENT_LOCKED") return "ENROLLMENT_LOCK_LOST";
  if (busyCode === "ADCS_WATERMARK_LOCKED") return "ADCS_WATERMARK_LOCK_LOST";
  return "LOCK_LOST";
}

/**
 * Parses the best-effort owner marker written beside an IPC lock
 * (`"<pid>\n<isoDate>\n<ownerToken>\n"`). The marker is diagnostic only;
 * exclusion comes from the pipe/socket listen, not from this file.
 * @param {string} contents
 * @returns {{ pid: number, createdAt: Date, ownerToken: string|null }|null}
 */
function parseStoreLockContents(contents) {
  const lines = String(contents).split("\n");
  const pid = Number(lines[0]);
  const createdAt = new Date(lines[1] ?? "");
  if (!Number.isInteger(pid) || pid < 0 || Number.isNaN(createdAt.getTime())) return null;
  const rawToken = lines[2] ?? "";
  const ownerToken = rawToken.length > 0 ? rawToken : null;
  return { pid, createdAt, ownerToken };
}

/**
 * Store-scoped mutex (ADR-0012 decision 13: "the per-target mutex covers
 * the store as well as the binding, since two jobs racing on the same
 * machine store is as damaging as two racing on one binding").
 *
 * Mutual exclusion is a kernel-mediated exclusive listen (Windows named
 * pipe / Linux abstract socket / short hashed pathname socket), held on a
 * dedicated worker thread so the public acquire API stays synchronous.
 * Process or worker death drops the listen automatically. Callers must
 * treat unexpected worker exit as loss of authority via `assertHeld()`
 * before further protected mutations. A marker file at `lockPath` is
 * diagnostic only.
 *
 * @param {string} lockPath
 * @param {string} busyCode
 * @param {string} busyMessage
 * @returns {{
 *   lockPath: string,
 *   ownerToken: string,
 *   lost: boolean,
 *   assertHeld: () => void,
 *   release: () => void,
 * }}
 */
function acquireExclusiveLockFile(lockPath, busyCode, busyMessage) {
  if (!isNonEmptyString(lockPath)) {
    throw buildError("acquireExclusiveLockFile requires a non-empty lockPath");
  }
  fs.mkdirSync(path.dirname(lockPath), { recursive: true });

  const { ipcPath, ipcKind } = exclusiveLockIpcTarget(lockPath);
  if (ipcKind === "file") {
    fs.mkdirSync(path.dirname(ipcPath), { recursive: true });
  }

  // [0]=state, [1]=heartbeat millis (worker ticks while held)
  const sab = new SharedArrayBuffer(8);
  const state = new Int32Array(sab);
  Atomics.store(state, 0, EXCLUSIVE_LOCK_STATE_PENDING);
  Atomics.store(state, 1, 0);

  const worker = new Worker(path.join(__dirname, "exclusive-lock-worker.js"), {
    workerData: { sab, ipcPath, ipcKind },
  });

  let workerFailed = null;
  worker.once("error", (err) => {
    workerFailed = err;
    Atomics.store(state, 0, EXCLUSIVE_LOCK_STATE_BUSY);
    Atomics.notify(state, 0);
  });

  Atomics.wait(state, 0, EXCLUSIVE_LOCK_STATE_PENDING, EXCLUSIVE_LOCK_ACQUIRE_TIMEOUT_MS);
  const acquireState = Atomics.load(state, 0);
  if (acquireState !== EXCLUSIVE_LOCK_STATE_HELD) {
    try {
      worker.terminate();
    } catch {
      // best-effort
    }
    if (workerFailed) {
      throw buildError(
        "exclusive lock worker failed for " + lockPath + ": " + workerFailed.message,
        busyCode,
      );
    }
    if (acquireState === EXCLUSIVE_LOCK_STATE_BUSY) {
      throw buildError(busyMessage, busyCode);
    }
    throw buildError(
      "timed out or failed acquiring exclusive lock for " + lockPath,
      busyCode,
    );
  }

  const ownerToken = crypto.randomBytes(16).toString("hex");
  // Marker is best-effort and never consulted for exclusion. Writing it
  // after the listen succeeds means a crash between listen and write leaves
  // no blocking artifact -- the next acquire binds the freed IPC name.
  try {
    fs.writeFileSync(
      lockPath,
      process.pid + "\n" + new Date().toISOString() + "\n" + ownerToken + "\n",
      "utf8",
    );
  } catch {
    // diagnostic only
  }

  let released = false;
  let lost = false;
  const lostError = buildError(
    `exclusive lock lost for ${lockPath}: lock worker exited unexpectedly`,
    lockLostCode(busyCode),
  );

  function markLost() {
    if (!released) {
      lost = true;
    }
  }

  worker.once("exit", () => {
    markLost();
  });

  function heartbeatIsFresh() {
    const beat = Atomics.load(state, 1);
    if (beat === 0) return false;
    const now = Date.now() & 0x7fffffff;
    // Handle 31-bit wrap by accepting either small forward delta.
    const delta = (now - beat + 0x80000000) % 0x80000000;
    return delta <= EXCLUSIVE_LOCK_HEARTBEAT_STALE_MS;
  }

  return {
    lockPath,
    ownerToken,
    get lost() {
      if (!lost && !released && !heartbeatIsFresh()) {
        lost = true;
      }
      return lost;
    },
    /**
     * Throws if the lock worker exited, stopped heartbeating, or release
     * already ran. Call after every await and before further protected
     * mutations inside a critical section.
     */
    assertHeld() {
      if (released) {
        throw buildError(
          `exclusive lock already released for ${lockPath}`,
          lockLostCode(busyCode),
        );
      }
      if (lost || !heartbeatIsFresh()) {
        lost = true;
        throw lostError;
      }
    },
    /**
     * Race `work` against lock loss. On loss the worker is terminated so the
     * IPC listen drops for a successor, and an AbortSignal is aborted for
     * cooperative cancellation (`work(signal)`). Callers that ignore the
     * signal must still treat the rejected `run` as authority loss and must
     * not perform further protected mutations (including finally cleanup).
     * @template T
     * @param {((signal: AbortSignal) => Promise<T>)|(() => Promise<T>)} work
     * @returns {Promise<T>}
     */
    async run(work) {
      this.assertHeld();
      let settled = false;
      const ac = new AbortController();
      const lossWatch = new Promise((resolve) => {
        const timer = setInterval(() => {
          if (settled) {
            clearInterval(timer);
            return;
          }
          try {
            this.assertHeld();
          } catch (err) {
            clearInterval(timer);
            lost = true;
            // Abort first; keep the IPC listen while the worker is still
            // alive so cooperative cancel can drain subprocesses before a
            // successor acquires. Unexpected worker death already drops the
            // listen (fail-open for successors; real-host qualification).
            try {
              ac.abort(err);
            } catch {
              // ignore
            }
            resolve(err);
          }
        }, 50);
        if (typeof timer.unref === "function") timer.unref();
      });
      const workPromise = Promise.resolve().then(() => {
        if (typeof work === "function" && work.length >= 1) {
          return work(ac.signal);
        }
        return work();
      });
      try {
        const outcome = await Promise.race([
          workPromise.then(
            (value) => ({ type: "ok", value }),
            (err) => ({ type: "work-err", err }),
          ),
          lossWatch.then((err) => ({ type: "lost", err })),
        ]);
        if (outcome.type === "ok") {
          return outcome.value;
        }
        if (outcome.type === "work-err") {
          throw outcome.err;
        }
        try {
          await Promise.race([
            workPromise.then(
              () => undefined,
              () => undefined,
            ),
            new Promise((r) => setTimeout(r, EXCLUSIVE_LOCK_ABORT_DRAIN_MS)),
          ]);
        } finally {
          try {
            worker.terminate();
          } catch {
            // best-effort
          }
        }
        throw outcome.err;
      } finally {
        settled = true;
      }
    },
    /**
     * Exposed for crash-boundary tests: abrupt worker death must release
     * the IPC listen so another contender can acquire.
     */
    _workerForTests: worker,
    release() {
      if (released) return;
      released = true;
      // Always terminate: heartbeat-based `lost` can be a false positive
      // (scheduler delay / sleep-resume) while the worker still holds the
      // listen. Skipping terminate would leave STORE_LOCKED until process exit.
      if (!lost) {
        try {
          worker.postMessage("release");
          Atomics.wait(state, 0, EXCLUSIVE_LOCK_STATE_HELD, EXCLUSIVE_LOCK_RELEASE_TIMEOUT_MS);
        } catch {
          // best-effort
        }
      }
      try {
        worker.terminate();
      } catch {
        // best-effort
      }
      try {
        const current = fs.readFileSync(lockPath, "utf8");
        const parsed = parseStoreLockContents(current);
        if (parsed && parsed.ownerToken === ownerToken) {
          fs.unlinkSync(lockPath);
        }
      } catch {
        // marker cleanup only; exclusion already dropped with the listen
      }
    },
  };
}

function acquireStoreLock(stateDir, storeName) {
  if (!WINDOWS_STORE_NAME_PATTERN.test(storeName)) {
    throw buildError(`invalid store name for lock: ${JSON.stringify(storeName)}`);
  }
  const lockDir = path.join(stateDir, "windows-cert-store");
  fs.mkdirSync(lockDir, { recursive: true });
  const lockPath = path.join(lockDir, `${storeName}.lock`);
  return acquireExclusiveLockFile(
    lockPath,
    "STORE_LOCKED",
    `store ${JSON.stringify(storeName)} is locked by a concurrent enrollment/binding operation (${lockPath})`,
  );
}

/**
 * Cross-process mutex for one AD CS enrollment (W6). The KSP existence
 * probe in generateCsrViaCng is not atomic with certreq -new; the
 * executor must hold this lock across probe, -new, submit/retrieve, and
 * -accept for that enrollmentId. Same IPC exclusive-listen rules as the
 * store lock. Distinct from acquireStoreLock: two enrollments may share
 * a store, and two stores must not serialize unrelated enrollments.
 *
 * @param {string} stateDir
 * @param {string} enrollmentId lowercase UUID
 * @returns {{
 *   lockPath: string,
 *   ownerToken: string,
 *   lost: boolean,
 *   assertHeld: () => void,
 *   run: (work: Function) => Promise<unknown>,
 *   release: () => void,
 * }}
 */
function acquireEnrollmentLock(stateDir, enrollmentId) {
  if (typeof enrollmentId !== "string" || !ENROLLMENT_ID_PATTERN.test(enrollmentId)) {
    throw buildError(`enrollmentId must be a lowercase UUID (got ${JSON.stringify(enrollmentId)})`);
  }
  if (!isNonEmptyString(stateDir)) {
    throw buildError("acquireEnrollmentLock requires a non-empty stateDir");
  }
  const lockDir = path.join(stateDir, "windows-cert-store");
  fs.mkdirSync(lockDir, { recursive: true });
  const lockPath = path.join(lockDir, `enrollment-${enrollmentId}.lock`);
  return acquireExclusiveLockFile(
    lockPath,
    "ENROLLMENT_LOCKED",
    `enrollment ${enrollmentId} is locked by a concurrent AD CS operation (${lockPath})`,
  );
}

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
  signal = undefined,
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
  const delstoreResult = await execWithoutShell(execFileImpl, delstoreArgv, timeoutMs, signal);
  if (delstoreResult.execError && delstoreResult.execError.code === "ABORT_ERR") {
    return guardReturnValue({
      ok: false,
      stage: "delstore",
      exitCode: null,
      reason: "aborted",
      stdoutExcerpt: "",
      stderrExcerpt: "",
    });
  }
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
  const delkeyResult = await execWithoutShell(execFileImpl, delkeyArgv, timeoutMs, signal);
  if (delkeyResult.execError && delkeyResult.execError.code === "ABORT_ERR") {
    return guardReturnValue({
      ok: false,
      stage: "delkey",
      exitCode: null,
      reason: "aborted",
      stdoutExcerpt: "",
      stderrExcerpt: "",
    });
  }
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
  signal = undefined,
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
  const delkeyResult = await execWithoutShell(execFileImpl, delkeyArgv, timeoutMs, signal);
  if (delkeyResult.execError && delkeyResult.execError.code === "ABORT_ERR") {
    return guardReturnValue({
      ok: false,
      exitCode: null,
      reason: "aborted",
      stdoutExcerpt: "",
      stderrExcerpt: "",
    });
  }
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
  buildEnrollmentContainerName,
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
  mirrorAcceptedCertificateToStore,
  acquireStoreLock,
  acquireEnrollmentLock,
  acquireExclusiveLockFile,
  exclusiveLockIpcPath,
  exclusiveLockIpcTarget,
  parseStoreLockContents,
  removeCertificateAndKeyContainer,
  removeAbandonedKeyContainer,
};
