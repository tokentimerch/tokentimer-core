"use strict";

/**
 * Agent-local key generation and CSR building.
 *
 * Zero private-key custody (ADR-0001):
 * private keys are generated locally on the agent host, written 0600 inside
 * 0700 directories, and NEVER returned from any exported function. Return
 * values contain only file paths, fingerprints, and public material (public
 * key PEM, CSR PEM). Every exported function's return value is passed
 * through the shared private-key-material detector as a last-resort guard
 * before it is handed back to the caller (mirroring
 * evidence/assertEvidencePayloadSafe).
 *
 * Memory hygiene note: JavaScript cannot guarantee zeroization.
 * Strings are immutable and copied freely by the engine, and node:crypto
 * KeyObject internal memory is owned by OpenSSL and not reachable from JS.
 * What this module *can* do, it does: private key PEM is exported into a
 * Buffer, written to disk from that Buffer, and the Buffer is fill(0)-ed
 * immediately after the write. The KeyObject itself and any transient
 * copies made inside OpenSSL/V8 are beyond zeroization from JS; this is a
 * documented platform limit, not an oversight.
 *
 * Module style follows the sibling policy/evidence modules: CommonJS,
 * node builtins only (node:crypto, node:fs, node:path), self-contained
 * plain-data functions with no sibling-module imports beyond the shared
 * detector seam already used by ../evidence.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

// Single source of truth for content-based private-key-material detection,
// required through the same compatibility seam ../evidence/index.js uses
// (apps/api/utils/secretMaterial.js -> packages/log-scrub/secret-material).
const {
  assertNoPrivateKeyMaterial,
} = require("../../../../apps/api/utils/secretMaterial.js");

/**
 * Supported key algorithms. Each entry maps the public algorithm name to
 * the node:crypto generateKeyPairSync type/options pair.
 */
const SUPPORTED_ALGORITHMS = Object.freeze({
  "ec-p256": Object.freeze({ type: "ec", options: Object.freeze({ namedCurve: "P-256" }) }),
  "rsa-2048": Object.freeze({ type: "rsa", options: Object.freeze({ modulusLength: 2048 }) }),
  "rsa-3072": Object.freeze({ type: "rsa", options: Object.freeze({ modulusLength: 3072 }) }),
  ed25519: Object.freeze({ type: "ed25519", options: Object.freeze({}) }),
});

const SUPPORTED_ALGORITHM_NAMES = Object.freeze(Object.keys(SUPPORTED_ALGORITHMS));

function buildError(message, code) {
  const error = new Error(message);
  if (code) error.code = code;
  return error;
}

/**
 * Last-resort custody guard: deep-scans a return value for private key
 * material immediately before it leaves this module. Same spirit (and same
 * shared detector) as evidence/assertEvidencePayloadSafe.
 *
 * Content-only scan, deliberately: the shared detector's *field-name*
 * heuristic bans any name containing "keyPem", which would reject this
 * module's own `publicKeyPem` field even though it holds public material
 * by construction. Field-name policy belongs to evidence/protocol payload
 * builders; the custody boundary here is the content check, applied to
 * every value in the return object. Throws with code
 * PRIVATE_KEY_MATERIAL_REJECTED if anything key-like is found.
 * @param {Record<string, *>} value flat plain-object return value
 * @returns {Record<string, *>} the value, unchanged, when safe
 */
function guardReturnValue(value) {
  for (const item of Object.values(value)) {
    assertNoPrivateKeyMaterial(item);
  }
  return value;
}

/**
 * Ensures the parent directory of keyPath exists with 0700 permissions,
 * re-asserting the mode on every call (same defense-in-depth discipline as
 * config/ensureConfigDir; best-effort on win32 where POSIX modes are not
 * meaningful).
 * @param {string} keyPath
 * @returns {void}
 */
function ensureKeyDir(keyPath) {
  const dir = path.dirname(keyPath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(dir, 0o700);
  } catch (_err) {
    // Best-effort on win32; see config/ensureConfigDir for rationale.
  }
}

/**
 * Inspects keyPath without following symlinks. Returns "absent" when the
 * path does not exist. Throws when the path exists but is a symlink or any
 * non-regular file: a symlink at the key path is a classic
 * swap-the-destination attack (write 0600 key bytes through a link into an
 * attacker-chosen location), so it is refused outright rather than
 * followed or silently replaced.
 * @param {string} keyPath
 * @returns {"absent"|"regular"}
 */
function classifyExistingKeyPath(keyPath) {
  let stats;
  try {
    stats = fs.lstatSync(keyPath);
  } catch (err) {
    if (err && err.code === "ENOENT") return "absent";
    throw buildError(
      `tokentimer-agent keys: could not inspect key path ${keyPath}: ${err.message}`,
    );
  }
  if (stats.isSymbolicLink() || !stats.isFile()) {
    throw buildError(
      `tokentimer-agent keys: key path ${keyPath} exists but is not a ` +
        "regular file (symlink or special file); refusing to write key " +
        "material through it",
    );
  }
  return "regular";
}

/**
 * Generates a keypair and writes the private key PEM (PKCS#8) with mode
 * 0600 (parent dir 0700), returning ONLY public material plus paths.
 *
 * Write discipline (crash-safe rotation):
 *   - fresh key (path absent): exclusive create (flag "wx") at keyPath;
 *   - rotation (overwrite: true, path already a regular file): the NEW key
 *     is written to a staging path alongside the target
 *     (`.${basename}.staging-<pid>-<random>`) and the LIVE keyPath is
 *     NEVER overwritten. Callers must only promote the staged key into
 *     keyPath together with a matching certificate (see
 *     deploy.deployCertificateAndKey). If issuance/deploy fails, call
 *     discardStagedKey to remove the staging file; the previous live key
 *     remains intact.
 *
 * The private key PEM is exported into a Buffer, written from that Buffer,
 * and the Buffer is zeroized (fill(0)) immediately after the write. See the
 * module doc comment for the documented limits of zeroization in JS.
 *
 * @param {object} input
 * @param {string} input.keyPath absolute or relative path for the live private key file
 * @param {"ec-p256"|"rsa-2048"|"rsa-3072"|"ed25519"} [input.algorithm]
 * @param {boolean} [input.overwrite] refuse to clobber an existing file unless true;
 *   when true and the file exists, writes to a staging path instead of keyPath
 * @returns {{ keyPath: string, stagedKeyPath: string, publicKeyPem: string, algorithm: string }}
 */
function generateKeyPairToFile({ keyPath, algorithm = "ec-p256", overwrite = false } = {}) {
  if (typeof keyPath !== "string" || keyPath.length === 0) {
    throw buildError("tokentimer-agent keys: keyPath must be a non-empty string");
  }
  const spec = SUPPORTED_ALGORITHMS[algorithm];
  if (!spec) {
    throw buildError(
      `tokentimer-agent keys: unsupported algorithm ${JSON.stringify(algorithm)}; ` +
        `supported: ${SUPPORTED_ALGORITHM_NAMES.join(", ")}`,
    );
  }

  // lstat-based classification: throws on symlinks/special files whether or
  // not overwrite was requested (see classifyExistingKeyPath).
  const existing = classifyExistingKeyPath(keyPath);
  if (!overwrite && existing === "regular") {
    throw buildError(
      `tokentimer-agent keys: refusing to overwrite existing key file at ${keyPath} ` +
        "(pass overwrite: true only when a rekey is explicitly intended)",
    );
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync(spec.type, spec.options);

  ensureKeyDir(keyPath);

  // Rotation must never replace the live key in place: write to a staging
  // sibling so a failed issuance cannot leave a new key paired with an old
  // (or missing) certificate. Fresh keys still land at keyPath.
  const isRotation = existing === "regular";
  const writePath = isRotation
    ? path.join(
        path.dirname(keyPath),
        `.${path.basename(keyPath)}.staging-${process.pid}-${crypto.randomBytes(6).toString("hex")}`,
      )
    : keyPath;

  // Export into a Buffer (not a string) so the bytes can be zeroized after
  // the write. KeyObject.export returns a Buffer when no encoding is given
  // beyond format: "pem" -- force Buffer via Buffer.from to be explicit.
  const privatePemBuffer = Buffer.from(
    privateKey.export({ type: "pkcs8", format: "pem" }),
  );
  try {
    // Exclusive create for both fresh and staging paths; never follows a
    // racing symlink into existence between classify and write.
    fs.writeFileSync(writePath, privatePemBuffer, { mode: 0o600, flag: "wx" });
    try {
      fs.chmodSync(writePath, 0o600);
    } catch (_err) {
      // Best-effort on win32; see ensureKeyDir.
    }
  } finally {
    // Zeroize what we can: the exported PEM bytes. The KeyObject's internal
    // OpenSSL memory and any engine-internal copies cannot be zeroized from
    // JS (documented limit, see module doc comment).
    privatePemBuffer.fill(0);
  }

  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();

  return guardReturnValue({
    keyPath,
    stagedKeyPath: writePath,
    publicKeyPem,
    algorithm,
  });
}

/**
 * Removes a staged rotation key when issuance/deploy aborts. No-op when
 * stagedKeyPath is absent or identical to the live keyPath (fresh install).
 * Never deletes the live keyPath.
 *
 * @param {object} input
 * @param {string} input.keyPath live key destination
 * @param {string} input.stagedKeyPath staging path returned by generateKeyPairToFile
 * @returns {void}
 */
function discardStagedKey({ keyPath, stagedKeyPath } = {}) {
  if (typeof stagedKeyPath !== "string" || stagedKeyPath.length === 0) return;
  if (typeof keyPath === "string" && stagedKeyPath === keyPath) return;
  try {
    fs.unlinkSync(stagedKeyPath);
  } catch (err) {
    if (err && err.code === "ENOENT") return;
    throw buildError(
      `tokentimer-agent keys: could not discard staged key at ${stagedKeyPath}: ${err.message}`,
    );
  }
}

/**
 * Computes the sha256 hex fingerprint of the public key DER (SPKI) for the
 * key stored at keyPath, for correlation/evidence purposes.
 * @param {object} input
 * @param {string} input.keyPath
 * @returns {{ fingerprintSha256: string }}
 */
function getPublicKeyFingerprint({ keyPath } = {}) {
  if (typeof keyPath !== "string" || keyPath.length === 0) {
    throw buildError("tokentimer-agent keys: keyPath must be a non-empty string");
  }

  const keyBuffer = fs.readFileSync(keyPath);
  let spkiDer;
  try {
    const privateKey = crypto.createPrivateKey(keyBuffer);
    const publicKey = crypto.createPublicKey(privateKey);
    spkiDer = publicKey.export({ type: "spki", format: "der" });
  } finally {
    keyBuffer.fill(0);
  }

  const fingerprintSha256 = crypto.createHash("sha256").update(spkiDer).digest("hex");
  return guardReturnValue({ fingerprintSha256 });
}

// ---------------------------------------------------------------------------
// Minimal ASN.1 DER encoding helpers for PKCS#10 CSR construction.
//
// Node has no built-in CSR API, so the CertificationRequest structure
// (RFC 2986) is assembled by hand from small, well-tested DER primitives.
// Only what a CSR needs is implemented: definite-length TLVs, SEQUENCE/SET,
// OID, UTF8String/PrintableString, BIT STRING, OCTET STRING, INTEGER 0,
// context tags, and BOOLEAN-free extension bodies. This is an *encoder*
// only; it never parses untrusted input.
// ---------------------------------------------------------------------------

/**
 * Encodes a DER definite length.
 * @param {number} length
 * @returns {Buffer}
 */
function derLength(length) {
  if (length < 0x80) return Buffer.from([length]);
  const bytes = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/**
 * Encodes one DER TLV.
 * @param {number} tag
 * @param {Buffer} value
 * @returns {Buffer}
 */
function derTlv(tag, value) {
  return Buffer.concat([Buffer.from([tag]), derLength(value.length), value]);
}

/** @param {Buffer[]} children @returns {Buffer} SEQUENCE (0x30) */
function derSequence(children) {
  return derTlv(0x30, Buffer.concat(children));
}

/** @param {Buffer[]} children @returns {Buffer} SET (0x31) */
function derSet(children) {
  return derTlv(0x31, Buffer.concat(children));
}

/**
 * Encodes an OBJECT IDENTIFIER from dotted-decimal notation.
 * @param {string} oid e.g. "2.5.4.3"
 * @returns {Buffer}
 */
function derOid(oid) {
  const parts = oid.split(".").map(Number);
  if (parts.length < 2 || parts.some((n) => !Number.isInteger(n) || n < 0)) {
    throw buildError(`tokentimer-agent keys: invalid OID ${JSON.stringify(oid)}`);
  }
  const bytes = [40 * parts[0] + parts[1]];
  for (const part of parts.slice(2)) {
    // Base-128 with high bit as continuation, per X.690.
    const stack = [part & 0x7f];
    let remaining = part >>> 7;
    while (remaining > 0) {
      stack.unshift((remaining & 0x7f) | 0x80);
      remaining >>>= 7;
    }
    bytes.push(...stack);
  }
  return derTlv(0x06, Buffer.from(bytes));
}

/** @param {string} value @returns {Buffer} UTF8String (0x0c) */
function derUtf8String(value) {
  return derTlv(0x0c, Buffer.from(value, "utf8"));
}

/** @param {string} value @returns {Buffer} PrintableString (0x13) */
function derPrintableString(value) {
  return derTlv(0x13, Buffer.from(value, "ascii"));
}

/**
 * BIT STRING (0x03) with zero unused bits, as used for signatures and
 * public keys in X.509 structures.
 * @param {Buffer} value
 * @returns {Buffer}
 */
function derBitString(value) {
  return derTlv(0x03, Buffer.concat([Buffer.from([0x00]), value]));
}

/** @param {Buffer} value @returns {Buffer} OCTET STRING (0x04) */
function derOctetString(value) {
  return derTlv(0x04, value);
}

/** INTEGER 0 (CSR version). @returns {Buffer} */
function derIntegerZero() {
  return Buffer.from([0x02, 0x01, 0x00]);
}

/**
 * Context-specific constructed tag [n], e.g. [0] for CSR attributes.
 * @param {number} tagNumber
 * @param {Buffer} value
 * @returns {Buffer}
 */
function derContextConstructed(tagNumber, value) {
  return derTlv(0xa0 | tagNumber, value);
}

// ---------------------------------------------------------------------------
// CSR structure building (RFC 2986 / RFC 5280)
// ---------------------------------------------------------------------------

// X.500 attribute type OIDs for the subject DN fields this module supports.
const DN_ATTRIBUTE_OIDS = Object.freeze({
  commonName: "2.5.4.3",
  organization: "2.5.4.10",
  organizationalUnit: "2.5.4.11",
  country: "2.5.4.6",
  state: "2.5.4.8",
  locality: "2.5.4.7",
});

// Fixed DN encoding order (matches conventional C, ST, L, O, OU, CN order).
const DN_FIELD_ORDER = Object.freeze([
  "country",
  "state",
  "locality",
  "organization",
  "organizationalUnit",
  "commonName",
]);

const OID_EXTENSION_REQUEST = "1.2.840.113549.1.9.14"; // pkcs-9-at-extensionRequest
const OID_SUBJECT_ALT_NAME = "2.5.29.17";
const OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
const OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11";

/**
 * Encodes one DN RelativeDistinguishedName:
 * SET { SEQUENCE { OID, string } }. country uses PrintableString per
 * RFC 5280's expectation for countryName; all other fields use UTF8String.
 * @param {string} fieldName
 * @param {string} value
 * @returns {Buffer}
 */
function derRdn(fieldName, value) {
  const oid = DN_ATTRIBUTE_OIDS[fieldName];
  const encodedValue =
    fieldName === "country" ? derPrintableString(value) : derUtf8String(value);
  return derSet([derSequence([derOid(oid), encodedValue])]);
}

/**
 * Encodes the subject Name (RDNSequence) from a plain subject object.
 * @param {{commonName: string, organization?: string, organizationalUnit?: string, country?: string, state?: string, locality?: string}} subject
 * @returns {Buffer}
 */
function derSubjectName(subject) {
  if (subject === null || typeof subject !== "object" || Array.isArray(subject)) {
    throw buildError("tokentimer-agent keys: subject must be an object with a commonName");
  }
  if (typeof subject.commonName !== "string" || subject.commonName.length === 0) {
    throw buildError("tokentimer-agent keys: subject.commonName must be a non-empty string");
  }
  if (subject.country !== undefined) {
    if (typeof subject.country !== "string" || !/^[A-Z]{2}$/.test(subject.country)) {
      throw buildError(
        "tokentimer-agent keys: subject.country must be a 2-letter uppercase ISO 3166 code",
      );
    }
  }

  const rdns = [];
  for (const fieldName of DN_FIELD_ORDER) {
    const value = subject[fieldName];
    if (value === undefined || value === null) continue;
    if (typeof value !== "string" || value.length === 0) {
      throw buildError(
        `tokentimer-agent keys: subject.${fieldName} must be a non-empty string`,
      );
    }
    rdns.push(derRdn(fieldName, value));
  }
  return derSequence(rdns);
}

/**
 * Encodes a subjectAltName extension value: SEQUENCE of GeneralName
 * dNSName ([2] IMPLICIT IA5String) entries.
 * @param {string[]} altNames
 * @returns {Buffer} the SAN extension inner value (not yet OCTET STRING wrapped)
 */
function derSubjectAltNameValue(altNames) {
  const generalNames = altNames.map((name) =>
    // GeneralName dNSName is context tag [2], primitive (0x82), IA5String body.
    derTlv(0x82, Buffer.from(name, "ascii")),
  );
  return derSequence(generalNames);
}

/**
 * Encodes the CSR attributes [0] block containing an extensionRequest with
 * a subjectAltName extension. When altNames is empty, returns an empty
 * attributes block ([0] with zero length), which RFC 2986 permits.
 * @param {string[]} altNames
 * @returns {Buffer}
 */
function derCsrAttributes(altNames) {
  if (altNames.length === 0) {
    return derContextConstructed(0, Buffer.alloc(0));
  }

  const sanExtension = derSequence([
    derOid(OID_SUBJECT_ALT_NAME),
    derOctetString(derSubjectAltNameValue(altNames)),
  ]);
  const extensions = derSequence([sanExtension]);
  const extensionRequestAttribute = derSequence([
    derOid(OID_EXTENSION_REQUEST),
    derSet([extensions]),
  ]);
  return derContextConstructed(0, extensionRequestAttribute);
}

/**
 * Returns the DER-encoded AlgorithmIdentifier and node:crypto sign options
 * for a private KeyObject's type. Ed25519 CSRs are intentionally not
 * supported (documented deviation): a hand-rolled Ed25519 CSR would add a
 * third signature path for a curve no target CA in scope currently issues
 * against, so it throws a clear error instead.
 * @param {crypto.KeyObject} privateKey
 * @returns {{ signatureAlgorithm: Buffer, signOptions: object|null, hash: string|null }}
 */
function resolveSignatureAlgorithm(privateKey) {
  const keyType = privateKey.asymmetricKeyType;
  if (keyType === "ec") {
    // ecdsa-with-SHA256; parameters MUST be absent for ECDSA.
    return {
      signatureAlgorithm: derSequence([derOid(OID_ECDSA_WITH_SHA256)]),
      hash: "sha256",
    };
  }
  if (keyType === "rsa") {
    // sha256WithRSAEncryption; parameters are explicit NULL for RSA.
    return {
      signatureAlgorithm: derSequence([
        derOid(OID_SHA256_WITH_RSA),
        Buffer.from([0x05, 0x00]),
      ]),
      hash: "sha256",
    };
  }
  if (keyType === "ed25519") {
    throw buildError(
      "tokentimer-agent keys: Ed25519 CSR generation is not supported " +
        "(documented deviation; generate the key as ec-p256 or rsa-* when a CSR is needed)",
    );
  }
  throw buildError(
    `tokentimer-agent keys: unsupported private key type ${JSON.stringify(keyType)} for CSR signing`,
  );
}

/**
 * Wraps DER bytes in a PEM envelope with the given label.
 * @param {Buffer} der
 * @param {string} label e.g. "CERTIFICATE REQUEST"
 * @returns {string}
 */
function derToPem(der, label) {
  const base64 = der.toString("base64");
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/**
 * Builds a PKCS#10 CSR signed with the private key stored at keyPath.
 *
 * The private key is read from disk only inside this function, used for a
 * single sign operation, and never cached; the read buffer is zeroized
 * after the KeyObject is created (KeyObject internals cannot be zeroized
 * from JS, see module doc comment).
 *
 * Supported signature algorithms: ECDSA-with-SHA256 (EC P-256 keys) and
 * sha256WithRSAEncryption (RSA keys). Ed25519 throws a clear "not
 * supported" error (documented deviation).
 *
 * @param {object} input
 * @param {string} input.keyPath path to the PKCS#8 private key PEM on disk
 * @param {{commonName: string, organization?: string, organizationalUnit?: string, country?: string, state?: string, locality?: string}} input.subject
 * @param {string[]} [input.altNames] dNSName SAN entries
 * @returns {{ csrPem: string, publicKeyPem: string }}
 */
function generateCsr({ keyPath, subject, altNames = [] } = {}) {
  if (typeof keyPath !== "string" || keyPath.length === 0) {
    throw buildError("tokentimer-agent keys: keyPath must be a non-empty string");
  }
  if (!Array.isArray(altNames) || !altNames.every((n) => typeof n === "string" && n.length > 0)) {
    throw buildError("tokentimer-agent keys: altNames must be an array of non-empty strings");
  }

  const subjectName = derSubjectName(subject);

  const keyBuffer = fs.readFileSync(keyPath);
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(keyBuffer);
  } finally {
    keyBuffer.fill(0);
  }

  const publicKey = crypto.createPublicKey(privateKey);
  const spkiDer = publicKey.export({ type: "spki", format: "der" });
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();

  const { signatureAlgorithm, hash } = resolveSignatureAlgorithm(privateKey);

  // CertificationRequestInfo ::= SEQUENCE {
  //   version INTEGER 0, subject Name, subjectPKInfo SPKI,
  //   attributes [0] IMPLICIT Attributes }
  const certificationRequestInfo = derSequence([
    derIntegerZero(),
    subjectName,
    spkiDer,
    derCsrAttributes(altNames),
  ]);

  // ECDSA signatures from crypto.sign default to DER format, which is what
  // X.509 structures require. RSA PKCS#1 v1.5 is the default padding.
  const signature = crypto.sign(hash, certificationRequestInfo, privateKey);

  const certificationRequest = derSequence([
    certificationRequestInfo,
    signatureAlgorithm,
    derBitString(signature),
  ]);

  const csrPem = derToPem(certificationRequest, "CERTIFICATE REQUEST");
  return guardReturnValue({ csrPem, publicKeyPem });
}

module.exports = {
  SUPPORTED_ALGORITHM_NAMES,
  generateKeyPairToFile,
  discardStagedKey,
  generateCsr,
  getPublicKeyFingerprint,
};
