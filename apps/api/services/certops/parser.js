"use strict";

const { createHash, X509Certificate } = require("crypto");
const {
  containsPrivateKeyMaterial,
} = require("../../utils/secretMaterial");
const {
  CertOpsIdentitySafetyError,
  assertSafeDnsIdentity,
  assertSafeIpIdentity,
  assertSafeNonDnsIdentity,
} = require("./identitySafety");

const PRIVATE_KEY_MATERIAL_REJECTED = "PRIVATE_KEY_MATERIAL_REJECTED";
const CERTOPS_CERTIFICATE_PARSE_FAILED = "CERTOPS_CERTIFICATE_PARSE_FAILED";
// Certificate chains are public metadata, but they still need a hard bound at
// the shared parser boundary. This matches the existing CertOps evidence
// payload ceiling and is deliberately independent of Kubernetes Secret limits.
const MAX_PUBLIC_CERTIFICATE_INPUT_BYTES = 64 * 1024;
const CERTOPS_CERTIFICATE_TOO_LARGE = "CERTOPS_CERTIFICATE_TOO_LARGE";

const CERTIFICATE_PEM_BLOCK_PATTERN =
  /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

class CertOpsCertificateParserError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "CertOpsCertificateParserError";
    this.code = code;
  }
}

function createParserError(message, code) {
  return new CertOpsCertificateParserError(message, code);
}

function rejectPrivateKeyMaterial(value) {
  if (!containsPrivateKeyMaterial(value)) return;
  throw createParserError(
    "Private key material is not accepted by CertOps certificate parsing",
    PRIVATE_KEY_MATERIAL_REJECTED,
  );
}

function publicCertificateInputSize(value) {
  if (typeof value === "string") return Buffer.byteLength(value, "utf8");
  if (Buffer.isBuffer(value)) return value.length;
  if (value instanceof Uint8Array) return value.byteLength;
  return null;
}

function assertBoundedPublicCertificateInput(value) {
  const size = publicCertificateInputSize(value);
  if (size === null || size === 0) {
    throw createParserError(
      "Certificate input must be a non-empty PEM string or DER byte sequence",
      CERTOPS_CERTIFICATE_PARSE_FAILED,
    );
  }
  if (size > MAX_PUBLIC_CERTIFICATE_INPUT_BYTES) {
    throw createParserError(
      "Certificate input exceeds the public certificate size limit",
      CERTOPS_CERTIFICATE_TOO_LARGE,
    );
  }
}

function normalizePublicCertificateInput(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  return value;
}

function normalizePemBlock(pemBlock) {
  const body = pemBlock
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  const lines = body.match(/.{1,64}/g) || [];
  return [
    "-----BEGIN CERTIFICATE-----",
    ...lines,
    "-----END CERTIFICATE-----",
  ].join("\n");
}

function extractCertificatePemBlocks(input) {
  if (typeof input !== "string") {
    throw createParserError(
      "Certificate input must be a PEM string",
      CERTOPS_CERTIFICATE_PARSE_FAILED,
    );
  }

  const matches = [...input.matchAll(CERTIFICATE_PEM_BLOCK_PATTERN)];
  if (matches.length === 0) {
    throw createParserError(
      "Certificate input must contain at least one PEM certificate block",
      CERTOPS_CERTIFICATE_PARSE_FAILED,
    );
  }

  const remainder = input.replace(CERTIFICATE_PEM_BLOCK_PATTERN, "");
  if (remainder.trim().length > 0) {
    throw createParserError(
      "Certificate input contains unsupported PEM or non-certificate content",
      CERTOPS_CERTIFICATE_PARSE_FAILED,
    );
  }

  return matches.map((match) => normalizePemBlock(match[0]));
}

function normalizeFingerprint(value) {
  if (!value) return null;
  return String(value).replace(/:/g, "").toLowerCase();
}

function hashHex(algorithm, value) {
  return createHash(algorithm).update(value).digest("hex");
}

function dateToIso(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

function normalizeDistinguishedName(value) {
  if (!value) return null;
  return String(value)
    .split(/\r?\n/)
    .map((part) => part.trim())
    .filter(Boolean)
    .join(", ");
}

function extractCommonName(subject) {
  if (!subject) return null;
  const match = /(?:^|,\s*)CN\s*=\s*([^,]+)/.exec(subject);
  return match ? match[1].trim() : null;
}

function splitSubjectAltName(subjectAltName) {
  if (!subjectAltName) return [];
  return String(subjectAltName)
    .split(/,\s*(?=(?:DNS|IP Address|URI|email|RID|Registered ID|DirName|othername):)/i)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function unquoteSanValue(value) {
  const trimmed = value.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function classifySanType(prefix) {
  const normalized = String(prefix || "")
    .trim()
    .toLowerCase();
  if (normalized === "dns") return "dns";
  if (normalized === "ip address" || normalized === "ip") return "ip";
  if (normalized === "uri") return "uri";
  if (normalized === "email") return "email";
  return "other";
}

function wrapIdentitySafetyError(error) {
  if (error instanceof CertOpsIdentitySafetyError) {
    return createParserError(error.message, CERTOPS_CERTIFICATE_PARSE_FAILED);
  }
  return error;
}

function assertSafeSanEntry(entry) {
  try {
    switch (entry.type) {
      case "dns":
        assertSafeDnsIdentity(entry.value, { field: "DNS SAN" });
        break;
      case "ip":
        assertSafeIpIdentity(entry.value, { field: "IP SAN" });
        break;
      case "uri":
        assertSafeNonDnsIdentity(entry.value, { field: "URI SAN" });
        break;
      case "email":
        assertSafeNonDnsIdentity(entry.value, { field: "email SAN" });
        break;
      default:
        assertSafeNonDnsIdentity(entry.value, { field: "SAN" });
        break;
    }
  } catch (error) {
    throw wrapIdentitySafetyError(error);
  }
}

/**
 * Typed SAN parse: keeps DNS / IP / URI / email distinct so DNS mixed-script
 * rules are not applied to IP addresses. Unsafe DNS values fail closed.
 */
function parseTypedSubjectAltNames(subjectAltName) {
  return splitSubjectAltName(subjectAltName).map((entry) => {
    const match = /^([^:]+):(.+)$/.exec(entry);
    if (!match) {
      const parsed = { type: "other", value: entry, prefix: null };
      assertSafeSanEntry(parsed);
      return parsed;
    }

    const prefix = match[1].trim();
    const parsed = {
      type: classifySanType(prefix),
      value: unquoteSanValue(match[2]),
      prefix,
    };
    assertSafeSanEntry(parsed);
    return parsed;
  });
}

/**
 * Backward-compatible flat string[] of SAN values (DNS, IP, URI, email, ...).
 * Inventory still consumes this shape; typed detail is on subjectAltNameEntries.
 */
function parseSubjectAltNames(subjectAltName) {
  return parseTypedSubjectAltNames(subjectAltName).map((entry) => entry.value);
}

function assertSafeCommonName(commonName) {
  if (commonName === null || commonName === undefined || commonName === "") {
    return commonName;
  }
  try {
    assertSafeDnsIdentity(commonName, { field: "commonName" });
  } catch (error) {
    throw wrapIdentitySafetyError(error);
  }
  return commonName;
}

function publicKeyMetadata(publicKey) {
  if (!publicKey) return {};
  const details = publicKey.asymmetricKeyDetails || {};
  const metadata = {
    asymmetricKeyType: publicKey.asymmetricKeyType || null,
    modulusLength: details.modulusLength || null,
    publicExponent: details.publicExponent
      ? String(details.publicExponent)
      : null,
    namedCurve: details.namedCurve || null,
  };

  return Object.fromEntries(
    Object.entries(metadata).filter(([_key, value]) => value !== null),
  );
}

function publicKeySize(publicKey) {
  if (!publicKey?.asymmetricKeyDetails) return null;
  return publicKey.asymmetricKeyDetails.modulusLength || null;
}

function spkiFingerprintSha256(publicKey) {
  if (!publicKey) return null;
  try {
    const spkiDer = publicKey.export({ type: "spki", format: "der" });
    return hashHex("sha256", spkiDer);
  } catch (_err) {
    return null;
  }
}

function certificatePemFromRaw(raw) {
  const body = Buffer.from(raw).toString("base64");
  const lines = body.match(/.{1,64}/g) || [];
  return [
    "-----BEGIN CERTIFICATE-----",
    ...lines,
    "-----END CERTIFICATE-----",
  ].join("\n");
}

function parseCertificateBlock(certificateInput, index) {
  let certificate;
  try {
    certificate = new X509Certificate(certificateInput);
  } catch (_err) {
    throw createParserError(
      `Certificate input ${index + 1} is malformed`,
      CERTOPS_CERTIFICATE_PARSE_FAILED,
    );
  }

  const certificatePem = certificatePemFromRaw(certificate.raw);

  const subject = normalizeDistinguishedName(certificate.subject);
  const issuer = normalizeDistinguishedName(certificate.issuer);
  const validFrom = dateToIso(certificate.validFromDate || certificate.validFrom);
  const validTo = dateToIso(certificate.validToDate || certificate.validTo);
  const fingerprint256 =
    normalizeFingerprint(certificate.fingerprint256) ||
    hashHex("sha256", certificate.raw);
  const fingerprint512 =
    normalizeFingerprint(certificate.fingerprint512) ||
    hashHex("sha512", certificate.raw);
  const commonName = assertSafeCommonName(extractCommonName(subject));
  const subjectAltNameEntries = parseTypedSubjectAltNames(
    certificate.subjectAltName,
  );

  return {
    subject,
    issuer,
    serialNumber: certificate.serialNumber || null,
    commonName,
    validFrom,
    validTo,
    notBefore: validFrom,
    notAfter: validTo,
    subjectAltName: certificate.subjectAltName || null,
    subjectAltNames: subjectAltNameEntries.map((entry) => entry.value),
    subjectAltNameEntries,
    fingerprint256,
    fingerprint512,
    fingerprintSha256: fingerprint256,
    spkiFingerprintSha256: spkiFingerprintSha256(certificate.publicKey),
    publicKeyAlgorithm: certificate.publicKey?.asymmetricKeyType || null,
    publicKeySize: publicKeySize(certificate.publicKey),
    publicKeyMetadata: publicKeyMetadata(certificate.publicKey),
    signatureAlgorithm: certificate.signatureAlgorithm || null,
    signatureAlgorithmOid: certificate.signatureAlgorithmOid || null,
    certificatePem,
  };
}

function parseExactDerCertificate(der) {
  let certificate;
  try {
    certificate = new X509Certificate(der);
  } catch (_err) {
    throw createParserError(
      "Certificate input 1 is malformed",
      CERTOPS_CERTIFICATE_PARSE_FAILED,
    );
  }
  // X509Certificate accepts a certificate prefix. Require byte-for-byte
  // identity so trailing data, concatenated certificates, and containers
  // cannot be accepted as a single public certificate.
  if (!certificate.raw.equals(der)) {
    throw createParserError(
      "DER certificate input contains trailing or bundled material",
      CERTOPS_CERTIFICATE_PARSE_FAILED,
    );
  }
  return parseCertificateBlock(der, 0);
}

function isAsciiPemInput(value) {
  for (const byte of value) {
    if (
      byte !== 0x09 &&
      byte !== 0x0a &&
      byte !== 0x0d &&
      (byte < 0x20 || byte > 0x7e)
    ) {
      return false;
    }
  }
  return true;
}

function parsePublicCertificateMaterial(input) {
  assertBoundedPublicCertificateInput(input);
  // The detector classifies binary material only when it receives a Buffer.
  // Normalize bounded Uint8Array views first so every accepted binary input
  // gets the same private-key, PFX, and JKS checks before parsing.
  const normalizedInput = normalizePublicCertificateInput(input);
  rejectPrivateKeyMaterial(normalizedInput);
  if (Buffer.isBuffer(normalizedInput)) {
    const der = normalizedInput;
    // Kubernetes tls.crt values are commonly base64-encoded PEM bytes. Decode
    // those bytes only after proving they are ASCII text; arbitrary binary is
    // never coerced to UTF-8 and remains subject to exact DER validation.
    if (isAsciiPemInput(der)) {
      const pemBlocks = extractCertificatePemBlocks(der.toString("ascii"));
      return pemBlocks.map(parseCertificateBlock);
    }
    return [parseExactDerCertificate(der)];
  }
  const pemBlocks = extractCertificatePemBlocks(normalizedInput);
  return pemBlocks.map(parseCertificateBlock);
}

module.exports = {
  PRIVATE_KEY_MATERIAL_REJECTED,
  CERTOPS_CERTIFICATE_PARSE_FAILED,
  CERTOPS_CERTIFICATE_TOO_LARGE,
  MAX_PUBLIC_CERTIFICATE_INPUT_BYTES,
  CertOpsCertificateParserError,
  classifySanType,
  parsePublicCertificateMaterial,
  parseSubjectAltNames,
  parseTypedSubjectAltNames,
};
