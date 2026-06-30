"use strict";

const { createHash, X509Certificate } = require("crypto");
const {
  containsPrivateKeyMaterial,
} = require("../../utils/secretMaterial");

const PRIVATE_KEY_MATERIAL_REJECTED = "PRIVATE_KEY_MATERIAL_REJECTED";
const CERTOPS_CERTIFICATE_PARSE_FAILED = "CERTOPS_CERTIFICATE_PARSE_FAILED";

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

function parseSubjectAltNames(subjectAltName) {
  return splitSubjectAltName(subjectAltName).map((entry) => {
    const match = /^([^:]+):(.+)$/.exec(entry);
    if (!match) return entry;
    return unquoteSanValue(match[2]);
  });
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

function parseCertificateBlock(certificatePem, index) {
  let certificate;
  try {
    certificate = new X509Certificate(certificatePem);
  } catch (_err) {
    throw createParserError(
      `Certificate PEM block ${index + 1} is malformed`,
      CERTOPS_CERTIFICATE_PARSE_FAILED,
    );
  }

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

  return {
    subject,
    issuer,
    serialNumber: certificate.serialNumber || null,
    commonName: extractCommonName(subject),
    validFrom,
    validTo,
    notBefore: validFrom,
    notAfter: validTo,
    subjectAltName: certificate.subjectAltName || null,
    subjectAltNames: parseSubjectAltNames(certificate.subjectAltName),
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

function parsePublicCertificateMaterial(input) {
  rejectPrivateKeyMaterial(input);
  const pemBlocks = extractCertificatePemBlocks(input);
  return pemBlocks.map(parseCertificateBlock);
}

module.exports = {
  PRIVATE_KEY_MATERIAL_REJECTED,
  CERTOPS_CERTIFICATE_PARSE_FAILED,
  CertOpsCertificateParserError,
  parsePublicCertificateMaterial,
};
