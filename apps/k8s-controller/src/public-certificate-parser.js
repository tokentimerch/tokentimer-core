"use strict";

const { scrubLogString } = require("@tokentimer/log-scrub");
const {
  parsePublicCertificateMaterial: parseCanonicalPublicCertificateMaterial,
} = require("../../api/services/certops/parser");
const {
  MAX_PUBLIC_PEM_BYTES,
  MAX_PUBLIC_SAN_ENTRIES,
  MAX_PUBLIC_SAN_LENGTH,
  MAX_PUBLIC_TEXT_LENGTH,
} = require("../../api/services/certops/controllerObservationLimits");

const MAX_CERTIFICATE_PEM_LENGTH = MAX_PUBLIC_PEM_BYTES;
const MAX_CERTIFICATE_TEXT_LENGTH = MAX_PUBLIC_TEXT_LENGTH;
const MAX_SUBJECT_ALT_NAME_LENGTH = MAX_PUBLIC_SAN_LENGTH;
const MAX_SUBJECT_ALT_NAMES = MAX_PUBLIC_SAN_ENTRIES;

function boundedText(value, maximumLength = MAX_CERTIFICATE_TEXT_LENGTH) {
  if (typeof value !== "string" && typeof value !== "number") return undefined;
  const scrubbed = scrubLogString(String(value).trim());
  if (
    typeof scrubbed !== "string" ||
    scrubbed === "" ||
    scrubbed.length > maximumLength
  ) {
    return undefined;
  }
  return scrubbed;
}

function boundedSubjectAltNames(value) {
  if (!Array.isArray(value)) return [];
  const names = new Set();
  for (const item of value) {
    const name = boundedText(item, MAX_SUBJECT_ALT_NAME_LENGTH);
    if (!name || names.has(name)) continue;
    names.add(name);
    if (names.size === MAX_SUBJECT_ALT_NAMES) break;
  }
  return [...names].sort();
}

function boundedCertificatePem(value) {
  if (typeof value !== "string" || value === "") return undefined;
  return Buffer.byteLength(value, "utf8") <= MAX_CERTIFICATE_PEM_LENGTH
    ? value
    : undefined;
}

/**
 * Converts the canonical parser's leaf result into the frozen controller
 * observation allowlist. The parser receives the complete PEM chain or exact
 * DER certificate; only its first certificate becomes public observation data.
 */
function parsePublicCertificateObservation(
  input,
  { parsePublicCertificateMaterial = parseCanonicalPublicCertificateMaterial } = {},
) {
  const certificates = parsePublicCertificateMaterial(input);
  const leaf = certificates[0];
  if (!leaf || typeof leaf !== "object") {
    const error = new Error("No public leaf certificate was parsed");
    error.code = "CERTOPS_CERTIFICATE_PARSE_FAILED";
    throw error;
  }

  const fingerprintSha256 = boundedText(leaf.fingerprintSha256, 128);
  if (!fingerprintSha256) {
    const error = new Error("Public certificate fingerprint is unavailable");
    error.code = "CERTOPS_CERTIFICATE_PARSE_FAILED";
    throw error;
  }

  const publicCertificate = { fingerprintSha256 };
  const serialNumber = boundedText(leaf.serialNumber);
  const subject = boundedText(leaf.subject);
  const issuer = boundedText(leaf.issuer);
  const subjectAltNames = boundedSubjectAltNames(leaf.subjectAltNames);
  const publicKeyAlgorithm = boundedText(leaf.publicKeyAlgorithm);
  const publicKeySize = Number.isSafeInteger(leaf.publicKeySize)
    ? leaf.publicKeySize
    : undefined;
  const signatureAlgorithm = boundedText(leaf.signatureAlgorithm);
  const certificatePem = boundedCertificatePem(leaf.certificatePem);

  if (serialNumber) publicCertificate.serialNumber = serialNumber;
  if (subject) publicCertificate.subject = subject;
  if (issuer) publicCertificate.issuer = issuer;
  if (subjectAltNames.length > 0) publicCertificate.subjectAltNames = subjectAltNames;
  if (publicKeyAlgorithm) publicCertificate.publicKeyAlgorithm = publicKeyAlgorithm;
  if (publicKeySize !== undefined) publicCertificate.publicKeySize = publicKeySize;
  if (signatureAlgorithm) publicCertificate.signatureAlgorithm = signatureAlgorithm;
  if (certificatePem) publicCertificate.certificatePem = certificatePem;

  return {
    notAfter: boundedText(leaf.notAfter, 64),
    notBefore: boundedText(leaf.notBefore, 64),
    publicCertificate,
  };
}

module.exports = {
  MAX_CERTIFICATE_PEM_LENGTH,
  MAX_CERTIFICATE_TEXT_LENGTH,
  MAX_SUBJECT_ALT_NAME_LENGTH,
  MAX_SUBJECT_ALT_NAMES,
  boundedCertificatePem,
  boundedSubjectAltNames,
  boundedText,
  parsePublicCertificateObservation,
};
