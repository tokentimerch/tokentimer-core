"use strict";

const { scrubLogString } = require("@tokentimer/log-scrub");
const {
  parsePublicCertificateMaterial: parseCanonicalPublicCertificateMaterial,
} = require("../../api/services/certops/parser");

const MAX_CERTIFICATE_PEM_LENGTH = 96 * 1024;
const MAX_CERTIFICATE_TEXT_LENGTH = 2_048;
const MAX_SUBJECT_ALT_NAMES = 64;

function boundedText(value, maximumLength = MAX_CERTIFICATE_TEXT_LENGTH) {
  if (typeof value !== "string" && typeof value !== "number") return undefined;
  const scrubbed = scrubLogString(String(value).trim());
  if (typeof scrubbed !== "string" || scrubbed === "") return undefined;
  return scrubbed.slice(0, maximumLength);
}

function boundedSubjectAltNames(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(
    value
      .slice(0, MAX_SUBJECT_ALT_NAMES)
      .map((item) => boundedText(item))
      .filter(Boolean),
  )].sort();
}

/**
 * Converts the canonical parser's leaf result into the frozen controller
 * observation allowlist. The parser receives the complete PEM chain or exact
 * DER certificate; only its first certificate becomes public observation data.
 */
function parsePublicCertificateObservation(input) {
  const certificates = parseCanonicalPublicCertificateMaterial(input);
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
  const serialNumber = boundedText(leaf.serialNumber, 256);
  const subject = boundedText(leaf.subject);
  const issuer = boundedText(leaf.issuer);
  const subjectAltNames = boundedSubjectAltNames(leaf.subjectAltNames);
  const publicKeyAlgorithm = boundedText(leaf.publicKeyAlgorithm, 128);
  const publicKeySize = Number.isSafeInteger(leaf.publicKeySize)
    ? leaf.publicKeySize
    : undefined;
  const signatureAlgorithm = boundedText(leaf.signatureAlgorithm, 256);
  const certificatePem = boundedText(leaf.certificatePem, MAX_CERTIFICATE_PEM_LENGTH);

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
  MAX_SUBJECT_ALT_NAMES,
  parsePublicCertificateObservation,
};
