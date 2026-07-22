"use strict";

const { containsPrivateKeyMaterial } = require("@tokentimer/log-scrub");
const {
  parsePublicCertificateObservation,
} = require("./public-certificate-parser");

// The decoded ceiling reuses CertOps' established 64 KiB bounded public-output
// limit. The larger encoded cap is checked first and permits base64 overhead
// for a maximum-size certificate without relying on Kubernetes' Secret limit.
const MAX_DECODED_TLS_CRT_BYTES = 64 * 1024;
const MAX_ENCODED_TLS_CRT_BYTES = 128 * 1024;

const SAFE_FALLBACK_CODES = new Set([
  "CERTOPS_TLS_CRT_READ_FAILED",
  "CERTOPS_TLS_CRT_INVALID_BASE64",
  "CERTOPS_TLS_CRT_MISSING",
  "CERTOPS_TLS_CRT_TOO_LARGE",
  "PRIVATE_KEY_MATERIAL_REJECTED",
  "CERTOPS_CERTIFICATE_PARSE_FAILED",
]);

function fallbackError(code) {
  const error = new Error(`Certificate fallback failed: ${code}`);
  error.code = code;
  return error;
}

function decodeTlsCertificateData(encoded) {
  if (typeof encoded !== "string" || encoded.length === 0) {
    throw fallbackError("CERTOPS_TLS_CRT_MISSING");
  }
  if (encoded.length > MAX_ENCODED_TLS_CRT_BYTES) {
    throw fallbackError("CERTOPS_TLS_CRT_TOO_LARGE");
  }
  if (
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      encoded,
    )
  ) {
    throw fallbackError("CERTOPS_TLS_CRT_INVALID_BASE64");
  }

  const decoded = Buffer.from(encoded, "base64");
  if (decoded.length === 0) throw fallbackError("CERTOPS_TLS_CRT_MISSING");
  if (decoded.length > MAX_DECODED_TLS_CRT_BYTES) {
    throw fallbackError("CERTOPS_TLS_CRT_TOO_LARGE");
  }
  // Buffer accepts a few permissive base64 forms; require the canonical form
  // Kubernetes writes so no alternate or partially-decoded input is accepted.
  if (decoded.toString("base64") !== encoded) {
    throw fallbackError("CERTOPS_TLS_CRT_INVALID_BASE64");
  }
  return decoded;
}

function hasUsablePublicFingerprint(observation) {
  return typeof observation?.publicCertificate?.fingerprintSha256 === "string" &&
    /^[a-f0-9]{64}$/i.test(observation.publicCertificate.fingerprintSha256);
}

function requiredSecretName(observation) {
  return typeof observation?.secretName === "string" &&
    observation.secretName.trim() !== ""
    ? observation.secretName
    : null;
}

function allowlistedPublicCertificate(value) {
  if (!value || typeof value !== "object") {
    throw fallbackError("CERTOPS_CERTIFICATE_PARSE_FAILED");
  }
  const fingerprintSha256 = value.fingerprintSha256;
  if (typeof fingerprintSha256 !== "string" || fingerprintSha256 === "") {
    throw fallbackError("CERTOPS_CERTIFICATE_PARSE_FAILED");
  }
  const result = { fingerprintSha256 };
  if (typeof value.serialNumber === "string") result.serialNumber = value.serialNumber;
  if (typeof value.subject === "string") result.subject = value.subject;
  if (typeof value.issuer === "string") result.issuer = value.issuer;
  if (Array.isArray(value.subjectAltNames)) result.subjectAltNames = value.subjectAltNames;
  if (typeof value.publicKeyAlgorithm === "string") {
    result.publicKeyAlgorithm = value.publicKeyAlgorithm;
  }
  if (Number.isSafeInteger(value.publicKeySize)) {
    result.publicKeySize = value.publicKeySize;
  }
  if (typeof value.signatureAlgorithm === "string") {
    result.signatureAlgorithm = value.signatureAlgorithm;
  }
  if (typeof value.certificatePem === "string") result.certificatePem = value.certificatePem;
  return result;
}

function fallbackErrorCode(error) {
  if (error?.code === "CERTOPS_CERTIFICATE_TOO_LARGE") {
    return "CERTOPS_TLS_CRT_TOO_LARGE";
  }
  return SAFE_FALLBACK_CODES.has(error?.code)
    ? error.code
    : "CERTOPS_CERTIFICATE_PARSE_FAILED";
}

function isRecoverableError(error) {
  return SAFE_FALLBACK_CODES.has(error?.code);
}

function createTlsCertificateFallback({
  containsPrivateKeyMaterial: detectPrivateKeyMaterial = containsPrivateKeyMaterial,
  enabled = false,
  kubernetesClient,
  parsePublicCertificateMaterial = parsePublicCertificateObservation,
} = {}) {
  if (enabled && typeof kubernetesClient?.readTlsCertificate !== "function") {
    throw new TypeError("A narrow TLS certificate reader is required when fallback is enabled");
  }
  if (typeof parsePublicCertificateMaterial !== "function") {
    throw new TypeError("parsePublicCertificateMaterial must be a function");
  }
  if (typeof detectPrivateKeyMaterial !== "function") {
    throw new TypeError("containsPrivateKeyMaterial must be a function");
  }

  async function enrichObservation(observation) {
    if (!enabled || !observation?.ready || hasUsablePublicFingerprint(observation)) {
      return observation;
    }

    const secretName = requiredSecretName(observation);
    if (!secretName) throw fallbackError("CERTOPS_TLS_CRT_MISSING");

    let encoded;
    try {
      encoded = await kubernetesClient.readTlsCertificate({
        namespace: observation.namespace,
        secretName,
      });
    } catch (_error) {
      throw fallbackError("CERTOPS_TLS_CRT_READ_FAILED");
    }

    const decoded = decodeTlsCertificateData(encoded);
    if (detectPrivateKeyMaterial(decoded)) {
      throw fallbackError("PRIVATE_KEY_MATERIAL_REJECTED");
    }

    let parsed;
    try {
      parsed = parsePublicCertificateMaterial(decoded);
    } catch (error) {
      throw fallbackError(fallbackErrorCode(error));
    }
    if (detectPrivateKeyMaterial(parsed)) {
      throw fallbackError("PRIVATE_KEY_MATERIAL_REJECTED");
    }

    const enriched = {
      ...observation,
      publicCertificate: allowlistedPublicCertificate(parsed?.publicCertificate),
    };
    if (!Object.hasOwn(enriched, "notBefore") && typeof parsed?.notBefore === "string") {
      enriched.notBefore = parsed.notBefore;
    }
    if (!Object.hasOwn(enriched, "notAfter") && typeof parsed?.notAfter === "string") {
      enriched.notAfter = parsed.notAfter;
    }
    return enriched;
  }

  return Object.freeze({
    enrichObservation,
    isEnabled: () => enabled,
    isRecoverableError,
  });
}

module.exports = {
  MAX_DECODED_TLS_CRT_BYTES,
  MAX_ENCODED_TLS_CRT_BYTES,
  allowlistedPublicCertificate,
  createTlsCertificateFallback,
  decodeTlsCertificateData,
  hasUsablePublicFingerprint,
  isRecoverableError,
};
