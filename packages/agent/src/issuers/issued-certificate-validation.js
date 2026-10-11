"use strict";

/**
 * Issuer-agnostic issued-certificate validation (ADR-0014 decision 6).
 * Runs before certreq -accept. Leaf checks are portable; chain/revocation
 * go through an injectable Windows CryptoAPI helper.
 */

const crypto = require("node:crypto");
const { X509Certificate } = require("node:crypto");

const {
  OID_SERVER_AUTH,
  readKeyUsageNames,
  readExtKeyUsageOids,
  readCertificateTemplateOid,
  extractSpkiFromCsr,
  extractSpkiFromCertificate,
  pemToDer,
} = require("./der-extensions");

const CLOCK_SKEW_FUTURE_MS = 300_000;

/**
 * @param {string} name
 * @param {string[]} authorizedDnsNames
 */
function dnsNameAuthorized(name, authorizedDnsNames) {
  const needle = String(name).toLowerCase();
  for (const allowed of authorizedDnsNames) {
    const rule = String(allowed).toLowerCase();
    if (rule === needle) return true;
    if (rule.startsWith("*.")) {
      const suffix = rule.slice(1); // ".example.com"
      if (needle.endsWith(suffix) && needle.length > suffix.length) {
        const label = needle.slice(0, needle.length - suffix.length);
        if (label.length > 0 && !label.includes(".")) return true;
      }
    }
  }
  return false;
}

function parseSubjectCn(subject) {
  if (typeof subject !== "string" || subject.length === 0) return null;
  // Node joins DN with \n; CN may appear as "CN=foo" among attributes.
  const match = /(?:^|\n)CN\s*=\s*([^\n]+)/i.exec(subject);
  if (!match) return null;
  return match[1].trim();
}

function parseDnsSans(subjectAltName) {
  if (typeof subjectAltName !== "string" || subjectAltName.length === 0) return [];
  const names = [];
  for (const part of subjectAltName.split(",")) {
    const trimmed = part.trim();
    const match = /^DNS:\s*(.+)$/i.exec(trimmed);
    if (match) names.push(match[1].trim());
  }
  return names;
}

function spkiSha256Hex(spkiDer) {
  return crypto.createHash("sha256").update(spkiDer).digest("hex");
}

function normalizeSerialHex(serial) {
  return String(serial || "")
    .replace(/:/g, "")
    .toLowerCase();
}

/**
 * Leaf + (optional) chain validation before accept.
 *
 * @param {object} params
 * @param {string} params.certificatePem
 * @param {string} [params.csrPem]
 * @param {string} [params.csrSpkiSha256] alternative to csrPem
 * @param {string[]} params.authorizedDnsNames
 * @param {string} params.requiredDnsName IIS binding hostname / target.reference
 * @param {string} params.templateOid msPKI-Cert-Template-OID from preflight
 * @param {string} params.caKeySha256
 * @param {number} params.minimumRemainingValidity seconds
 * @param {boolean} params.requireLaterNotAfter
 * @param {Date|string|null} [params.existingNotAfter]
 * @param {string|null} [params.existingSerialHex]
 * @param {Date} [params.now]
 * @param {string} [params.keyAlgorithm] "rsa" | "ecdsa" from snapshot
 * @param {(args: object) => Promise<object>} [params.chainValidateImpl]
 * @param {"require"|"best-effort"} [params.revocationCheck]
 * @param {string} [params.helperPath]
 * @param {string} [params.extraStorePath]
 * @param {string} [params.caCertPath]
 */
async function validateIssuedCertificate(params) {
  const {
    certificatePem,
    csrPem,
    csrSpkiSha256,
    authorizedDnsNames,
    requiredDnsName,
    templateOid,
    caKeySha256,
    minimumRemainingValidity,
    requireLaterNotAfter,
    existingNotAfter = null,
    existingSerialHex = null,
    now = new Date(),
    keyAlgorithm,
    chainValidateImpl = null,
    revocationCheck = "require",
    helperPath,
    extraStorePath,
    caCertPath,
  } = params;

  const invalid = (detail) => ({
    ok: false,
    state: "rejected_invalid",
    errorCode: "ADCS_CERTIFICATE_INVALID",
    detail,
  });
  const caKeyChanged = (detail) => ({
    ok: false,
    state: "rejected_invalid",
    errorCode: "ADCS_CA_KEY_CHANGED",
    detail,
  });

  if (typeof certificatePem !== "string" || !certificatePem.includes("BEGIN CERTIFICATE")) {
    return invalid("certificatePem must be a PEM certificate");
  }
  if (!Array.isArray(authorizedDnsNames) || authorizedDnsNames.length === 0) {
    return invalid("authorizedDnsNames must be a non-empty array");
  }
  if (typeof requiredDnsName !== "string" || requiredDnsName.length === 0) {
    return invalid("requiredDnsName is required");
  }
  if (typeof templateOid !== "string" || !/^[0-2](\.(0|[1-9][0-9]{0,9})){1,63}$/.test(templateOid)) {
    return invalid("templateOid is required (from AD CS preflight)");
  }
  if (typeof caKeySha256 !== "string" || !/^[a-f0-9]{64}$/.test(caKeySha256)) {
    return invalid("caKeySha256 must be 64 lowercase hex characters");
  }
  if (!Number.isInteger(minimumRemainingValidity) || minimumRemainingValidity < 0) {
    return invalid("minimumRemainingValidity must be an integer >= 0");
  }
  if (typeof requireLaterNotAfter !== "boolean") {
    return invalid("requireLaterNotAfter must be a boolean");
  }

  let cert;
  let certDer;
  try {
    cert = new X509Certificate(certificatePem);
    certDer = cert.raw;
  } catch (err) {
    return invalid(`certificate is not valid X.509: ${err.message}`);
  }

  let expectedSpkiHex;
  try {
    if (typeof csrSpkiSha256 === "string" && /^[a-f0-9]{64}$/.test(csrSpkiSha256)) {
      expectedSpkiHex = csrSpkiSha256;
    } else if (typeof csrPem === "string" && csrPem.includes("CERTIFICATE REQUEST")) {
      expectedSpkiHex = spkiSha256Hex(extractSpkiFromCsr(csrPem));
    } else {
      return invalid("csrPem or csrSpkiSha256 is required to bind the certificate to the request");
    }
  } catch (err) {
    return invalid(`could not read CSR public key: ${err.message}`);
  }

  let certSpkiHex;
  try {
    certSpkiHex = spkiSha256Hex(extractSpkiFromCertificate(certificatePem));
  } catch (err) {
    return invalid(`could not read certificate public key: ${err.message}`);
  }
  if (certSpkiHex !== expectedSpkiHex) {
    return invalid("certificate SubjectPublicKeyInfo does not match the journaled CSR");
  }

  const cn = parseSubjectCn(cert.subject);
  if (cn !== null && !dnsNameAuthorized(cn, authorizedDnsNames)) {
    return invalid(`subject CN ${JSON.stringify(cn)} is outside authorizedDnsNames`);
  }

  const sans = parseDnsSans(cert.subjectAltName);
  for (const san of sans) {
    if (!dnsNameAuthorized(san, authorizedDnsNames)) {
      return invalid(`SAN ${JSON.stringify(san)} is outside authorizedDnsNames`);
    }
  }

  // DNS SAN takes precedence for hostname matching (TLS name verification).
  const required = requiredDnsName.toLowerCase();
  if (sans.length > 0) {
    const sanMatch = sans.some((san) => san.toLowerCase() === required);
    if (!sanMatch) {
      return invalid(
        `required DNS name ${JSON.stringify(requiredDnsName)} is not present in DNS SAN`,
      );
    }
  } else if (cn === null || cn.toLowerCase() !== required) {
    return invalid(
      `certificate does not cover required DNS name ${JSON.stringify(requiredDnsName)}`,
    );
  }

  const eku = readExtKeyUsageOids(certDer);
  if (eku.length !== 1 || eku[0] !== OID_SERVER_AUTH) {
    return invalid("EKU must be Server Authentication only");
  }

  const keyUsage = readKeyUsageNames(certDer);
  if (keyUsage.includes("keyCertSign")) {
    return invalid("key usage must not include keyCertSign");
  }
  const algo =
    keyAlgorithm === "rsa" || keyAlgorithm === "ecdsa"
      ? keyAlgorithm
      : cert.publicKey.asymmetricKeyType === "rsa"
        ? "rsa"
        : cert.publicKey.asymmetricKeyType === "ec"
          ? "ecdsa"
          : null;
  if (algo === "rsa") {
    if (!keyUsage.includes("digitalSignature") || !keyUsage.includes("keyEncipherment")) {
      return invalid("RSA key usage must include digitalSignature and keyEncipherment");
    }
  } else if (algo === "ecdsa") {
    if (!keyUsage.includes("digitalSignature") || keyUsage.includes("keyEncipherment")) {
      return invalid("EC key usage must be digitalSignature only");
    }
  } else {
    return invalid("unsupported certificate public key algorithm");
  }

  if (cert.ca === true) {
    return invalid("certificate basicConstraints CA flag must not be set");
  }

  const nowMs = now instanceof Date ? now.getTime() : Date.parse(now);
  if (!Number.isFinite(nowMs)) return invalid("now must be a valid Date");
  const notBefore = cert.validFromDate.getTime();
  const notAfter = cert.validToDate.getTime();
  if (notBefore > nowMs + CLOCK_SKEW_FUTURE_MS) {
    return invalid("certificate notBefore is more than 300s in the future");
  }
  if (notAfter <= nowMs + minimumRemainingValidity * 1000) {
    return invalid("certificate notAfter does not satisfy minimumRemainingValidity");
  }
  // Only compare when an installed certificate was observed. First install
  // (no binding / empty store) skips requireLaterNotAfter.
  if (requireLaterNotAfter && existingNotAfter != null) {
    const existingMs =
      existingNotAfter instanceof Date
        ? existingNotAfter.getTime()
        : Date.parse(existingNotAfter);
    if (!Number.isFinite(existingMs)) {
      return invalid("existingNotAfter is not a valid date");
    }
    if (notAfter <= existingMs) {
      return invalid("certificate notAfter is not later than the installed certificate");
    }
  }
  if (existingSerialHex != null) {
    if (normalizeSerialHex(cert.serialNumber) === normalizeSerialHex(existingSerialHex)) {
      return invalid("certificate serial equals the currently installed certificate");
    }
  }

  const templateFromCert = readCertificateTemplateOid(certDer);
  if (templateFromCert == null) {
    return invalid("certificate is missing the Certificate Template Information extension");
  }
  if (templateFromCert !== templateOid) {
    return invalid(
      `certificate template OID ${templateFromCert} does not match preflight ${templateOid}`,
    );
  }

  if (typeof chainValidateImpl !== "function") {
    // Callers on the dormant path must still supply a helper (or a test stub).
    return invalid("chain validation helper is not configured");
  }

  let chainResult;
  try {
    chainResult = await chainValidateImpl({
      certificatePem,
      caKeySha256,
      revocationCheck,
      helperPath,
      extraStorePath,
      caCertPath,
    });
  } catch (err) {
    return invalid(`chain validation helper failed: ${err.message}`);
  }

  if (!chainResult || typeof chainResult !== "object") {
    return invalid("chain validation helper returned a malformed result");
  }
  if (chainResult.verdict === "valid") {
    return { ok: true, state: "validated" };
  }
  if (chainResult.verdict === "ca_key_changed") {
    return caKeyChanged(chainResult.detail || "issuing CA key does not match caKeySha256");
  }
  if (chainResult.verdict === "revocation_unknown") {
    if (revocationCheck === "best-effort") {
      return {
        ok: true,
        state: "validated",
        revocationBestEffort: true,
        detail: chainResult.detail || "revocation status unknown; accepted under best-effort",
      };
    }
    return {
      ok: false,
      state: "validation_deferred",
      errorCode: null,
      detail: chainResult.detail || "revocation status unknown or offline",
    };
  }
  return invalid(chainResult.detail || "chain or revocation policy failed");
}

module.exports = {
  validateIssuedCertificate,
  dnsNameAuthorized,
  parseSubjectCn,
  parseDnsSans,
  spkiSha256Hex,
  CLOCK_SKEW_FUTURE_MS,
  pemToDer,
  extractSpkiFromCsr,
  extractSpkiFromCertificate,
};
