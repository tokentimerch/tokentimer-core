"use strict";

const { createHash } = require("node:crypto");
const { isIP } = require("node:net");
const asn1js = require("asn1js");
const pkijs = require("pkijs");
const { containsPrivateKeyMaterial } = require("../../utils/secretMaterial");
const { assertSafeDnsIdentity, assertSafeIpIdentity } = require("./identitySafety");

const MAX_CSR_BYTES = 64 * 1024;
const CSR_PEM = /^\s*-----BEGIN CERTIFICATE REQUEST-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE REQUEST-----\s*$/;
const EXTENSION_REQUEST_OID = "1.2.840.113549.1.9.14";
const SUBJECT_ALT_NAME_OID = "2.5.29.17";
const COMMON_NAME_OID = "2.5.4.3";

class CsrParseError extends Error {
  constructor(message = "Invalid public certificate signing request") {
    super(message);
    this.code = "CERTOPS_CSR_INVALID";
    this.status = 400;
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function normalizedPem(der) {
  const lines = der.toString("base64").match(/.{1,64}/g) || [];
  return ["-----BEGIN CERTIFICATE REQUEST-----", ...lines, "-----END CERTIFICATE REQUEST-----"].join("\n");
}

function strictDerFromPem(input) {
  if (typeof input !== "string" || !input || Buffer.byteLength(input, "utf8") > MAX_CSR_BYTES) {
    throw new CsrParseError();
  }
  if (containsPrivateKeyMaterial(input)) {
    const error = new CsrParseError("Private key material is not accepted");
    error.code = "PRIVATE_KEY_MATERIAL_REJECTED";
    error.status = 422;
    throw error;
  }
  const match = CSR_PEM.exec(input);
  if (!match) throw new CsrParseError();
  const encoded = match[1].replace(/\s+/g, "");
  const der = Buffer.from(encoded, "base64");
  if (!der.length || der.toString("base64") !== encoded) throw new CsrParseError();
  const decoded = asn1js.fromBER(der);
  if (decoded.offset !== der.length || decoded.result?.idBlock?.tagNumber !== 16) {
    throw new CsrParseError();
  }
  return der;
}

function ipName(value) {
  if (typeof value === "string" && isIP(value)) return value;
  const bytes = Buffer.from(value?.valueBlock?.valueHexView || value || []);
  if (bytes.length === 4) return [...bytes].join(".");
  if (bytes.length === 16) {
    return Array.from({ length: 8 }, (_, index) => bytes.readUInt16BE(index * 2).toString(16)).join(":");
  }
  throw new CsrParseError("CSR contains invalid IP SAN");
}

function requestedNamesFrom(csr) {
  const names = [];
  for (const item of csr.subject.typesAndValues || []) {
    if (item.type === COMMON_NAME_OID && typeof item.value?.valueBlock?.value === "string") {
      const commonName = item.value.valueBlock.value;
      assertSafeDnsIdentity(commonName, { field: "CSR commonName" });
      names.push(commonName);
    }
  }
  const attributes = csr.attributes || [];
  if (attributes.length > 1 || attributes.some((attribute) => attribute.type !== EXTENSION_REQUEST_OID)) {
    throw new CsrParseError("CSR contains unsupported attributes");
  }
  if (attributes.length) {
    if (attributes[0].values.length !== 1) throw new CsrParseError();
    const extensions = new pkijs.Extensions({ schema: attributes[0].values[0] });
    if (extensions.extensions.some((extension) => extension.extnID !== SUBJECT_ALT_NAME_OID)) {
      throw new CsrParseError("CSR contains unsupported extensions");
    }
    for (const extension of extensions.extensions) {
      const decoded = asn1js.fromBER(extension.extnValue.valueBlock.valueHexView);
      if (decoded.offset < 0) throw new CsrParseError();
      const san = new pkijs.GeneralNames({ schema: decoded.result });
      for (const name of san.names) {
        if (name.type !== 2 && name.type !== 7) throw new CsrParseError("CSR contains unsupported SAN type");
        if (name.type === 7) {
          const ip = ipName(name.value);
          assertSafeIpIdentity(ip, { field: "CSR IP SAN" });
          names.push(ip);
        } else {
          const dns = String(name.value);
          assertSafeDnsIdentity(dns, { field: "CSR DNS SAN" });
          names.push(dns);
        }
      }
    }
  }
  return [...new Set(names.map((name) => name.trim()).filter(Boolean))].sort();
}

async function parsePublicCsr(input) {
  try {
    const der = strictDerFromPem(input);
    const csr = pkijs.CertificationRequest.fromBER(der);
    if (csr.version !== 0 || !(await csr.verify())) throw new CsrParseError();
    const spki = Buffer.from(csr.subjectPublicKeyInfo.toSchema().toBER(false));
    const requestedNames = requestedNamesFrom(csr);
    const subject = csr.subject.typesAndValues.map((item) =>
      `${item.type}=${String(item.value?.valueBlock?.value ?? "")}`,
    ).join(", ");
    if (containsPrivateKeyMaterial({ subject, requestedNames })) throw new CsrParseError();
    return {
      csrPem: normalizedPem(der),
      csrDerSha256: sha256(der),
      spkiFingerprintSha256: sha256(spki),
      subject,
      requestedNames,
    };
  } catch (error) {
    if (error instanceof CsrParseError) throw error;
    throw new CsrParseError();
  }
}

module.exports = { CsrParseError, MAX_CSR_BYTES, parsePublicCsr };
