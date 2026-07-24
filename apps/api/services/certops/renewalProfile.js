"use strict";

/**
 * CertOps renewal profile (schemaVersion 1).
 *
 * Operators store a mutable source profile on
 * certificate_profiles.public_metadata.renewalProfile. Before a renew job is
 * created (scheduler) or approved (approval gate), that source is validated
 * and snapshotted into certificate_jobs.payload.renewalProfile as an
 * immutable execution contract. Approval hashes the full job payload, so a
 * later edit of the live profile cannot change what was approved.
 *
 * Zero-custody: only public/non-secret references (CA URL, account/EAB
 * refs, DNS provider+zone names, paths, command refs). Never private keys
 * or credential material.
 */

const CERTOPS_RENEWAL_PROFILE_INVALID = "CERTOPS_RENEWAL_PROFILE_INVALID";
const CERTOPS_RENEWAL_PROFILE_INCOMPLETE =
  "CERTOPS_RENEWAL_PROFILE_INCOMPLETE";

const RENEWAL_PROFILE_SCHEMA_VERSION = 1;

const TARGET_TYPES = Object.freeze([
  "domain",
  "endpoint",
  "kubernetes",
  "appliance",
  "load-balancer",
  "external",
]);
const TARGET_TYPE_SET = new Set(TARGET_TYPES);

const SAN_POLICY_MODES = Object.freeze(["exact", "template", "inherit"]);
const SAN_POLICY_MODE_SET = new Set(SAN_POLICY_MODES);

const KEY_ALGORITHMS = Object.freeze(["rsa", "ecdsa"]);
const KEY_ALGORITHM_SET = new Set(KEY_ALGORITHMS);

const RSA_KEY_SIZES = Object.freeze([2048, 3072, 4096]);
const ECDSA_KEY_SIZES = Object.freeze([256, 384]);

const ACME_KINDS = Object.freeze(["certbot", "acme.sh"]);
const ACME_KIND_SET = new Set(ACME_KINDS);

const COMMAND_REF_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
const DNS_PROVIDER_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;
const RELOAD_SERVICE_PATTERN = /^[A-Za-z0-9_.:@-]{1,128}$/;

function profileError(message, code = CERTOPS_RENEWAL_PROFILE_INVALID) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function isNonEmptyString(value, maxLength) {
  return (
    typeof value === "string" &&
    value.trim().length >= 1 &&
    value.trim().length <= maxLength
  );
}

function isValidHttpUrl(value) {
  if (typeof value !== "string" || value.length > 512) return false;
  let parsed;
  try {
    parsed = new URL(value);
  } catch (_error) {
    return false;
  }
  return parsed.protocol === "https:" || parsed.protocol === "http:";
}

function optionalStringOrNull(value, fieldName, maxLength) {
  if (value === undefined || value === null) return null;
  if (!isNonEmptyString(value, maxLength)) {
    throw profileError(`renewalProfile.${fieldName} is invalid`);
  }
  return value.trim();
}

function requireString(value, fieldName, maxLength, pattern = null) {
  if (!isNonEmptyString(value, maxLength)) {
    throw profileError(`renewalProfile.${fieldName} is invalid`);
  }
  const trimmed = value.trim();
  if (pattern && !pattern.test(trimmed)) {
    throw profileError(`renewalProfile.${fieldName} is invalid`);
  }
  return trimmed;
}

function validateKeySize(algorithm, keySize) {
  if (!Number.isInteger(keySize)) {
    throw profileError("renewalProfile.keySize is invalid");
  }
  const allowed = algorithm === "rsa" ? RSA_KEY_SIZES : ECDSA_KEY_SIZES;
  if (!allowed.includes(keySize)) {
    throw profileError(
      `renewalProfile.keySize is invalid for ${algorithm}`,
    );
  }
  return keySize;
}

function validateTarget(value, fieldName) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw profileError(`renewalProfile.${fieldName} is invalid`);
  }
  if (!TARGET_TYPE_SET.has(value.type)) {
    throw profileError(`renewalProfile.${fieldName}.type is invalid`);
  }
  const reference = requireString(
    value.reference,
    `${fieldName}.reference`,
    512,
  );
  const certPath =
    value.certPath === undefined || value.certPath === null
      ? null
      : requireString(value.certPath, `${fieldName}.certPath`, 512);
  const result = { type: value.type, reference, certPath };
  if (Object.prototype.hasOwnProperty.call(value, "reloadService")) {
    result.reloadService =
      value.reloadService === undefined || value.reloadService === null
        ? null
        : requireString(
            value.reloadService,
            `${fieldName}.reloadService`,
            128,
            RELOAD_SERVICE_PATTERN,
          );
  }
  return result;
}

/**
 * Validate and normalize a renewal profile object. Returns a frozen-shape
 * plain object suitable for JSONB persistence (immutable snapshot).
 */
function validateRenewalProfile(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw profileError(
      "renewalProfile is required",
      CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
    );
  }
  if (raw.schemaVersion !== RENEWAL_PROFILE_SCHEMA_VERSION) {
    throw profileError(
      `renewalProfile.schemaVersion must be ${RENEWAL_PROFILE_SCHEMA_VERSION}`,
    );
  }

  const sanPolicyRaw = raw.sanPolicy;
  if (
    !sanPolicyRaw ||
    typeof sanPolicyRaw !== "object" ||
    Array.isArray(sanPolicyRaw)
  ) {
    throw profileError("renewalProfile.sanPolicy is invalid");
  }
  if (!SAN_POLICY_MODE_SET.has(sanPolicyRaw.mode)) {
    throw profileError("renewalProfile.sanPolicy.mode is invalid");
  }
  if (
    !Array.isArray(sanPolicyRaw.sans) ||
    sanPolicyRaw.sans.length < 1 ||
    sanPolicyRaw.sans.length > 100
  ) {
    throw profileError(
      "renewalProfile.sanPolicy.sans must be a non-empty array",
      CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
    );
  }
  const sans = sanPolicyRaw.sans.map((san, index) =>
    requireString(san, `sanPolicy.sans[${index}]`, 255),
  );
  if (typeof sanPolicyRaw.allowWildcards !== "boolean") {
    throw profileError("renewalProfile.sanPolicy.allowWildcards is invalid");
  }
  if (
    !sanPolicyRaw.allowWildcards &&
    sans.some((san) => san.includes("*"))
  ) {
    throw profileError(
      "renewalProfile.sanPolicy rejects wildcard SANs when allowWildcards is false",
    );
  }

  if (!KEY_ALGORITHM_SET.has(raw.keyAlgorithm)) {
    throw profileError("renewalProfile.keyAlgorithm is invalid");
  }
  const keySize = validateKeySize(raw.keyAlgorithm, raw.keySize);

  const rotation = raw.keyRotationPolicy;
  if (!rotation || typeof rotation !== "object" || Array.isArray(rotation)) {
    throw profileError("renewalProfile.keyRotationPolicy is invalid");
  }
  if (typeof rotation.rotateOnRenew !== "boolean") {
    throw profileError(
      "renewalProfile.keyRotationPolicy.rotateOnRenew is invalid",
    );
  }

  const preferredChain = optionalStringOrNull(
    raw.preferredChain,
    "preferredChain",
    256,
  );

  const ca = raw.ca;
  if (!ca || typeof ca !== "object" || Array.isArray(ca)) {
    throw profileError("renewalProfile.ca is invalid");
  }
  if (!isValidHttpUrl(ca.endpoint)) {
    throw profileError(
      "renewalProfile.ca.endpoint is invalid",
      CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
    );
  }
  const accountRef = optionalStringOrNull(ca.accountRef, "ca.accountRef", 128);
  const eabRef = optionalStringOrNull(ca.eabRef, "ca.eabRef", 128);

  const acme = raw.acme;
  if (!acme || typeof acme !== "object" || Array.isArray(acme)) {
    throw profileError("renewalProfile.acme is invalid");
  }
  if (!ACME_KIND_SET.has(acme.kind)) {
    throw profileError("renewalProfile.acme.kind is invalid");
  }
  const commandRef = requireString(
    acme.commandRef,
    "acme.commandRef",
    128,
    COMMAND_REF_PATTERN,
  );

  const dns = raw.dns;
  if (!dns || typeof dns !== "object" || Array.isArray(dns)) {
    throw profileError("renewalProfile.dns is invalid");
  }
  const dnsProvider = requireString(
    dns.provider,
    "dns.provider",
    64,
    DNS_PROVIDER_PATTERN,
  );
  const dnsZone = requireString(dns.zone, "dns.zone", 255);

  if (
    !Array.isArray(raw.deploymentTargets) ||
    raw.deploymentTargets.length < 1 ||
    raw.deploymentTargets.length > 32
  ) {
    throw profileError(
      "renewalProfile.deploymentTargets must contain at least one target",
      CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
    );
  }
  const deploymentTargets = raw.deploymentTargets.map((target, index) =>
    validateTarget(target, `deploymentTargets[${index}]`),
  );

  const target = validateTarget(raw.target || deploymentTargets[0], "target");

  const verification = raw.verification;
  if (
    !verification ||
    typeof verification !== "object" ||
    Array.isArray(verification)
  ) {
    throw profileError("renewalProfile.verification is invalid");
  }
  if (typeof verification.requireMatch !== "boolean") {
    throw profileError("renewalProfile.verification.requireMatch is invalid");
  }
  const verifyHost = optionalStringOrNull(
    verification.host,
    "verification.host",
    255,
  );
  let verifyPort = null;
  if (verification.port !== undefined && verification.port !== null) {
    if (
      !Number.isInteger(verification.port) ||
      verification.port < 1 ||
      verification.port > 65535
    ) {
      throw profileError("renewalProfile.verification.port is invalid");
    }
    verifyPort = verification.port;
  }
  if (verification.requireMatch && !verifyHost) {
    throw profileError(
      "renewalProfile.verification.host is required when requireMatch is true",
      CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
    );
  }

  return {
    schemaVersion: RENEWAL_PROFILE_SCHEMA_VERSION,
    profileId:
      raw.profileId === undefined || raw.profileId === null
        ? null
        : requireString(String(raw.profileId), "profileId", 128),
    profileName: optionalStringOrNull(raw.profileName, "profileName", 256),
    sanPolicy: {
      mode: sanPolicyRaw.mode,
      sans,
      allowWildcards: sanPolicyRaw.allowWildcards,
    },
    keyAlgorithm: raw.keyAlgorithm,
    keySize,
    keyRotationPolicy: { rotateOnRenew: rotation.rotateOnRenew },
    preferredChain,
    ca: {
      endpoint: ca.endpoint.trim(),
      accountRef,
      eabRef,
    },
    acme: {
      kind: acme.kind,
      commandRef,
    },
    dns: {
      provider: dnsProvider,
      zone: dnsZone,
    },
    deploymentTargets,
    target,
    verification: {
      host: verifyHost,
      port: verifyPort,
      requireMatch: verification.requireMatch,
    },
  };
}

/**
 * Resolve SANs for the job snapshot from the profile policy and the
 * managed certificate inventory row.
 */
function resolveSans(sanPolicy, certificate) {
  const mode = sanPolicy?.mode || "inherit";
  if (mode === "exact" || mode === "template") {
    if (Array.isArray(sanPolicy.sans) && sanPolicy.sans.length > 0) {
      return sanPolicy.sans.map((san) => String(san).trim()).filter(Boolean);
    }
  }
  // inherit (default): certificate SANs, falling back to common_name.
  const fromCert = Array.isArray(certificate?.subject_alt_names)
    ? certificate.subject_alt_names
        .map((san) => (typeof san === "string" ? san.trim() : ""))
        .filter(Boolean)
    : [];
  if (fromCert.length > 0) return fromCert;
  if (
    typeof certificate?.common_name === "string" &&
    certificate.common_name.trim()
  ) {
    return [certificate.common_name.trim()];
  }
  return [];
}

function parseProfilePublicMetadata(value) {
  if (value === null || value === undefined) return {};
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed)
        ? parsed
        : {};
    } catch (_error) {
      return {};
    }
  }
  if (typeof value === "object" && !Array.isArray(value)) return value;
  return {};
}

/**
 * Build an immutable renewal-profile snapshot for a due certificate.
 * Throws CERTOPS_RENEWAL_PROFILE_INCOMPLETE when the live profile cannot
 * produce a complete, agent-executable contract.
 */
function resolveRenewalProfileSnapshot(certificate) {
  if (!certificate?.profile_id) {
    throw profileError(
      "Certificate has no linked renewal profile",
      CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
    );
  }

  const publicMetadata = parseProfilePublicMetadata(
    certificate.profile_public_metadata,
  );
  const source = publicMetadata.renewalProfile;
  if (!source || typeof source !== "object" || Array.isArray(source)) {
    throw profileError(
      "certificate_profiles.public_metadata.renewalProfile is missing",
      CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
    );
  }

  const sans = resolveSans(source.sanPolicy, certificate);
  if (sans.length === 0) {
    throw profileError(
      "Resolved SAN list is empty",
      CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
    );
  }

  const candidate = {
    ...source,
    schemaVersion: source.schemaVersion ?? RENEWAL_PROFILE_SCHEMA_VERSION,
    profileId: String(certificate.profile_id),
    profileName:
      typeof certificate.profile_name === "string"
        ? certificate.profile_name
        : source.profileName ?? null,
    sanPolicy: {
      mode: source.sanPolicy?.mode || "inherit",
      sans,
      allowWildcards: source.sanPolicy?.allowWildcards === true,
    },
  };

  // Fill keyRotationPolicy.rotateOnRenew from inventory key_mode when the
  // live profile omits it: agent-local custody can rotate; others cannot.
  if (
    !candidate.keyRotationPolicy ||
    typeof candidate.keyRotationPolicy !== "object"
  ) {
    const keyMode = certificate.key_mode || certificate.profile_key_mode;
    candidate.keyRotationPolicy = {
      rotateOnRenew:
        keyMode === "agent-local" || keyMode === "proxy-agent-local",
    };
  }

  return validateRenewalProfile(candidate);
}

/**
 * Map a validated renewal profile snapshot onto the blessed agent execution
 * fields stored alongside it on the job payload.
 */
function executionFieldsFromRenewalProfile(profile) {
  const fields = {
    commandRef: profile.acme.commandRef,
    caEndpoint: profile.ca.endpoint,
    acmeKind: profile.acme.kind,
    keyRotation: profile.keyRotationPolicy.rotateOnRenew,
    dnsProvider: profile.dns.provider,
    dnsZone: profile.dns.zone,
    target: {
      type: profile.target.type,
      reference: profile.target.reference,
    },
    sans: [...profile.sanPolicy.sans],
  };
  if (profile.target.certPath) {
    fields.certPath = profile.target.certPath;
  } else {
    const withPath = profile.deploymentTargets.find((t) => t.certPath);
    if (withPath?.certPath) fields.certPath = withPath.certPath;
  }
  const reload = profile.deploymentTargets.find((t) => t.reloadService);
  if (reload?.reloadService) fields.reloadService = reload.reloadService;
  if (profile.verification.host) {
    fields.verifyHost = profile.verification.host;
    if (profile.verification.port != null) {
      fields.verifyPort = profile.verification.port;
    }
  }
  if (profile.preferredChain) {
    fields.preferredChain = profile.preferredChain;
  }
  return fields;
}

/**
 * Build a complete renew job payload: immutable profile snapshot + agent
 * execution fields. Used by the scheduler at schedule time.
 */
function buildRenewalJobPayload({ certificate, reason = "expiry-threshold" }) {
  const renewalProfile = resolveRenewalProfileSnapshot(certificate);
  const executionFields = executionFieldsFromRenewalProfile(renewalProfile);
  return {
    certificateId: String(certificate.id),
    notAfter: new Date(certificate.not_after).toISOString(),
    reason,
    renewalProfile,
    ...executionFields,
  };
}

module.exports = {
  ACME_KINDS,
  CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
  CERTOPS_RENEWAL_PROFILE_INVALID,
  KEY_ALGORITHMS,
  RENEWAL_PROFILE_SCHEMA_VERSION,
  SAN_POLICY_MODES,
  TARGET_TYPES,
  buildRenewalJobPayload,
  executionFieldsFromRenewalProfile,
  resolveRenewalProfileSnapshot,
  resolveSans,
  validateRenewalProfile,
};
