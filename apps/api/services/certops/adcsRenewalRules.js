"use strict";

/**
 * AD CS renewal profile rules. The profile write path, the renewal scheduler,
 * and renewal health all judge a profile with these functions.
 *
 * Kept free of other certops imports: renewalProfileAdmin already requires
 * renewalScheduler, so anything the scheduler needs from here must not loop
 * back through the admin module.
 */

const CERTOPS_PROFILE_INVALID = "CERTOPS_PROFILE_INVALID";

function profileError(message, code = CERTOPS_PROFILE_INVALID, details = null) {
  const error = new Error(message);
  error.code = code;
  if (details) error.details = details;
  return error;
}

// An AD CS issuer can only renew a profile that carries a complete Windows/IIS
// target and a confirmed CA. Checked on edit so Save never leaves automatic
// renewal on for a profile the scheduler will refuse.
const CERTOPS_PROFILE_ISSUER_INCOMPATIBLE = "CERTOPS_PROFILE_ISSUER_INCOMPATIBLE";

function adcsTargetComplete(target) {
  return Boolean(
    target &&
      target.type === "windows-iis" &&
      typeof target.reference === "string" &&
      typeof target.store === "string" &&
      typeof target.binding?.site === "string" &&
      Number.isInteger(target.binding?.port),
  );
}

/**
 * Full AD CS rule set for a stored profile: the Windows/IIS target the AD CS
 * renewal path reads, then the create/edit policy. Read paths and the
 * scheduler use this so a native AD CS profile is judged by the rules its
 * writes were held to.
 */
function validateAdcsRenewalProfile(profile) {
  if (!adcsTargetComplete(profile?.target)) {
    throw profileError(
      "This profile has no complete Windows/IIS deployment target, so AD CS cannot renew it.",
      CERTOPS_PROFILE_ISSUER_INCOMPATIBLE,
    );
  }
  return validateAdcsRenewalPolicy(profile);
}

const ADCS_HOST_PATTERN =
  /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const ADCS_STORE_PATTERN = /^[A-Za-z0-9 _.-]{1,64}$/;
const ADCS_SITE_PATTERN = /^[A-Za-z0-9 _.:-]{1,256}$/;
const ADCS_RSA_SIZES = new Set([2048, 3072, 4096]);
const ADCS_ECDSA_SIZES = new Set([256, 384]);

function adcsHost(value, field) {
  if (typeof value !== "string" || !ADCS_HOST_PATTERN.test(value.trim())) {
    throw profileError(`${field} must be a DNS name`);
  }
  return value.trim();
}

// Same rules as create. The certificate name must stay in the SAN list, or the
// scheduler refuses the profile on its next renewal.
function validateAdcsRenewalPolicy(profile) {
  const hosts = [];
  for (const entry of Array.isArray(profile.sanPolicy?.sans) ? profile.sanPolicy.sans : []) {
    const host = adcsHost(entry, "DNS name");
    if (!hosts.includes(host)) hosts.push(host);
  }
  if (hosts.length === 0 || hosts.length > 16) {
    throw profileError("a renewal profile accepts 1 to 16 DNS names");
  }
  if (!hosts.includes(profile.target?.reference)) {
    throw profileError("DNS names must include the certificate name");
  }
  const { keyAlgorithm } = profile;
  if (keyAlgorithm !== "rsa" && keyAlgorithm !== "ecdsa") {
    throw profileError("keyAlgorithm must be rsa or ecdsa");
  }
  const keySize = Number(profile.keySize);
  const allowed = keyAlgorithm === "rsa" ? ADCS_RSA_SIZES : ADCS_ECDSA_SIZES;
  if (!allowed.has(keySize)) {
    throw profileError(`keySize is invalid for ${keyAlgorithm}`);
  }
  return { ...profile, sanPolicy: { sans: hosts }, keySize };
}

module.exports = {
  ADCS_ECDSA_SIZES,
  ADCS_RSA_SIZES,
  ADCS_SITE_PATTERN,
  ADCS_STORE_PATTERN,
  CERTOPS_PROFILE_INVALID,
  CERTOPS_PROFILE_ISSUER_INCOMPATIBLE,
  adcsHost,
  adcsTargetComplete,
  profileError,
  validateAdcsRenewalPolicy,
  validateAdcsRenewalProfile,
};
