"use strict";

/**
 * Strict claimed-job validation for the bootstrap agent.
 *
 * Jobs are control-plane input, not a trusted instruction stream. M4 does
 * not execute any action, but it still validates the complete public job
 * shape and every policy dimension before handing it to the local policy
 * engine. Action dimensions are carried in the existing public metadata
 * array, keeping this boundary aligned with the frozen job-payload schema
 * without introducing signed-dispatch/PR #88 execution fields.
 */

const JOB_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ISO_DATE_TIME_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const ACTIONS = new Set(["renew", "deploy", "reload", "revoke", "noop"]);
const KEY_MODES = new Set([
  "agent-local",
  "proxy-agent-local",
  "cert-manager-managed",
  "appliance-managed",
  "hsm-managed",
  "vault-managed",
  "os-store-managed",
  "external-unknown",
]);
const TARGET_TYPES = new Set(["domain", "endpoint", "kubernetes", "appliance", "load-balancer", "external"]);
const POLICY_METADATA_NAMES = new Set(["commandRef", "path", "caEndpoint", "dnsZone", "dnsProvider"]);
const ACTION_REQUIRED_POLICY_DIMENSIONS = Object.freeze({
  renew: ["caEndpoint", "dnsZone", "dnsProvider"],
  deploy: ["commandRef", "path"],
  reload: ["commandRef"],
  revoke: ["caEndpoint"],
  noop: [],
});

class ClaimedJobValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ClaimedJobValidationError";
    this.code = "CLAIMED_JOB_INVALID";
  }
}

function fail(message) {
  throw new ClaimedJobValidationError(`tokentimer-agent: claimed job ${message}`);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireExactKeys(value, allowedKeys, requiredKeys, label) {
  if (!isPlainObject(value)) fail(`${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (!allowedKeys.has(key)) fail(`${label} contains unknown field "${key}"`);
  }
  for (const key of requiredKeys) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) fail(`${label} is missing "${key}"`);
  }
}

function requireString(value, label, { min = 1, max, pattern } = {}) {
  if (typeof value !== "string" || value.length < min || (max !== undefined && value.length > max) || (pattern && !pattern.test(value))) {
    fail(`${label} has an invalid type, format, or size`);
  }
}

function requireDate(value, label) {
  if (typeof value !== "string" || !ISO_DATE_TIME_PATTERN.test(value) || Number.isNaN(Date.parse(value))) {
    fail(`${label} must be an ISO date-time`);
  }
}

function extractPolicyMetadata(metadata) {
  if (metadata === undefined) return {};
  if (!Array.isArray(metadata) || metadata.length > 32) fail("metadata must contain at most 32 entries");
  const dimensions = {};
  metadata.forEach((entry, index) => {
    requireExactKeys(entry, new Set(["name", "value"]), ["name", "value"], `metadata[${index}]`);
    requireString(entry.name, `metadata[${index}].name`, { max: 64, pattern: /^[A-Za-z0-9_.:-]+$/ });
    const value = entry.value;
    if (value !== null && typeof value !== "string" && typeof value !== "boolean" && (typeof value !== "number" || !Number.isFinite(value))) {
      fail(`metadata[${index}].value has an invalid type`);
    }
    if (typeof value === "string" && value.length > 512) fail(`metadata[${index}].value is oversized`);
    if (!POLICY_METADATA_NAMES.has(entry.name)) return;
    if (typeof value !== "string" || value.length === 0 || value.length > 512 || Object.prototype.hasOwnProperty.call(dimensions, entry.name)) {
      fail(`policy metadata "${entry.name}" must appear once as a non-empty bounded string`);
    }
    dimensions[entry.name] = value;
  });
  return dimensions;
}

function validateClaimedJob(job) {
  requireExactKeys(
    job,
    new Set(["schemaVersion", "jobId", "workspaceId", "certificateId", "tokenId", "action", "target", "keyMode", "keyReference", "metadata", "requestedAt", "requestedBy"]),
    ["schemaVersion", "jobId", "workspaceId", "certificateId", "action", "target", "keyMode", "requestedAt"],
    "job",
  );
  if (job.schemaVersion !== 1) fail("schemaVersion must be 1");
  requireString(job.jobId, "jobId", { max: 128, pattern: JOB_ID_PATTERN });
  requireString(job.workspaceId, "workspaceId", { pattern: UUID_PATTERN });
  requireString(job.certificateId, "certificateId", { max: 128, pattern: JOB_ID_PATTERN });
  if (!ACTIONS.has(job.action)) fail("action is invalid");
  if (!KEY_MODES.has(job.keyMode)) fail("keyMode is invalid");
  requireDate(job.requestedAt, "requestedAt");

  if (job.tokenId !== undefined && job.tokenId !== null && (!Number.isInteger(job.tokenId) || job.tokenId < 1)) fail("tokenId is invalid");
  if (job.keyReference !== undefined && job.keyReference !== null) requireString(job.keyReference, "keyReference", { max: 512 });
  if (job.requestedBy !== undefined && job.requestedBy !== null) {
    requireExactKeys(job.requestedBy, new Set(["actorType", "actorId", "displayName"]), ["actorType"], "requestedBy");
    if (!["user", "system", "automation"].includes(job.requestedBy.actorType)) fail("requestedBy.actorType is invalid");
    if (job.requestedBy.actorId !== undefined && job.requestedBy.actorId !== null) requireString(job.requestedBy.actorId, "requestedBy.actorId", { max: 128 });
    if (job.requestedBy.displayName !== undefined && job.requestedBy.displayName !== null) requireString(job.requestedBy.displayName, "requestedBy.displayName", { max: 256 });
  }

  requireExactKeys(job.target, new Set(["type", "reference", "managedCertificateId", "certificateInstanceId", "fingerprintSha256"]), ["type", "reference"], "target");
  if (!TARGET_TYPES.has(job.target.type)) fail("target.type is invalid");
  requireString(job.target.reference, "target.reference", { max: 512 });
  for (const field of ["managedCertificateId", "certificateInstanceId"]) {
    if (job.target[field] !== undefined && job.target[field] !== null) requireString(job.target[field], `target.${field}`, { max: 128 });
  }
  if (job.target.fingerprintSha256 !== undefined && job.target.fingerprintSha256 !== null) requireString(job.target.fingerprintSha256, "target.fingerprintSha256", { pattern: /^[a-f0-9]{64}$/ });

  const policyDimensions = extractPolicyMetadata(job.metadata);
  for (const dimension of ACTION_REQUIRED_POLICY_DIMENSIONS[job.action]) {
    if (!Object.prototype.hasOwnProperty.call(policyDimensions, dimension)) {
      fail(`${job.action} action is missing required policy dimension "${dimension}"`);
    }
  }

  return {
    job,
    policyDescriptor: {
      targetSelector: job.target.reference,
      ...policyDimensions,
    },
  };
}

function hasReportableJobId(value) {
  return typeof value === "string" && JOB_ID_PATTERN.test(value);
}

module.exports = {
  ACTION_REQUIRED_POLICY_DIMENSIONS,
  ClaimedJobValidationError,
  validateClaimedJob,
  hasReportableJobId,
};
