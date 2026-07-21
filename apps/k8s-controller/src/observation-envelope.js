"use strict";

const crypto = require("node:crypto");
const { containsPrivateKeyMaterial } = require("@tokentimer/log-scrub");

const CONTROLLER_OBSERVATION_PROTOCOL_VERSION = "certops-controller-observation-v1";
const PRIVATE_KEY_MATERIAL_REJECTED = "PRIVATE_KEY_MATERIAL_REJECTED";

function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
    .join(",")}}`;
}

function readyConditionIdentity(conditions) {
  const ready = Array.isArray(conditions)
    ? conditions.find((condition) => condition && condition.type === "Ready")
    : null;
  if (!ready) return null;
  return {
    lastTransitionTime: ready.lastTransitionTime || null,
    message: ready.message || null,
    reason: ready.reason || null,
    status: ready.status || null,
    type: "Ready",
  };
}

function semanticTuple(observation) {
  return {
    certificateGeneration: observation.certificateGeneration ?? null,
    certificateUid: observation.certificateUid || null,
    clusterId: observation.clusterId || null,
    fingerprintSha256: observation.publicCertificate?.fingerprintSha256 || null,
    namespace: observation.namespace || null,
    protocolVersion: CONTROLLER_OBSERVATION_PROTOCOL_VERSION,
    readyCondition: readyConditionIdentity(observation.conditions),
    resourceVersion: observation.resourceVersion || null,
    workspaceId: observation.workspaceId || null,
  };
}

function idempotencyKeyFor(observation) {
  return crypto
    .createHash("sha256")
    .update(stableStringify(semanticTuple(observation)), "utf8")
    .digest("hex");
}

function deterministicUuidFromKey(idempotencyKey) {
  const bytes = Buffer.from(idempotencyKey, "hex").subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function createObservationEnvelope(observation, { now = () => new Date().toISOString() } = {}) {
  const idempotencyKey = idempotencyKeyFor(observation);
  const envelope = {
    ...observation,
    schemaVersion: 1,
    observationSource: "cert_manager",
    observationId: deterministicUuidFromKey(idempotencyKey),
    idempotencyKey,
    observedAt: observation.observedAt || now(),
  };
  if (containsPrivateKeyMaterial(envelope)) {
    const error = new Error("Private key material is not accepted in controller observations");
    error.code = PRIVATE_KEY_MATERIAL_REJECTED;
    throw error;
  }
  return envelope;
}

module.exports = {
  CONTROLLER_OBSERVATION_PROTOCOL_VERSION,
  PRIVATE_KEY_MATERIAL_REJECTED,
  createObservationEnvelope,
  deterministicUuidFromKey,
  idempotencyKeyFor,
  readyConditionIdentity,
  semanticTuple,
  stableStringify,
};
