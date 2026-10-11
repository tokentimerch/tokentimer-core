"use strict";

const crypto = require("node:crypto");

const ISSUER_KINDS = Object.freeze(["acme", "adcs"]);
const ADCS_METADATA_MAX_BYTES = 4096;
const DEFAULT_POLL_INTERVAL_SECONDS = 900;
const DEFAULT_PENDING_TIMEOUT_SECONDS = 14 * 24 * 60 * 60;
const PREFLIGHT_PER_HOUR = 20;
const UNREACHABLE_ERROR = "ADCS_CA_UNREACHABLE";

const ENROLLMENT_STATES = Object.freeze([
  "requested",
  "prepared",
  "submitting",
  "pending_issuance",
  "submission_uncertain",
  "issued",
  "validation_deferred",
  "validated",
  "installing",
  "installed",
  "install_failed",
  "denied",
  "rejected_invalid",
  "validation_expired",
  "refused",
  "abandoned",
  "expired",
  "cancelled",
]);

const FORWARD = Object.freeze({
  requested: ["prepared", "refused", "cancelled"],
  prepared: ["submitting", "refused", "cancelled"],
  submitting: ["pending_issuance", "issued", "denied", "submission_uncertain", "refused", "cancelled"],
  submission_uncertain: ["pending_issuance", "issued", "abandoned", "refused", "cancelled"],
  pending_issuance: ["issued", "denied", "expired", "cancelled"],
  issued: ["validated", "rejected_invalid", "validation_deferred"],
  validation_deferred: ["validated", "rejected_invalid", "validation_expired"],
  validated: ["installing"],
  installing: ["installed", "install_failed"],
  // Agent install recovery can finish after a recorded failure.
  install_failed: ["installed"],
});

const TERMINAL = new Set([
  "refused",
  "denied",
  "abandoned",
  "expired",
  "cancelled",
  "rejected_invalid",
  "validation_expired",
  "installed",
]);

const CONTINUATION_STATES = new Set([
  "pending_issuance",
  "submitting",
  "submission_uncertain",
  "validation_deferred",
  "cancelled",
  "expired",
]);

function serviceError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function assertIssuerKind(kind) {
  if (!ISSUER_KINDS.includes(kind)) {
    throw serviceError(
      `issuer kind ${JSON.stringify(kind)} is not registered`,
      "CERTOPS_ISSUER_KIND_INVALID",
    );
  }
  return kind;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = canonicalize(value[key]);
    return out;
  }
  return value;
}

function freezeSnapshot(input) {
  const snapshot = {
    schemaVersion: 1,
    kind: "adcs",
    issuerId: input.issuerId,
    issuerVersion: input.issuerVersion,
    caConfig: input.caConfig,
    caKeySha256: input.caKeySha256,
    template: input.template,
    transport: input.transport || "dcom",
    authorizedDnsNames: input.authorizedDnsNames,
    keyAlgorithm: input.keyAlgorithm,
    keySize: input.keySize,
    policyVersion: input.policyVersion || 1,
    pollInterval: input.pollInterval || DEFAULT_POLL_INTERVAL_SECONDS,
    pendingTimeout: input.pendingTimeout || DEFAULT_PENDING_TIMEOUT_SECONDS,
    minimumRemainingValidity: input.minimumRemainingValidity || 0,
    requireLaterNotAfter: input.requireLaterNotAfter === true,
  };
  if (snapshot.transport !== "dcom") {
    throw serviceError("AD CS transport must be dcom", "CERTOPS_SNAPSHOT_INVALID");
  }
  if (!Array.isArray(snapshot.authorizedDnsNames) || snapshot.authorizedDnsNames.length === 0) {
    throw serviceError("snapshot authorizedDnsNames is required", "CERTOPS_SNAPSHOT_INVALID");
  }
  const bytes = Buffer.from(JSON.stringify(canonicalize(snapshot)), "utf8");
  if (bytes.length > 28 * 1024) {
    throw serviceError("enrollment snapshot exceeds 28 KiB", "CERTOPS_SNAPSHOT_INVALID");
  }
  const sha256 = crypto.createHash("sha256").update(bytes).digest("hex");
  return {
    snapshot,
    bytes,
    sha256,
    b64: bytes.toString("base64"),
  };
}

function canReachEnrollmentState(from, to) {
  if (from === to) return true;
  const seen = new Set([from]);
  const queue = [from];
  while (queue.length > 0) {
    const current = queue.shift();
    for (const next of FORWARD[current] || []) {
      if (next === to) return true;
      if (!seen.has(next)) {
        seen.add(next);
        queue.push(next);
      }
    }
  }
  return false;
}

function assertForwardTransition(from, to) {
  if (canReachEnrollmentState(from, to)) return;
  throw serviceError(
    `enrollment cannot move from ${from} to ${to}`,
    "CERTOPS_ENROLLMENT_TRANSITION_INVALID",
  );
}

function nextPollAt(now, seconds) {
  return new Date(now.getTime() + seconds * 1000);
}

function decideContinuation(enrollment, snapshot, now) {
  if (!CONTINUATION_STATES.has(enrollment.state)) return null;
  if (enrollment.activeJob) return null;
  if (enrollment.state === "pending_issuance" && enrollment.pendingSince) {
    const deadline = enrollment.pendingSince.getTime() + snapshot.pendingTimeout * 1000;
    if (now.getTime() >= deadline) return { state: "expired", reason: "pending_timeout" };
  }
  if (enrollment.nextPollAt && enrollment.nextPollAt.getTime() > now.getTime()) return null;
  if (enrollment.state === "submitting" && enrollment.lastErrorCode === UNREACHABLE_ERROR) {
    return { dispatch: true, reason: UNREACHABLE_ERROR };
  }
  if (enrollment.state === "submission_uncertain") {
    if (!Number.isInteger(enrollment.operatorRequestId) || enrollment.operatorRequestId < 1) {
      return null;
    }
    return { dispatch: true, reason: "reconcile" };
  }
  if (enrollment.state === "cancelled" || enrollment.state === "expired") {
    return { dispatch: true, reason: "free_key" };
  }
  if (enrollment.state === "pending_issuance" || enrollment.state === "validation_deferred") {
    return { dispatch: true, reason: "poll" };
  }
  return null;
}

function storedAdcsPayload({ certificateId, target, metadata }) {
  const payload = {
    schemaVersion: 1,
    certificateId,
    keyMode: "os-store-managed",
    target,
  };
  if (metadata != null) {
    const encoded = JSON.stringify(metadata);
    if (Buffer.byteLength(encoded) > ADCS_METADATA_MAX_BYTES) {
      throw serviceError(
        "AD CS job metadata exceeds 4096 bytes",
        "CERTOPS_SIGNING_PAYLOAD_TOO_LARGE",
      );
    }
    payload.metadata = metadata;
  }
  if (payload.issuerKind || payload.enrollment) {
    throw serviceError(
      "issuerKind and enrollment are attached at signed dispatch",
      "CERTOPS_ENROLLMENT_DISPATCH_ONLY",
    );
  }
  return payload;
}

function attachEnrollmentDispatch(stored, enrollment) {
  if (stored && (stored.issuerKind || stored.enrollment)) {
    throw serviceError(
      "issuerKind and enrollment must not be stored on the job",
      "CERTOPS_ENROLLMENT_DISPATCH_ONLY",
    );
  }
  const metadata = Array.isArray(stored.metadata) ? stored.metadata.slice() : [];
  if (
    Number.isInteger(enrollment.operatorRequestId) &&
    enrollment.operatorRequestId >= 1 &&
    !metadata.some((entry) => entry && entry.name === "adcs.reconcileRequestId")
  ) {
    metadata.push({
      name: "adcs.reconcileRequestId",
      value: enrollment.operatorRequestId,
    });
  }
  return {
    ...stored,
    issuerKind: "adcs",
    enrollment: {
      enrollmentId: enrollment.id,
      attempt: enrollment.attempt,
      snapshotB64: enrollment.snapshotB64,
      snapshotSha256: enrollment.snapshotSha256,
    },
    ...(metadata.length ? { metadata } : {}),
  };
}

function assertPayloadHasNoEnrollmentFields(payload) {
  if (!payload || typeof payload !== "object") return;
  if (Object.prototype.hasOwnProperty.call(payload, "issuerKind")
    || Object.prototype.hasOwnProperty.call(payload, "enrollment")) {
    throw serviceError(
      "issuerKind and enrollment are attached at signed dispatch",
      "CERTOPS_ENROLLMENT_DISPATCH_ONLY",
    );
  }
}

function confirmedKeyAllowed(preflight, caKeySha256) {
  if (!preflight || preflight.templateCheck?.verdict !== "safe") return false;
  if (preflight.caCheck?.verdict !== "safe") return false;
  const certs = Array.isArray(preflight.caCertificates) ? preflight.caCertificates : [];
  return certs.some((cert) => cert && cert.keySha256 === caKeySha256);
}

module.exports = {
  ADCS_METADATA_MAX_BYTES,
  CONTINUATION_STATES,
  DEFAULT_PENDING_TIMEOUT_SECONDS,
  DEFAULT_POLL_INTERVAL_SECONDS,
  ENROLLMENT_STATES,
  ISSUER_KINDS,
  PREFLIGHT_PER_HOUR,
  TERMINAL,
  UNREACHABLE_ERROR,
  assertForwardTransition,
  canReachEnrollmentState,
  assertIssuerKind,
  assertPayloadHasNoEnrollmentFields,
  attachEnrollmentDispatch,
  canonicalize,
  confirmedKeyAllowed,
  decideContinuation,
  freezeSnapshot,
  nextPollAt,
  serviceError,
  storedAdcsPayload,
};
