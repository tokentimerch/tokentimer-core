"use strict";

/**
 * CertOps agent evidence builder (agent bootstrap).
 *
 * Builds schema-valid `evidenceBody` / `evidenceItems` payloads (see
 * packages/contracts/certops/agent-protocol.schema.json, definitions
 * `evidenceBody` and `publicMetadataEntry`) for agent-side callers: the
 * policy engine (rejections), discovery findings, and deploy/renewal
 * outcomes in later phases.
 *
 * Zero-custody guarantee: every free-text/metadata value that flows through
 * this module is (a) rejected outright if it contains private key material,
 * using the shared detector below as the single source of truth, and
 * (b) defensively redacted for generic secret patterns even when the caller
 * did not intend to pass one. `assertEvidencePayloadSafe` is a last-resort
 * deep scan callers MUST run immediately before any evidence POST, per the
 * packaging decision that an in-core agent package reuses
 * the shared detector directly rather than duplicating detection logic or
 * pinning a cross-repo digest.
 *
 * This module is self-contained: it does not import sibling agent modules
 * (../config, ../policy, etc). Callers pass in whatever plain data they have.
 */

// Single source of truth for content-based private-key-material detection
// and generic-secret redaction. Vendored from @tokentimer/log-scrub so the
// installed agent never depends on the API app or sibling monorepo packages.
const {
  containsPrivateKeyMaterial: sharedContainsPrivateKeyMaterial,
  assertNoPrivateKeyMaterial: sharedAssertNoPrivateKeyMaterial,
  redactGenericSecrets: sharedRedactGenericSecrets,
} = require("../../vendor/log-scrub/secret-material.js");

/**
 * evidenceItems[].eventType enum, mirrored exactly from
 * packages/contracts/certops/agent-protocol.schema.json
 * (definitions.evidenceBody.properties.evidenceItems.items.properties.eventType).
 * Keep in sync with that schema; do not add values here without adding them
 * there first.
 */
const EVENT_TYPES = Object.freeze([
  "certificate.observed",
  "deployment.checked",
  "deployment.updated",
  "validation.passed",
  "validation.failed",
  "policy.checked",
]);

const EVENT_TYPE_SET = new Set(EVENT_TYPES);

// Mirrored exactly from packages/contracts/certops/agent-protocol.schema.json
// definitions.publicMetadataEntry.properties.name.pattern. Re-validated here
// so a schema-invalid metadata name fails at build time (in this module),
// not only at wire-serialization/server-validation time. Keep in sync with
// the schema file; the shared secretMaterial detector below is defense in
// depth on top of this pattern, not a replacement for it.
const METADATA_NAME_PATTERN =
  /^(?!.*(?:[Pp][Rr][Ii][Vv][Aa][Tt][Ee][-_]?[Kk][Ee][Yy]|[Ee][Nn][Cc][Rr][Yy][Pp][Tt][Ee][Dd][-_]?[Pp][Rr][Ii][Vv][Aa][Tt][Ee][-_]?[Kk][Ee][Yy]|[Kk][Ee][Yy][-_]?[Mm][Aa][Tt][Ee][Rr][Ii][Aa][Ll]|[Pp][Ff][Xx][-_]?[Bb][Ll][Oo][Bb]|[Jj][Kk][Ss][-_]?[Bb][Ll][Oo][Bb]|[Tt][Ll][Ss][-_]?[Kk][Ee][Yy]|[Cc][Aa][-_]?[Pp][Rr][Ii][Vv][Aa][Tt][Ee][-_]?[Kk][Ee][Yy]|[Kk][Ee][Yy][Ss][Tt][Oo][Rr][Ee][-_]?[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Rr][Ii][Vv][Aa][Tt][Ee][-_]?[Kk][Ee][Yy][-_]?[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Kk][Ee][Yy][-_]?[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Kk][Ee][Yy][-_]?[Pp][Ee][Mm]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll]))[A-Za-z0-9_.:-]{1,64}$/;

// Mirrored from the schema's evidenceItems[].fingerprintSha256 pattern.
const FINGERPRINT_SHA256_PATTERN = /^[a-f0-9]{64}$/;

const SUMMARY_MAX_LENGTH = 1024;
const METADATA_VALUE_MAX_LENGTH = 512;
const METADATA_MAX_ITEMS = 32;
const EVIDENCE_ITEMS_MIN = 1;
const EVIDENCE_ITEMS_MAX = 16;

const PRIVATE_KEY_MATERIAL_REJECTED = "PRIVATE_KEY_MATERIAL_REJECTED";

function buildError(message, code) {
  const error = new Error(message);
  if (code) error.code = code;
  return error;
}

/**
 * Re-exported as-is from the vendored @tokentimer/log-scrub detector
 * (packages/agent/vendor/log-scrub/secret-material.js). Throws an Error with
 * `.code === "PRIVATE_KEY_MATERIAL_REJECTED"` when `value` contains private
 * key material anywhere (deep-scanned for strings/arrays/objects/buffers).
 * @param {*} value
 * @returns {void}
 */
function assertNoPrivateKeyMaterial(value) {
  sharedAssertNoPrivateKeyMaterial(value);
}

/**
 * Re-exported as-is from the vendored log-scrub detector. Returns true if
 * private key material is detected anywhere in `value`.
 * @param {*} value
 * @returns {boolean}
 */
function containsPrivateKeyMaterial(value) {
  return sharedContainsPrivateKeyMaterial(value);
}

/**
 * Re-exported as-is from the vendored log-scrub detector. Returns a copy of
 * `value` with generic secret patterns (password=, Authorization: Bearer,
 * cookies, API keys, etc) replaced with a redaction placeholder. Private key
 * material is rejected (throws) before any redaction is attempted.
 * @param {*} value
 * @returns {*}
 */
function redactGenericSecrets(value) {
  return sharedRedactGenericSecrets(value);
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function toIsoDateTime(value, fieldName) {
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) {
      throw buildError(`tokentimer-agent evidence: ${fieldName} is an invalid Date`);
    }
    return value.toISOString();
  }
  if (typeof value === "string" && value.length > 0) {
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      throw buildError(
        `tokentimer-agent evidence: ${fieldName} must be a valid ISO date-time string, got: ${JSON.stringify(value)}`,
      );
    }
    return value;
  }
  throw buildError(
    `tokentimer-agent evidence: ${fieldName} must be an ISO date-time string or Date instance, got: ${JSON.stringify(value)}`,
  );
}

/**
 * Builds one `publicMetadataEntry` (`{ name, value }`) matching
 * packages/contracts/certops/agent-protocol.schema.json's shape.
 *
 * - `name` is re-validated against the same key-material-excluding pattern
 *   used by the schema, so a bad name fails here rather than only at
 *   wire-serialization/server time.
 * - `value` must be a string (<=512 chars) / number / integer / boolean /
 *   null, per the schema's oneOf.
 * - String values are deep-scanned for private key material
 *   (`assertNoPrivateKeyMaterial`, throws `PRIVATE_KEY_MATERIAL_REJECTED`)
 *   and then defensively redacted for generic secret patterns
 *   (`redactGenericSecrets`) before being stored, regardless of whether the
 *   caller intended to pass a secret.
 *
 * @param {string} name
 * @param {string|number|boolean|null} value
 * @returns {{name: string, value: string|number|boolean|null}}
 */
function buildMetadataEntry(name, value) {
  if (typeof name !== "string" || !METADATA_NAME_PATTERN.test(name)) {
    throw buildError(
      `tokentimer-agent evidence: metadata name ${JSON.stringify(name)} is invalid ` +
        "(must be 1-64 chars matching the schema's key-material-excluding pattern)",
    );
  }

  if (value === null) {
    return { name, value: null };
  }

  if (typeof value === "boolean" || typeof value === "number") {
    return { name, value };
  }

  if (typeof value === "string") {
    if (value.length > METADATA_VALUE_MAX_LENGTH) {
      throw buildError(
        `tokentimer-agent evidence: metadata "${name}" value exceeds ${METADATA_VALUE_MAX_LENGTH} chars`,
      );
    }
    assertNoPrivateKeyMaterial(value);
    return { name, value: redactGenericSecrets(value) };
  }

  throw buildError(
    `tokentimer-agent evidence: metadata "${name}" value must be a string, number, boolean, or null, got: ${typeof value}`,
  );
}

function normalizeMetadataList(metadata) {
  if (metadata === undefined || metadata === null) return [];
  if (!Array.isArray(metadata)) {
    throw buildError("tokentimer-agent evidence: metadata must be an array");
  }
  if (metadata.length > METADATA_MAX_ITEMS) {
    throw buildError(
      `tokentimer-agent evidence: metadata has ${metadata.length} entries, max is ${METADATA_MAX_ITEMS}`,
    );
  }
  return metadata.map((entry) => {
    if (
      isPlainObject(entry) &&
      typeof entry.name === "string" &&
      Object.prototype.hasOwnProperty.call(entry, "value") &&
      Object.keys(entry).length === 2
    ) {
      // Already a `{ name, value }` pair (pre-built or raw); re-validate and
      // re-redact through buildMetadataEntry rather than trusting it as-is.
      return buildMetadataEntry(entry.name, entry.value);
    }
    throw buildError(
      `tokentimer-agent evidence: metadata entry must be a {name, value} pair, got: ${JSON.stringify(entry)}`,
    );
  });
}

/**
 * Builds one evidenceItems[] element matching
 * packages/contracts/certops/agent-protocol.schema.json exactly
 * (additionalProperties: false, so no extra fields are ever included).
 *
 * @param {object} input
 * @param {string} input.eventType one of EVENT_TYPES
 * @param {string|Date} input.observedAt ISO date-time string or Date
 * @param {string} [input.fingerprintSha256] must match ^[a-f0-9]{64}$
 * @param {string} [input.summary] <=1024 chars, redacted + rejected for key material
 * @param {Array<{name:string,value:*}>} [input.metadata]
 * @returns {{eventType:string, observedAt:string, fingerprintSha256?:string, summary?:string, metadata?:Array<{name:string,value:*}>}}
 */
function buildEvidenceItem({ eventType, observedAt, fingerprintSha256, summary, metadata = [] } = {}) {
  if (!EVENT_TYPE_SET.has(eventType)) {
    throw buildError(
      `tokentimer-agent evidence: eventType must be one of ${EVENT_TYPES.join(", ")}, got: ${JSON.stringify(eventType)}`,
    );
  }

  const item = {
    eventType,
    observedAt: toIsoDateTime(observedAt, "observedAt"),
  };

  if (fingerprintSha256 !== undefined && fingerprintSha256 !== null) {
    if (typeof fingerprintSha256 !== "string" || !FINGERPRINT_SHA256_PATTERN.test(fingerprintSha256)) {
      throw buildError(
        `tokentimer-agent evidence: fingerprintSha256 must match ${FINGERPRINT_SHA256_PATTERN}, got: ${JSON.stringify(fingerprintSha256)}`,
      );
    }
    item.fingerprintSha256 = fingerprintSha256;
  }

  if (summary !== undefined && summary !== null) {
    if (typeof summary !== "string") {
      throw buildError("tokentimer-agent evidence: summary must be a string");
    }
    if (summary.length > SUMMARY_MAX_LENGTH) {
      throw buildError(
        `tokentimer-agent evidence: summary exceeds ${SUMMARY_MAX_LENGTH} chars`,
      );
    }
    assertNoPrivateKeyMaterial(summary);
    item.summary = redactGenericSecrets(summary);
  }

  const normalizedMetadata = normalizeMetadataList(metadata);
  if (normalizedMetadata.length > 0) {
    item.metadata = normalizedMetadata;
  }

  return item;
}

/**
 * Builds an `evidenceBody` (`{ jobId, evidenceItems }`) matching
 * packages/contracts/certops/agent-protocol.schema.json's evidenceBody
 * definition exactly. Enforces the schema's `minItems: 1, maxItems: 16`.
 *
 * @param {object} input
 * @param {string|null} [input.jobId]
 * @param {Array<object>} input.evidenceItems raw or pre-built evidence items
 * @returns {{jobId: string|null, evidenceItems: Array<object>}}
 */
function buildEvidenceBody({ jobId = null, evidenceItems } = {}) {
  if (!Array.isArray(evidenceItems) || evidenceItems.length < EVIDENCE_ITEMS_MIN) {
    throw buildError(
      `tokentimer-agent evidence: evidenceItems must be an array with at least ${EVIDENCE_ITEMS_MIN} item`,
    );
  }
  if (evidenceItems.length > EVIDENCE_ITEMS_MAX) {
    throw buildError(
      `tokentimer-agent evidence: evidenceItems has ${evidenceItems.length} items, max is ${EVIDENCE_ITEMS_MAX}`,
    );
  }

  const builtItems = evidenceItems.map((item) => {
    if (isPlainObject(item) && EVENT_TYPE_SET.has(item.eventType) && typeof item.observedAt === "string") {
      // Looks already-built; still re-run it through buildEvidenceItem so
      // validation/redaction is never bypassed for pre-built items.
      return buildEvidenceItem(item);
    }
    return buildEvidenceItem(item);
  });

  return { jobId, evidenceItems: builtItems };
}

/**
 * Convenience helper for the policy engine's rejection shape
 * (`{ allowed: false, rejectionReason, detail }`, without importing the
 * sibling policy module) that produces a single `policy.checked` evidence
 * item. This is the glue that turns every policy rejection into an evidence
 * record automatically, so operators see policy conflicts, not silent
 * failures (operators see policy conflicts, not silent failures).
 *
 * @param {object} input
 * @param {string} input.rejectionReason
 * @param {string} input.detail
 * @param {string|null} [input.jobId]
 * @returns {{jobId: string|null, evidenceItems: Array<object>}}
 */
function buildPolicyRejectionEvidence({ rejectionReason, detail, jobId = null } = {}) {
  if (typeof rejectionReason !== "string" || rejectionReason.length === 0) {
    throw buildError(
      "tokentimer-agent evidence: buildPolicyRejectionEvidence requires a non-empty rejectionReason string",
    );
  }

  const item = buildEvidenceItem({
    eventType: "policy.checked",
    observedAt: new Date().toISOString(),
    summary: detail,
    metadata: [{ name: "rejectionReason", value: rejectionReason }],
  });

  return buildEvidenceBody({ jobId, evidenceItems: [item] });
}

/**
 * Final defense-in-depth deep scan: runs the shared detector's
 * `assertNoPrivateKeyMaterial` over an entire constructed evidence body (or
 * any object) right before it would be sent over the wire, so even a bug in
 * the builder functions above still gets caught at the last possible moment
 * before network I/O.
 *
 * Call sites (the eventual protocol client integration) MUST call this
 * immediately before every evidence POST.
 *
 * @param {*} payload
 * @returns {void}
 */
function assertEvidencePayloadSafe(payload) {
  assertNoPrivateKeyMaterial(payload);
}

module.exports = {
  EVENT_TYPES,
  buildMetadataEntry,
  buildEvidenceItem,
  buildEvidenceBody,
  buildPolicyRejectionEvidence,
  assertEvidencePayloadSafe,
  containsPrivateKeyMaterial,
  assertNoPrivateKeyMaterial,
  redactGenericSecrets,
  PRIVATE_KEY_MATERIAL_REJECTED,
};
