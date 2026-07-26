"use strict";

/**
 * Upfront certificate issuance (ADR-0008).
 *
 * Every other agent-executed operation (renew/deploy/reload/revoke) binds to a
 * managed_certificate that already exists. Issuance is the case where the
 * certificate does not exist yet, and that asymmetry used to be a real product
 * hole: an operator could create a bare manual renew job with no subject, the
 * agent would run a full ACME order and deploy a genuine certificate, and
 * TokenTimer would record nothing. No inventory row, no expiry tracking, no
 * renewal, no dashboard entry. The work succeeded and the product forgot it.
 *
 * The fix mirrors the controller-provisioning pattern: create the identity
 * first, inside the same transaction as the job, so
 *
 *   - the job has a real subject_id to bind to (approvals, evidence, timeline,
 *     alerts and the retire flow all key off subject_id),
 *   - the operator sees the pending certificate immediately rather than after
 *     some later discovery scan happens to notice a new file, and
 *   - a failed issuance leaves an auditable row instead of silence.
 *
 * The row starts at status 'provisioning' and is reconciled to 'active' with
 * real x509 metadata when the agent reports success (see agentDispatch's
 * reconcileProvisionedCertificate). Zero-custody is unaffected: the key and
 * CSR are generated agent-side and key_reference is an opaque path pointer,
 * never key material.
 */

const { createCertificateJob } = require("./jobs");
const { assertNoPrivateKeyMaterial } = require("../../utils/secretMaterial");

const CERTOPS_JOB_INVALID = "CERTOPS_JOB_INVALID";
const ISSUANCE_SOURCE = "agent_issuance";
const ISSUANCE_STATUS = "provisioning";
// An issue job always ends with the agent holding the key on its own
// filesystem: it generates the key, submits the CSR, and deploys to certPath.
const ISSUANCE_KEY_MODE = "agent-local";

const MAX_DNS_NAME_LENGTH = 253;
const MAX_SANS = 100;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
// Same shape the agent enforces on a job's certificateId, so a name that
// cannot round-trip through the signed payload is rejected at creation rather
// than failing later on the host.
const DNS_NAME_PATTERN =
  /^(\*\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/;

function issuanceError(message) {
  const error = new Error(message);
  error.code = CERTOPS_JOB_INVALID;
  return error;
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function normalizeDnsName(value, fieldName) {
  if (typeof value !== "string") {
    throw issuanceError(`${fieldName} must be a string`);
  }
  const normalized = value.trim().toLowerCase();
  if (!normalized || normalized.length > MAX_DNS_NAME_LENGTH) {
    throw issuanceError(`${fieldName} must be 1-${MAX_DNS_NAME_LENGTH} characters`);
  }
  if (!DNS_NAME_PATTERN.test(normalized)) {
    throw issuanceError(`${fieldName} is not a valid DNS name`);
  }
  const labels = normalized.replace(/^\*\./, "").split(".");
  if (!labels.every((label) => label.length > 0 && label.length <= 63)) {
    throw issuanceError(`${fieldName} has an invalid DNS label`);
  }
  return normalized;
}

/**
 * The caller describes what to issue; the server owns the identity. Anything
 * that would let a caller point a brand-new issuance at an existing row (or
 * pre-seed the id the server is about to assign) is rejected outright rather
 * than silently ignored, so an operator never believes they targeted a
 * certificate that the server actually replaced.
 */
function normalizeIssuanceRequest(options) {
  const idempotencyKey = options.idempotencyKey;
  // Required, unlike other operations: without it a retried POST creates a
  // second certificate identity and a second real ACME order.
  if (typeof idempotencyKey !== "string" || !IDEMPOTENCY_KEY_PATTERN.test(idempotencyKey)) {
    throw issuanceError(
      "issue jobs require an idempotencyKey (1-128 chars matching " +
        "^[A-Za-z0-9._:-]+$) so a retried request cannot create a duplicate " +
        "certificate",
    );
  }

  if (options.subjectType != null || options.subjectId != null) {
    throw issuanceError(
      "issue jobs must not carry subjectType or subjectId: the certificate " +
        "does not exist yet and the server assigns its identity. Use a renew " +
        "job to act on a certificate TokenTimer already tracks",
    );
  }

  const payload = options.payload;
  if (!isPlainObject(payload)) {
    throw issuanceError("issue jobs require a payload object");
  }
  assertNoPrivateKeyMaterial(payload);

  if (payload.certificateId !== undefined) {
    throw issuanceError(
      "issue jobs must not carry payload.certificateId: the server assigns it " +
        "from the certificate it creates",
    );
  }

  const target = payload.target;
  if (!isPlainObject(target)) {
    throw issuanceError("issue jobs require payload.target");
  }
  const commonName = normalizeDnsName(target.reference, "payload.target.reference");

  let sans = [commonName];
  if (payload.sans !== undefined) {
    if (!Array.isArray(payload.sans) || payload.sans.length === 0) {
      throw issuanceError("payload.sans must be a non-empty array when present");
    }
    if (payload.sans.length > MAX_SANS) {
      throw issuanceError(`payload.sans must contain at most ${MAX_SANS} names`);
    }
    const normalized = payload.sans.map((value, index) =>
      normalizeDnsName(value, `payload.sans[${index}]`),
    );
    // The CN must be covered by the SAN set: a certificate whose SANs omit the
    // name the row is keyed on would deploy and then fail every verification.
    if (!normalized.includes(commonName)) {
      throw issuanceError(
        "payload.sans must include payload.target.reference",
      );
    }
    sans = [...new Set(normalized)];
  }

  // certPath is where the agent writes the issued certificate, and it is the
  // only durable pointer back to the material, so it is required here even
  // though a renew job can inherit it from a renewal profile.
  const certPath = payload.certPath;
  if (typeof certPath !== "string" || certPath.trim() === "") {
    throw issuanceError("issue jobs require payload.certPath");
  }

  return { idempotencyKey, commonName, sans, certPath: certPath.trim() };
}

async function insertProvisioningCertificate(client, options) {
  const result = await client.query(
    `INSERT INTO managed_certificates (
       workspace_id, status, source, source_ref, name, common_name,
       subject_alt_names, key_mode, key_reference, public_metadata
     ) VALUES ($1, $2, $3, $4, $5, $5, $6, $7, $8, $9::jsonb)
     RETURNING id, status, source, source_ref, common_name`,
    [
      options.workspaceId,
      ISSUANCE_STATUS,
      ISSUANCE_SOURCE,
      options.idempotencyKey,
      options.commonName,
      options.sans,
      ISSUANCE_KEY_MODE,
      `file://${options.certPath}`,
      JSON.stringify({
        issuance: {
          requestedAt: new Date().toISOString(),
          certPath: options.certPath,
        },
      }),
    ],
  );
  return result.rows[0];
}

/**
 * Creates the provisioning certificate and its issue job atomically.
 *
 * Must be called with a client that already holds the workspace CertOps lock
 * (createManualCertificateJob does this), so the global/workspace kill switch
 * is enforced before any row is written.
 */
async function createCertificateIssuanceJob(options = {}) {
  const client = options.client;
  if (!client) {
    throw new Error(
      "createCertificateIssuanceJob requires the kill-switch-locked client",
    );
  }
  // Injection point for tests, mirroring createManualCertificateJob's
  // jobCreator: the issuance contract is what matters here, not re-running the
  // job INSERT that jobs.js already covers.
  const { jobCreatorOverride, ...jobOptions } = options;
  const createJob = jobCreatorOverride || createCertificateJob;
  const workspaceId = options.workspaceId;
  const { idempotencyKey, commonName, sans, certPath } =
    normalizeIssuanceRequest(options);

  // Replay check before inserting the certificate: createCertificateJob would
  // return the original job for a repeated key, but only after this function
  // had already created a second orphan provisioning row.
  const replay = await client.query(
    `SELECT id FROM certificate_jobs
      WHERE workspace_id = $1 AND idempotency_key = $2
      LIMIT 1`,
    [workspaceId, idempotencyKey],
  );
  if (replay.rows[0]) {
    return await createJob({
      ...jobOptions,
      client,
      operation: "issue",
      idempotencyKey,
      returnOutcome: true,
    });
  }

  const certificate = await insertProvisioningCertificate(client, {
    workspaceId,
    idempotencyKey,
    commonName,
    sans,
    certPath,
  });

  return await createJob({
    ...jobOptions,
    client,
    operation: "issue",
    idempotencyKey,
    subjectType: "managed_certificate",
    subjectId: certificate.id,
    payload: {
      ...options.payload,
      // Server-assigned: the agent uses certificateId as the job's identity
      // for its own state and logging, and it must match the row this job
      // reconciles.
      certificateId: certificate.id,
      sans,
      certPath,
    },
    returnOutcome: true,
  });
}

module.exports = {
  CERTOPS_JOB_INVALID,
  ISSUANCE_KEY_MODE,
  ISSUANCE_SOURCE,
  ISSUANCE_STATUS,
  createCertificateIssuanceJob,
  normalizeIssuanceRequest,
};
