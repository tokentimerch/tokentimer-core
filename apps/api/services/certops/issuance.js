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

const crypto = require("crypto");

const { createCertificateJob } = require("./jobs");
const { assertNoPrivateKeyMaterial } = require("../../utils/secretMaterial");

const CERTOPS_JOB_INVALID = "CERTOPS_JOB_INVALID";
const ISSUANCE_SOURCE = "agent_issuance";
const ISSUANCE_STATUS = "provisioning";
// An issue job for a filesystem target always ends with the agent holding
// the key on its own filesystem: it generates the key, submits the CSR, and
// deploys to certPath. A windows-iis target (ADR-0012 decision 9) has no
// filesystem key at all -- the key is generated inside the CNG machine key
// store -- so its custody is os-store-managed instead. See
// keyModeForTargetType below, the single place that maps target.type to the
// custody the rest of issuance (the certificate row, and the job payload the
// agent dispatches to) must agree on.
const ISSUANCE_KEY_MODE = "agent-local";
const WINDOWS_IIS_ISSUANCE_KEY_MODE = "os-store-managed";

const MAX_DNS_NAME_LENGTH = 253;
const MAX_SANS = 100;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
// Same shape the agent enforces on a job's certificateId, so a name that
// cannot round-trip through the signed payload is rejected at creation rather
// than failing later on the host.
const DNS_NAME_PATTERN =
  /^(\*\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/;

// Mirrors job-payload.schema.json's windowsStoreName/windowsIisBinding/
// windowsThumbprintSha1 definitions and renewalProfile.js's identical
// validateWindowsBinding (kept as a separate, small copy here rather than an
// import: issuance's error code is CERTOPS_JOB_INVALID, not
// CERTOPS_RENEWAL_PROFILE_INVALID, and the two validators already run at
// different points in two different request lifecycles).
const WINDOWS_STORE_NAME_PATTERN = /^[A-Za-z0-9 _.-]{1,64}$/;
const WINDOWS_IIS_SITE_PATTERN = /^[A-Za-z0-9 _.:-]{1,256}$/;
const WINDOWS_SNI_HOST_PATTERN =
  /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const WINDOWS_THUMBPRINT_SHA1_PATTERN = /^[A-Fa-f0-9]{40}$/;

function keyModeForTargetType(targetType) {
  return targetType === "windows-iis"
    ? WINDOWS_IIS_ISSUANCE_KEY_MODE
    : ISSUANCE_KEY_MODE;
}

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
 * Validates the store/binding shape of a windows-iis target (ADR-0012),
 * mirroring renewalProfile.js's validateWindowsBinding and
 * job-payload.schema.json's windowsIisBinding definition. Unlike the
 * filesystem case, there is no certPath: the destination is a machine
 * certificate store plus an IIS site binding, keyed on thumbprint.
 */
function normalizeWindowsIssuanceTarget(target) {
  const store = target.store;
  if (typeof store !== "string" || !WINDOWS_STORE_NAME_PATTERN.test(store)) {
    throw issuanceError(
      "payload.target.store is required for a windows-iis target (1-64 chars matching ^[A-Za-z0-9 _.-]+$)",
    );
  }

  const binding = target.binding;
  if (!isPlainObject(binding)) {
    throw issuanceError("payload.target.binding is required for a windows-iis target");
  }
  if (
    typeof binding.site !== "string" ||
    !WINDOWS_IIS_SITE_PATTERN.test(binding.site)
  ) {
    throw issuanceError(
      "payload.target.binding.site is required for a windows-iis target",
    );
  }
  if (
    !Number.isInteger(binding.port) ||
    binding.port < 1 ||
    binding.port > 65535
  ) {
    throw issuanceError("payload.target.binding.port must be an integer 1-65535");
  }
  let sniHost = null;
  if (binding.sniHost !== undefined && binding.sniHost !== null) {
    if (
      typeof binding.sniHost !== "string" ||
      !WINDOWS_SNI_HOST_PATTERN.test(binding.sniHost)
    ) {
      throw issuanceError("payload.target.binding.sniHost is not a valid hostname");
    }
    sniHost = binding.sniHost;
  }

  let thumbprintSha1 = null;
  if (target.thumbprintSha1 !== undefined && target.thumbprintSha1 !== null) {
    if (
      typeof target.thumbprintSha1 !== "string" ||
      !WINDOWS_THUMBPRINT_SHA1_PATTERN.test(target.thumbprintSha1)
    ) {
      throw issuanceError("payload.target.thumbprintSha1 is not a valid SHA-1 thumbprint");
    }
    thumbprintSha1 = target.thumbprintSha1;
  }

  // certPath describes a filesystem deploy destination, which a machine
  // certificate store + IIS binding is not (renewalProfile.js's validateTarget
  // keeps the same separation); accepting one here would silently create a
  // certificate row that neither issuance path can actually satisfy. Checked
  // by the caller against payload.certPath (the field issuance actually
  // reads), not target.certPath, since payload.certPath is where a filesystem
  // issuance's path lives (see normalizeIssuanceRequest below).

  return { store, binding: { site: binding.site, port: binding.port, sniHost }, thumbprintSha1 };
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

  const targetType = target.type;
  if (targetType === "windows-iis") {
    if (payload.certPath !== undefined && payload.certPath !== null) {
      throw issuanceError(
        "payload.certPath is not valid for a windows-iis target (it deploys to a certificate store + IIS binding, not a filesystem path)",
      );
    }
    const windowsTarget = normalizeWindowsIssuanceTarget(target);
    return {
      idempotencyKey,
      commonName,
      sans,
      targetType,
      certPath: null,
      windowsTarget,
    };
  }

  // certPath is where the agent writes the issued certificate, and it is the
  // only durable pointer back to the material, so it is required here even
  // though a renew job can inherit it from a renewal profile.
  const certPath = payload.certPath;
  if (typeof certPath !== "string" || certPath.trim() === "") {
    throw issuanceError("issue jobs require payload.certPath");
  }
  const trimmedCertPath = certPath.trim();
  // A file path, not a directory. Live issuance against a directory path fails
  // agent-side only after the ACME order has already been placed, which burns a
  // real rate-limited order and leaves the row stuck in provisioning. Rejecting
  // it here costs nothing and the agent's own deploy step enforces the same
  // shape. A relative path is equally unusable: the agent resolves it against
  // an unspecified working directory.
  if (!trimmedCertPath.startsWith("/")) {
    throw issuanceError(
      "payload.certPath must be an absolute path (the agent resolves it on the host filesystem)",
    );
  }
  if (trimmedCertPath.endsWith("/")) {
    throw issuanceError(
      "payload.certPath must be a file path, not a directory (e.g. /etc/ssl/certs/example.com.pem)",
    );
  }

  return { idempotencyKey, commonName, sans, certPath: trimmedCertPath };
}

/**
 * Stable signed bigint for pg_advisory_xact_lock, scoped to one issuance
 * identity within one workspace.
 */
function advisoryLockKeyForIssuance(workspaceId, idempotencyKey) {
  const digest = crypto
    .createHash("sha256")
    .update(`certops-issuance-identity:${workspaceId}:${idempotencyKey}`)
    .digest();
  return digest.readBigInt64BE(0).toString();
}

async function insertProvisioningCertificate(client, options) {
  const keyMode = keyModeForTargetType(options.targetType);
  const windowsTarget = options.windowsTarget;
  // A filesystem target's key_reference/deployed_cert_path correlate this
  // row to the agent's later filesystem discovery scan of the same path
  // (see the class doc comment above). A windows-iis target has no
  // filesystem path to correlate against at all: its destination is a
  // machine certificate store + IIS binding, addressed by store/binding, not
  // a path, so deployed_cert_path stays NULL and key_reference is instead an
  // opaque store/binding pointer (never key material -- the CNG key never
  // leaves the machine key store, let alone this row).
  const keyReference = windowsTarget
    ? `winstore://${windowsTarget.store}/${windowsTarget.binding.site}:${windowsTarget.binding.port}`
    : `file://${options.certPath}`;
  const deployedCertPath = windowsTarget ? null : options.certPath;
  const publicMetadata = windowsTarget
    ? {
        issuance: {
          requestedAt: new Date().toISOString(),
          target: {
            type: "windows-iis",
            store: windowsTarget.store,
            binding: windowsTarget.binding,
            ...(windowsTarget.thumbprintSha1
              ? { thumbprintSha1: windowsTarget.thumbprintSha1 }
              : {}),
          },
        },
      }
    : {
        issuance: {
          requestedAt: new Date().toISOString(),
          certPath: options.certPath,
        },
      };

  const result = await client.query(
    `INSERT INTO managed_certificates (
       workspace_id, status, source, source_ref, name, common_name,
       subject_alt_names, key_mode, key_reference, public_metadata,
       deployed_cert_path, deployed_agent_id
     ) VALUES ($1, $2, $3, $4, $5, $5, $6, $7, $8, $9::jsonb, $10, $11)
     RETURNING id, status, source, source_ref, common_name`,
    [
      options.workspaceId,
      ISSUANCE_STATUS,
      ISSUANCE_SOURCE,
      options.idempotencyKey,
      options.commonName,
      options.sans,
      keyMode,
      keyReference,
      JSON.stringify(publicMetadata),
      // Correlation key for the later filesystem scan of this same path, so the
      // certificate this operator requested and the one an agent subsequently
      // discovers are one identity rather than two. Null for windows-iis: there
      // is no filesystem path to correlate against.
      deployedCertPath,
      options.assignedAgentId || null,
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
  const { idempotencyKey, commonName, sans, targetType, certPath, windowsTarget } =
    normalizeIssuanceRequest(options);

  // Resolve the identity before touching certificate_jobs. A retried POST must
  // reuse the certificate its first attempt created; inserting unconditionally
  // would either collide on the source_ref unique index or, worse, leave an
  // orphan provisioning row behind when createCertificateJob then replayed the
  // original job.
  //
  // The workspace kill-switch lock is FOR SHARE, which is correct for its own
  // purpose (it conflicts with the FOR UPDATE pause transition) but does NOT
  // serialize two issuance requests against each other. So two concurrent POSTs
  // with the same idempotency key could both read "no existing certificate" and
  // both attempt the insert: one wins, the other fails on the unique index with
  // a raw 23505 surfacing as an opaque 500, when the honest answer is the same
  // job the first request created. An advisory lock on the identity makes the
  // read-then-insert atomic without serializing unrelated issuance in the same
  // workspace (unlike promoting the workspace lock to FOR UPDATE).
  await client.query("SELECT pg_advisory_xact_lock($1)", [
    advisoryLockKeyForIssuance(workspaceId, idempotencyKey),
  ]);

  const existing = await client.query(
    `SELECT id FROM managed_certificates
      WHERE workspace_id = $1 AND source = $2 AND source_ref = $3
      LIMIT 1`,
    [workspaceId, ISSUANCE_SOURCE, idempotencyKey],
  );

  let certificateId = existing.rows[0]?.id || null;
  if (!certificateId) {
    // The key may still be taken by a non-issuance job (an operator reusing a
    // key across operations). Do not create an identity in that case: hand the
    // bare request to createCertificateJob so it raises its own idempotency
    // conflict, which is the honest answer.
    const conflicting = await client.query(
      `SELECT 1 FROM certificate_jobs
        WHERE workspace_id = $1 AND idempotency_key = $2
        LIMIT 1`,
      [workspaceId, idempotencyKey],
    );
    if (conflicting.rows[0]) {
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
      targetType,
      certPath,
      windowsTarget,
      // Mirrors the resolution createCertificateJob performs for the job row, so
      // the certificate is correlated to the same agent that will deploy it.
      assignedAgentId:
        jobOptions.assignedAgentId ?? options.payload?.assignedAgentId ?? null,
    });
    certificateId = certificate.id;
  }

  // One call site, on both the first attempt and the replay, so the derived
  // options are byte-identical. createCertificateJob hashes the creation
  // request to decide replay-vs-conflict, so a replay that reconstructed the
  // payload differently would be reported as a conflicting reuse of the key
  // instead of returning the original job.
  return await createJob({
    ...jobOptions,
    client,
    operation: "issue",
    idempotencyKey,
    subjectType: "managed_certificate",
    subjectId: certificateId,
    payload: {
      ...options.payload,
      // Server-assigned: the agent uses certificateId as the job's identity
      // for its own state and logging, and it must match the row this job
      // reconciles.
      certificateId,
      sans,
      // A windows-iis issuance carries no certPath at all (its destination is
      // target.store/target.binding, already present on options.payload.target
      // and left untouched above); keyMode: os-store-managed is what routes
      // this job, once dispatched, to the agent's CNG-native executor instead
      // of the file-based one (see AGENT_DEPLOYABLE_KEY_MODES's doc comment in
      // jobs.js and executeJob's dispatch check in packages/agent/src/index.js).
      ...(windowsTarget
        ? { keyMode: WINDOWS_IIS_ISSUANCE_KEY_MODE }
        : { certPath }),
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
