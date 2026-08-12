"use strict";

/**
 * Adopting an existing certificate into automatic renewal.
 *
 * Automation is never armed as a side effect of a job succeeding. A renewal
 * profile is only ever derived for an already-active certificate when an
 * operator asked for it, and that request is recorded as a durable outbox
 * intent in the same transaction that creates the renew job. Without the intent
 * row, "active with profile_id IS NULL" is the state a detached certificate
 * sits in, so any rule that derived from that state alone would silently turn a
 * deliberate off switch back on at the operator's next manual renew.
 *
 * Zero-custody is unchanged: nothing here reads or writes key material.
 */

const { pool } = require("../../db/database");
const { writeAudit } = require("../audit");
const {
  CERTOPS_OUTBOX_EVENT_NOT_FOUND,
  CERTOPS_OUTBOX_EVENT_NOT_RETRYABLE,
  OUTBOX_EVENT_TYPES,
  OUTBOX_OUTCOME_DETACHED,
  enqueueOutboxEvent,
  invalidateProfileDerivationIntents,
  resetOutboxEventForRetry,
} = require("./outbox");
const {
  createCertificateJob,
  isAgentDeployableKeyMode,
  CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE,
} = require("./jobs");
const {
  WINDOWS_IIS_SITE_PATTERN,
  WINDOWS_SNI_HOST_PATTERN,
  WINDOWS_STORE_NAME_PATTERN,
} = require("./renewalProfile");

const CERTOPS_CERTIFICATE_NOT_FOUND = "CERTOPS_CERTIFICATE_NOT_FOUND";
const CERTOPS_CERTIFICATE_NOT_PROFILED = "CERTOPS_CERTIFICATE_NOT_PROFILED";
const CERTOPS_RENEWAL_SETUP_ALREADY_CONFIGURED =
  "CERTOPS_RENEWAL_SETUP_ALREADY_CONFIGURED";
const CERTOPS_RENEWAL_SETUP_MULTI_LOCATION =
  "CERTOPS_RENEWAL_SETUP_MULTI_LOCATION";
const CERTOPS_RENEWAL_SETUP_NO_DEPLOYED_PATH =
  "CERTOPS_RENEWAL_SETUP_NO_DEPLOYED_PATH";
const CERTOPS_RENEWAL_SETUP_WINDOWS_TOPOLOGY_INCOMPLETE =
  "CERTOPS_RENEWAL_SETUP_WINDOWS_TOPOLOGY_INCOMPLETE";
const CERTOPS_RENEWAL_SETUP_NO_COMMON_NAME =
  "CERTOPS_RENEWAL_SETUP_NO_COMMON_NAME";

/**
 * A discovered SAN entry is reported in typed form ("DNS:example.com",
 * "IP Address:127.0.0.1", ...; see parser.js's splitSubjectAltName and
 * agentObservations.js's commonNameFromSubject fallback chain). An ACME
 * certificate frequently has no Subject CN at all, so a filesystem/agent
 * discovery's commonName column is, in practice, often the first typed SAN
 * copied verbatim - agentObservations.js's certificateFor() prefers
 * subjectAltNames[0] over the parsed Subject CN specifically because SAN is
 * the field browsers and ACME actually trust. executeRenewJob (packages/
 * agent) uses job.target.reference as a bare name for the renewal CSR's
 * commonName, so that type prefix has to be stripped before it is usable as
 * a renew job's target.
 */
const SUBJECT_ALT_NAME_TYPE_PREFIX =
  /^(?:DNS|IP Address|URI|email|RID|Registered ID|DirName|othername):\s*/i;

function deriveDomainTargetReference(certificate) {
  const rawCommonName =
    typeof certificate.common_name === "string" ? certificate.common_name.trim() : "";
  const rawFirstSan =
    Array.isArray(certificate.subject_alt_names) &&
    typeof certificate.subject_alt_names[0] === "string"
      ? certificate.subject_alt_names[0].trim()
      : "";
  const raw = rawCommonName || rawFirstSan;
  const stripped = raw.replace(SUBJECT_ALT_NAME_TYPE_PREFIX, "").trim();
  return stripped || null;
}

/**
 * Dedupe key for an adoption intent.
 *
 * Keyed on the job, not the certificate: the unique index is
 * (workspace_id, event_type, dedupe_key) and the enqueue is
 * ON CONFLICT DO NOTHING, so a replayed job creation (the manual-creation path
 * returns the existing job on an idempotency hit, producing the same job id)
 * enqueues nothing the second time instead of arming a second derivation.
 */
const ADOPTION_DEDUPE_KEY_PREFIX = "derive-profile:";

function adoptionIntentDedupeKey(jobId) {
  return `${ADOPTION_DEDUPE_KEY_PREFIX}${String(jobId)}`;
}

/**
 * Sources that describe a place the certificate is actually installed, as
 * opposed to a vantage point it was merely observed from. Only a deployment
 * location can be renewed into, so only these count towards the adoption block.
 * agent_windows belongs here only for actionable IIS binding observations.
 * A machine-store row can accompany the same IIS certificate, but it is the
 * underlying observation rather than a second place to deploy. http.sys is
 * likewise observation-only until it has its own renewal executor.
 */
const DEPLOYMENT_INSTANCE_SOURCES = Object.freeze([
  "agent_filesystem",
  "agent_windows",
  "cert_manager",
]);

/**
 * Instance statuses that no longer describe a live location.
 */
const RETIRED_INSTANCE_STATUSES = Object.freeze(["decommissioned", "missing"]);

function adoptionError(message, code) {
  const error = new Error(message);
  error.code = code || CERTOPS_CERTIFICATE_NOT_FOUND;
  error.statusCode = code === CERTOPS_CERTIFICATE_NOT_FOUND ? 404 : 422;
  return error;
}

function renewalSetupError(message, code, statusCode = 409) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = statusCode;
  return error;
}

/**
 * Record the operator's intent to derive a renewal profile from a job.
 *
 * Takes the caller's transaction client so the intent and the job it depends on
 * commit together: an intent without its job would never terminate, and a job
 * without its intent would leave the operator watching a form that armed
 * nothing.
 */
async function enqueueRenewalAdoptionIntent({
  client,
  workspaceId,
  jobId,
  certificateId,
  operation = null,
} = {}) {
  return await enqueueOutboxEvent({
    client,
    workspaceId,
    eventType: OUTBOX_EVENT_TYPES.PROFILE_DERIVATION_REQUESTED,
    dedupeKey: adoptionIntentDedupeKey(jobId),
    payload: {
      jobId: String(jobId),
      certificateId: String(certificateId),
      operation: operation || null,
    },
  });
}

/**
 * How many live deployment locations a certificate has.
 *
 * COUNT(DISTINCT target_id), never COUNT(*). certificate_instances is unique on
 * (workspace_id, target_id, managed_certificate_id, observed_fingerprint_sha256)
 * and a new fingerprint at the same target appends a row as rotation history,
 * so COUNT(*) counts rotations: an ordinary single-location certificate that has
 * rotated three times would look like a three-location one. Superseded rotation
 * rows are never restatused either, so filtering on the live statuses does not
 * deduplicate them.
 */
async function countCertificateDeploymentLocations({
  db = pool,
  workspaceId,
  certificateId,
} = {}) {
  const result = await db.query(
    `SELECT COUNT(DISTINCT ci.target_id)::int AS locations
       FROM certificate_instances ci
      WHERE ci.workspace_id = $1
        AND ci.managed_certificate_id = $2::uuid
        AND ci.source = ANY($3::text[])
        AND (ci.source <> 'agent_windows' OR ci.location_kind = 'iis_binding')
        AND NOT (ci.status = ANY($4::text[]))`,
    [
      workspaceId,
      certificateId,
      DEPLOYMENT_INSTANCE_SOURCES,
      RETIRED_INSTANCE_STATUSES,
    ],
  );
  return Number(result.rows[0]?.locations || 0);
}

async function loadWindowsRenewalTopology({
  db = pool,
  workspaceId,
  certificateId,
  deployedAgentId,
} = {}) {
  const result = await db.query(
    `SELECT ct.id AS target_id,
            ct.deployment_reference AS target_reference,
            ct.windows_store,
            ct.windows_site,
            ct.windows_port,
            ct.windows_sni_host,
            a.id AS agent_row_id,
            a.declared_target_selectors
       FROM certificate_instances ci
       JOIN certificate_targets ct
         ON ct.workspace_id = ci.workspace_id AND ct.id = ci.target_id
       JOIN certops_agents a
         ON a.workspace_id = ci.workspace_id
        AND a.id = $3::uuid
        AND a.status <> 'retired'
      WHERE ci.workspace_id = $1
        AND ci.managed_certificate_id = $2::uuid
        AND ci.source = 'agent_windows'
        AND ci.location_kind = 'iis_binding'
        AND ct.target_type = 'windows-iis'
        AND NOT (ci.status = ANY($4::text[]))
      ORDER BY ci.observed_at DESC NULLS LAST, ci.updated_at DESC`,
    [workspaceId, certificateId, deployedAgentId, RETIRED_INSTANCE_STATUSES],
  );

  const byTarget = new Map();
  for (const row of result.rows) {
    if (!byTarget.has(String(row.target_id))) byTarget.set(String(row.target_id), row);
  }
  if (byTarget.size !== 1) return null;
  const row = [...byTarget.values()][0];
  const selectors = Array.isArray(row.declared_target_selectors)
    ? row.declared_target_selectors.filter((value) => typeof value === "string" && value)
    : [];
  const storedReference =
    typeof row.target_reference === "string" && row.target_reference.trim()
      ? row.target_reference.trim()
      : null;
  const targetReference =
    storedReference && selectors.includes(storedReference)
      ? storedReference
      : null;
  if (
    !targetReference ||
    typeof row.windows_store !== "string" ||
    !WINDOWS_STORE_NAME_PATTERN.test(row.windows_store) ||
    typeof row.windows_site !== "string" ||
    !WINDOWS_IIS_SITE_PATTERN.test(row.windows_site) ||
    !Number.isSafeInteger(row.windows_port) ||
    row.windows_port < 1 ||
    row.windows_port > 65535 ||
    (row.windows_sni_host !== null &&
      row.windows_sni_host !== undefined &&
      (typeof row.windows_sni_host !== "string" ||
        !WINDOWS_SNI_HOST_PATTERN.test(row.windows_sni_host)))
  ) {
    return null;
  }
  return {
    assignedAgentId: row.agent_row_id,
    target: {
      type: "windows-iis",
      reference: targetReference,
      store: row.windows_store,
      binding: {
        site: row.windows_site,
        port: row.windows_port,
        sniHost: row.windows_sni_host || null,
      },
      thumbprintSha1: null,
    },
  };
}

/**
 * Detach a certificate from its renewal profile.
 *
 * One transaction does three things that must not be separable: nulling
 * profile_id, recording the audit event, and invalidating any outstanding
 * adoption intent. Skipping the third would let the drain re-attach a profile
 * minutes after the operator removed it, and the profile_id IS NULL guard in
 * derivation cannot catch that, because after a detach that is exactly the
 * state.
 *
 * The profile row itself is left alone. Profiles can cover several
 * certificates, so deleting one would silently change what runs for a sibling.
 */
async function detachRenewalProfile({
  dbPool = pool,
  workspaceId,
  certificateId,
  actorUserId = null,
  auditWriter = writeAudit,
} = {}) {
  const client = await dbPool.connect();
  let transactionStarted = false;
  try {
    await client.query("BEGIN");
    transactionStarted = true;

    const locked = await client.query(
      `SELECT mc.id, mc.common_name, mc.profile_id, cp.name AS profile_name
         FROM managed_certificates mc
         LEFT JOIN certificate_profiles cp
           ON cp.workspace_id = mc.workspace_id AND cp.id = mc.profile_id
        WHERE mc.workspace_id = $1 AND mc.id = $2::uuid
        FOR UPDATE OF mc`,
      [workspaceId, certificateId],
    );
    const row = locked.rows[0];
    if (!row) {
      throw adoptionError("Certificate not found", CERTOPS_CERTIFICATE_NOT_FOUND);
    }
    if (!row.profile_id) {
      throw adoptionError(
        "This certificate is not linked to a renewal profile",
        CERTOPS_CERTIFICATE_NOT_PROFILED,
      );
    }

    const detachedProfileId = String(row.profile_id);

    await client.query(
      `UPDATE managed_certificates
          SET profile_id = NULL,
              updated_at = NOW()
        WHERE workspace_id = $1 AND id = $2::uuid`,
      [workspaceId, certificateId],
    );

    const invalidated = await invalidateProfileDerivationIntents({
      client,
      workspaceId,
      certificateId,
      reason: OUTBOX_OUTCOME_DETACHED,
    });

    // Withdrawing standing authority to re-run a command on a host is as much
    // an authority change as granting it, so it gets the same durable record
    // the derivation grant does.
    await auditWriter({
      client,
      actorUserId,
      subjectUserId: actorUserId,
      action: "CERTOPS_RENEWAL_PROFILE_DETACHED",
      targetType: "managed_certificate",
      targetId: null,
      workspaceId,
      metadata: {
        managedCertificateId: String(certificateId),
        commonName: row.common_name || null,
        profileId: detachedProfileId,
        profileName: row.profile_name || null,
        invalidatedIntents: invalidated.invalidated,
      },
    });

    await client.query("COMMIT");
    transactionStarted = false;

    return {
      certificateId: String(certificateId),
      detachedProfileId,
      invalidatedIntents: invalidated.invalidated,
    };
  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {
        // Preserve the primary failure for the caller.
      }
    }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Builds the jobCreator swapped into createManualCertificateJob for
 * "Set up automatic renewal". Runs inside that function's workspace-locked
 * transaction, so eligibility is checked against the same row the job is
 * about to reference, and (for a real run) the adoption intent is enqueued
 * in the same transaction that creates the job.
 *
 * A dry run enqueues no intent even if the job succeeds: only the confirm
 * step arms derivation, so a preflight can never adopt anything on its own.
 * The check is on the requested mode, not the eventual outcome, because the
 * intent has to be decided at creation time alongside the job.
 */
function renewalSetupJobCreator({
  certificateId,
  countLocations = countCertificateDeploymentLocations,
  loadWindowsTopology = loadWindowsRenewalTopology,
  createJob = createCertificateJob,
  enqueueIntent = enqueueRenewalAdoptionIntent,
} = {}) {
  return async function renewalSetupJobCreator(options) {
    const { client, workspaceId } = options;

    const certResult = await client.query(
      `SELECT id, status, key_mode, profile_id, deployed_cert_path,
              deployed_agent_id, common_name, subject_alt_names
         FROM managed_certificates
        WHERE workspace_id = $1 AND id = $2::uuid
        FOR UPDATE`,
      [workspaceId, certificateId],
    );
    const certificate = certResult.rows[0];
    if (!certificate) {
      throw adoptionError("Certificate not found", CERTOPS_CERTIFICATE_NOT_FOUND);
    }
    if (certificate.profile_id) {
      throw renewalSetupError(
        "This certificate already has a renewal profile. Detach it before setting renewal up again.",
        CERTOPS_RENEWAL_SETUP_ALREADY_CONFIGURED,
      );
    }
    if (!isAgentDeployableKeyMode(certificate)) {
      throw renewalSetupError(
        "TokenTimer does not hold this certificate's key, so it is monitored only and cannot be renewed by an agent.",
        CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE,
      );
    }
    const isWindowsDeployment = certificate.key_mode === "os-store-managed";
    if (!isWindowsDeployment && !certificate.deployed_cert_path) {
      throw renewalSetupError(
        "No discovered deployment path is recorded for this certificate, so automatic renewal has nowhere to deploy to.",
        CERTOPS_RENEWAL_SETUP_NO_DEPLOYED_PATH,
        422,
      );
    }

    // The schema has one deployed_cert_path per certificate and no path or
    // reload column on instances/targets at all, so a second location has
    // nowhere to be recorded and would silently go unrenewed under a badge
    // that reads "auto". Refusing is the honest answer until the schema can
    // describe more than one deployment.
    const locations = await countLocations({
      db: client,
      workspaceId,
      certificateId,
    });
    if (locations > 1) {
      throw renewalSetupError(
        `Automatic renewal setup is refused: this certificate is deployed to ${locations} locations and only one can be automated today.`,
        CERTOPS_RENEWAL_SETUP_MULTI_LOCATION,
      );
    }

    let windowsTopology = null;
    let domainTargetReference = null;
    if (isWindowsDeployment) {
      if (!certificate.deployed_agent_id) {
        throw renewalSetupError(
          "The discovered Windows deployment is not associated with an executor agent.",
          CERTOPS_RENEWAL_SETUP_WINDOWS_TOPOLOGY_INCOMPLETE,
          422,
        );
      }
      windowsTopology = await loadWindowsTopology({
        db: client,
        workspaceId,
        certificateId,
        deployedAgentId: certificate.deployed_agent_id,
      });
      if (!windowsTopology) {
        throw renewalSetupError(
          "The discovered Windows certificate does not have one complete IIS store/binding topology with a claimable target selector.",
          CERTOPS_RENEWAL_SETUP_WINDOWS_TOPOLOGY_INCOMPLETE,
          422,
        );
      }
    } else {
      // executeRenewJob (packages/agent) unconditionally requires
      // job.target.reference to use as the renewal CSR's commonName, for
      // every renew job regardless of deployment type - not just windows-iis.
      // Without this, every filesystem-discovered certificate's "Set up
      // renewal" job fails immediately with "renew job has no
      // target.reference to use as the certificate CN" once claimed, and the
      // certificate is left parked in renewalSetup state "skipped" /
      // outcomeCode "job_failed".
      domainTargetReference = deriveDomainTargetReference(certificate);
      if (!domainTargetReference) {
        throw renewalSetupError(
          "This certificate has no usable common name or subject alternative name on record, so an automatic renewal job cannot be built.",
          CERTOPS_RENEWAL_SETUP_NO_COMMON_NAME,
          422,
        );
      }
    }

    const payload = {
      ...(options.payload || {}),
      certificateId: String(certificateId),
    };
    if (windowsTopology) {
      // A Windows store/IIS executor has no filesystem certificate path.
      // Discard a caller-supplied legacy field rather than persisting a mixed
      // custody shape that no canonical executor should consume.
      delete payload.certPath;
      payload.keyMode = "os-store-managed";
      payload.target = windowsTopology.target;
    } else {
      payload.certPath = certificate.deployed_cert_path;
      payload.target = { type: "domain", reference: domainTargetReference };
    }

    const outcome = await createJob({
      ...options,
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: certificateId,
      // Explicit pin from the discovery that found this path: leaving the
      // assignment open would let whichever eligible agent polls first write
      // to a path only this host has.
      assignedAgentId:
        windowsTopology?.assignedAgentId ||
        options.assignedAgentId ||
        certificate.deployed_agent_id ||
        null,
      payload,
      returnOutcome: true,
    });

    const job = outcome?.job || outcome;
    const created = outcome?.created === true;
    if (created && job?.mode !== "dry_run") {
      await enqueueIntent({
        client,
        workspaceId,
        jobId: job.id,
        certificateId,
        operation: "renew",
      });
    }
    return outcome;
  };
}

/**
 * `renewalSetup` projection states: `none` (no intent has ever been recorded
 * for this certificate), `waiting` (the drain has not yet decided a pending
 * row), `configured` (the most recent intent succeeded), `skipped` (a
 * terminal, non-failure decision: dry run, detach, an unrenewable job
 * outcome, or a derivation conflict the operator must resolve some other
 * way), `failed` (parked after exhausting max_attempts, or currently
 * retryable).
 */
const RENEWAL_SETUP_STATES = Object.freeze({
  NONE: "none",
  WAITING: "waiting",
  CONFIGURED: "configured",
  SKIPPED: "skipped",
  FAILED: "failed",
});

/**
 * Operator-facing outcome codes. These are the only values `outcomeCode` can
 * ever hold, which is the point: the row's own `outcome_reason` is written by
 * the drain and `last_error` is a raw exception message, so both are
 * translated into this closed vocabulary rather than forwarded.
 */
const RENEWAL_SETUP_OUTCOME_CODES = Object.freeze({
  ALREADY_LINKED: "already_linked",
  DETACHED: "detached",
  DRY_RUN: "dry_run",
  JOB_NEVER_TERMINATED: "job_never_terminated",
  JOB_NOT_FOUND: "job_not_found",
  CERTIFICATE_NOT_FOUND: "certificate_not_found",
  NO_CLAIM_BOUND_EVIDENCE: "no_claim_bound_verify_evidence",
  MISSING_CERTIFICATE_ID: "missing_certificate_id",
  MISSING_JOB_ID: "missing_job_id",
  PROFILE_OPERATOR_OWNED: "profile_operator_owned",
  CERTIFICATE_LINK_CONFLICT: "certificate_link_conflict",
  JOB_FAILED: "job_failed",
  JOB_REJECTED: "job_rejected",
  JOB_CANCELLED: "job_cancelled",
  JOB_BLOCKED: "job_blocked",
  ORPHANED_UNKNOWN_EFFECT: "orphaned_unknown_effect",
  PROFILE_INCOMPLETE: "renewal_profile_incomplete",
  PROFILE_INVALID: "renewal_profile_invalid",
  DERIVATION_FAILED: "derivation_failed",
  UNKNOWN: "unknown",
});

/**
 * Terminal non-failure decisions, keyed by the `outcome_reason` the drain
 * persists. A reason outside this table is reported as `unknown` rather than
 * echoed: the column is 256 characters of free text at the database level, so
 * treating it as a closed vocabulary is a property of this projection, not
 * something the schema guarantees.
 */
const RENEWAL_SETUP_SKIP_MESSAGES = Object.freeze({
  [RENEWAL_SETUP_OUTCOME_CODES.ALREADY_LINKED]:
    "This certificate already had a renewal profile, so setup changed nothing.",
  [RENEWAL_SETUP_OUTCOME_CODES.DETACHED]:
    "Setup was cancelled because the certificate was detached from its renewal profile. Set it up again if you still want automatic renewal.",
  [RENEWAL_SETUP_OUTCOME_CODES.DRY_RUN]:
    "This was a preflight run, so nothing was configured. Confirm the setup to configure automatic renewal.",
  [RENEWAL_SETUP_OUTCOME_CODES.JOB_NEVER_TERMINATED]:
    "The renewal job never finished, so nothing was configured. Check that an agent can claim work for this certificate, then set it up again.",
  [RENEWAL_SETUP_OUTCOME_CODES.JOB_NOT_FOUND]:
    "The renewal job this setup depended on no longer exists, so nothing was configured.",
  [RENEWAL_SETUP_OUTCOME_CODES.CERTIFICATE_NOT_FOUND]:
    "The certificate no longer exists, so nothing was configured.",
  [RENEWAL_SETUP_OUTCOME_CODES.NO_CLAIM_BOUND_EVIDENCE]:
    "The renewal completed without verified deployment evidence for that attempt, so no renewal profile was built from it.",
  [RENEWAL_SETUP_OUTCOME_CODES.MISSING_CERTIFICATE_ID]:
    "The setup request was incomplete, so nothing was configured. Set the certificate up again.",
  [RENEWAL_SETUP_OUTCOME_CODES.MISSING_JOB_ID]:
    "The setup request was incomplete, so nothing was configured. Set the certificate up again.",
  [RENEWAL_SETUP_OUTCOME_CODES.PROFILE_OPERATOR_OWNED]:
    "A renewal profile for this certificate has been edited by an operator, so it was left untouched. Edit that profile directly, or detach it before setting renewal up again.",
  [RENEWAL_SETUP_OUTCOME_CODES.CERTIFICATE_LINK_CONFLICT]:
    "The certificate changed while setup was running, so no renewal profile was linked. Set it up again.",
  [RENEWAL_SETUP_OUTCOME_CODES.JOB_FAILED]:
    "The renewal job failed, so no renewal profile was built from it. Fix the failure and set the certificate up again.",
  [RENEWAL_SETUP_OUTCOME_CODES.JOB_REJECTED]:
    "The renewal job was rejected, so nothing was configured.",
  [RENEWAL_SETUP_OUTCOME_CODES.JOB_CANCELLED]:
    "The renewal job was cancelled, so nothing was configured.",
  [RENEWAL_SETUP_OUTCOME_CODES.JOB_BLOCKED]:
    "The renewal job was blocked, so nothing was configured.",
  [RENEWAL_SETUP_OUTCOME_CODES.ORPHANED_UNKNOWN_EFFECT]:
    "Nobody confirmed the result of the renewal job, so no renewal profile was built from it. Reconcile the certificate before setting renewal up again.",
  [RENEWAL_SETUP_OUTCOME_CODES.UNKNOWN]:
    "Automatic renewal was not configured. Check this certificate's jobs for the reason.",
});

/**
 * Failure classification.
 *
 * `last_error` is `String(error?.message)` truncated to 2048 characters, so it
 * can carry a driver or constraint message and must never reach a response.
 * The drain does not persist the error code either, so the known derivation
 * failures are recognised by their message signature and answered with text
 * authored here. `field` is a literal from this table, never a fragment cut
 * out of the stored message, so nothing from the raw error can travel with it.
 */
const RENEWAL_SETUP_FAILURE_SIGNATURES = Object.freeze([
  {
    pattern: /has no caEndpoint/i,
    outcomeCode: RENEWAL_SETUP_OUTCOME_CODES.PROFILE_INCOMPLETE,
    field: "the CA endpoint",
  },
  {
    pattern: /has no commandRef/i,
    outcomeCode: RENEWAL_SETUP_OUTCOME_CODES.PROFILE_INCOMPLETE,
    field: "the ACME command profile",
  },
  {
    pattern: /has no dnsProvider/i,
    outcomeCode: RENEWAL_SETUP_OUTCOME_CODES.PROFILE_INCOMPLETE,
    field: "the DNS provider and zone",
  },
  {
    pattern: /has no certPath/i,
    outcomeCode: RENEWAL_SETUP_OUTCOME_CODES.PROFILE_INCOMPLETE,
    field: "the deployment path",
  },
  {
    pattern: /has no common name/i,
    outcomeCode: RENEWAL_SETUP_OUTCOME_CODES.PROFILE_INCOMPLETE,
    field: "the common name",
  },
  {
    pattern: /^(issue job payload|reconciled certificate) is missing/i,
    outcomeCode: RENEWAL_SETUP_OUTCOME_CODES.PROFILE_INCOMPLETE,
    field: null,
  },
  {
    pattern: /renewalProfile is required/i,
    outcomeCode: RENEWAL_SETUP_OUTCOME_CODES.PROFILE_INCOMPLETE,
    field: null,
  },
  {
    pattern: /renewalProfile\.[a-z]/i,
    outcomeCode: RENEWAL_SETUP_OUTCOME_CODES.PROFILE_INVALID,
    field: null,
  },
]);

function renewalSetupFailureMessage(outcomeCode, field) {
  if (outcomeCode === RENEWAL_SETUP_OUTCOME_CODES.PROFILE_INCOMPLETE) {
    return field
      ? `Automatic renewal could not be configured because the renewal profile would be incomplete: ${field} was not recorded for this certificate. Supply it and set the certificate up again.`
      : "Automatic renewal could not be configured because the renewal profile would be incomplete: a required renewal setting was not recorded for this certificate.";
  }
  if (outcomeCode === RENEWAL_SETUP_OUTCOME_CODES.PROFILE_INVALID) {
    return "Automatic renewal could not be configured: the renewal profile built from this certificate was refused as invalid. Set the certificate up again with corrected values.";
  }
  return "The renewal profile could not be built from this job. Retry, or set the certificate up again once the underlying problem is fixed.";
}

/**
 * Classify a stored failure into a code and an authored message. Returns the
 * generic derivation failure for anything unrecognised, which keeps the raw
 * text server-side where the drain's own logging already has it.
 */
function classifyRenewalSetupFailure(lastError) {
  const text = typeof lastError === "string" ? lastError : "";
  const signature = RENEWAL_SETUP_FAILURE_SIGNATURES.find((candidate) =>
    candidate.pattern.test(text),
  );
  const outcomeCode =
    signature?.outcomeCode || RENEWAL_SETUP_OUTCOME_CODES.DERIVATION_FAILED;
  return {
    outcomeCode,
    message: renewalSetupFailureMessage(outcomeCode, signature?.field || null),
  };
}

function renewalSetupSkipOutcome(outcomeReason) {
  const reason = typeof outcomeReason === "string" ? outcomeReason : "";
  const outcomeCode = Object.prototype.hasOwnProperty.call(
    RENEWAL_SETUP_SKIP_MESSAGES,
    reason,
  )
    ? reason
    : RENEWAL_SETUP_OUTCOME_CODES.UNKNOWN;
  return {
    outcomeCode,
    message: RENEWAL_SETUP_SKIP_MESSAGES[outcomeCode],
  };
}

/**
 * Load the most recent profile-derivation intent per certificate, keyed by
 * `certificateId`. Callers project each row into the `renewalSetup` shape
 * with projectRenewalSetupState; kept separate so a single-certificate fetch
 * (the detail route) and a batched one (any list route that wants the same
 * projection) share one query shape.
 *
 * DISTINCT ON ... ORDER BY created_at DESC: a certificate can accumulate more
 * than one intent over its lifetime (adopt, detach, adopt again), and only
 * the latest one describes the current setup attempt.
 */
async function loadRenewalSetupIntents({
  db = pool,
  workspaceId,
  certificateIds,
} = {}) {
  const ids = Array.isArray(certificateIds)
    ? certificateIds.filter(Boolean).map(String)
    : [];
  if (ids.length === 0) return new Map();

  const result = await db.query(
    `SELECT DISTINCT ON (payload->>'certificateId')
            payload->>'certificateId' AS certificate_id,
            id,
            payload->>'jobId' AS job_id,
            status,
            outcome_reason,
            attempt_count,
            max_attempts,
            last_error,
            created_at,
            updated_at
       FROM certops_outbox
      WHERE workspace_id = $1
        AND event_type = $2
        AND payload->>'certificateId' = ANY($3::text[])
      ORDER BY payload->>'certificateId', created_at DESC`,
    [workspaceId, OUTBOX_EVENT_TYPES.PROFILE_DERIVATION_REQUESTED, ids],
  );

  return new Map(
    result.rows.map((row) => [String(row.certificate_id), row]),
  );
}

/**
 * Project one outbox row (as returned by loadRenewalSetupIntents) into the
 * dashboard-facing `renewalSetup` shape. Returns the `none` state when no
 * intent has ever been recorded, which is the ordinary case for a
 * certificate nobody has tried to adopt.
 *
 * `intentId` is present only while the row is retryable, because it exists
 * for exactly one caller: the retry route. Offering it on a `skipped` row
 * would invite a UI to present a retry action the service refuses, and a
 * detached intent is precisely the row that must not come back.
 */
function projectRenewalSetupState(row) {
  if (!row) {
    return {
      state: RENEWAL_SETUP_STATES.NONE,
      jobId: null,
      attempts: 0,
      outcomeCode: null,
      message: null,
      intentId: null,
    };
  }

  const attempts = Number(row.attempt_count || 0);
  const jobId = row.job_id ? String(row.job_id) : null;

  if (row.status === "succeeded") {
    return {
      state: RENEWAL_SETUP_STATES.CONFIGURED,
      jobId,
      attempts,
      outcomeCode: null,
      message: null,
      intentId: null,
    };
  }
  if (row.status === "skipped") {
    const outcome = renewalSetupSkipOutcome(row.outcome_reason);
    return {
      state: RENEWAL_SETUP_STATES.SKIPPED,
      jobId,
      attempts,
      outcomeCode: outcome.outcomeCode,
      message: outcome.message,
      intentId: null,
    };
  }
  if (row.status === "failed") {
    const outcome = classifyRenewalSetupFailure(row.last_error);
    return {
      state: RENEWAL_SETUP_STATES.FAILED,
      jobId,
      attempts,
      outcomeCode: outcome.outcomeCode,
      message: outcome.message,
      intentId: row.id ? String(row.id) : null,
    };
  }
  // 'pending': either not yet claimed or deferred and rescheduled.
  return {
    state: RENEWAL_SETUP_STATES.WAITING,
    jobId,
    attempts,
    outcomeCode: null,
    message: null,
    intentId: null,
  };
}

/**
 * Job statuses a preflight can terminate in. A dry run never reports
 * `succeeded`, so `dry_run_complete` is the only status that means "the
 * preflight ran and produced a result the operator can resume from".
 */
const PREFLIGHT_COMPLETE_JOB_STATUS = "dry_run_complete";

/**
 * Completed preflights with nothing armed behind them, keyed by
 * `certificateId`.
 *
 * The preflight's state has to be server state: it is an asynchronous job, so
 * closing the modal or reloading the page must not lose a completed one.
 * Rows whose certificate already has an adoption intent are excluded, because
 * once the confirm step has run the preflight is history rather than a step
 * still waiting to be finished.
 */
async function loadResumablePreflights({
  db = pool,
  workspaceId,
  certificateIds,
} = {}) {
  const ids = Array.isArray(certificateIds)
    ? certificateIds.filter(Boolean).map(String)
    : [];
  if (ids.length === 0) return new Map();

  const result = await db.query(
    `SELECT DISTINCT ON (j.subject_id)
            j.subject_id::text AS certificate_id,
            j.id,
            j.status,
            j.completed_at,
            j.created_at
       FROM certificate_jobs j
      WHERE j.workspace_id = $1
        AND j.subject_type = 'managed_certificate'
        AND j.subject_id::text = ANY($2::text[])
        AND j.operation = 'renew'
        AND j.mode = 'dry_run'
        AND j.status = $3
        AND NOT EXISTS (
              SELECT 1
                FROM certops_outbox o
               WHERE o.workspace_id = j.workspace_id
                 AND o.event_type = $4
                 AND o.payload->>'certificateId' = j.subject_id::text
            )
      ORDER BY j.subject_id, j.created_at DESC`,
    [
      workspaceId,
      ids,
      PREFLIGHT_COMPLETE_JOB_STATUS,
      OUTBOX_EVENT_TYPES.PROFILE_DERIVATION_REQUESTED,
    ],
  );

  return new Map(result.rows.map((row) => [String(row.certificate_id), row]));
}

/**
 * Project a resumable preflight row into the certificate response. Ids and
 * timestamps only: the job detail route already serves the preflight's own
 * result, so duplicating any of it here would be a second copy to keep true.
 */
function projectRenewalPreflight(row) {
  if (!row) {
    return { available: false, jobId: null, completedAt: null };
  }
  const completedAt = row.completed_at || row.created_at || null;
  return {
    available: true,
    jobId: String(row.id),
    completedAt:
      completedAt instanceof Date
        ? completedAt.toISOString()
        : completedAt
          ? String(completedAt)
          : null,
  };
}

/**
 * Retry a parked adoption intent. Thin wrapper over
 * resetOutboxEventForRetry, scoped to profile-derivation rows only so this
 * route can never be repurposed to revive a renewal-alert intent: retry is
 * part of the adopt-flow contract, not a generic outbox admin surface.
 */
async function retryRenewalSetupIntent({
  dbPool = pool,
  workspaceId,
  outboxId,
} = {}) {
  const existing = await dbPool.query(
    `SELECT event_type FROM certops_outbox
      WHERE workspace_id = $1 AND id = $2::uuid`,
    [workspaceId, outboxId],
  );
  const row = existing.rows[0];
  if (!row) {
    throw renewalSetupError(
      "Outbox event not found",
      CERTOPS_OUTBOX_EVENT_NOT_FOUND,
      404,
    );
  }
  if (row.event_type !== OUTBOX_EVENT_TYPES.PROFILE_DERIVATION_REQUESTED) {
    throw renewalSetupError(
      "Only a profile-derivation intent can be retried through this route",
      CERTOPS_OUTBOX_EVENT_NOT_RETRYABLE,
      422,
    );
  }
  return await resetOutboxEventForRetry({ client: dbPool, workspaceId, outboxId });
}

module.exports = {
  ADOPTION_DEDUPE_KEY_PREFIX,
  CERTOPS_CERTIFICATE_NOT_FOUND,
  CERTOPS_CERTIFICATE_NOT_PROFILED,
  CERTOPS_RENEWAL_SETUP_ALREADY_CONFIGURED,
  CERTOPS_RENEWAL_SETUP_MULTI_LOCATION,
  CERTOPS_RENEWAL_SETUP_NO_DEPLOYED_PATH,
  CERTOPS_RENEWAL_SETUP_NO_COMMON_NAME,
  CERTOPS_RENEWAL_SETUP_WINDOWS_TOPOLOGY_INCOMPLETE,
  DEPLOYMENT_INSTANCE_SOURCES,
  PREFLIGHT_COMPLETE_JOB_STATUS,
  RETIRED_INSTANCE_STATUSES,
  RENEWAL_SETUP_OUTCOME_CODES,
  RENEWAL_SETUP_STATES,
  adoptionIntentDedupeKey,
  classifyRenewalSetupFailure,
  countCertificateDeploymentLocations,
  detachRenewalProfile,
  enqueueRenewalAdoptionIntent,
  loadRenewalSetupIntents,
  loadResumablePreflights,
  loadWindowsRenewalTopology,
  projectRenewalPreflight,
  projectRenewalSetupState,
  renewalSetupJobCreator,
  retryRenewalSetupIntent,
};
