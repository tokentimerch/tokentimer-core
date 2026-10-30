"use strict";

// Read models for the operator namespace. Each function calls an existing
// CertOps service and hands the result to a projection that names every field
// it returns. No SQL on certificate, agent or job tables lives here: the
// lifecycle, status and renewal rules stay in the services that own them.

const { pool } = require("../../db/database");
const { logger } = require("../../utils/logger");
const { listCertificateIdentities } = require("../certops/certificateIdentity");
const { listAgents } = require("../certops/agentRegistry");
const { getCertificateJobById, listCertificateJobs } = require("../certops/jobs");
const { resolveRenewalPathsForCertificateIds } = require("../certops/renewalPathHealth");
const read = require("./readProjections");
const { isoOrNull, snakeCodeOrNull } = require("./projections");

const DAY_MS = 24 * 60 * 60 * 1000;

// The topology switch is forced off for every connection regardless of the
// represented user's role: key references, deployed paths and source
// references are never returned (ADR-0015).
const NO_TOPOLOGY = Object.freeze({ canReadTopology: false });

async function loadRenewalPaths({ workspaceId, records }) {
  const ids = records.map((r) => r.managedCertificateId).filter(Boolean);
  if (ids.length === 0) return new Map();
  try {
    return await resolveRenewalPathsForCertificateIds({ db: pool, workspaceId, certificateIds: ids });
  } catch (error) {
    // Renewal-path health is an enrichment. Losing it must not hide the
    // certificates, so the field reports null ("unknown") instead.
    logger.warn("Operator renewal-path enrichment failed", { error: error.message });
    return new Map();
  }
}

async function isWorkspacePaused(workspaceId) {
  try {
    const row = await pool.query("SELECT certops_paused FROM workspaces WHERE id = $1", [workspaceId]);
    return row.rows[0]?.certops_paused === true;
  } catch (_error) {
    return false;
  }
}

async function listCertificates({
  workspaceId,
  status,
  includeRetired = false,
  expiresWithinDays,
  expiresBefore,
  query,
  limit,
  offset,
  now = Date.now(),
}) {
  let bound = null;
  if (expiresWithinDays) bound = new Date(now + expiresWithinDays * DAY_MS);
  else if (expiresBefore) bound = new Date(expiresBefore);
  const result = await listCertificateIdentities({
    workspaceId,
    limit,
    offset,
    status,
    excludeRetired: !includeRetired,
    // A retired certificate that is still being observed is exactly what an
    // operator needs to see, so it stays visible even when retired ones are not.
    includeObservedRetired: true,
    q: query,
    restrictedSearch: true,
    expiresBefore: bound,
    ...NO_TOPOLOGY,
  });
  const paths = await loadRenewalPaths({ workspaceId, records: result.items });
  const items = result.items.map((record) =>
    read.projectCertificateSummary(record, {
      renewalPathState: paths.get(String(record.managedCertificateId))?.renewalPathState ?? null,
      now,
    }),
  );
  return {
    items,
    completeness: read.completeness({ offset, returned: items.length, total: result.pagination.total }),
  };
}

async function loadIdentity({ workspaceId, identityId, fingerprintSha256 }) {
  const result = await listCertificateIdentities({
    workspaceId,
    identityId,
    // An id may name a provisional certificate, which has no fingerprint.
    includeProvisional: Boolean(identityId),
    q: identityId ? undefined : fingerprintSha256,
    restrictedSearch: true,
    limit: 1,
    offset: 0,
    excludeRetired: false,
    ...NO_TOPOLOGY,
  });
  // A provisional record's `id` is the handle the list returned.
  return (
    result.items.find((item) =>
      identityId ? (item.identityId || item.id) === identityId : item.fingerprintSha256 && item.fingerprintSha256 === fingerprintSha256,
    ) || null
  );
}

async function getCertificate({ workspaceId, identityId, fingerprintSha256, now = Date.now() }) {
  const record = await loadIdentity({ workspaceId, identityId, fingerprintSha256 });
  if (!record) return null;
  const [paths, paused] = await Promise.all([
    loadRenewalPaths({ workspaceId, records: [record] }),
    isWorkspacePaused(workspaceId),
  ]);
  return {
    certificate: read.projectCertificateDetail(record, {
      renewalPath: paths.get(String(record.managedCertificateId)) || null,
      workspacePaused: paused,
      now,
    }),
  };
}

async function getObservations({ workspaceId, identityId, limit, offset }) {
  const record = await loadIdentity({ workspaceId, identityId });
  if (!record) return null;
  return read.projectObservations(record, { limit, offset });
}

async function listAgentHealth({ workspaceId, limit, offset, now = Date.now() }) {
  const result = await listAgents({ workspaceId, limit, offset });
  const items = result.items.map((agent) => read.projectAgent(agent, { now }));
  return {
    items,
    completeness: read.completeness({ offset, returned: items.length, total: result.pagination.total }),
  };
}

async function listJobs({ workspaceId, status, operation, subjectId, createdSince, limit, offset }) {
  const result = await listCertificateJobs({
    workspaceId,
    status,
    operation,
    subjectId,
    createdSince,
    limit,
    offset,
    // The free-text job search also reads agent names and hostnames, so it is
    // never passed through.
    q: undefined,
  });
  const items = result.items.map(read.projectJobSummary);
  return {
    items,
    completeness: read.completeness({ offset, returned: items.length, total: result.pagination.total }),
  };
}

async function getJob({ workspaceId, jobId }) {
  const job = await getCertificateJobById({ workspaceId, jobId });
  if (!job) return null;
  return { job: read.projectJobDetail(job) };
}

// ---------------------------------------------------------------------------
// Explanation
//
// Deterministic and server-side. It composes reason codes the existing
// services already produce and words them from a fixed table. It never uses a
// service's free-text summary or dependency list, because those can contain
// agent names and hostnames. When the evidence is missing it says so (an
// unknown area) instead of sounding certain.

const RENEWAL_PATH_WORDING = Object.freeze({
  all_paths_available: ["info", "Every renewal path for this certificate is available."],
  partial_location_outage: ["warning", "Some locations that serve this certificate have no available renewal path."],
  agent_offline: ["warning", "An agent that this renewal depends on is offline."],
  all_executors_offline: ["blocking", "Every agent that this renewal depends on is offline, so renewal cannot run."],
  no_execution_target: ["blocking", "No agent or target is configured to perform renewal."],
  topology_unknown: ["warning", "TokenTimer cannot determine the renewal path from the facts it holds."],
  assigned_agent_retired: ["blocking", "The agent pinned to this certificate has been retired, so renewal must be re-homed."],
  assigned_agent_ineligible: ["blocking", "The agent pinned to this certificate cannot currently claim renewal work."],
  adcs_enroll_capability_unavailable: ["blocking", "No agent has recently declared support for AD CS enrollment."],
  waiting_for_fresh_preflight: ["warning", "Renewal is waiting for a fresh AD CS preflight check."],
  auto_renew_disabled: ["warning", "Automatic renewal is switched off for this certificate."],
  not_agent_deployable: ["info", "TokenTimer does not hold this certificate's key, so it is monitored only and cannot be renewed by an agent."],
  no_profile: ["warning", "No renewal profile is linked to this certificate."],
  certificate_retired: ["info", "The certificate is retired, so renewal does not apply."],
});

const LIFECYCLE_WORDING = Object.freeze({
  revoked: ["lifecycle_revoked", "Recorded as revoked in TokenTimer. This does not mean the issuing CA revoked it."],
  decommissioned: [
    "lifecycle_decommissioned",
    "Recorded as decommissioned in TokenTimer. This is an operator declaration, not proof the certificate is gone.",
  ],
});

const AWAITING_JOB_STATUSES = new Set(["pending_approval", "approved", "pending", "claimed", "running"]);

function reason({ code, domain, severity, message, evidenceAt = null, sourceRef = null }) {
  return { code, domain, severity, message: message.slice(0, read.MAX_MESSAGE), evidenceAt, sourceRef };
}

function renewalReasons(path, unknownAreas) {
  if (!path) {
    unknownAreas.add("renewal_path");
    return [];
  }
  const code = path.renewalPathReason;
  const [severity, message] = RENEWAL_PATH_WORDING[code] || [];
  if (path.renewalPathState === "unknown") unknownAreas.add("renewal_path");
  if (!code || !message) {
    if (!code && path.renewalPathState === "healthy") {
      return [reason({ code: "all_paths_available", domain: "renewal_path", severity: "info", message: RENEWAL_PATH_WORDING.all_paths_available[1] })];
    }
    return [];
  }
  const offline = (path.dependencies || []).find((d) => d.required && d.online === false);
  const wantsAgent = code === "agent_offline" || code === "all_executors_offline";
  return [
    reason({
      code,
      domain: "renewal_path",
      severity,
      message,
      sourceRef: wantsAgent && offline && read.isUuid(offline.agentRowId) ? { kind: "agent", id: offline.agentRowId } : null,
    }),
  ];
}

function jobReasons(jobs) {
  const out = [];
  const [latest] = jobs;
  for (const job of jobs) {
    if (AWAITING_JOB_STATUSES.has(job.status) && job.pendingReason?.code) {
      const pendingCode = snakeCodeOrNull(job.pendingReason.code);
      if (!pendingCode) continue;
      out.push(
        reason({
          code: pendingCode,
          domain: "job",
          severity: "warning",
          // Fixed wording; the upstream message can carry agent-declared text.
          message: read.pendingWording(pendingCode),
          evidenceAt: isoOrNull(job.updatedAt),
          sourceRef: read.isUuid(job.id) ? { kind: "job", id: job.id } : null,
        }),
      );
    }
    if (job.needsOperatorReconciliation === true) {
      out.push(
        reason({
          code: "job_needs_reconciliation",
          domain: "job",
          severity: "blocking",
          message: "A job for this certificate has an unknown outcome and needs operator reconciliation.",
          evidenceAt: isoOrNull(job.updatedAt),
          sourceRef: read.isUuid(job.id) ? { kind: "job", id: job.id } : null,
        }),
      );
    }
  }
  if (latest && latest.status === "failed") {
    out.push(
      reason({
        code: "last_job_failed",
        domain: "job",
        severity: "warning",
        message: "The most recent job for this certificate failed.",
        evidenceAt: isoOrNull(latest.updatedAt),
        sourceRef: read.isUuid(latest.id) ? { kind: "job", id: latest.id } : null,
      }),
    );
  }
  return out;
}

function overallState({ lifecycleStatus, reasons, unknownAreas }) {
  if (lifecycleStatus !== "active") return "retired";
  if (reasons.some((r) => r.severity === "blocking")) return "blocked";
  if (reasons.some((r) => r.severity === "warning")) return "attention";
  if (unknownAreas.length > 0) return "unknown";
  return "healthy";
}

async function explainCertificate({ workspaceId, identityId, now = Date.now() }) {
  const record = await loadIdentity({ workspaceId, identityId });
  if (!record) return null;

  const unknownAreas = new Set();
  const reasons = [];
  const lifecycleStatus = ["active", "revoked", "decommissioned"].includes(record.lifecycleStatus)
    ? record.lifecycleStatus
    : "active";

  const wording = LIFECYCLE_WORDING[lifecycleStatus];
  if (wording) {
    reasons.push(reason({ code: wording[0], domain: "lifecycle", severity: "info", message: wording[1] }));
    if (record.stillObserved) {
      reasons.push(
        reason({
          code: "retired_still_observed",
          domain: "lifecycle",
          severity: "warning",
          message: "A retired certificate is still being observed in service.",
        }),
      );
    }
  } else {
    const expires = record.notAfter ? new Date(record.notAfter).getTime() : NaN;
    if (!Number.isFinite(expires)) {
      reasons.push(
        reason({ code: "expiry_unknown", domain: "lifecycle", severity: "warning", message: "The certificate's expiry date is not known." }),
      );
    } else if (expires < now) {
      reasons.push(
        reason({
          code: "certificate_expired",
          domain: "lifecycle",
          severity: "blocking",
          message: "The certificate's validity period has ended.",
          evidenceAt: isoOrNull(record.notAfter),
        }),
      );
    }
  }

  if (lifecycleStatus === "active") {
    const paths = await loadRenewalPaths({ workspaceId, records: [record] });
    const path = record.managedCertificateId ? paths.get(String(record.managedCertificateId)) : null;
    if (record.managedCertificateId) reasons.push(...renewalReasons(path || null, unknownAreas));

    if (record.visibilityUnknown === true) {
      unknownAreas.add("observations");
      reasons.push(
        reason({
          code: "visibility_unknown",
          domain: "observation",
          severity: "info",
          message: "Some locations have no confirmed observation.",
        }),
      );
    } else if (!record.stillObserved && Number(record.locationCount || 0) === 0) {
      reasons.push(
        reason({
          code: "not_observed",
          domain: "observation",
          severity: "info",
          message: "No location currently confirms this certificate in service.",
        }),
      );
    }
  }

  if (record.managedCertificateId) {
    try {
      const recent = await listCertificateJobs({
        workspaceId,
        subjectId: record.managedCertificateId,
        limit: 10,
        offset: 0,
      });
      reasons.push(...jobReasons(recent.items));
    } catch (error) {
      logger.warn("Operator explain could not read recent jobs", { error: error.message });
      unknownAreas.add("jobs");
    }
  }

  const areas = [...unknownAreas];
  return {
    identityId: record.identityId || record.id,
    evaluatedAt: new Date(now).toISOString(),
    lifecycleStatus,
    overall: overallState({ lifecycleStatus, reasons, unknownAreas: areas }),
    reasons: reasons.slice(0, 40),
    unknownAreas: areas,
  };
}

module.exports = {
  explainCertificate,
  getCertificate,
  getJob,
  getObservations,
  listAgentHealth,
  listCertificates,
  listJobs,
  loadIdentity,
  _test: { jobReasons, overallState, renewalReasons },
};
