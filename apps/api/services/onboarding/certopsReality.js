"use strict";

// CertOps part of the verified onboarding summary. Reads the same agent
// metadata the fleet panel shows so the wizard and the Agents page cannot
// disagree. Returns null when the caller cannot see it or CertOps is off, and
// callers must treat null as "unknown", never as "nothing installed".

const { listAgents } = require("../certops/agentRegistry");
const {
  CONTINUATION_STATES,
  DEFAULT_POLL_INTERVAL_SECONDS,
} = require("../certops/enrollmentLifecycle");

// Operations that only exist once execution is switched on in the agent.
const EXECUTION_OPERATIONS = new Set([
  "issue",
  "renew",
  "deploy",
  "reload",
  "revoke",
]);

function summarizeAgents(items, { now = Date.now(), since = null } = {}) {
  const agents = (items || []).filter(
    (a) => a.status !== "retired" && a.agentKind !== "diagnostic",
  );
  const sinceMs = since ? new Date(since).getTime() : null;
  const live = agents.filter((a) => a.livenessState === "live");
  const recent =
    sinceMs === null
      ? []
      : agents.filter((a) => new Date(a.createdAt).getTime() >= sinceMs);
  return {
    total: agents.length,
    live: live.length,
    registeredSinceToken: recent.length,
    executionEnabled: live.some((a) =>
      (a.supportedOperations || []).some((op) => EXECUTION_OPERATIONS.has(op)),
    ),
    items: agents.slice(0, 10).map((a) => ({
      id: a.id,
      wireAgentId: a.agentId,
      name: a.name,
      hostname: a.hostname,
      platform: a.platform,
      agentVersion: a.agentVersion,
      livenessState: a.livenessState,
      lastSeenAt: a.lastSeenAt,
      createdAt: a.createdAt || null,
      // True for an agent already in the workspace when the session began, so
      // the guide never counts it as installed by the session unless the
      // operator chose it ("My agent is already set up").
      existedBeforeSession:
        sinceMs !== null && new Date(a.createdAt).getTime() < sinceMs,
      compatibilityState: a.compatibilityState,
      clockDriftState: a.clockDriftState,
      ntpSynced: a.ntpSynced,
      declaredCapabilities: a.declaredCapabilities || [],
      supportedOperations: a.supportedOperations || [],
      targetSelectors: a.targetSelectors || [],
      commandProfiles: a.commandProfiles || [],
    })),
    nowIso: new Date(now).toISOString(),
  };
}

/**
 * Distribution is verified only when a rollout reached the verified state,
 * which requires consumer evidence. Existing groups alone prove nothing.
 */
async function loadDistributionReality(
  pool,
  workspaceId,
  { now = Date.now() } = {},
) {
  const { rows } = await pool.query(
    `SELECT (SELECT COUNT(*)::int FROM certops_distribution_groups WHERE workspace_id = $1) AS groups,
            (SELECT COUNT(*)::int FROM certops_consumer_bindings WHERE workspace_id = $1) AS bindings,
            (SELECT COUNT(*)::int FROM certops_distribution_rollouts
              WHERE workspace_id = $1 AND state = 'verified' AND verification_only = false) AS verified_rollouts`,
    [workspaceId],
  );
  const row = rows[0] || {};
  return {
    groups: row.groups || 0,
    bindings: row.bindings || 0,
    verified: (row.verified_rollouts || 0) > 0,
    outboxBacklog: await loadOutboxBacklog(pool, workspaceId, { now }),
  };
}

// Pending outbox rows that have been due for a while with nobody working on
// them. A deferred or backing-off row has a future next_retry_at, and a row a
// live worker holds has an unexpired lease, so neither counts. The window is
// generous (the worker defers for 60 s) because under Helm the worker starts
// fresh once a minute.
const OUTBOX_BACKLOG_MIN_AGE_MS = 5 * 60 * 1000;

async function loadOutboxBacklog(pool, workspaceId, { now = Date.now() } = {}) {
  const cutoff = new Date(now - OUTBOX_BACKLOG_MIN_AGE_MS);
  const { rows } = await pool.query(
    `SELECT COUNT(*)::int AS n, MIN(next_retry_at) AS oldest
       FROM certops_outbox
      WHERE workspace_id = $1
        AND status = 'pending'
        AND next_retry_at <= $2
        AND (claimed_until IS NULL OR claimed_until < $3)`,
    [workspaceId, cutoff, new Date(now)],
  );
  const row = rows[0] || {};
  const count = row.n || 0;
  return {
    count,
    oldestAt: count > 0 && row.oldest ? new Date(row.oldest).toISOString() : null,
  };
}

/**
 * Status of a job the wizard created, scoped to this workspace. Reading it
 * from the database means a dry run only counts when it really ended as
 * dry_run_complete.
 */
async function loadJobStatus(pool, workspaceId, jobId) {
  if (typeof jobId !== "string" || !/^[0-9a-f-]{36}$/i.test(jobId)) return null;
  const { rows } = await pool.query(
    `SELECT j.id, j.operation, j.status, j.mode, j.error_code, j.error_message,
            mc.status AS certificate_status, mc.id AS certificate_id,
            mc.token_id AS certificate_token_id
       FROM certificate_jobs j
       LEFT JOIN managed_certificates mc
         ON j.subject_type = 'managed_certificate' AND mc.id::text = j.subject_id
      WHERE j.workspace_id = $1 AND j.id = $2`,
    [workspaceId, jobId],
  );
  const row = rows[0];
  if (!row) return null;
  return {
    id: row.id,
    operation: row.operation,
    status: row.status,
    mode: row.mode,
    errorCode: row.error_code || null,
    // Shown in the wizard, so bounded; the full text stays in the job log.
    errorMessage: row.error_message ? String(row.error_message).slice(0, 300) : null,
    certificateStatus: row.certificate_status || null,
    certificateId: row.certificate_id || null,
    // Set once the issued certificate has an inventory token to carry groups.
    tokenId: row.certificate_token_id ?? null,
  };
}

const MAX_SESSION_CERTIFICATES = 20;

/**
 * The managed certificates this guide session produced: the issue and publish
 * jobs it created, AD CS enrollments started since the session began, and the
 * certificates an AD CS renewal profile of this session is attached to (the
 * chosen issuer's profiles when the operator reuses an issuer, else profiles
 * created since the session began). The last kind exists long before the
 * first enrollment. tokenId is null until the certificate has an inventory
 * token, and only tokens that still exist are returned.
 */
async function loadSessionCertificates(
  pool,
  workspaceId,
  { jobs = [], since = null, adcsIssuerId = null } = {},
) {
  const found = new Map();
  const add = (certificateId, tokenId, source) => {
    if (!certificateId || found.has(certificateId)) return;
    found.set(certificateId, {
      certificateId,
      tokenId: tokenId ?? null,
      source,
    });
  };
  for (const { job, source } of jobs) {
    add(job?.certificateId, job?.tokenId, source);
  }
  if (since) {
    const { rows } = await pool.query(
      `SELECT mc.id AS certificate_id, mc.token_id
         FROM certificate_enrollments e
         JOIN managed_certificates mc
           ON mc.workspace_id = e.workspace_id AND mc.id = e.certificate_id
        WHERE e.workspace_id = $1 AND e.created_at >= $2
          AND mc.status NOT IN ('decommissioned')
        ORDER BY e.created_at DESC
        LIMIT ${MAX_SESSION_CERTIFICATES}`,
      [workspaceId, since],
    );
    for (const row of rows) add(row.certificate_id, row.token_id, "enrollment");
  }
  const issuerId =
    typeof adcsIssuerId === "string" && UUID_PATTERN.test(adcsIssuerId)
      ? adcsIssuerId
      : null;
  if (since || issuerId) {
    const { rows } = await pool.query(
      `SELECT mc.id AS certificate_id, mc.token_id
         FROM managed_certificates mc
         JOIN certificate_profiles p
           ON p.workspace_id = mc.workspace_id AND p.id = mc.profile_id
         JOIN certificate_issuers i
           ON i.workspace_id = p.workspace_id AND i.id = p.issuer_id
        WHERE mc.workspace_id = $1
          AND i.kind = 'adcs'
          AND mc.status NOT IN ('decommissioned')
          AND (
            ($2::uuid IS NOT NULL AND i.id = $2::uuid)
            OR ($2::uuid IS NULL AND p.created_at >= $3::timestamptz)
          )
        ORDER BY mc.created_at DESC
        LIMIT ${MAX_SESSION_CERTIFICATES}`,
      [workspaceId, issuerId, since],
    );
    for (const row of rows) add(row.certificate_id, row.token_id, "profile");
  }
  return Array.from(found.values()).slice(0, MAX_SESSION_CERTIFICATES);
}

const MAX_OBSERVED_CERTIFICATES = 50;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CLUSTER_ID_PATTERN = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/**
 * Certificates that agents or the Kubernetes controller reported, narrowed to
 * what this session can own: those of the agent the operator chose, else of
 * agents enrolled since the session began; those of the named cluster, else
 * reported since the session began. The client narrows further by platform.
 * `total` counts the whole match, `items` is capped. tokenId is null until
 * the certificate has an inventory token to carry groups.
 */
async function loadObservedCertificates(
  pool,
  workspaceId,
  { since = null, agentId = null, clusterId = null } = {},
) {
  const agent =
    typeof agentId === "string" && UUID_PATTERN.test(agentId) ? agentId : null;
  const cluster =
    typeof clusterId === "string" && CLUSTER_ID_PATTERN.test(clusterId)
      ? clusterId
      : null;
  if (!since && !agent && !cluster) return { total: 0, items: [] };
  const { rows } = await pool.query(
    `SELECT mc.id AS certificate_id, mc.token_id, mc.source,
            mc.deployed_agent_id AS agent_id,
            split_part(mc.source_ref, '/', 1) AS cluster_id,
            COUNT(*) OVER()::int AS total
       FROM managed_certificates mc
       LEFT JOIN certops_agents a
         ON a.workspace_id = mc.workspace_id AND a.id = mc.deployed_agent_id
      WHERE mc.workspace_id = $1
        AND mc.status NOT IN ('decommissioned')
        AND (
          (mc.source IN ('agent_filesystem', 'agent_windows')
            AND (
              ($2::uuid IS NOT NULL AND mc.deployed_agent_id = $2::uuid)
              OR ($2::uuid IS NULL AND $3::timestamptz IS NOT NULL
                  AND a.created_at >= $3::timestamptz)
            ))
          OR (mc.source = 'cert_manager'
            AND (
              ($4::text IS NOT NULL AND split_part(mc.source_ref, '/', 1) = $4::text)
              OR ($4::text IS NULL AND $3::timestamptz IS NOT NULL
                  AND mc.created_at >= $3::timestamptz)
            ))
        )
      ORDER BY mc.created_at DESC
      LIMIT ${MAX_OBSERVED_CERTIFICATES}`,
    [workspaceId, agent, since, cluster],
  );
  return {
    total: rows[0]?.total || 0,
    items: rows.map((row) => ({
      certificateId: row.certificate_id,
      tokenId: row.token_id ?? null,
      source: row.source,
      agentId: row.agent_id || null,
      clusterId: row.source === "cert_manager" ? row.cluster_id || null : null,
    })),
  };
}

const PREFLIGHT_REASON_LIMIT = 6;

// What the guide needs to tell a draft from a failed check: whether a check
// has reported, the CA and template it ran against, and why it was unsafe.
function preflightFacts(row) {
  const pre = row.last_preflight;
  const reasons = [pre?.templateCheck, pre?.caCheck]
    .flatMap((check) => (Array.isArray(check?.reasons) ? check.reasons : []))
    .filter((r) => typeof r === "string" && r)
    .map((r) => r.slice(0, 200))
    .slice(0, PREFLIGHT_REASON_LIMIT);
  return {
    configured: Number(row.current_version) > 0,
    checked: Boolean(pre),
    caConfig: typeof pre?.caConfig === "string" ? pre.caConfig : null,
    template: typeof pre?.template === "string" ? pre.template : null,
    reasons,
  };
}

/**
 * AD CS issuers and profiles, by name and state only. An issuer counts as
 * confirmed once its current version has a pinned CA certificate, and as safe
 * once the last check found both the template and the CA safe.
 */
async function loadAdcsReality(
  pool,
  workspaceId,
  { now = Date.now(), since = null } = {},
) {
  const sinceMs = since ? new Date(since).getTime() : null;
  const issuers = await pool.query(
    `SELECT i.id, i.name, i.last_preflight, i.current_version, i.created_at,
            i.revalidation_required,
            (v.confirmed_at IS NOT NULL AND v.ca_key_sha256 IS NOT NULL) AS confirmed,
            (SELECT COUNT(*)::int FROM certificate_profiles p
              WHERE p.workspace_id = i.workspace_id AND p.issuer_id = i.id) AS profile_count,
            (SELECT COUNT(*)::int FROM managed_certificates mc
               JOIN certificate_profiles p
                 ON p.workspace_id = mc.workspace_id AND p.id = mc.profile_id
              WHERE mc.workspace_id = i.workspace_id AND p.issuer_id = i.id
                AND mc.status NOT IN ('decommissioned')) AS attached_certificates,
            (j.id IS NOT NULL AND v.confirmed_at IS NOT NULL
              AND COALESCE(j.completed_at, j.updated_at) >= v.confirmed_at) AS checked_after_pin
       FROM certificate_issuers i
       LEFT JOIN certificate_issuer_versions v
         ON v.issuer_id = i.id AND v.version = i.current_version
       LEFT JOIN certificate_jobs j
         ON j.workspace_id = i.workspace_id AND j.id = i.last_preflight_job_id
      WHERE i.workspace_id = $1 AND i.kind = 'adcs'
      ORDER BY i.created_at DESC
      LIMIT 20`,
    [workspaceId],
  );
  const profiles = await pool.query(
    `SELECT COUNT(*)::int AS n
       FROM certificate_profiles p
       JOIN certificate_issuers i ON i.id = p.issuer_id
      WHERE p.workspace_id = $1 AND i.kind = 'adcs'`,
    [workspaceId],
  );
  const enrollments = await pool.query(
    `SELECT COUNT(*) FILTER (WHERE state = 'installed')::int AS installed
       FROM certificate_enrollments
      WHERE workspace_id = $1`,
    [workspaceId],
  );
  const overdue = await loadOverdueEnrollments(pool, workspaceId, { now });
  return {
    issuers: issuers.rows.map((row) => {
      const confirmed = row.confirmed === true;
      const createdMs = row.created_at
        ? new Date(row.created_at).getTime()
        : null;
      return {
        id: row.id,
        name: row.name,
        confirmed,
        safe:
          row.last_preflight?.templateCheck?.verdict === "safe" &&
          row.last_preflight?.caCheck?.verdict === "safe",
        ...preflightFacts(row),
        createdAt:
          createdMs === null ? null : new Date(createdMs).toISOString(),
        // True for an issuer already in the workspace when the session began,
        // so the guide never counts it as created by the session unless the
        // operator chose it ("My Microsoft CA issuer is already set up").
        existedBeforeSession:
          sinceMs !== null && createdMs !== null && createdMs < sinceMs,
        profileCount: Number(row.profile_count) || 0,
        attachedCertificates: Number(row.attached_certificates) || 0,
        revalidationRequired: row.revalidation_required === true,
        // Renewal waits for a CA check taken after the CA certificate was
        // pinned. Null until a certificate is pinned.
        checkedAfterPin: confirmed ? row.checked_after_pin === true : null,
      };
    }),
    profiles: profiles.rows[0]?.n || 0,
    installedEnrollments: enrollments.rows[0]?.installed || 0,
    enrollments: { overdue },
  };
}

// Enrollments the CertOps worker should have picked up by now. The worker
// claims a due row (next_poll_at <= now) and clears next_poll_at, so a poll
// date that stays in the past with no job running means nobody is scheduling.
// A row waiting on the CA has a future poll date, and one waiting on a human
// (an approved job, or an uncertain submission with no operator request id)
// is skipped. The 2x poll interval and 5 minute floor absorb a worker that
// starts fresh every minute (Helm) and a slow sweep.
const ENROLLMENT_OVERDUE_MIN_SECONDS = 5 * 60;
const ENROLLMENT_OVERDUE_SCAN_LIMIT = 200;
const ACTIVE_JOB_STATUSES = [
  "pending_approval",
  "approved",
  "pending",
  "claimed",
  "running",
];

function snapshotPollSeconds(bytes) {
  try {
    const snapshot = JSON.parse(Buffer.from(bytes).toString("utf8"));
    const seconds = Number(snapshot?.pollInterval);
    if (Number.isFinite(seconds) && seconds > 0) return seconds;
  } catch (_) {
    // Fall through to the default poll interval.
  }
  return DEFAULT_POLL_INTERVAL_SECONDS;
}

async function loadOverdueEnrollments(
  pool,
  workspaceId,
  { now = Date.now() } = {},
) {
  const nowMs = typeof now === "number" ? now : new Date(now).getTime();
  const floor = new Date(nowMs - ENROLLMENT_OVERDUE_MIN_SECONDS * 1000);
  const { rows } = await pool.query(
    `SELECT e.next_poll_at, e.snapshot_bytes
       FROM certificate_enrollments e
       LEFT JOIN certificate_jobs j
         ON j.workspace_id = e.workspace_id AND j.id = e.current_job_id
      WHERE e.workspace_id = $1
        AND e.state = ANY($2::text[])
        AND e.next_poll_at IS NOT NULL
        AND e.next_poll_at <= $3
        AND (j.status IS NULL OR NOT (j.status = ANY($4::text[])))
        AND (e.state <> 'submission_uncertain' OR e.operator_request_id IS NOT NULL)
      ORDER BY e.next_poll_at ASC
      LIMIT ${ENROLLMENT_OVERDUE_SCAN_LIMIT}`,
    [workspaceId, [...CONTINUATION_STATES], floor, ACTIVE_JOB_STATUSES],
  );
  let count = 0;
  let oldest = null;
  for (const row of rows) {
    const dueMs = new Date(row.next_poll_at).getTime();
    const graceSeconds = Math.max(
      2 * snapshotPollSeconds(row.snapshot_bytes),
      ENROLLMENT_OVERDUE_MIN_SECONDS,
    );
    if (!Number.isFinite(dueMs) || nowMs - dueMs < graceSeconds * 1000) continue;
    count += 1;
    if (oldest === null || dueMs < oldest) oldest = dueMs;
  }
  return {
    count,
    oldestDueAt: oldest === null ? null : new Date(oldest).toISOString(),
  };
}

async function loadControllerReality(pool, workspaceId) {
  const { rows } = await pool.query(
    `SELECT controller_cluster_id AS cluster_id, MAX(created_at) AS last_reported_at
       FROM certificate_controller_observations
      WHERE workspace_id = $1
      GROUP BY controller_cluster_id
      ORDER BY MAX(created_at) DESC
      LIMIT 10`,
    [workspaceId],
  );
  return {
    clusters: rows.map((row) => ({
      clusterId: row.cluster_id,
      lastReportedAt: row.last_reported_at
        ? new Date(row.last_reported_at).toISOString()
        : null,
    })),
  };
}

async function loadCertopsReality(
  pool,
  {
    workspaceId,
    role,
    enabled,
    since,
    dryRunJobId,
    issueJobId,
    publishJobId,
    chosenAgentId,
    adcsIssuerId,
    clusterId,
  },
) {
  if (enabled !== true) return null;
  if (role !== "admin" && role !== "workspace_manager") return null;
  const agents = await listAgents({ workspaceId, client: pool });
  // A row in "provisioning" only means an order was requested. It becomes an
  // observed certificate once it holds real material.
  const certs = await pool.query(
    `SELECT COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE status = 'active')::int AS active,
            COUNT(*) FILTER (
              WHERE status IN ('discovered', 'active', 'renewing', 'expiring', 'expired')
            )::int AS observed
       FROM managed_certificates
      WHERE workspace_id = $1 AND status NOT IN ('decommissioned')`,
    [workspaceId],
  );
  const distribution = await loadDistributionReality(pool, workspaceId);
  const dryRun = await loadJobStatus(pool, workspaceId, dryRunJobId);
  const issueJob = await loadJobStatus(pool, workspaceId, issueJobId);
  const publishJob = await loadJobStatus(pool, workspaceId, publishJobId);
  const adcs = await loadAdcsReality(pool, workspaceId, { since });
  const sessionCertificates = await loadSessionCertificates(pool, workspaceId, {
    jobs: [
      { job: issueJob, source: "issue" },
      { job: publishJob, source: "publish" },
    ],
    since,
    adcsIssuerId,
  });
  const controllers = await loadControllerReality(pool, workspaceId);
  const observed = await loadObservedCertificates(pool, workspaceId, {
    since,
    agentId: chosenAgentId,
    clusterId,
  });
  return {
    adcs,
    controllers,
    agents: summarizeAgents(agents.items, { since }),
    distribution,
    dryRun,
    issueJob,
    sessionCertificates,
    observedCertificates: observed,
    certificates: {
      total: certs.rows[0]?.total || 0,
      active: certs.rows[0]?.active || 0,
      observed: certs.rows[0]?.observed || 0,
    },
  };
}

module.exports = {
  summarizeAgents,
  loadCertopsReality,
  loadAdcsReality,
  loadControllerReality,
  loadDistributionReality,
  loadOutboxBacklog,
  loadOverdueEnrollments,
  loadJobStatus,
  loadSessionCertificates,
  loadObservedCertificates,
  EXECUTION_OPERATIONS,
};
