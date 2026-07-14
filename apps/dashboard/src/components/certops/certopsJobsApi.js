import apiClient from '../../utils/apiClient';

/**
 * CertOps jobs API helpers (M2 read-only job / log / evidence surface).
 *
 * Additive module scoped to `/api/v1/workspaces/:id/certops/jobs/*`.
 * Returns 404 when `certops.enabled` is off.
 */

export const CERTOPS_JOB_STATUSES = [
  'pending_approval',
  'approved',
  'rejected',
  'pending',
  'claimed',
  'running',
  'succeeded',
  'failed',
  'blocked',
  'cancelled',
];

export const CERTOPS_JOB_OPERATIONS = [
  'renew',
  'deploy',
  'reload',
  'revoke',
  'noop',
];

export const CERTOPS_JOB_LOG_EVENT_TYPES = [
  'job.created',
  'job.accepted',
  'job.started',
  'job.progress',
  'job.completed',
  'job.failed',
  'job.rejected',
  'job.cancelled',
  'job.status_updated',
  'evidence.attached',
];

export const CERTOPS_EVIDENCE_TYPES = [
  'certificate.observed',
  'deployment.checked',
  'deployment.updated',
  'validation.passed',
  'validation.failed',
  'policy.checked',
];

function workspaceBase(workspaceId) {
  return `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops`;
}

/**
 * List CertOps jobs for a workspace.
 * Only defined filter values are sent as query params.
 * @returns {Promise<{ items: object[], pagination: { limit: number, offset: number } }>}
 */
export async function listJobs(
  workspaceId,
  {
    limit = 20,
    offset = 0,
    status,
    subjectType,
    subjectId,
    operation,
    source,
    signal,
  } = {}
) {
  const params = { limit, offset };
  if (status !== undefined) params.status = status;
  if (subjectType !== undefined) params.subjectType = subjectType;
  if (subjectId !== undefined) params.subjectId = subjectId;
  if (operation !== undefined) params.operation = operation;
  if (source !== undefined) params.source = source;

  const res = await apiClient.get(`${workspaceBase(workspaceId)}/jobs`, {
    params,
    signal,
  });
  return res.data;
}

/**
 * Fetch a single CertOps job by id.
 * @returns {Promise<{ job: object }>}
 */
export async function getJob(workspaceId, jobId, { signal } = {}) {
  const res = await apiClient.get(
    `${workspaceBase(workspaceId)}/jobs/${encodeURIComponent(jobId)}`,
    { signal }
  );
  return res.data;
}

/**
 * Fetch timeline log entries for a job.
 * @returns {Promise<{ items: object[], pagination: { limit: number, offset: number } }>}
 */
export async function listJobLog(
  workspaceId,
  jobId,
  { limit = 100, offset = 0, signal } = {}
) {
  const res = await apiClient.get(
    `${workspaceBase(workspaceId)}/jobs/${encodeURIComponent(jobId)}/log`,
    {
      params: { limit, offset },
      signal,
    }
  );
  return res.data;
}

/**
 * Fetch evidence items attached to a job.
 * @returns {Promise<{ items: object[], pagination: { limit: number, offset: number } }>}
 */
export async function listJobEvidence(
  workspaceId,
  jobId,
  { limit = 100, offset = 0, signal } = {}
) {
  const res = await apiClient.get(
    `${workspaceBase(workspaceId)}/jobs/${encodeURIComponent(jobId)}/evidence`,
    {
      params: { limit, offset },
      signal,
    }
  );
  return res.data;
}
