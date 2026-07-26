import apiClient from '../../utils/apiClient';

/**
 * CertOps jobs API helpers (read-only job / log / evidence surface).
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
  'issue',
  'renew',
  'deploy',
  'reload',
  'revoke',
  'noop',
];

export const CERTOPS_SUBJECT_TYPES = [
  'managed_certificate',
  'certificate_instance',
  'certificate_target',
  'token',
  'domain',
  'endpoint',
  'external',
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

/**
 * Create a manual CertOps job through the session-authenticated workspace
 * surface. source is always forced to "api" by the server. Requires
 * workspace_manager role or above.
 * @returns {Promise<{ job: object }>}
 */
export async function createJob(
  workspaceId,
  {
    operation,
    subjectType,
    subjectId,
    payload,
    idempotencyKey,
    requiresApproval,
    assignedAgentId,
  } = {}
) {
  const body = { operation };
  if (subjectType !== undefined) body.subjectType = subjectType;
  if (subjectId !== undefined) body.subjectId = subjectId;
  if (payload !== undefined) body.payload = payload;
  if (idempotencyKey !== undefined) body.idempotencyKey = idempotencyKey;
  if (requiresApproval !== undefined) body.requiresApproval = requiresApproval;
  if (assignedAgentId !== undefined) body.assignedAgentId = assignedAgentId;

  const res = await apiClient.post(`${workspaceBase(workspaceId)}/jobs`, body);
  return res.data;
}

/**
 * Approve a job sitting at `pending_approval`, moving it to `pending`
 * (claimable). Requires workspace_manager role or above; the requester of
 * the job cannot approve their own job
 * (403 CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN).
 * @returns {Promise<{ job: object }>}
 */
export async function approveJob(workspaceId, jobId, { reason } = {}) {
  const body = {};
  if (reason !== undefined) body.reason = reason;
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/jobs/${encodeURIComponent(jobId)}/approve`,
    body
  );
  return res.data;
}

/**
 * Reject a job sitting at `pending_approval`, moving it directly to the
 * terminal `rejected` status. Unlike approve, any authorized member
 * (including the original requester) can reject a job.
 * @returns {Promise<{ job: object }>}
 */
export async function rejectJob(workspaceId, jobId, { reason } = {}) {
  const body = {};
  if (reason !== undefined) body.reason = reason;
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/jobs/${encodeURIComponent(jobId)}/reject`,
    body
  );
  return res.data;
}
