import apiClient from '../../utils/apiClient';

function workspaceBase(workspaceId) {
  return `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops`;
}

export async function listIssuers(workspaceId, { signal, limit } = {}) {
  const res = await apiClient.get(`${workspaceBase(workspaceId)}/issuers`, {
    signal,
    params: limit ? { limit } : undefined,
  });
  return res.data;
}

export async function createIssuer(workspaceId, body) {
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/issuers`,
    body
  );
  return res.data;
}

export async function dispatchIssuerPreflight(workspaceId, issuerId, body) {
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/issuers/${encodeURIComponent(issuerId)}/preflight`,
    body
  );
  return res.data;
}

export async function confirmIssuerKey(workspaceId, issuerId, body) {
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/issuers/${encodeURIComponent(issuerId)}/confirm`,
    body
  );
  return res.data;
}

export async function listEnrollments(workspaceId, { signal, limit } = {}) {
  const res = await apiClient.get(`${workspaceBase(workspaceId)}/enrollments`, {
    signal,
    params: limit ? { limit } : undefined,
  });
  return res.data;
}

export async function proposeEnrollmentRequestId(
  workspaceId,
  enrollmentId,
  requestId
) {
  await apiClient.post(
    `${workspaceBase(workspaceId)}/enrollments/${encodeURIComponent(enrollmentId)}/reconcile`,
    { requestId }
  );
}

export async function abandonEnrollment(workspaceId, enrollmentId) {
  await apiClient.post(
    `${workspaceBase(workspaceId)}/enrollments/${encodeURIComponent(enrollmentId)}/abandon`
  );
}

export const ENROLLMENT_STATE_LABELS = {
  pending_issuance: 'Awaiting CA approval',
  submission_uncertain: 'Submission uncertain',
  validation_deferred: 'Validation deferred',
  requested: 'Requested',
  installed: 'Installed',
  abandoned: 'Abandoned',
  cancelled: 'Cancelled',
  expired: 'Expired',
};

export function enrollmentStateLabel(state) {
  return ENROLLMENT_STATE_LABELS[state] || state || 'Unknown';
}
