import apiClient from '../../utils/apiClient';

const base = (workspaceId, groupId) =>
  `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops/distribution-groups/${encodeURIComponent(groupId)}`;

export async function readDistribution(workspaceId, groupId, { signal } = {}) {
  const url = base(workspaceId, groupId);
  const [versions, consumers] = await Promise.all([
    apiClient.get(`${url}/versions`, { signal }),
    apiClient.get(`${url}/consumers`, { signal }),
  ]);
  return {
    versions: versions.data.versions || [],
    consumers: consumers.data.consumers || [],
  };
}

export async function assignConsumer(workspaceId, groupId, bindingId, binding) {
  const res = await apiClient.put(
    `${base(workspaceId, groupId)}/consumers/${encodeURIComponent(bindingId)}`,
    binding
  );
  return res.data;
}

export async function requestRollout(workspaceId, groupId, body, key) {
  const res = await apiClient.post(
    `${base(workspaceId, groupId)}/rollouts`,
    body,
    {
      headers: { 'Idempotency-Key': key },
    }
  );
  return res.data;
}

export async function retryDeployment(workspaceId, jobId) {
  const res = await apiClient.post(
    `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops/distribution-jobs/${encodeURIComponent(jobId)}/retry`,
    {}
  );
  return res.data;
}
