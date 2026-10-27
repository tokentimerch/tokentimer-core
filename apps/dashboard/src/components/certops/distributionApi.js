import apiClient from '../../utils/apiClient';
const root = workspaceId =>
  `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops`;
const groupRoot = (workspaceId, groupId) =>
  `${root(workspaceId)}/distribution-groups/${encodeURIComponent(groupId)}`;
export const distributionApi = {
  groups: async (workspaceId, signal) =>
    (
      await apiClient.get(`${root(workspaceId)}/distribution-groups`, {
        signal,
      })
    ).data,
  management: async (workspaceId, groupId, signal) =>
    (
      await apiClient.get(`${groupRoot(workspaceId, groupId)}/management`, {
        signal,
      })
    ).data,
  preflight: async (workspaceId, groupId, version) =>
    (
      await apiClient.get(`${groupRoot(workspaceId, groupId)}/preflight`, {
        params: { materialVersionId: version },
      })
    ).data,
  retention: async (workspaceId, groupId) =>
    (await apiClient.get(`${groupRoot(workspaceId, groupId)}/retention`)).data,
  policy: async (workspaceId, groupId, policy, expectedRevision) =>
    (
      await apiClient.put(`${groupRoot(workspaceId, groupId)}/policy`, {
        policy,
        expectedRevision,
      })
    ).data,
  consumer: async (workspaceId, groupId, bindingId, binding) =>
    (
      await apiClient.put(
        `${groupRoot(workspaceId, groupId)}/consumers/${bindingId}`,
        binding
      )
    ).data,
  activation: async (
    workspaceId,
    groupId,
    bindingId,
    policy,
    expectedAuthorizationRevision
  ) =>
    (
      await apiClient.put(
        `${groupRoot(workspaceId, groupId)}/consumers/${bindingId}/activation-policy`,
        { policy, expectedAuthorizationRevision }
      )
    ).data,
  rollout: async (workspaceId, groupId, body, key) =>
    (
      await apiClient.post(
        `${groupRoot(workspaceId, groupId)}/rollouts`,
        body,
        { headers: { 'Idempotency-Key': key } }
      )
    ).data,
  state: async (workspaceId, groupId, rolloutId, state) =>
    (
      await apiClient.post(
        `${groupRoot(workspaceId, groupId)}/rollouts/${rolloutId}/state`,
        { state }
      )
    ).data,
  retry: async (workspaceId, jobId) =>
    (
      await apiClient.post(
        `${root(workspaceId)}/distribution-jobs/${jobId}/retry`,
        {}
      )
    ).data,
};
