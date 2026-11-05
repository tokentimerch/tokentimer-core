import apiClient from '../../utils/apiClient.js';

const base = workspaceId =>
  `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/operator`;

// Enrollment responses contain a one-time secret. Keep them out of diagnostic logs.
const options = signal => ({
  signal,
  _suppressLog: true,
  _suppressToast: true,
});

export async function loadAssistantConnections(workspaceId, signal) {
  const root = base(workspaceId);
  const [settings, connections, enrollments] = await Promise.all([
    apiClient.get(`${root}/settings`, options(signal)),
    apiClient.get(`${root}/connections`, options(signal)),
    apiClient.get(`${root}/enrollments`, options(signal)),
  ]);
  return {
    writesEnabled: settings.data.writesEnabled === true,
    remote: settings.data.remote || { enabled: false, serverUrl: null },
    connections: connections.data.items,
    enrollments: enrollments.data.items,
  };
}

export async function loadAssistantSettings(workspaceId, signal) {
  const response = await apiClient.get(
    `${base(workspaceId)}/settings`,
    options(signal)
  );
  return response.data;
}

export async function createAssistantSetup(workspaceId, input) {
  const response = await apiClient.post(
    `${base(workspaceId)}/enrollments`,
    input,
    options()
  );
  return response.data;
}

export async function revokeAssistantAccess(workspaceId, kind, id) {
  await apiClient.post(
    `${base(workspaceId)}/${kind}/${encodeURIComponent(id)}/revoke`,
    {},
    options()
  );
}

export async function setAssistantWrites(workspaceId, writesEnabled) {
  const response = await apiClient.put(
    `${base(workspaceId)}/settings`,
    { writesEnabled },
    options()
  );
  return response.data.writesEnabled === true;
}

export async function loadAssistantIssuanceSettings(workspaceId, signal) {
  const response = await apiClient.get(
    `${base(workspaceId)}/issuance-settings`,
    options(signal)
  );
  return response.data;
}

export async function setAssistantIssuance(workspaceId, issuanceEnabled) {
  const response = await apiClient.put(
    `${base(workspaceId)}/issuance-settings`,
    { issuanceEnabled },
    options()
  );
  return response.data.issuanceEnabled === true;
}
