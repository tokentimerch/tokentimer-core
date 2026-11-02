import apiClient, { handleApiError } from './apiClient';

// Kept out of apiClient.js on purpose: cloud and enterprise override that
// file, and the onboarding surface only needs its default export.

const base = workspaceId => `/api/v1/workspaces/${workspaceId}/onboarding`;

export class RevisionConflictError extends Error {
  constructor(current) {
    super('Onboarding was updated from another tab or device');
    this.name = 'RevisionConflictError';
    this.current = current;
  }
}

export const onboardingAPI = {
  async getCapabilities(workspaceId) {
    try {
      const res = await apiClient.get(`${base(workspaceId)}/capabilities`);
      return res.data;
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },

  async getSession(workspaceId, flow) {
    try {
      const res = await apiClient.get(`${base(workspaceId)}/${flow}`);
      return res.data.session;
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },

  async putSession(workspaceId, flow, body) {
    try {
      const res = await apiClient.put(`${base(workspaceId)}/${flow}`, body);
      return res.data.session;
    } catch (e) {
      if (e?.response?.status === 409 && e.response.data?.current) {
        throw new RevisionConflictError(e.response.data.current);
      }
      throw new Error(handleApiError(e));
    }
  },

  async getSummary(workspaceId, flow) {
    try {
      const res = await apiClient.get(`${base(workspaceId)}/${flow}/summary`);
      return res.data.summary;
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },

  async resetSession(workspaceId, flow) {
    try {
      const res = await apiClient.post(`${base(workspaceId)}/${flow}/reset`);
      return res.data.reset;
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },
};
