import apiClient, { handleApiError } from './apiClient';

// Thin calls over existing endpoints used by the first-value journey. They
// reuse the same server contracts as the existing modals; nothing here adds
// parallel business logic.

const ws = id => `/api/v1/workspaces/${id}`;

function rethrow(e) {
  throw new Error(handleApiError(e));
}

export const onboardingActions = {
  async listMonitors(workspaceId) {
    try {
      const res = await apiClient.get(`${ws(workspaceId)}/domains`);
      return Array.isArray(res.data) ? res.data : res.data?.items || [];
    } catch (e) {
      return rethrow(e);
    }
  },

  async createMonitor(workspaceId, { url, contactGroupIds }) {
    try {
      const body = {
        url,
        health_check_enabled: true,
        check_interval: 'hourly',
        alert_after_failures: 2,
      };
      if (contactGroupIds?.length) body.contact_group_ids = contactGroupIds;
      const res = await apiClient.post(`${ws(workspaceId)}/domains`, body);
      return res.data;
    } catch (e) {
      return rethrow(e);
    }
  },

  async getAlertSettings(workspaceId) {
    try {
      const res = await apiClient.get(`${ws(workspaceId)}/alert-settings`);
      return res.data;
    } catch (e) {
      return rethrow(e);
    }
  },

  async putAlertSettings(workspaceId, body) {
    try {
      const res = await apiClient.put(
        `${ws(workspaceId)}/alert-settings`,
        body
      );
      return res.data;
    } catch (e) {
      return rethrow(e);
    }
  },

  async listContacts(workspaceId) {
    try {
      const res = await apiClient.get(`${ws(workspaceId)}/contacts`);
      return res.data?.items || [];
    } catch (e) {
      return rethrow(e);
    }
  },

  async createContact(workspaceId, body) {
    try {
      const res = await apiClient.post(`${ws(workspaceId)}/contacts`, body);
      return res.data;
    } catch (e) {
      return rethrow(e);
    }
  },

  async findTokens(workspaceId, query) {
    try {
      const res = await apiClient.get('/api/tokens', {
        params: { workspace_id: workspaceId, q: query, limit: 20 },
      });
      return res.data?.items || [];
    } catch (e) {
      return rethrow(e);
    }
  },

  async createToken(body) {
    try {
      const res = await apiClient.post('/api/tokens', body);
      return res.data;
    } catch (e) {
      // Surface the duplicate so the caller can reconcile; never auto-confirm.
      if (
        e?.response?.status === 409 &&
        e.response.data?.code === 'DUPLICATE_TOKEN'
      ) {
        throw { conflict: e.response.data.existing_token };
      }
      return rethrow(e);
    }
  },

  async getToken(tokenId) {
    try {
      const res = await apiClient.get(`/api/tokens/${tokenId}`);
      return res.data;
    } catch (e) {
      return rethrow(e);
    }
  },
};

/**
 * Adds a group (with a first email recipient) without disturbing existing
 * ones. The alert-settings PUT replaces the whole group list, so this appends
 * to the live list and keeps every existing field.
 */
export function appendContactGroup(
  existingGroups,
  { id, name, emailContactIds }
) {
  const groups = Array.isArray(existingGroups) ? existingGroups : [];
  return [
    ...groups,
    {
      id,
      name,
      email_contact_ids: emailContactIds,
      weekly_digest_email: false,
      weekly_digest_whatsapp: false,
      weekly_digest_webhooks: false,
    },
  ];
}

/** Adds a recipient to an existing group without dropping its other members. */
export function addRecipientToGroup(existingGroups, groupId, contactId) {
  return (existingGroups || []).map(group =>
    String(group.id) === String(groupId)
      ? {
          ...group,
          email_contact_ids: Array.from(
            new Set([...(group.email_contact_ids || []), contactId])
          ),
        }
      : group
  );
}
