import apiClient, { handleApiError } from './apiClient';

// Thin calls over existing endpoints used by the first-value journey. They
// reuse the same server contracts as the existing modals; nothing here adds
// parallel business logic.

const ws = id => `/api/v1/workspaces/${id}`;

function rethrow(e) {
  throw new Error(handleApiError(e));
}

const isCanceled = e =>
  e?.code === 'ERR_CANCELED' || e?.name === 'CanceledError';

/**
 * Keeps the API's error code and retry hint on the thrown error so the panel
 * can word the failure. Codes the panel words itself skip the generic error
 * toast, since the panel shows the message inline.
 */
function rethrowDiscovery(e) {
  if (isCanceled(e)) {
    throw Object.assign(new Error('Search cancelled.'), {
      code: 'ERR_CANCELED',
    });
  }
  const data = e?.response?.data;
  const status = e?.response?.status;
  const code = typeof data?.code === 'string' ? data.code : undefined;
  const headerRetry = Number(e?.response?.headers?.['retry-after']);
  const retry = Number(data?.retry_after_seconds);
  const retryAfterSeconds = Number.isFinite(retry)
    ? retry
    : Number.isFinite(headerRetry)
      ? headerRetry
      : undefined;
  const handled =
    Boolean(code?.startsWith('DOMAIN_CHECKER_')) || code === 'INVALID_DOMAIN';
  const message = handled
    ? data?.error || 'The lookup failed.'
    : handleApiError(e);
  throw Object.assign(new Error(message), {
    code,
    status,
    retryAfterSeconds,
  });
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

  async createMonitor(
    workspaceId,
    {
      url,
      contactGroupIds,
      checkInterval,
      healthCheckEnabled,
      alertAfterFailures,
      section,
    }
  ) {
    try {
      // Defaults are what the wizard always sent, so callers that pass only
      // a URL behave exactly as before.
      const body = {
        url,
        health_check_enabled: healthCheckEnabled !== false,
        check_interval: checkInterval || 'hourly',
        alert_after_failures: alertAfterFailures ?? 2,
      };
      if (contactGroupIds?.length) body.contact_group_ids = contactGroupIds;
      if (section?.length) body.section = section;
      const res = await apiClient.post(`${ws(workspaceId)}/domains`, body);
      return res.data;
    } catch (e) {
      return rethrow(e);
    }
  },

  /**
   * Passive subdomain discovery for a root domain, the same endpoint the
   * Endpoint & SSL monitor window uses. Slow by nature, so it gets the same
   * long timeout and a bounded retry on dropped connections.
   */
  async discoverHostnames(
    workspaceId,
    domain,
    { includeAllSources = false, signal } = {}
  ) {
    const url = `${ws(workspaceId)}/domain-checker/lookup`;
    const body = { domain };
    if (includeAllSources) body.subfinder_all = true;
    // Only a dropped connection is worth another try. A timeout, a busy or
    // missing tool and a rate limit would just repeat, and each attempt can
    // take minutes.
    const retriable = e =>
      !isCanceled(e) && !e?.response && e?.code !== 'ECONNABORTED';
    const attempts = 3;
    for (let i = 0; i < attempts; i += 1) {
      try {
        const res = await apiClient.post(url, body, {
          timeout: 300_000,
          signal,
        });
        const meta = res.data?.meta || {};
        return {
          items: Array.isArray(res.data?.items) ? res.data.items : [],
          partial: Boolean(res.data?.partial),
          truncated: Boolean(meta.truncated),
          cap: Number(meta.maxResults) > 0 ? Number(meta.maxResults) : null,
          // Codes only: the panel words them, and paths or arguments never
          // reach the browser.
          failedCodes: (Array.isArray(res.data?.toolErrors)
            ? res.data.toolErrors
            : []
          )
            .map(t => t?.code)
            .filter(Boolean),
        };
      } catch (e) {
        if (i === attempts - 1 || !retriable(e)) return rethrowDiscovery(e);
        await new Promise(r => setTimeout(r, 2000 * (i + 1)));
      }
    }
    return { items: [], partial: false, truncated: false, cap: null };
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
  // System settings: system administrators only. The server masks the SMTP
  // password and reports environment-supplied fields as locked.
  async getSystemSettings() {
    try {
      const res = await apiClient.get('/api/admin/system-settings');
      return res.data;
    } catch (e) {
      return rethrow(e);
    }
  },

  async putSmtpSettings(smtp) {
    try {
      const res = await apiClient.put('/api/admin/system-settings', { smtp });
      return res.data;
    } catch (e) {
      return rethrow(e);
    }
  },

  async testSmtp(email) {
    try {
      const res = await apiClient.post('/api/admin/test-smtp', { email });
      return res.data;
    } catch (e) {
      const data = e?.response?.data;
      const error = new Error(data?.error || handleApiError(e));
      error.code = data?.code;
      throw error;
    }
  },

  /** The soonest-expiring asset: the most useful sample for routing checks. */
  async soonestToken(workspaceId) {
    try {
      const res = await apiClient.get('/api/tokens', {
        params: { workspace_id: workspaceId, sort: 'expiration_asc', limit: 1 },
      });
      return res.data?.items?.[0] || null;
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

export class GroupWriteNotPersistedError extends Error {
  constructor(reason) {
    super(
      reason === 'member_limit'
        ? 'Your plan allows no more recipients in this group. Pick another group or remove a recipient first.'
        : reason === 'group_limit'
          ? 'Your plan allows no more contact groups. Reuse an existing group instead.'
          : 'The recipient could not be saved. Check your plan limits and try again.'
    );
    this.name = 'GroupWriteNotPersistedError';
    this.reason = reason;
  }
}

/**
 * The alert-settings write silently trims groups and members over the plan
 * cap, so success must be proven by reading the settings back.
 */
export function assertRecipientPersisted(
  settings,
  { groupId, contactId, expectDefault = true }
) {
  const groups = Array.isArray(settings?.contact_groups)
    ? settings.contact_groups
    : [];
  const group = groups.find(g => String(g.id) === String(groupId));
  if (!group) throw new GroupWriteNotPersistedError('group_limit');
  const members = (group.email_contact_ids || []).map(String);
  if (!members.includes(String(contactId))) {
    throw new GroupWriteNotPersistedError('member_limit');
  }
  if (
    expectDefault &&
    String(settings.default_contact_group_id || '') !== String(groupId)
  ) {
    throw new GroupWriteNotPersistedError('not_default');
  }
  return true;
}
