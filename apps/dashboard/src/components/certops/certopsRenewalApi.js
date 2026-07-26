import apiClient from '../../utils/apiClient';

/**
 * CertOps renewal-profile API helpers.
 *
 * A renewal profile is the execution contract the renewal scheduler hands to an
 * agent: SAN policy, key parameters, CA endpoint, ACME command, DNS provider,
 * and deployment paths. Profiles are normally derived automatically from a
 * successful issuance, so this surface is mostly about inspecting and
 * constraining what already runs, not authoring new configuration.
 *
 * Only the fields the server reports in `editableFields` may be patched. The
 * server rejects anything else, so the UI never needs to guess which fields are
 * safe.
 */

function workspaceBase(workspaceId) {
  return `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops`;
}

/**
 * List renewal profiles for a workspace.
 * @returns {Promise<{ items: object[], total: number, limit: number, offset: number }>}
 */
export async function listRenewalProfiles(
  workspaceId,
  { limit = 50, offset = 0, signal } = {}
) {
  const res = await apiClient.get(`${workspaceBase(workspaceId)}/profiles`, {
    params: { limit, offset },
    signal,
  });
  return res.data;
}

/**
 * Fetch a single renewal profile, including its full stored execution contract.
 * @returns {Promise<object>}
 */
export async function getRenewalProfile(workspaceId, profileId, { signal } = {}) {
  const res = await apiClient.get(
    `${workspaceBase(workspaceId)}/profiles/${encodeURIComponent(profileId)}`,
    { signal }
  );
  return res.data;
}

/**
 * Update a renewal profile.
 *
 * Requires the workspace admin role server-side. Only send fields listed in the
 * profile's `editableFields`; host-affecting fields (deployment paths, reload
 * service, ACME command, CA endpoint, DNS provider) are immutable after
 * issuance and are refused with CERTOPS_PROFILE_FIELD_IMMUTABLE.
 *
 * @param {object} changes - Any of autoRenewEnabled, renewBeforeDays,
 *   description, renewalProfile (partial patch of editable fields).
 * @returns {Promise<object>} The updated profile.
 */
export async function updateRenewalProfile(
  workspaceId,
  profileId,
  changes,
  { signal } = {}
) {
  const res = await apiClient.patch(
    `${workspaceBase(workspaceId)}/profiles/${encodeURIComponent(profileId)}`,
    changes,
    { signal }
  );
  return res.data;
}

/**
 * List certificates the renewal scheduler is expected to act on next.
 *
 * Includes certificates whose automatic renewal is switched off, because an
 * operator needs to see that a certificate is expiring AND that renewal was
 * deliberately disabled. Omitting them would make a switched-off certificate
 * indistinguishable from nothing being due.
 *
 * @returns {Promise<{ items: object[], total: number, limit: number, offset: number }>}
 */
export async function listUpcomingRenewals(
  workspaceId,
  { limit = 50, offset = 0, signal } = {}
) {
  const res = await apiClient.get(
    `${workspaceBase(workspaceId)}/renewals/upcoming`,
    {
      params: { limit, offset },
      signal,
    }
  );
  return res.data;
}
