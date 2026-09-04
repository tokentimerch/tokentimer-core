import { useCallback, useEffect, useState } from 'react';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import {
  listRenewalProfiles,
  listUpcomingRenewals,
  updateRenewalProfile,
} from './certopsRenewalApi';
import { useCertOpsEnabled } from './useCertOps.js';

/**
 * Renewal-profile data hooks.
 *
 * Reads are not gated on a client-side role check. A boolean permission flag
 * cannot distinguish "still resolving" and "lookup failed" from "denied", and
 * collapsing any of those into an empty list makes this page report "nothing
 * scheduled to renew" when the truth is unknown. On a page whose purpose is to
 * expose certificates that will silently fail to renew, a reassuring false
 * negative is the worst possible failure. So these hooks always ask the server,
 * which enforces RBAC anyway, and surface a refusal as a refusal.
 *
 * Writes are admin-only server-side; callers gate the affordance with
 * useCertOpsIsWorkspaceAdmin purely to avoid offering a button that would 403.
 */

const READ_FORBIDDEN_MESSAGE =
  'You do not have permission to view renewal automation for this workspace.';

/**
 * Turns a failed read into an operator-actionable message.
 *
 * A 403 is deliberately not treated as "no results": the caller needs to know
 * the list is withheld rather than empty.
 */
function readErrorMessage(err, fallback) {
  if (err?.response?.status === 403) return READ_FORBIDDEN_MESSAGE;
  return err?.response?.data?.error || err?.message || fallback;
}

/**
 * Normalizes both shapes the renewal routes answer with into one envelope.
 *
 * These two endpoints predate the nested `pagination` object and still send
 * flat `total`/`limit`/`offset` alongside it, so read whichever is present.
 * Returns null when the response carries no page information at all, because a
 * page position that has to be guessed would render a control the server never
 * agreed to.
 */
function readPagination(data, requested) {
  const source = data?.pagination || data;
  const total = Number(source?.total);
  if (!Number.isFinite(total)) return null;
  const limit = Number(source?.limit);
  const offset = Number(source?.offset);
  return {
    limit: Number.isFinite(limit) && limit > 0 ? limit : requested.limit,
    offset: Number.isFinite(offset) && offset >= 0 ? offset : requested.offset,
    total,
  };
}

/**
 * Loads renewal profiles for the active workspace.
 *
 * @param {number} [externalRefreshSignal] - Changing this refetches.
 * @param {{ limit?: number, offset?: number, sort?: string, direction?: 'asc'|'desc' }} [page] - Page position; the
 *   caller owns it (it lives in the URL), so this hook never adjusts it.
 * @returns {{ enabled: boolean|null, profiles: object[], total: number, pagination: { limit: number, offset: number, total: number }|null, loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsRenewalProfiles(externalRefreshSignal, page = {}) {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const { limit = 20, offset = 0, sort, direction } = page;
  const [profiles, setProfiles] = useState([]);
  // Null until the server answers: an absent page block must stay
  // distinguishable from a real total of 0.
  const [pagination, setPagination] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    // CertOps switched off is a settled answer, so stop and show nothing. A
    // missing workspace or an unresolved availability check is not an answer
    // yet, so stay in the loading state rather than rendering an empty table.
    if (enabled === false) {
      setProfiles([]);
      setPagination(null);
      setLoading(false);
      setError('');
      return undefined;
    }
    if (!workspaceId || enabled !== true) {
      setLoading(true);
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    listRenewalProfiles(workspaceId, {
      limit,
      offset,
      ...(sort ? { sort, direction } : {}),
      signal: controller.signal,
    })
      .then(data => {
        if (cancelled) return;
        setProfiles(Array.isArray(data?.items) ? data.items : []);
        setPagination(readPagination(data, { limit, offset }));
      })
      .catch(err => {
        if (cancelled) return;
        setProfiles([]);
        setPagination(null);
        setError(readErrorMessage(err, 'Could not load renewal profiles.'));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [
    workspaceId,
    enabled,
    reloadTick,
    externalRefreshSignal,
    limit,
    offset,
    sort,
    direction,
  ]);

  return {
    enabled,
    profiles,
    total: pagination ? pagination.total : 0,
    pagination,
    loading,
    error,
    refresh,
  };
}

/**
 * Loads the upcoming automatic renewal schedule for the active workspace.
 *
 * @param {number} [externalRefreshSignal] - Changing this refetches.
 * @param {{ limit?: number, offset?: number, sort?: string, direction?: 'asc'|'desc' }} [page]
 * @returns {{ enabled: boolean|null, renewals: object[], total: number, pagination: { limit: number, offset: number, total: number }|null, loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsUpcomingRenewals(externalRefreshSignal, page = {}) {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const { limit = 20, offset = 0, sort, direction } = page;
  const [renewals, setRenewals] = useState([]);
  const [pagination, setPagination] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    if (enabled === false) {
      setRenewals([]);
      setPagination(null);
      setLoading(false);
      setError('');
      return undefined;
    }
    if (!workspaceId || enabled !== true) {
      setLoading(true);
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    listUpcomingRenewals(workspaceId, {
      limit,
      offset,
      ...(sort ? { sort, direction } : {}),
      signal: controller.signal,
    })
      .then(data => {
        if (cancelled) return;
        setRenewals(Array.isArray(data?.items) ? data.items : []);
        setPagination(readPagination(data, { limit, offset }));
      })
      .catch(err => {
        if (cancelled) return;
        setRenewals([]);
        setPagination(null);
        setError(
          readErrorMessage(err, 'Could not load the upcoming renewal schedule.')
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [
    workspaceId,
    enabled,
    reloadTick,
    externalRefreshSignal,
    limit,
    offset,
    sort,
    direction,
  ]);

  return {
    enabled,
    renewals,
    total: pagination ? pagination.total : 0,
    pagination,
    loading,
    error,
    refresh,
  };
}

/**
 * Mutation helper for renewal profiles.
 *
 * `saving` carries the profile id being written rather than a boolean so a table
 * of profiles can disable only the row in flight instead of freezing every
 * control on the page.
 *
 * @returns {{ saving: string|null, error: string, clearError: function, save: function }}
 */
export function useUpdateRenewalProfile() {
  const { workspaceId } = useWorkspace();
  const [saving, setSaving] = useState(null);
  const [error, setError] = useState('');

  const clearError = useCallback(() => setError(''), []);

  const save = useCallback(
    async (profileId, changes) => {
      if (!workspaceId || !profileId) return null;
      setSaving(profileId);
      setError('');
      try {
        return await updateRenewalProfile(workspaceId, profileId, changes);
      } catch (err) {
        // The immutable-field refusal carries the offending field names, and it
        // is the one failure an operator can act on, so surface it verbatim
        // instead of collapsing it into a generic message.
        const fields = err?.response?.data?.fields;
        const detail = err?.response?.data?.error;
        setError(
          Array.isArray(fields) && fields.length > 0
            ? `${detail} (${fields.join(', ')})`
            : detail || err?.message || 'Could not update the renewal profile.'
        );
        return null;
      } finally {
        setSaving(null);
      }
    },
    [workspaceId]
  );

  return { saving, error, clearError, save };
}
