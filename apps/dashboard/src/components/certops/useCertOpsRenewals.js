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
 * Loads renewal profiles for the active workspace.
 * @returns {{ enabled: boolean|null, profiles: object[], total: number, loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsRenewalProfiles(externalRefreshSignal) {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const [profiles, setProfiles] = useState([]);
  const [total, setTotal] = useState(0);
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
      setTotal(0);
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

    listRenewalProfiles(workspaceId, { signal: controller.signal })
      .then(data => {
        if (cancelled) return;
        setProfiles(Array.isArray(data?.items) ? data.items : []);
        setTotal(Number.isFinite(Number(data?.total)) ? Number(data.total) : 0);
      })
      .catch(err => {
        if (cancelled) return;
        setProfiles([]);
        setTotal(0);
        setError(readErrorMessage(err, 'Could not load renewal profiles.'));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [workspaceId, enabled, reloadTick, externalRefreshSignal]);

  return { enabled, profiles, total, loading, error, refresh };
}

/**
 * Loads the upcoming automatic renewal schedule for the active workspace.
 * @returns {{ enabled: boolean|null, renewals: object[], total: number, loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsUpcomingRenewals(externalRefreshSignal) {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const [renewals, setRenewals] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    if (enabled === false) {
      setRenewals([]);
      setTotal(0);
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

    listUpcomingRenewals(workspaceId, { signal: controller.signal })
      .then(data => {
        if (cancelled) return;
        setRenewals(Array.isArray(data?.items) ? data.items : []);
        setTotal(Number.isFinite(Number(data?.total)) ? Number(data.total) : 0);
      })
      .catch(err => {
        if (cancelled) return;
        setRenewals([]);
        setTotal(0);
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
  }, [workspaceId, enabled, reloadTick, externalRefreshSignal]);

  return { enabled, renewals, total, loading, error, refresh };
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
