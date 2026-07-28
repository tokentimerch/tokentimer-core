import { useCallback, useEffect, useState } from 'react';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { listCertificates } from './certopsApi';
import { useCertOpsEnabled } from './useCertOps.js';

/**
 * Loads the managed certificate inventory for the active workspace.
 *
 * Gated on workspaceId and `certops.enabled === true` (same pattern as
 * useCertOpsJobs). Re-fetches when any filter or page position changes.
 *
 * @param {{ limit?: number, offset?: number, status?: string, source?: string, excludeRetired?: boolean }} [filters]
 * @returns {{ enabled: boolean|null, certificates: object[], pagination: { limit: number, offset: number, total: number }|null, loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsCertificates(filters = {}) {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const { limit = 20, offset = 0, status, source, excludeRetired } = filters;

  const [certificates, setCertificates] = useState([]);
  const [pagination, setPagination] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    if (!workspaceId || enabled !== true) {
      setCertificates([]);
      setPagination(null);
      setLoading(false);
      setError('');
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    listCertificates(workspaceId, {
      limit,
      offset,
      status,
      source,
      excludeRetired,
      signal: controller.signal,
    })
      .then(data => {
        if (!cancelled) {
          setCertificates(Array.isArray(data?.items) ? data.items : []);
          setPagination(data?.pagination || null);
        }
      })
      .catch(err => {
        if (cancelled) return;
        setCertificates([]);
        setPagination(null);
        setError(
          err?.response?.data?.error ||
            err?.message ||
            'Could not load the managed certificate inventory.'
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
    limit,
    offset,
    status,
    source,
    excludeRetired,
  ]);

  return { enabled, certificates, pagination, loading, error, refresh };
}
