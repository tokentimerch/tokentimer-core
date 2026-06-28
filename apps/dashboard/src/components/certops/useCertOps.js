import { useCallback, useEffect, useState } from 'react';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { workspaceAPI } from '../../utils/apiClient';
import {
  getCertificateInstances,
  getManagedCertificateForToken,
  invalidateCertOpsInventoryCache,
  loadCertOpsInventoryIndex,
  probeCertOpsEnabled,
} from './certopsApi';

/**
 * Resolves whether the CertOps surface is available for the active workspace.
 *
 * CertOps ships behind the `certops.enabled` rollout flag. The backend hides
 * its routes (404) while the flag is off, so the dashboard derives availability
 * by probing the workspace-scoped list endpoint. State is one of:
 *   null    -> still resolving
 *   true    -> CertOps API available (enrich cert tokens / PEM import)
 *   false   -> hidden (rollout flag off)
 */
export function useCertOpsEnabled() {
  const { workspaceId } = useWorkspace();
  const [enabled, setEnabled] = useState(null);

  useEffect(() => {
    if (!workspaceId) {
      setEnabled(null);
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setEnabled(null);

    probeCertOpsEnabled(workspaceId, { signal: controller.signal })
      .then(result => {
        if (!cancelled) setEnabled(result);
      })
      .catch(() => {
        if (!cancelled) setEnabled(false);
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [workspaceId]);

  return enabled;
}

/**
 * Resolves whether the current user can perform CertOps write actions (import)
 * in the active workspace. Backend RBAC remains authoritative (403 for viewers);
 * this only drives whether write affordances are shown.
 */
export function useCertOpsCanManage() {
  const { workspaceId } = useWorkspace();
  const [canManage, setCanManage] = useState(false);

  useEffect(() => {
    if (!workspaceId) {
      setCanManage(false);
      return undefined;
    }

    let cancelled = false;
    workspaceAPI
      .get(workspaceId)
      .then(ws => {
        if (cancelled) return;
        const role = String(ws?.role || '').toLowerCase();
        setCanManage(role === 'admin' || role === 'workspace_manager');
      })
      .catch(() => {
        if (!cancelled) setCanManage(false);
      });

    return () => {
      cancelled = true;
    };
  }, [workspaceId]);

  return canManage;
}

/**
 * Loads the whole workspace CertOps inventory once and exposes a tokenId ->
 * managed certificate lookup, so the asset list can tell which token rows are
 * backed by a managed certificate (delete gating + retired filtering, plan D7).
 *
 * Returns a stable `byTokenId` Map (empty when CertOps is disabled/resolving),
 * the enabled flag, a loading flag, and a `refresh()` that re-fetches after a
 * retire so the list reflects the new lifecycle status.
 */
export function useWorkspaceCertOps() {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const [byTokenId, setByTokenId] = useState(() => new Map());
  const [loading, setLoading] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    if (workspaceId) invalidateCertOpsInventoryCache(workspaceId);
    setReloadTick(tick => tick + 1);
  }, [workspaceId]);

  useEffect(() => {
    if (!workspaceId || enabled !== true) {
      setByTokenId(new Map());
      setLoading(false);
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);

    loadCertOpsInventoryIndex(workspaceId, { signal: controller.signal })
      .then(index => {
        if (!cancelled) setByTokenId(new Map(index.byTokenId));
      })
      .catch(() => {
        if (!cancelled) setByTokenId(new Map());
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [workspaceId, enabled, reloadTick]);

  return { enabled, byTokenId, loading, refresh };
}

/**
 * Loads CertOps enrichment (managed certificate + deployment history) for an
 * existing cert token row, keyed by tokens.id via managed_certificates.token_id.
 */
export function useCertOpsForToken(tokenId) {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const [certificate, setCertificate] = useState(null);
  const [instances, setInstances] = useState([]);
  const [instancesAvailable, setInstancesAvailable] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!workspaceId || !tokenId || enabled !== true) {
      setCertificate(null);
      setInstances([]);
      setInstancesAvailable(true);
      setLoading(false);
      setError('');
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    (async () => {
      try {
        const managed = await getManagedCertificateForToken(
          workspaceId,
          tokenId,
          { signal: controller.signal }
        );
        if (cancelled) return;
        setCertificate(managed);
        if (!managed?.id) {
          setInstances([]);
          setInstancesAvailable(true);
          setLoading(false);
          return;
        }

        try {
          const data = await getCertificateInstances(workspaceId, managed.id, {
            signal: controller.signal,
          });
          if (!cancelled) {
            setInstances(Array.isArray(data?.items) ? data.items : []);
            setInstancesAvailable(true);
          }
        } catch (err) {
          if (!cancelled) {
            setInstances([]);
            setInstancesAvailable(err?.response?.status !== 404);
          }
        }
      } catch (err) {
        if (!cancelled) {
          setCertificate(null);
          setInstances([]);
          setError(
            err?.response?.data?.error ||
              'Could not load certificate operations data.'
          );
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [workspaceId, tokenId, enabled]);

  return {
    enabled,
    certificate,
    instances,
    instancesAvailable,
    loading,
    error,
  };
}
