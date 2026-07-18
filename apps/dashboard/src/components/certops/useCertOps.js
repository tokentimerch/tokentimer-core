import { useCallback, useEffect, useState } from 'react';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { workspaceAPI } from '../../utils/apiClient';
import {
  getCertificateInstances,
  getManagedCertificatesForToken,
  invalidateCertOpsInventoryCache,
  loadCertOpsInventoryIndex,
  probeCertOpsEnabled,
} from './certopsApi';
import { pickPrimaryCertificate } from './certopsFormat';

/**
 * Resolves CertOps availability for the active workspace.
 *
 * CertOps ships behind the `certops.enabled` rollout flag. The backend hides
 * its routes (404) while the flag is off. Only 404 means disabled; other
 * failures are surfaced as `error` so outages are not mistaken for "feature off".
 *
 * @returns {{ ready: boolean, enabled: boolean|null, error: string|null, retry: function }}
 */
export function useCertOpsAvailability() {
  const { workspaceId } = useWorkspace();
  const [state, setState] = useState({
    ready: false,
    enabled: null,
    error: null,
  });
  const [reloadTick, setReloadTick] = useState(0);

  const retry = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    if (!workspaceId) {
      setState({ ready: false, enabled: null, error: null });
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setState({ ready: false, enabled: null, error: null });

    probeCertOpsEnabled(workspaceId, { signal: controller.signal })
      .then(result => {
        if (!cancelled) {
          setState({
            ready: true,
            enabled: result.enabled,
            error: null,
          });
        }
      })
      .catch(err => {
        if (cancelled) return;
        const message =
          err?.response?.data?.error ||
          err?.message ||
          'Could not check certificate operations availability.';
        setState({ ready: true, enabled: null, error: message });
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [workspaceId, reloadTick]);

  return { ...state, retry };
}

/**
 * Resolves whether the CertOps surface is available for the active workspace.
 *
 * Returns null while resolving or when availability could not be determined
 * (use `useCertOpsAvailability` for explicit error vs disabled).
 * @returns {boolean|null}
 */
export function useCertOpsEnabled() {
  const { ready, enabled } = useCertOpsAvailability();
  if (!ready) return null;
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
 * Returns a stable `byTokenId` Map of tokenId -> certificate[] (empty when
 * CertOps is disabled/resolving; D8 allows several certificates per token),
 * the enabled flag, a loading flag, and a `refresh()` that re-fetches after a
 * retire so the list reflects the new lifecycle status.
 */
export function useWorkspaceCertOps() {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const [byTokenId, setByTokenId] = useState(() => new Map());
  const [items, setItems] = useState(() => []);
  const [loading, setLoading] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    if (workspaceId) invalidateCertOpsInventoryCache(workspaceId);
    setReloadTick(tick => tick + 1);
  }, [workspaceId]);

  useEffect(() => {
    if (!workspaceId || enabled !== true) {
      setByTokenId(new Map());
      setItems([]);
      setLoading(false);
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);

    loadCertOpsInventoryIndex(workspaceId, { signal: controller.signal })
      .then(index => {
        if (!cancelled) {
          setByTokenId(new Map(index.byTokenId));
          setItems(Array.isArray(index.items) ? index.items : []);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setByTokenId(new Map());
          setItems([]);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [workspaceId, enabled, reloadTick]);

  return { enabled, byTokenId, items, loading, refresh };
}

/**
 * Loads CertOps enrichment (managed certificate + deployment history) for an
 * existing cert token row, keyed by tokens.id via managed_certificates.token_id.
 *
 * D8: several managed certificates can reference the same token. `certificate`
 * is the deterministic primary pick (active preferred, most recently updated);
 * `certificates` and `certificateCount` expose the full set so callers can
 * surface a multi-cert notice.
 */
export function useCertOpsForToken(tokenId) {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const [certificate, setCertificate] = useState(null);
  const [certificates, setCertificates] = useState([]);
  const [instances, setInstances] = useState([]);
  const [instancesAvailable, setInstancesAvailable] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!workspaceId || !tokenId || enabled !== true) {
      setCertificate(null);
      setCertificates([]);
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
        const linked = await getManagedCertificatesForToken(
          workspaceId,
          tokenId,
          { signal: controller.signal }
        );
        if (cancelled) return;
        const managed = pickPrimaryCertificate(linked);
        setCertificates(Array.isArray(linked) ? linked : []);
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
          setCertificates([]);
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
    certificates,
    certificateCount: certificates.length,
    instances,
    instancesAvailable,
    loading,
    error,
  };
}
