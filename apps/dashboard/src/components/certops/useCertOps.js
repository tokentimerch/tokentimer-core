import { useCallback, useEffect, useState } from 'react';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { workspaceAPI } from '../../utils/apiClient';
import {
  getCachedCertOpsEnabled,
  getCertificateInstances,
  getManagedCertificatesForToken,
  getWorkspaceCertOpsPauseState,
  invalidateCertOpsInventoryCache,
  loadCertOpsInventoryIndex,
  probeCertOpsEnabled,
  updateWorkspaceCertOpsPauseState,
} from './certopsApi';
import { pickPrimaryCertificate } from './certopsFormat';

/**
 * Resolves CertOps availability for the active workspace.
 *
 * CertOps ships behind the `certops.enabled` rollout flag. The backend hides
 * its routes (404) while the flag is off. Only 404 means disabled; other
 * failures are surfaced as `error` so outages are not mistaken for "feature off".
 * One nuance when a fresh cached verdict exists: a cached `enabled: true` is
 * served through a failed background revalidation (the gated screens' own
 * requests surface the outage), but a cached `enabled: false` is not, since
 * a "feature off" panel makes no further requests that could reveal it.
 *
 * @returns {{ ready: boolean, enabled: boolean|null, error: string|null, retry: function }}
 */
export function useCertOpsAvailability() {
  const { workspaceId } = useWorkspace();
  // Lazy-initialized from the module-level cache (not just re-applied inside
  // the effect below) so a cache hit is reflected in the *first* render, not
  // one tick later. Every CertOps screen (Jobs, Certificates, Agents, a
  // single job's evidence timeline, ...) mounts its own copy of this hook;
  // without this, re-mounting one (e.g. re-opening a job row) always
  // rendered `enabled: null` for at least one frame before the effect could
  // apply the cache, which was enough for a child like the evidence timeline
  // to render "Job not found" before flipping to the real data.
  const [state, setState] = useState(() => {
    const cached = workspaceId ? getCachedCertOpsEnabled(workspaceId) : null;
    return cached
      ? { ready: true, enabled: cached.enabled, error: null }
      : { ready: false, enabled: null, error: null };
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

    // Serve the cached verdict immediately when fresh (matches the lazy
    // initial state above; re-applied here too since `workspaceId` can
    // change after mount), then still revalidate in the background so a
    // real change (flag flipped, workspace switched) is picked up within
    // the cache TTL.
    const cached = getCachedCertOpsEnabled(workspaceId);
    if (cached) {
      setState({ ready: true, enabled: cached.enabled, error: null });
    } else {
      setState({ ready: false, enabled: null, error: null });
    }

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
        // A cached *enabled* verdict keeps being served through a failed
        // background revalidation: the screens it gates are already fetching
        // real data, and those requests surface the outage loudly on their
        // own. A cached *disabled* verdict must not be retained the same
        // way: it renders "feature off" panels that make no follow-up
        // requests, so keeping it would let a revalidation outage silently
        // masquerade as "CertOps is not enabled" (only a 404 may mean
        // disabled).
        if (cached?.enabled === true) return;
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
 * Resolves whether the current user holds the workspace admin role. The
 * kill switch (PUT /certops/settings) requires admin specifically
 * (certops.kill_switch.manage), stricter than the workspace_manager-or-above
 * gate used for other CertOps writes; backend RBAC remains authoritative
 * (403 for non-admins), this only drives whether the control is shown.
 */
export function useCertOpsIsWorkspaceAdmin() {
  const { workspaceId } = useWorkspace();
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    if (!workspaceId) {
      setIsAdmin(false);
      return undefined;
    }

    let cancelled = false;
    workspaceAPI
      .get(workspaceId)
      .then(ws => {
        if (cancelled) return;
        const role = String(ws?.role || '').toLowerCase();
        setIsAdmin(role === 'admin');
      })
      .catch(() => {
        if (!cancelled) setIsAdmin(false);
      });

    return () => {
      cancelled = true;
    };
  }, [workspaceId]);

  return isAdmin;
}

/**
 * Loads and manages the workspace CertOps kill-switch state.
 *
 * Reads GET /certops/settings (available to any human session member, even
 * while the deployment-wide certops.enabled rollout is off) and exposes a
 * `setPaused` action mapped to PUT /certops/settings (admin-only
 * server-side). `certOpsActive` mirrors the server's composed
 * `certOpsEnabled && !certOpsPaused` so callers do not need to re-derive it.
 */
export function useCertOpsWorkspaceKillSwitch() {
  const { workspaceId } = useWorkspace();
  const [state, setState] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    if (!workspaceId) {
      setState(null);
      setLoading(false);
      setError('');
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    getWorkspaceCertOpsPauseState(workspaceId, { signal: controller.signal })
      .then(data => {
        if (!cancelled) setState(data);
      })
      .catch(err => {
        if (cancelled) return;
        setState(null);
        setError(
          err?.response?.data?.error ||
            'Could not load the certificate operations kill switch.'
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [workspaceId, reloadTick]);

  const setPaused = useCallback(
    async (certOpsPaused, reason) => {
      if (!workspaceId) return null;
      setSaving(true);
      try {
        const data = await updateWorkspaceCertOpsPauseState(workspaceId, {
          certOpsPaused,
          reason,
        });
        setState(data);
        setError('');
        return data;
      } finally {
        setSaving(false);
      }
    },
    [workspaceId]
  );

  return { ...state, loading, error, saving, setPaused, refresh };
}

/**
 * Loads the whole workspace CertOps inventory once and exposes a tokenId ->
 * managed certificate lookup, so the asset list can tell which token rows are
 * backed by a managed certificate (delete gating + retired filtering).
 *
 * Returns a stable `byTokenId` Map of tokenId -> certificate[] (empty when
 * CertOps is disabled/resolving; several certificates may reference the same
 * token), the enabled flag, a loading flag, and a `refresh()` that re-fetches
 * after a retire so the list reflects the new lifecycle status.
 */
export function useWorkspaceCertOps() {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const [byTokenId, setByTokenId] = useState(() => new Map());
  const [items, setItems] = useState(() => []);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
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
      setError('');
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    loadCertOpsInventoryIndex(workspaceId, { signal: controller.signal })
      .then(index => {
        if (!cancelled) {
          setByTokenId(new Map(index.byTokenId));
          setItems(Array.isArray(index.items) ? index.items : []);
          setError('');
        }
      })
      .catch(err => {
        if (!cancelled) {
          setByTokenId(new Map());
          setItems([]);
          setError(
            err?.response?.data?.error ||
              'Could not load the certificate inventory.'
          );
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

  // `resolved` is the fail-closed signal for delete gating: while CertOps
  // availability or the inventory is still resolving, or the fetch
  // failed, callers must not assume a token is unmanaged just because it is
  // missing from `byTokenId`. `resolved` is true when CertOps is known to be
  // disabled (nothing is managed) or the inventory loaded successfully.
  const resolved =
    enabled === false || (enabled === true && !loading && !error);

  return { enabled, byTokenId, items, loading, error, resolved, refresh };
}

/**
 * Loads CertOps enrichment (managed certificate + deployment history) for an
 * existing cert token row, keyed by tokens.id via managed_certificates.token_id.
 *
 * Several managed certificates can reference the same token. `certificate`
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
  const [instancesError, setInstancesError] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!workspaceId || !tokenId || enabled !== true) {
      setCertificate(null);
      setCertificates([]);
      setInstances([]);
      setInstancesAvailable(true);
      setInstancesError('');
      setLoading(false);
      setError('');
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');
    setInstancesError('');

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
            setInstancesError('');
          }
        } catch (err) {
          if (!cancelled) {
            setInstances([]);
            // Only 404 means "history not recorded for this certificate yet".
            // Network/server failures must not masquerade as a successful
            // empty result, so they surface as a distinct instances error.
            const notFound = err?.response?.status === 404;
            setInstancesAvailable(!notFound);
            setInstancesError(
              notFound
                ? ''
                : err?.response?.data?.error ||
                    'Could not load certificate locations.'
            );
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
    instancesError,
    loading,
    error,
  };
}
