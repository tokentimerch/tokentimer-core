import { useCallback, useEffect, useState } from 'react';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import {
  listTrustAnchorInstallations,
  listTrustAnchors,
} from './certopsTrustAnchorsApi';
import { useCertOpsEnabled, useCertOpsIsWorkspaceAdmin } from './useCertOps.js';

/**
 * Loads the trust-anchor list for the active workspace.
 *
 * Gated on admin, not manager: every trust-anchor route requires
 * certops.trust_anchor.manage server-side, above the workspace_manager bar
 * useCertOpsAgents uses, since a trust anchor changes what every
 * certificate on a host is trusted against. Non-admins get an empty list
 * instead of a 403 banner, same pattern as useCertOpsAgents for viewers.
 *
 * @returns {{ enabled: boolean|null, isAdmin: boolean, anchors: object[], loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsTrustAnchors() {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const isAdmin = useCertOpsIsWorkspaceAdmin();
  const [anchors, setAnchors] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    if (!workspaceId || enabled !== true || !isAdmin) {
      setAnchors([]);
      setLoading(false);
      setError('');
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    listTrustAnchors(workspaceId, { signal: controller.signal })
      .then(data => {
        if (!cancelled) {
          setAnchors(Array.isArray(data?.items) ? data.items : []);
        }
      })
      .catch(err => {
        if (cancelled) return;
        setAnchors([]);
        setError(
          err?.response?.data?.error ||
            err?.message ||
            'Could not load trust anchors.'
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [workspaceId, enabled, isAdmin, reloadTick]);

  return { enabled, isAdmin, anchors, loading, error, refresh };
}

/**
 * Loads installation rows for one trust anchor, on demand (only while a
 * row is expanded in TrustAnchorsPanel). `anchorId` null/undefined skips
 * the fetch and clears state, so collapsing a row does not leave stale
 * data around for the next one expanded.
 *
 * @param {string|null} anchorId
 * @returns {{ installations: object[], loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsTrustAnchorInstallations(anchorId) {
  const { workspaceId } = useWorkspace();
  const [installations, setInstallations] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    if (!workspaceId || !anchorId) {
      setInstallations([]);
      setLoading(false);
      setError('');
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    listTrustAnchorInstallations(workspaceId, anchorId, {
      signal: controller.signal,
    })
      .then(data => {
        if (!cancelled) {
          setInstallations(Array.isArray(data?.items) ? data.items : []);
        }
      })
      .catch(err => {
        if (cancelled) return;
        setInstallations([]);
        setError(
          err?.response?.data?.error ||
            err?.message ||
            'Could not load trust anchor installations.'
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [workspaceId, anchorId, reloadTick]);

  return { installations, loading, error, refresh };
}
