import { useCallback, useEffect, useState } from 'react';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import {
  CERTOPS_CONTROLLER_TOKEN_SCOPES,
  listApiTokens,
} from './certopsTokensApi';
import { useCertOpsCanManage, useCertOpsEnabled } from './useCertOps.js';

/**
 * Mirrors displayStatus in ApiTokenList.jsx: a token is usable if its
 * status is not revoked/expired and its expiresAt (if any) has not passed.
 */
function isTokenActive(token) {
  const status = String(token?.status || '').toLowerCase();
  if (status === 'revoked' || status === 'expired') return false;
  if (token?.expiresAt) {
    const expires = new Date(token.expiresAt);
    if (!Number.isNaN(expires.getTime()) && expires.getTime() < Date.now()) {
      return false;
    }
  }
  return true;
}

function isProvisioningToken(token) {
  const scopes = Array.isArray(token?.scopes) ? token.scopes : [];
  return (
    Boolean(token?.controllerClusterId) &&
    scopes.some(scope => CERTOPS_CONTROLLER_TOKEN_SCOPES.includes(scope))
  );
}

/**
 * Distinct cluster ids with at least one active, controller-scoped API
 * token, i.e. clusters a controller could actually be running against.
 *
 * Backs the cluster picker on the "provision via controller" path in
 * CreateManualJobModal: a free-text cluster id field would let an operator
 * target a typo'd or never-wired-up cluster, so the picker only offers ids
 * this workspace has already issued a controller credential for.
 *
 * Same gating pattern as useCertOpsApiTokens (manager-only server-side).
 * @returns {{ enabled: boolean|null, clusters: string[], loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsControllerClusters() {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const canManage = useCertOpsCanManage();
  const [clusters, setClusters] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    if (!workspaceId || enabled !== true || !canManage) {
      setClusters([]);
      setLoading(false);
      setError('');
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    // No `limit`: this is a lookup source (see listApiTokens docs), not a
    // paginated view, so it must see the whole token inventory.
    listApiTokens(workspaceId, { signal: controller.signal })
      .then(data => {
        if (cancelled) return;
        const items = Array.isArray(data?.items) ? data.items : [];
        const ids = [
          ...new Set(
            items
              .filter(token => isTokenActive(token) && isProvisioningToken(token))
              .map(token => token.controllerClusterId)
          ),
        ];
        setClusters(ids);
      })
      .catch(err => {
        if (cancelled) return;
        setClusters([]);
        setError(
          err?.response?.data?.error ||
            err?.message ||
            'Could not load controller-bound clusters.'
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [workspaceId, enabled, canManage, reloadTick]);

  return { enabled, clusters, loading, error, refresh };
}
