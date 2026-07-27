import { useCallback, useEffect, useState } from 'react';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { listAgents, listBootstrapTokens } from './certopsAgentsApi';
import { useCertOpsCanManage, useCertOpsEnabled } from './useCertOps.js';

/**
 * Loads the CertOps agent fleet for the active workspace.
 *
 * Same gating pattern as useCertOpsApiTokens: skipped without a workspace,
 * while `certops.enabled !== true`, or for non-managers (the endpoint is
 * manager-only server-side, so viewers get an empty state instead of a 403
 * banner). Retire is called imperatively via certopsAgentsApi from the panel.
 *
 * @param {number} [externalRefreshSignal] - Optional value from a sibling
 *   component (e.g. DeployAgentModal's onAgentRegistered callback); changing
 *   it triggers an immediate refetch, without waiting for the internal poll.
 * @param {{ limit?: number, offset?: number }} [page] - Page position. Omitting
 *   `limit` asks for the whole fleet, which is what a caller using the list as
 *   a lookup source wants; a caller rendering a page control passes one.
 * @returns {{ enabled: boolean|null, agents: object[], pagination: { limit: number|null, offset: number, total: number }|null, loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsAgents(externalRefreshSignal, page = {}) {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const canManage = useCertOpsCanManage();
  const { limit, offset = 0 } = page;
  const [agents, setAgents] = useState([]);
  // Null, not a zeroed envelope: an absent pagination block means "no answer
  // from the server yet", which must stay distinguishable from a real
  // total of 0.
  const [pagination, setPagination] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    if (!workspaceId || enabled !== true || !canManage) {
      setAgents([]);
      setPagination(null);
      setLoading(false);
      setError('');
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    listAgents(workspaceId, { limit, offset, signal: controller.signal })
      .then(data => {
        if (!cancelled) {
          setAgents(Array.isArray(data?.items) ? data.items : []);
          setPagination(data?.pagination || null);
        }
      })
      .catch(err => {
        if (cancelled) return;
        setAgents([]);
        setPagination(null);
        setError(
          err?.response?.data?.error ||
            err?.message ||
            'Could not load certificate operations agents.'
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
    canManage,
    reloadTick,
    externalRefreshSignal,
    limit,
    offset,
  ]);

  return { enabled, agents, pagination, loading, error, refresh };
}

/**
 * Loads agent bootstrap-token metadata for the active workspace (read-only;
 * the ttboot_ secret is only ever returned once at creation). Create/revoke
 * are called imperatively via certopsAgentsApi from the panel.
 *
 * Manager-gated exactly like useCertOpsAgents.
 *
 * @param {{ limit?: number, offset?: number }} [page] - Page position. Same
 *   convention as useCertOpsAgents: omitting `limit` asks for the whole
 *   token inventory.
 * @returns {{ enabled: boolean|null, tokens: object[], pagination: { limit: number|null, offset: number, total: number }|null, loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsBootstrapTokens(page = {}) {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const canManage = useCertOpsCanManage();
  const { limit, offset = 0 } = page;
  const [tokens, setTokens] = useState([]);
  const [pagination, setPagination] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    if (!workspaceId || enabled !== true || !canManage) {
      setTokens([]);
      setPagination(null);
      setLoading(false);
      setError('');
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    listBootstrapTokens(workspaceId, { limit, offset, signal: controller.signal })
      .then(data => {
        if (!cancelled) {
          setTokens(Array.isArray(data?.items) ? data.items : []);
          setPagination(data?.pagination || null);
        }
      })
      .catch(err => {
        if (cancelled) return;
        setTokens([]);
        setPagination(null);
        setError(
          err?.response?.data?.error ||
            err?.message ||
            'Could not load agent bootstrap tokens.'
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [workspaceId, enabled, canManage, reloadTick, limit, offset]);

  return { enabled, tokens, pagination, loading, error, refresh };
}
