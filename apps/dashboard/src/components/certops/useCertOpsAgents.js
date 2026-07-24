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
 * @returns {{ enabled: boolean|null, agents: object[], loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsAgents() {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const canManage = useCertOpsCanManage();
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    if (!workspaceId || enabled !== true || !canManage) {
      setAgents([]);
      setLoading(false);
      setError('');
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    listAgents(workspaceId, { signal: controller.signal })
      .then(data => {
        if (!cancelled) {
          setAgents(Array.isArray(data?.items) ? data.items : []);
        }
      })
      .catch(err => {
        if (cancelled) return;
        setAgents([]);
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
  }, [workspaceId, enabled, canManage, reloadTick]);

  return { enabled, agents, loading, error, refresh };
}

/**
 * Loads agent bootstrap-token metadata for the active workspace (read-only;
 * the ttboot_ secret is only ever returned once at creation). Create/revoke
 * are called imperatively via certopsAgentsApi from the panel.
 *
 * Manager-gated exactly like useCertOpsAgents.
 *
 * @returns {{ enabled: boolean|null, tokens: object[], loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsBootstrapTokens() {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const canManage = useCertOpsCanManage();
  const [tokens, setTokens] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    if (!workspaceId || enabled !== true || !canManage) {
      setTokens([]);
      setLoading(false);
      setError('');
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    listBootstrapTokens(workspaceId, { signal: controller.signal })
      .then(data => {
        if (!cancelled) {
          setTokens(Array.isArray(data?.items) ? data.items : []);
        }
      })
      .catch(err => {
        if (cancelled) return;
        setTokens([]);
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
  }, [workspaceId, enabled, canManage, reloadTick]);

  return { enabled, tokens, loading, error, refresh };
}
