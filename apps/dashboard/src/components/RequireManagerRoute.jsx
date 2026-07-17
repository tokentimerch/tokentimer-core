import { useEffect, useState } from 'react';
import { Navigate } from 'react-router-dom';
import { workspaceAPI } from '../utils/apiClient';
import { useWorkspace } from '../utils/WorkspaceContext.jsx';

/**
 * Manager/admin route guard.
 *
 * Default (`scope='any-workspace'`): passes when the user is a system admin or
 * a manager/admin in ANY workspace (pre-existing semantics for
 * /control-center, /workspaces, /audit, /workspace-preferences).
 *
 * `scope='active-workspace'`: passes only when the user is a system admin or a
 * manager/admin in the CURRENTLY SELECTED workspace (same data source as
 * useCertOpsCanManage: workspaceAPI.get(workspaceId).role). Used for
 * /certops/* so a viewer of the active workspace cannot reach CertOps
 * surfaces via a manager role held in another workspace. Backend RBAC remains
 * authoritative; this only gates routing.
 *
 * Must render inside WorkspaceProvider (uses useWorkspace).
 */
export default function RequireManagerRoute({
  session,
  scope = 'any-workspace',
  children,
}) {
  // Fail-closed: the authorization result is stored together with the
  // workspace it was computed for, so a stale grant from workspace A can
  // never leak through while workspace B's check is in flight.
  const [authorization, setAuthorization] = useState({
    workspaceId: null,
    allowed: null,
  });
  const activeWorkspace = scope === 'active-workspace';
  const { workspaceId } = useWorkspace();

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!session) {
        if (!cancelled)
          setAuthorization({
            workspaceId: workspaceId ?? null,
            allowed: false,
          });
        return;
      }
      const isSystemAdmin = session?.isAdmin === true;
      if (isSystemAdmin) {
        if (!cancelled)
          setAuthorization({ workspaceId: workspaceId ?? null, allowed: true });
        return;
      }
      if (activeWorkspace) {
        // Wait for workspace selection to resolve before deciding. Any prior
        // grant is stale for a falsy workspaceId, so drop it (fail closed to
        // the loading state, not to a redirect).
        if (!workspaceId) {
          if (!cancelled)
            setAuthorization({ workspaceId: null, allowed: null });
          return;
        }
        try {
          const ws = await workspaceAPI.get(workspaceId);
          const role = String(ws?.role || '').toLowerCase();
          if (!cancelled)
            setAuthorization({
              workspaceId,
              allowed: role === 'admin' || role === 'workspace_manager',
            });
        } catch (_) {
          if (!cancelled) setAuthorization({ workspaceId, allowed: false });
        }
        return;
      }
      try {
        const ws = await workspaceAPI.list(50, 0);
        const items = ws?.items || [];
        const roles = items.map(w => String(w.role || '').toLowerCase());
        const hasManagerOrAdmin =
          roles.includes('admin') || roles.includes('workspace_manager');
        if (!cancelled)
          setAuthorization({
            workspaceId: workspaceId ?? null,
            allowed: hasManagerOrAdmin,
          });
      } catch (_) {
        if (!cancelled)
          setAuthorization({
            workspaceId: workspaceId ?? null,
            allowed: false,
          });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [session, activeWorkspace, workspaceId]);

  if (!session) return <Navigate to='/login' replace />;

  // For active-workspace scope, a stored result only counts when it belongs
  // to the CURRENT workspace; otherwise treat the check as pending (render
  // the loading state, never stale children and never a redirect-flicker).
  const isCurrent = activeWorkspace
    ? authorization.workspaceId === (workspaceId ?? null)
    : true;
  if (!isCurrent || authorization.allowed === null) return null;
  if (!authorization.allowed) return <Navigate to='/dashboard' replace />;
  return children;
}
