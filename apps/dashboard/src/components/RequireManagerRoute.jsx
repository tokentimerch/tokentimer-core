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
  const [isAllowed, setIsAllowed] = useState(null);
  const activeWorkspace = scope === 'active-workspace';
  const { workspaceId } = useWorkspace();

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!session) {
        if (!cancelled) setIsAllowed(false);
        return;
      }
      const isSystemAdmin = session?.isAdmin === true;
      if (isSystemAdmin) {
        if (!cancelled) setIsAllowed(true);
        return;
      }
      if (activeWorkspace) {
        // Wait for workspace selection to resolve before deciding.
        if (!workspaceId) return;
        try {
          const ws = await workspaceAPI.get(workspaceId);
          const role = String(ws?.role || '').toLowerCase();
          if (!cancelled)
            setIsAllowed(role === 'admin' || role === 'workspace_manager');
        } catch (_) {
          if (!cancelled) setIsAllowed(false);
        }
        return;
      }
      try {
        const ws = await workspaceAPI.list(50, 0);
        const items = ws?.items || [];
        const roles = items.map(w => String(w.role || '').toLowerCase());
        const hasManagerOrAdmin =
          roles.includes('admin') || roles.includes('workspace_manager');
        if (!cancelled) setIsAllowed(hasManagerOrAdmin);
      } catch (_) {
        if (!cancelled) setIsAllowed(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [session, activeWorkspace, workspaceId]);

  if (!session) return <Navigate to='/login' replace />;
  if (isAllowed === null) return null;
  if (!isAllowed) return <Navigate to='/dashboard' replace />;
  return children;
}
