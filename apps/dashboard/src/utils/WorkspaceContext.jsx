import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useCallback,
  useRef,
  useState,
} from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router';
import { workspaceAPI } from './apiClient';
import {
  pickAccessibleWorkspace,
  readLastWorkspaceId,
  readSessionLastWorkspaceId,
  writeLastWorkspaceId,
} from './lastWorkspacePreference';
import {
  clearInventoryFiltersForWorkspaceSwitch,
  isInventoryDashboardPath,
} from '../hooks/useInventoryUrlState.js';

const WorkspaceContext = createContext(null);

const PUBLIC_WORKSPACE_PATHS = new Set([
  '/login',
  '/register',
  '/reset-password',
  '/verify-email',
  '/',
  '/pricing',
  '/privacy-policy',
  '/terms-of-service',
]);

function isPublicWorkspacePath(path) {
  if (PUBLIC_WORKSPACE_PATHS.has(path)) return true;
  return (
    path.startsWith('/solutions') ||
    path.startsWith('/blog') ||
    path.startsWith('/faq')
  );
}

function idsEqual(left, right) {
  if (left == null || left === '' || right == null || right === '') {
    return false;
  }
  return String(left) === String(right);
}

export function WorkspaceProvider({ children, accountId = null }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const pendingIdRef = useRef(null);
  const selectionEpochRef = useRef(0);
  const searchParamsRef = useRef(searchParams);
  const locationRef = useRef(location);
  const selectWorkspaceRef = useRef(null);
  searchParamsRef.current = searchParams;
  locationRef.current = location;

  const [workspaceId, setWorkspaceId] = useState(() => {
    return searchParams.get('workspace') || null;
  });

  const selectWorkspace = useCallback(
    (id, { replace = false } = {}) => {
      if (id == null || id === '') return;
      pendingIdRef.current = String(id);
      selectionEpochRef.current += 1;
      const current = locationRef.current;
      const params = new URLSearchParams(current.search);
      const previous = params.get('workspace');
      params.set('workspace', id);
      if (
        previous &&
        String(previous) !== String(id) &&
        isInventoryDashboardPath(current.pathname)
      ) {
        clearInventoryFiltersForWorkspaceSwitch(params);
      }
      const path =
        current.pathname ||
        (typeof window !== 'undefined' ? window.location.pathname : '/') ||
        '/';
      const hash =
        current.hash ||
        (typeof window !== 'undefined' ? window.location.hash : '') ||
        '';
      navigate(`${path}?${params.toString()}${hash}`, { replace });
      setWorkspaceId(id);
      writeLastWorkspaceId(accountId, id);
    },
    [navigate, accountId]
  );
  selectWorkspaceRef.current = selectWorkspace;

  useEffect(() => {
    const inUrl = searchParams.get('workspace');
    if (!inUrl) return;
    if (pendingIdRef.current && !idsEqual(inUrl, pendingIdRef.current)) {
      return;
    }
    setWorkspaceId(inUrl);
    if (idsEqual(inUrl, pendingIdRef.current)) {
      pendingIdRef.current = null;
    }
  }, [searchParams]);

  useEffect(() => {
    const path = location.pathname || '';
    if (isPublicWorkspacePath(path)) return;

    let cancelled = false;
    const epochAtStart = selectionEpochRef.current;

    async function restoreAccessibleWorkspace() {
      let items = [];
      try {
        const ws = await workspaceAPI.list(50, 0);
        items = ws?.items || [];
      } catch (_) {
        items = [];
      }
      if (cancelled) return;

      const lastWorkspaceId =
        accountId != null && accountId !== ''
          ? readLastWorkspaceId(accountId)
          : readSessionLastWorkspaceId();

      const applyChosen = chosen => {
        if (!chosen) return;
        const inUrl = searchParamsRef.current.get('workspace');
        if (idsEqual(inUrl, chosen)) {
          setWorkspaceId(chosen);
          if (idsEqual(pendingIdRef.current, chosen)) {
            pendingIdRef.current = null;
          }
          return;
        }
        selectWorkspaceRef.current(chosen, { replace: true });
      };

      const livePending = pendingIdRef.current;
      if (livePending) {
        const pendingChosen = pickAccessibleWorkspace({
          urlWorkspaceId: livePending,
          lastWorkspaceId,
          workspaces: items,
        });
        if (idsEqual(pendingChosen, livePending)) {
          applyChosen(pendingChosen);
          return;
        }
      }

      if (selectionEpochRef.current !== epochAtStart) {
        const liveUrl = searchParamsRef.current.get('workspace');
        const liveChosen = pickAccessibleWorkspace({
          urlWorkspaceId: liveUrl,
          lastWorkspaceId,
          workspaces: items,
        });
        if (idsEqual(liveUrl, liveChosen)) {
          applyChosen(liveChosen);
        }
        return;
      }

      const chosen = pickAccessibleWorkspace({
        urlWorkspaceId: searchParamsRef.current.get('workspace'),
        lastWorkspaceId,
        workspaces: items,
      });
      applyChosen(chosen);
    }

    restoreAccessibleWorkspace();
    return () => {
      cancelled = true;
    };
  }, [accountId, location.pathname]);

  const value = useMemo(
    () => ({ workspaceId, selectWorkspace }),
    [workspaceId, selectWorkspace]
  );

  return (
    <WorkspaceContext.Provider value={value}>
      {children}
    </WorkspaceContext.Provider>
  );
}

export function useWorkspace() {
  const ctx = useContext(WorkspaceContext);
  if (!ctx)
    throw new Error('useWorkspace must be used within WorkspaceProvider');
  return ctx;
}
