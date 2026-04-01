import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useCallback,
  useRef,
  useState,
} from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { workspaceAPI } from './apiClient';

const WorkspaceContext = createContext(null);

export function WorkspaceProvider({ children }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  const [workspaceId, setWorkspaceId] = useState(() => {
    const inUrl = searchParams.get('workspace');
    if (inUrl) return inUrl;
    try {
      const last = localStorage.getItem('tt_last_workspace_id');
      return last || null;
    } catch (_) {
      return null;
    }
  });
  const normalizedRef = useRef(false);

  const selectWorkspace = useCallback(
    (id, { replace = false } = {}) => {
      const params = new URLSearchParams(location.search);
      params.set('workspace', id);
      // Always preserve the current path; avoid redirecting to dashboard
      const path =
        location.pathname ||
        (typeof window !== 'undefined' ? window.location.pathname : '/') ||
        '/';
      const hash =
        location.hash ||
        (typeof window !== 'undefined' ? window.location.hash : '') ||
        '';
      navigate(`${path}?${params.toString()}${hash}`, { replace });
      try {
        localStorage.setItem('tt_last_workspace_id', id);
      } catch (_) {}
    },
    [navigate, location.pathname, location.search, location.hash]
  );

  // Sync local state when URL changes (e.g., back/forward, programmatic navigation).
  // Only update when a workspace IS present in the URL; don't clear when navigating
  // to routes without the param (e.g., docs, help) to avoid losing context.
  useEffect(() => {
    const inUrl = searchParams.get('workspace');
    if (inUrl) {
      setWorkspaceId(inUrl);
    }
  }, [searchParams]);

  // Ensure a workspace is always selected/defined by normalizing URL and state
  useEffect(() => {
    const path = location.pathname || '';
    const isPublicRoute =
      path === '/login' ||
      path === '/register' ||
      path === '/reset-password' ||
      path === '/verify-email' ||
      path === '/' ||
      path === '/pricing' ||
      path === '/help' ||
      path === '/privacy-policy' ||
      path === '/terms-of-service' ||
      path.startsWith('/docs') ||
      path.startsWith('/solutions') ||
      path.startsWith('/blog') ||
      path.startsWith('/faq');
    if (isPublicRoute) return;
    const onboardingActive = [
      'new_user',
      'first_login',
      'registered',
      'verification_success',
    ].some(key => searchParams.get(key) === 'true');
    if (onboardingActive) return;

    const workspaceInUrl = searchParams.get('workspace');
    if (workspaceInUrl && workspaceInUrl === workspaceId) return;

    if (workspaceId && !workspaceInUrl) return;
    if (normalizedRef.current) return;
    normalizedRef.current = true;
    (async () => {
      let items = [];
      try {
        const ws = await workspaceAPI.list(50, 0);
        items = ws?.items || [];
      } catch (_) {}

      const ids = new Set(items.map(w => w.id));

      try {
        const last = localStorage.getItem('tt_last_workspace_id');
        if (last && ids.has(last)) {
          selectWorkspace(last, { replace: true });
          setWorkspaceId(last);
          return;
        }
      } catch (_) {}

      const first = items[0];
      if (first && first.id) {
        selectWorkspace(first.id, { replace: true });
        setWorkspaceId(first.id);
        try {
          localStorage.setItem('tt_last_workspace_id', first.id);
        } catch (_) {}
      }
    })();
  }, [workspaceId, searchParams, location.pathname, selectWorkspace]);

  // Validate that selected workspace is accessible; if not, switch to the first accessible one
  useEffect(() => {
    const path = location.pathname || '';
    const isPublicRoute =
      path === '/login' ||
      path === '/register' ||
      path === '/reset-password' ||
      path === '/verify-email' ||
      path === '/' ||
      path === '/pricing' ||
      path === '/help' ||
      path === '/privacy-policy' ||
      path === '/terms-of-service' ||
      path.startsWith('/docs') ||
      path.startsWith('/solutions') ||
      path.startsWith('/blog') ||
      path.startsWith('/faq');
    if (isPublicRoute) return;
    const onboardingActive = [
      'new_user',
      'first_login',
      'registered',
      'verification_success',
    ].some(key => searchParams.get(key) === 'true');
    if (onboardingActive) return;

    const inUrl = searchParams.get('workspace');
    if (inUrl && inUrl === workspaceId) return;

    let cancelled = false;
    async function normalizeToAccessible() {
      try {
        const ws = await workspaceAPI.list(50, 0);
        if (cancelled) return;
        const items = ws?.items || [];
        if (items.length === 0) return;
        const ids = new Set(items.map(w => w.id));

        if (workspaceId && ids.has(workspaceId) && inUrl === workspaceId)
          return;

        let last = null;
        try {
          last = localStorage.getItem('tt_last_workspace_id');
        } catch (_) {
          last = null;
        }
        const chosen =
          inUrl && ids.has(inUrl)
            ? inUrl
            : last && ids.has(last)
              ? last
              : items[0].id;
        if (!workspaceId || !ids.has(workspaceId) || inUrl !== chosen) {
          selectWorkspace(chosen, { replace: true });
          setWorkspaceId(chosen);
          try {
            localStorage.setItem('tt_last_workspace_id', chosen);
          } catch (_) {}
        }
      } catch (_) {
        // ignore
      }
    }
    normalizeToAccessible();
    return () => {
      cancelled = true;
    };
  }, [searchParams, workspaceId, location.pathname, selectWorkspace]);

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
