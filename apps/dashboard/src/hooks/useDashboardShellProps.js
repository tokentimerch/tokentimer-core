import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useLocation } from 'react-router';
import { useDashboardTheme } from './useDashboardTheme';
import { useDashboardNotifications } from './useDashboardNotifications.js';
import { workspaceAPI } from '../utils/apiClient';
import { useWorkspace } from '../utils/WorkspaceContext.jsx';
import {
  pickAccessibleWorkspace,
  readLastWorkspaceId,
  writeLastWorkspaceId,
} from '../utils/lastWorkspacePreference.js';

function buildSessionIdentity(session) {
  const sessionName =
    session?.displayName || session?.name || session?.email || 'User';
  const sessionEmail = session?.email || '';
  const sessionInitials = String(sessionName)
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map(part => part[0])
    .join('')
    .toUpperCase();

  return { sessionName, sessionEmail, sessionInitials };
}

/**
 * Shared DashboardShell props: session identity, workspace list/selection,
 * role flags, notifications, and chrome callbacks.
 *
 * @param {object} options
 * @param {object|null} [options.session]
 * @param {() => void} [options.onLogout]
 * @param {() => void} [options.onAccountClick]
 * @param {string} [options.pageTitle='']
 * @param {boolean} [options.isViewer=false]
 * @param {object[]} [options.dashboardWorkspaces]
 * @param {object|null} [options.dashboardWorkspace]
 * @param {(workspace: object) => void} [options.onWorkspaceSelect]
 * @param {object[]} [options.dashboardNotifications]
 * @param {boolean} [options.dashboardCanSeeManagerNav]
 */
export function useDashboardShellProps({
  session = null,
  onLogout,
  onAccountClick,
  pageTitle = '',
  isViewer = false,
  dashboardWorkspaces: workspacesOverride,
  dashboardWorkspace: workspaceOverride,
  onWorkspaceSelect: onWorkspaceSelectOverride,
  dashboardNotifications: notificationsOverride,
  dashboardCanSeeManagerNav: managerNavOverride,
}) {
  const location = useLocation();
  const { workspaceId, selectWorkspace } = useWorkspace();
  const dashboardSelectionIdRef = useRef(workspaceId);
  useEffect(() => {
    if (workspaceId) dashboardSelectionIdRef.current = workspaceId;
  }, [workspaceId]);
  const theme = useDashboardTheme();
  const { pageBg, surface, text, muted, border, borderStrong, inputBg } = theme;

  const { sessionName, sessionEmail, sessionInitials } = useMemo(
    () => buildSessionIdentity(session),
    [session]
  );

  const isSystemAdmin = session?.isAdmin === true;
  const workspaceLabel =
    workspaceOverride?.name ||
    session?.workspaceName ||
    session?.workspace?.name ||
    'Current workspace';

  const [dashboardWorkspaces, setDashboardWorkspaces] = useState([]);
  const [dashboardWorkspace, setDashboardWorkspace] = useState(null);
  const [dashboardCanSeeManagerNav, setDashboardCanSeeManagerNav] =
    useState(false);
  const useWorkspaceOverrides = workspacesOverride !== undefined;

  useEffect(() => {
    if (useWorkspaceOverrides) return undefined;

    let cancelled = false;
    async function loadDashboardWorkspaces() {
      if (!session) {
        if (!cancelled) {
          setDashboardWorkspaces([]);
          setDashboardWorkspace(null);
          setDashboardCanSeeManagerNav(false);
        }
        return;
      }

      try {
        const ws = await workspaceAPI.list(50, 0);
        if (cancelled) return;
        const items = ws?.items || [];
        const chosenId = pickAccessibleWorkspace({
          urlWorkspaceId:
            dashboardSelectionIdRef.current || workspaceId || null,
          lastWorkspaceId: readLastWorkspaceId(session?.id),
          workspaces: items,
        });
        const selected = chosenId
          ? items.find(w => String(w.id) === String(chosenId)) || null
          : null;

        setDashboardWorkspaces(items);
        setDashboardWorkspace(selected);
        const selectedRole = String(selected?.role || '').toLowerCase();
        setDashboardCanSeeManagerNav(
          isSystemAdmin ||
            selectedRole === 'admin' ||
            selectedRole === 'workspace_manager'
        );
      } catch (_) {
        if (!cancelled) {
          setDashboardWorkspaces([]);
          setDashboardWorkspace(null);
          setDashboardCanSeeManagerNav(isSystemAdmin);
        }
      }
    }

    loadDashboardWorkspaces();
    const refresh = () => loadDashboardWorkspaces();
    window.addEventListener('tt:workspaces-updated', refresh);
    window.addEventListener('tt:plan-updated', refresh);
    return () => {
      cancelled = true;
      window.removeEventListener('tt:workspaces-updated', refresh);
      window.removeEventListener('tt:plan-updated', refresh);
    };
  }, [session, isSystemAdmin, workspaceId, useWorkspaceOverrides]);

  const handleDashboardWorkspaceSelect = useCallback(
    workspace => {
      if (!workspace?.id) return;
      dashboardSelectionIdRef.current = String(workspace.id);
      setDashboardWorkspace(workspace);
      const role = String(workspace?.role || '').toLowerCase();
      setDashboardCanSeeManagerNav(
        isSystemAdmin || role === 'admin' || role === 'workspace_manager'
      );
      try {
        selectWorkspace(workspace.id);
        writeLastWorkspaceId(session?.id, workspace.id);
      } catch (_) {}
    },
    [selectWorkspace, isSystemAdmin, session?.id]
  );

  const activeWorkspace = useWorkspaceOverrides
    ? workspaceOverride
    : dashboardWorkspace;

  const {
    dashboardNotifications,
    dashboardUnreadCount,
    onNotificationClick,
    onMarkAllNotificationsRead,
  } = useDashboardNotifications({
    session,
    workspace: activeWorkspace,
    enabled: notificationsOverride === undefined,
  });

  return useMemo(
    () => ({
      dashboardColors: {
        pageBg,
        surface,
        text,
        muted,
        border,
        borderStrong,
        inputBg,
      },
      currentPath: location.pathname,
      sessionName,
      sessionEmail,
      sessionInitials,
      dashboardWorkspaces: useWorkspaceOverrides
        ? workspacesOverride
        : dashboardWorkspaces,
      dashboardWorkspace: useWorkspaceOverrides
        ? workspaceOverride
        : dashboardWorkspace,
      workspaceLabel: useWorkspaceOverrides
        ? workspaceOverride?.name || 'Current workspace'
        : dashboardWorkspace?.name || workspaceLabel,
      onWorkspaceSelect: useWorkspaceOverrides
        ? onWorkspaceSelectOverride
        : handleDashboardWorkspaceSelect,
      dashboardNotifications:
        notificationsOverride !== undefined
          ? notificationsOverride
          : dashboardNotifications,
      dashboardUnreadCount:
        notificationsOverride !== undefined ? undefined : dashboardUnreadCount,
      onNotificationClick:
        notificationsOverride !== undefined ? undefined : onNotificationClick,
      onMarkAllNotificationsRead:
        notificationsOverride !== undefined
          ? undefined
          : onMarkAllNotificationsRead,
      onLogout,
      onAccountClick,
      isViewer,
      dashboardCanSeeManagerNav:
        managerNavOverride !== undefined
          ? managerNavOverride
          : dashboardCanSeeManagerNav,
      isSystemAdmin,
      pageTitle,
    }),
    [
      pageBg,
      surface,
      text,
      muted,
      border,
      borderStrong,
      inputBg,
      location.pathname,
      sessionName,
      sessionEmail,
      sessionInitials,
      useWorkspaceOverrides,
      workspacesOverride,
      workspaceOverride,
      dashboardWorkspaces,
      dashboardWorkspace,
      workspaceLabel,
      onWorkspaceSelectOverride,
      handleDashboardWorkspaceSelect,
      notificationsOverride,
      dashboardNotifications,
      dashboardUnreadCount,
      onNotificationClick,
      onMarkAllNotificationsRead,
      onLogout,
      onAccountClick,
      isViewer,
      managerNavOverride,
      dashboardCanSeeManagerNav,
      isSystemAdmin,
      pageTitle,
    ]
  );
}
