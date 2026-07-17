import { useCallback, useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useDashboardTheme } from './useDashboardTheme';
import { workspaceAPI } from '../utils/apiClient';
import { useWorkspace } from '../utils/WorkspaceContext.jsx';

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
  const navigate = useNavigate();
  const { workspaceId, selectWorkspace } = useWorkspace();
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
  const [dashboardNotifications, setDashboardNotifications] = useState([]);
  const [dashboardUnreadCount, setDashboardUnreadCount] = useState(0);

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
        let desiredId = workspaceId || null;
        if (!desiredId) {
          try {
            desiredId = localStorage.getItem('tt_last_workspace_id') || null;
          } catch (_) {
            desiredId = null;
          }
        }
        const selected =
          (desiredId && items.find(w => w.id === desiredId)) ||
          items[0] ||
          null;

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
      setDashboardWorkspace(workspace);
      const role = String(workspace?.role || '').toLowerCase();
      setDashboardCanSeeManagerNav(
        isSystemAdmin || role === 'admin' || role === 'workspace_manager'
      );
      try {
        selectWorkspace(workspace.id);
        localStorage.setItem('tt_last_workspace_id', workspace.id);
      } catch (_) {}
      try {
        window.dispatchEvent(new CustomEvent('tt:workspaces-updated'));
      } catch (_) {}
    },
    [selectWorkspace, isSystemAdmin]
  );

  const activeWorkspace = useWorkspaceOverrides
    ? workspaceOverride
    : dashboardWorkspace;

  useEffect(() => {
    if (notificationsOverride !== undefined) return undefined;

    let cancelled = false;
    async function loadDashboardNotifications() {
      if (!session || !activeWorkspace?.id) {
        if (!cancelled) setDashboardNotifications([]);
        return;
      }

      try {
        const [settingsRes, notificationsRes] = await Promise.all([
          workspaceAPI.getAlertSettings(activeWorkspace.id),
          workspaceAPI
            .getNotifications(activeWorkspace.id)
            .catch(() => ({ items: [] })),
        ]);
        if (cancelled) return;

        const data = settingsRes?.data || settingsRes || {};
        const emailEnabled = data.email_alerts_enabled === true;
        const webhooks = data.webhook_urls;
        const hasWebhooks = Array.isArray(webhooks) && webhooks.length > 0;
        const smtpConfigured = data.smtp_configured !== false;
        const allDisabled = !emailEnabled && !hasWebhooks;
        const contactGroups = Array.isArray(data.contact_groups)
          ? data.contact_groups
          : [];
        const hasAnyContact = contactGroups.some(group => {
          const emailIds = Array.isArray(group.email_contact_ids)
            ? group.email_contact_ids
            : [];
          const whatsappIds = Array.isArray(group.whatsapp_contact_ids)
            ? group.whatsapp_contact_ids
            : [];
          return emailIds.length > 0 || whatsappIds.length > 0;
        });
        const currentRole = String(activeWorkspace?.role || '').toLowerCase();
        const canManageWorkspaceAlerts =
          isSystemAdmin ||
          currentRole === 'admin' ||
          currentRole === 'workspace_manager';
        const list = [];

        // Server already scopes items to what this user may see (privileged
        // roles get workspace-wide items; everyone else gets only
        // notifications about their own tokens), so no client-side gating.
        const operational = Array.isArray(notificationsRes?.items)
          ? notificationsRes.items
          : [];
        for (const item of operational) {
          const href =
            item.href === '/usage' ? '/control-center' : item.href || null;
          list.push({
            id: item.id,
            kind: item.kind === 'error' ? 'error' : 'warning',
            text: item.text,
            href,
            isRead: item.isRead,
            persisted: item.persisted === true,
          });
        }
        setDashboardUnreadCount(
          Number.isFinite(notificationsRes?.unreadCount)
            ? notificationsRes.unreadCount
            : 0
        );

        if (!canManageWorkspaceAlerts) {
          setDashboardNotifications(list);
          return;
        }

        if (!smtpConfigured) {
          list.push({
            id: 'smtp-not-configured',
            kind: 'warning',
            text: isSystemAdmin
              ? 'SMTP is not configured. Email notifications will not be sent.'
              : 'SMTP is not configured. Ask a system administrator to configure email delivery.',
            href: isSystemAdmin ? '/system-settings' : null,
          });
        }
        if (allDisabled) {
          list.push({
            id: 'alerts-disabled',
            kind: 'warning',
            text: 'Alerts are disabled until a channel is defined.',
            href: '/workspace-preferences',
          });
        }
        if (!hasAnyContact) {
          list.push({
            id: 'no-contacts-defined',
            kind: 'warning',
            text: 'No contacts assigned to any contact group. Alerts will not reach anyone.',
            href: '/workspace-preferences',
          });
        }
        setDashboardNotifications(list);
      } catch (_) {
        if (!cancelled) {
          setDashboardNotifications([]);
          setDashboardUnreadCount(0);
        }
      }
    }

    loadDashboardNotifications();
    const refresh = () => loadDashboardNotifications();
    window.addEventListener('tt:notifications-refresh', refresh);
    return () => {
      cancelled = true;
      window.removeEventListener('tt:notifications-refresh', refresh);
    };
  }, [session, activeWorkspace, isSystemAdmin, notificationsOverride]);

  const handleNotificationClick = useCallback(
    notification => {
      if (notification?.persisted && activeWorkspace?.id && notification?.id) {
        workspaceAPI
          .markNotificationRead(activeWorkspace.id, notification.id)
          .then(() => {
            setDashboardNotifications(prev =>
              prev.map(item =>
                item.id === notification.id ? { ...item, isRead: true } : item
              )
            );
            setDashboardUnreadCount(prev => Math.max(0, prev - 1));
          })
          .catch(() => {});
      }
      if (notification?.href) navigate(notification.href);
    },
    [activeWorkspace, navigate]
  );

  const handleMarkAllNotificationsRead = useCallback(() => {
    if (!activeWorkspace?.id) return;
    workspaceAPI
      .markAllNotificationsRead(activeWorkspace.id)
      .then(() => {
        setDashboardNotifications(prev =>
          prev.map(item => ({ ...item, isRead: true }))
        );
        setDashboardUnreadCount(0);
      })
      .catch(() => {});
  }, [activeWorkspace]);

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
        notificationsOverride !== undefined
          ? undefined
          : handleNotificationClick,
      onMarkAllNotificationsRead:
        notificationsOverride !== undefined
          ? undefined
          : handleMarkAllNotificationsRead,
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
      handleNotificationClick,
      handleMarkAllNotificationsRead,
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
