import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router';
import { workspaceAPI } from '../utils/apiClient';

const NOTIFICATION_POLL_INTERVAL_MS = 45_000;
const SETTINGS_WARNING_IDS = new Set([
  'smtp-not-configured',
  'alerts-disabled',
  'no-contacts-defined',
]);

function mapOperationalNotifications(response) {
  return (Array.isArray(response?.items) ? response.items : []).map(item => ({
    id: item.id,
    kind: item.kind === 'error' ? 'error' : 'warning',
    text: item.text,
    href: item.href === '/usage' ? '/control-center' : item.href || null,
    isRead: item.isRead,
    persisted: item.persisted === true,
  }));
}

export function useDashboardNotifications({
  session,
  workspace,
  enabled = true,
}) {
  const navigate = useNavigate();
  const [dashboardNotifications, setDashboardNotifications] = useState([]);
  const [dashboardUnreadCount, setDashboardUnreadCount] = useState(0);
  const isSystemAdmin = session?.isAdmin === true;

  useEffect(() => {
    if (!enabled) return undefined;

    let cancelled = false;
    let inFlight = false;
    let refreshQueued = false;
    function finishRequest() {
      inFlight = false;
      if (refreshQueued && !cancelled) {
        refreshQueued = false;
        void loadDashboardNotifications();
      }
    }
    async function loadDashboardNotifications() {
      if (inFlight) {
        refreshQueued = true;
        return;
      }
      if (!session || !workspace?.id) {
        if (!cancelled) {
          setDashboardNotifications([]);
          setDashboardUnreadCount(0);
        }
        return;
      }

      inFlight = true;
      try {
        const [settingsRes, notificationsRes] = await Promise.all([
          workspaceAPI.getAlertSettings(workspace.id).catch(() => null),
          workspaceAPI.getNotifications(workspace.id).catch(() => null),
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
          // Webhook channels (Slack/Teams/Discord/...) are valid alert
          // destinations too; also honor the legacy single webhook_name field.
          const webhookNames = Array.isArray(group.webhook_names)
            ? group.webhook_names.filter(Boolean)
            : [];
          const hasLegacyWebhook =
            typeof group.webhook_name === 'string' &&
            group.webhook_name.trim().length > 0;
          return (
            emailIds.length > 0 ||
            whatsappIds.length > 0 ||
            webhookNames.length > 0 ||
            hasLegacyWebhook
          );
        });
        const currentRole = String(workspace?.role || '').toLowerCase();
        const canManageWorkspaceAlerts =
          isSystemAdmin ||
          currentRole === 'admin' ||
          currentRole === 'workspace_manager';
        // The server scopes persisted items to the current user's access.
        const list = mapOperationalNotifications(notificationsRes);
        setDashboardUnreadCount(
          Number.isFinite(notificationsRes?.unreadCount)
            ? notificationsRes.unreadCount
            : 0
        );

        if (!settingsRes) {
          setDashboardNotifications(list);
          return;
        }

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
      } finally {
        finishRequest();
      }
    }

    async function pollNotifications() {
      if (inFlight || cancelled || !session || !workspace?.id) return;
      inFlight = true;
      try {
        const response = await workspaceAPI
          .getNotifications(workspace.id)
          .catch(() => null);
        if (cancelled || !response) return;
        setDashboardNotifications(previous => [
          ...mapOperationalNotifications(response),
          ...previous.filter(item => SETTINGS_WARNING_IDS.has(item.id)),
        ]);
        setDashboardUnreadCount(
          Number.isFinite(response.unreadCount) ? response.unreadCount : 0
        );
      } finally {
        finishRequest();
      }
    }

    void loadDashboardNotifications();
    const refresh = () => loadDashboardNotifications();
    window.addEventListener('tt:notifications-refresh', refresh);
    const pollTimer =
      session && workspace?.id
        ? window.setInterval(pollNotifications, NOTIFICATION_POLL_INTERVAL_MS)
        : null;
    return () => {
      cancelled = true;
      window.removeEventListener('tt:notifications-refresh', refresh);
      if (pollTimer !== null) window.clearInterval(pollTimer);
    };
  }, [session, workspace, isSystemAdmin, enabled]);

  const onNotificationClick = useCallback(
    notification => {
      if (
        notification?.persisted &&
        notification?.isRead === false &&
        workspace?.id &&
        notification?.id
      ) {
        workspaceAPI
          .markNotificationRead(workspace.id, notification.id)
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
    [workspace, navigate]
  );

  const onMarkAllNotificationsRead = useCallback(() => {
    if (!workspace?.id) return;
    workspaceAPI
      .markAllNotificationsRead(workspace.id)
      .then(() => {
        setDashboardNotifications(prev =>
          prev.map(item => (item.persisted ? { ...item, isRead: true } : item))
        );
        setDashboardUnreadCount(0);
      })
      .catch(() => {});
  }, [workspace]);

  return {
    dashboardNotifications,
    dashboardUnreadCount,
    onNotificationClick,
    onMarkAllNotificationsRead,
  };
}
