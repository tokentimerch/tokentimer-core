import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { useDashboardNotifications } from '../../src/hooks/useDashboardNotifications.js';

const {
  getAlertSettings,
  getNotifications,
  markNotificationRead,
  markAllNotificationsRead,
} = vi.hoisted(() => ({
  getAlertSettings: vi.fn(),
  getNotifications: vi.fn(),
  markNotificationRead: vi.fn(),
  markAllNotificationsRead: vi.fn(),
}));

vi.mock('../../src/utils/apiClient', () => ({
  workspaceAPI: {
    getAlertSettings,
    getNotifications,
    markNotificationRead,
    markAllNotificationsRead,
  },
}));

function wrapper({ children }) {
  return <MemoryRouter>{children}</MemoryRouter>;
}

const session = { id: 1, isAdmin: true };
const workspace = { id: 'ws-1', role: 'admin' };

beforeEach(() => {
  vi.clearAllMocks();
  getAlertSettings.mockResolvedValue({
    email_alerts_enabled: false,
    smtp_configured: false,
    webhook_urls: [],
    contact_groups: [],
  });
  getNotifications.mockResolvedValue({
    unreadCount: 1,
    items: [
      {
        id: 'incident-1',
        persisted: true,
        isRead: false,
        kind: 'error',
        text: 'Delivery blocked',
        href: '/usage',
      },
    ],
  });
  markNotificationRead.mockResolvedValue({});
  markAllNotificationsRead.mockResolvedValue({});
});

describe('useDashboardNotifications', () => {
  it('maps persisted incidents and computed warnings, then marks one incident read', async () => {
    const { result } = renderHook(
      () => useDashboardNotifications({ session, workspace }),
      { wrapper }
    );

    await waitFor(() =>
      expect(result.current.dashboardNotifications).toHaveLength(4)
    );
    expect(result.current.dashboardUnreadCount).toBe(1);
    expect(result.current.dashboardNotifications[0]).toMatchObject({
      id: 'incident-1',
      persisted: true,
      isRead: false,
      href: '/control-center',
    });
    expect(
      result.current.dashboardNotifications.slice(1).map(item => item.id)
    ).toEqual([
      'smtp-not-configured',
      'alerts-disabled',
      'no-contacts-defined',
    ]);

    await act(async () => {
      result.current.onNotificationClick(
        result.current.dashboardNotifications[0]
      );
      await markNotificationRead.mock.results.at(-1).value;
    });

    expect(markNotificationRead).toHaveBeenCalledWith('ws-1', 'incident-1');
    expect(result.current.dashboardUnreadCount).toBe(0);
    expect(result.current.dashboardNotifications[0].isRead).toBe(true);
    expect(result.current.dashboardNotifications.slice(1)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'smtp-not-configured' }),
      ])
    );
  });

  it('marks all persisted incidents without changing computed warnings', async () => {
    const { result } = renderHook(
      () => useDashboardNotifications({ session, workspace }),
      { wrapper }
    );
    await waitFor(() =>
      expect(result.current.dashboardNotifications).toHaveLength(4)
    );

    await act(async () => {
      result.current.onMarkAllNotificationsRead();
      await markAllNotificationsRead.mock.results.at(-1).value;
    });

    expect(markAllNotificationsRead).toHaveBeenCalledWith('ws-1');
    expect(result.current.dashboardUnreadCount).toBe(0);
    expect(result.current.dashboardNotifications[0].isRead).toBe(true);
    expect(
      result.current.dashboardNotifications
        .slice(1)
        .every(item => item.persisted !== true && item.isRead === undefined)
    ).toBe(true);
  });

  it('loads the selected workspace and refreshes only the current workspace', async () => {
    getAlertSettings.mockResolvedValue({
      email_alerts_enabled: true,
      smtp_configured: true,
      contact_groups: [{ email_contact_ids: [1] }],
    });
    getNotifications.mockImplementation(id =>
      Promise.resolve({
        unreadCount: 1,
        items: [{ id: `incident-${id}`, persisted: true, isRead: false }],
      })
    );

    const { result, rerender } = renderHook(
      ({ selectedWorkspace }) =>
        useDashboardNotifications({ session, workspace: selectedWorkspace }),
      { initialProps: { selectedWorkspace: workspace }, wrapper }
    );
    await waitFor(() =>
      expect(result.current.dashboardNotifications[0]?.id).toBe('incident-ws-1')
    );

    rerender({ selectedWorkspace: { id: 'ws-2', role: 'admin' } });
    await waitFor(() =>
      expect(result.current.dashboardNotifications[0]?.id).toBe('incident-ws-2')
    );
    await act(async () => {
      window.dispatchEvent(new Event('tt:notifications-refresh'));
    });
    await waitFor(() => expect(getNotifications).toHaveBeenCalledTimes(3));
    expect(getNotifications.mock.calls.map(([id]) => id)).toEqual([
      'ws-1',
      'ws-2',
      'ws-2',
    ]);
  });

  it('keeps server-scoped incidents for viewers without manager warnings', async () => {
    const { result } = renderHook(
      () =>
        useDashboardNotifications({
          session: { id: 2, isAdmin: false },
          workspace: { id: 'ws-1', role: 'viewer' },
        }),
      { wrapper }
    );
    await waitFor(() =>
      expect(result.current.dashboardNotifications).toHaveLength(1)
    );
    expect(result.current.dashboardNotifications[0].id).toBe('incident-1');
    expect(result.current.dashboardUnreadCount).toBe(1);
  });
});
