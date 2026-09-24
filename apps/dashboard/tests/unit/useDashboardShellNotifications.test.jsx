import { describe, expect, it, vi } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';

import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import { useDashboardShellProps } from '../../src/hooks/useDashboardShellProps.js';

const { markAllNotificationsRead } = vi.hoisted(() => ({
  markAllNotificationsRead: vi.fn().mockResolvedValue({}),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'ws-1', selectWorkspace: vi.fn() }),
}));

vi.mock('../../src/utils/apiClient', () => ({
  workspaceAPI: {
    getAlertSettings: vi.fn().mockResolvedValue({
      email_alerts_enabled: true,
      smtp_configured: true,
      contact_groups: [{ email_contact_ids: [1] }],
    }),
    getNotifications: vi.fn().mockResolvedValue({
      unreadCount: 1,
      items: [
        { id: 'incident-1', persisted: true, isRead: false, text: 'Blocked' },
        { id: 'alerts-out-of-window', text: 'Deferred alerts' },
      ],
    }),
    markAllNotificationsRead,
  },
}));

function wrapper({ children }) {
  return (
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>{children}</MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

const shellOptions = {
  session: { id: 1 },
  dashboardWorkspaces: [],
  dashboardWorkspace: { id: 'ws-1', role: 'admin' },
};

describe('useDashboardShellProps notification read state', () => {
  it('marks persisted incidents read without changing computed warnings', async () => {
    const { result } = renderHook(() => useDashboardShellProps(shellOptions), {
      wrapper,
    });

    await waitFor(() =>
      expect(result.current.dashboardNotifications).toHaveLength(2)
    );
    await act(async () => {
      result.current.onMarkAllNotificationsRead();
      await markAllNotificationsRead.mock.results.at(-1).value;
    });

    expect(result.current.dashboardUnreadCount).toBe(0);
    expect(result.current.dashboardNotifications[0]).toMatchObject({
      persisted: true,
      isRead: true,
    });
    expect(result.current.dashboardNotifications[1]).toMatchObject({
      persisted: false,
      isRead: undefined,
    });
  });
});
