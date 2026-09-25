import { describe, expect, it } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';

import DashboardShell from '../../src/components/DashboardShell.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

function renderNotifications(notifications, unreadCount) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>
          <DashboardShell
            currentPath='/dashboard'
            dashboardNotifications={notifications}
            dashboardUnreadCount={unreadCount}
            onMarkAllNotificationsRead={() => {}}
          >
            Dashboard content
          </DashboardShell>
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

describe('DashboardShell notification indicator', () => {
  it('shows the persisted auto-sync error and Manage auto-sync action', () => {
    renderNotifications(
      [
        {
          id: '11111111-1111-4111-8111-111111111111',
          category: 'auto_sync',
          type: 'auto_sync_failed',
          persisted: true,
          isRead: false,
          text: 'Auto-sync failing repeatedly: gitlab',
          message: '<Bad credentials>',
          href: '/dashboard?import=gitlab&autoSyncManage=1',
        },
      ],
      1
    );
    fireEvent.click(screen.getByLabelText('Notifications'));
    expect(screen.getByText('<Bad credentials>')).toBeInTheDocument();
    expect(
      screen.getByText('Opens Import tokens on the Manage auto-sync tab.')
    ).toBeInTheDocument();
  });
  it.each([
    [
      {
        id: 'smtp-not-configured',
        kind: 'warning',
        text: 'SMTP is not configured.',
      },
    ],
    [{ id: 'alerts-out-of-window', persisted: false, text: 'Deferred alerts' }],
  ])(
    'shows attention for computed warnings with zero persisted unread items',
    notification => {
      renderNotifications([notification], 0);

      expect(
        screen.getByTestId('notification-attention-indicator')
      ).toBeInTheDocument();
      expect(screen.queryByText('Mark all as read')).not.toBeInTheDocument();
    }
  );

  it('still shows attention for unread persisted incidents', () => {
    renderNotifications(
      [
        {
          id: 'incident-1',
          persisted: true,
          isRead: false,
          text: 'Delivery blocked',
        },
      ],
      1
    );

    expect(
      screen.getByTestId('notification-attention-indicator')
    ).toBeInTheDocument();
  });

  it('does not show attention for only read persisted incidents', () => {
    renderNotifications(
      [
        {
          id: 'incident-1',
          persisted: true,
          isRead: true,
          text: 'Delivery blocked',
        },
      ],
      0
    );

    expect(
      screen.queryByTestId('notification-attention-indicator')
    ).not.toBeInTheDocument();
  });
});
