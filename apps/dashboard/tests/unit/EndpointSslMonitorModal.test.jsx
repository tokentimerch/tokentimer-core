import { ChakraProvider } from '@chakra-ui/react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import EndpointSslMonitorModal from '../../src/components/EndpointSslMonitorModal.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const { listMonitors, postRequest, showSuccessMessage, breakpoint } =
  vi.hoisted(() => ({
    listMonitors: vi.fn(),
    postRequest: vi.fn(),
    showSuccessMessage: vi.fn(),
    breakpoint: vi.fn(),
  }));

vi.mock('@chakra-ui/react', async importOriginal => ({
  ...(await importOriginal()),
  useBreakpointValue: breakpoint,
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'ws-1' }),
}));

vi.mock('../../src/utils/apiClient', () => ({
  default: { get: listMonitors, post: postRequest },
  showSuccessMessage,
}));

beforeEach(() => {
  postRequest.mockReset();
  listMonitors.mockReset();
  showSuccessMessage.mockClear();
});

const monitor = {
  id: 'monitor-1',
  url: 'https://blocked.example.test',
  check_interval: 'hourly',
  last_health_status: 'healthy',
  last_health_status_code: 200,
  last_health_response_ms: 145,
  last_health_check_at: '2026-11-19T08:00:00Z',
};

function renderMonitor(overrides) {
  listMonitors.mockResolvedValue({
    data: { items: [{ ...monitor, ...overrides }] },
  });
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <EndpointSslMonitorModal
          isOpen
          onClose={vi.fn()}
          contactGroups={[]}
          TOKEN_CATEGORIES={[]}
        />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

function expectHealthVisible(visible) {
  for (const value of ['healthy', '145ms']) {
    const detail = screen.queryByText(value, { exact: true });
    if (visible) expect(detail).toBeVisible();
    else expect(detail).not.toBeInTheDocument();
  }
}

describe.each([
  ['desktop', true],
  ['mobile', false],
])('%s endpoint monitor controls', (_layout, isDesktop) => {
  beforeEach(() => {
    breakpoint.mockReturnValue(isDesktop);
  });

  it.each([
    ['both', true, 'Blocked by outbound policy'],
    ['manual only', false, 'Manual check blocked by outbound policy'],
  ])(
    'shows the policy block for %s checks when listed',
    async (_scope, scheduledBlocked, description) => {
      renderMonitor({
        health_check_enabled: scheduledBlocked,
        outbound_policy_blocked: scheduledBlocked,
        outbound_manual_check_blocked: true,
      });

      expect(await screen.findByText(description)).toBeVisible();
      expect(screen.getByText('blocked.example.test')).toBeVisible();
      expect(
        screen.getByText(/Ask your administrator to review/)
      ).toBeVisible();
      expect(listMonitors).toHaveBeenCalledWith(
        '/api/v1/workspaces/ws-1/domains'
      );
      expectHealthVisible(!scheduledBlocked);
      const check = screen.getByRole('button', { name: 'Check now' });
      expect(check).toHaveAccessibleDescription(description);
      expect(check).toBeDisabled();
      fireEvent.click(check);
      expect(postRequest).not.toHaveBeenCalled();
    }
  );

  it.each([
    ['scheduled HTTP monitoring', true, 'Blocked by outbound policy'],
    [
      'scheduled TLS monitoring only',
      false,
      'Manual check blocked by outbound policy',
    ],
  ])(
    'updates a denied manual check for %s',
    async (_monitoring, healthEnabled, description) => {
      renderMonitor({ health_check_enabled: healthEnabled });
      postRequest.mockRejectedValueOnce({
        response: { status: 403, data: { code: 'OUTBOUND_POLICY_DENIED' } },
      });

      expect(await screen.findByText('healthy')).toBeVisible();
      const check = screen.getByRole('button', { name: 'Check now' });
      expect(check).toBeEnabled();
      fireEvent.click(check);
      expect(await screen.findByText(description)).toBeVisible();
      expect(postRequest).toHaveBeenCalledExactlyOnceWith(
        '/api/v1/workspaces/ws-1/domains/monitor-1/check'
      );
      const blockedCheck = screen.getByRole('button', { name: 'Check now' });
      expect(blockedCheck).toHaveAccessibleDescription(description);
      expect(blockedCheck).toBeDisabled();
      expectHealthVisible(!healthEnabled);
    }
  );
});

it.each([
  ['completed', '3 endpoint monitors blocked by outbound policy.'],
  ['rejected', '2 endpoint monitors blocked by outbound policy.'],
  [
    'disconnected',
    '2 endpoint monitors blocked by outbound policy in completed batches.',
  ],
])(
  'reports blocked monitors when the final import batch is %s',
  async (finalBatch, feedback) => {
    breakpoint.mockReturnValue(true);
    renderMonitor();
    const hosts = Array.from({ length: 26 }, (_, index) => ({
      id: String(index),
      name: `sub-${index}.example.test`,
    }));
    postRequest
      .mockResolvedValueOnce({ data: { items: hosts } })
      .mockResolvedValueOnce({
        data: {
          imported: hosts
            .slice(0, 25)
            .map(host => ({ certificateId: host.id })),
          monitors: { created: 23, blocked: 2 },
        },
      });
    if (finalBatch === 'completed') {
      postRequest.mockResolvedValueOnce({
        data: {
          imported: [{ certificateId: hosts[25].id }],
          monitors: { blocked: 1 },
        },
      });
    } else {
      postRequest.mockRejectedValueOnce(
        finalBatch === 'rejected'
          ? { response: { status: 500 } }
          : new Error('Connection closed')
      );
    }

    fireEvent.change(screen.getByRole('textbox', { name: 'Root domain' }), {
      target: { value: 'example.test' },
    });
    await act(async () => {
      fireEvent.click(
        screen.getByRole('button', { name: 'Discover subdomains' })
      );
    });
    const importButton = screen.getByRole('button', {
      name: 'Import selected (26)',
    });
    fireEvent.click(
      screen.getByRole('checkbox', { name: 'Also create endpoint monitors' })
    );
    const modalBody = document.querySelector('[data-endpoint-ssl-modal-body]');
    modalBody.scrollTo = vi.fn();
    await act(async () => {
      fireEvent.click(importButton);
    });

    expect(
      screen.getByText(
        `${feedback} After the outbound policy allows the hosts, add their monitors individually.`
      )
    ).toBeVisible();
    expect(postRequest).toHaveBeenNthCalledWith(
      2,
      '/api/v1/workspaces/ws-1/domain-checker/import',
      expect.objectContaining({
        monitorOptions: expect.objectContaining({ enabled: true }),
      }),
      expect.any(Object)
    );
    expect(postRequest).toHaveBeenCalledTimes(3);
    if (finalBatch === 'completed') {
      expect(showSuccessMessage).toHaveBeenCalledWith(
        'Imported 26 SSL tokens (23 new monitors, 3 monitors blocked by outbound policy).'
      );
    }
  }
);
