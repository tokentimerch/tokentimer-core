import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import AutoSyncMultiConfigPanel from '../../src/components/AutoSyncMultiConfigPanel.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const { apiGetMock, apiPostMock } = vi.hoisted(() => ({
  apiGetMock: vi.fn(),
  apiPostMock: vi.fn(),
}));

vi.mock('../../src/utils/apiClient', () => ({
  default: {
    get: apiGetMock,
    post: apiPostMock,
  },
}));

vi.mock('../../src/utils/toast.js', () => ({
  showSuccess: vi.fn(),
  showWarning: vi.fn(),
}));

function renderPanel() {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>
          <AutoSyncMultiConfigPanel />
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

describe('AutoSyncMultiConfigPanel', () => {
  beforeEach(() => {
    apiGetMock.mockReset();
    apiPostMock.mockReset();
    apiGetMock.mockResolvedValue({ data: { enabled: false } });
    apiPostMock.mockResolvedValue({
      data: { enabled: true, activated_at: '2026-10-05T12:00:00.000Z' },
    });
  });

  it('activates after both operator attestations', async () => {
    renderPanel();
    const activate = await screen.findByRole('button', {
      name: 'Allow multiple configurations',
    });
    expect(activate).toBeDisabled();
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'Old auto-sync workers have been drained',
      })
    );
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'This deployment uses the fencing-aware worker image',
      })
    );
    expect(activate).toBeEnabled();
    fireEvent.click(activate);
    await waitFor(() =>
      expect(apiPostMock).toHaveBeenCalledWith(
        '/api/v1/admin/auto-sync/activation',
        { workers_drained: true, worker_image_verified: true }
      )
    );
    await waitFor(() =>
      expect(
        screen.queryByRole('button', {
          name: 'Allow multiple configurations',
        })
      ).not.toBeInTheDocument()
    );
  });

  it('renders nothing when already enabled', async () => {
    apiGetMock.mockResolvedValue({ data: { enabled: true } });
    renderPanel();
    await waitFor(() => expect(apiGetMock).toHaveBeenCalled());
    expect(
      screen.queryByRole('button', { name: 'Allow multiple configurations' })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText('Loading activation state...')
    ).not.toBeInTheDocument();
  });
});
