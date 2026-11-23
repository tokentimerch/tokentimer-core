import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter, useLocation } from 'react-router';
import { it, expect, vi } from 'vitest';
import SystemSettings from '../../src/pages/SystemSettings.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import apiClient from '../../src/utils/apiClient';
vi.mock('../../src/utils/apiClient', () => ({
  default: { get: vi.fn(), put: vi.fn() },
}));
vi.mock('../../src/components/DashboardPageLayout', () => ({
  default: ({ children }) => children,
}));
vi.mock('../../src/components/SEO.jsx', () => ({ default: () => null }));
vi.mock('../../src/components/AutoSyncSystemMetricSettings.jsx', () => ({
  default: () => null,
}));
vi.mock('../../src/components/AutoSyncMultiConfigPanel.jsx', () => ({
  default: () => null,
}));
vi.mock('../../src/utils/toast.js', () => ({
  showSuccess: vi.fn(),
  showWarning: vi.fn(),
}));

function LocationSearch() {
  const { search } = useLocation();
  return <output aria-label='Location query'>{search}</output>;
}

it('opens group mappings directly after setup and saves only unlocked SSO policy', async () => {
  const sso = {
    allow_auto_link_local_accounts: { value: false, locked: true },
    strict_membership_sync: { value: false, locked: false },
  };
  apiClient.get.mockImplementation(async url => ({
    data:
      url === '/api/admin/system-settings'
        ? { sso }
        : url === '/api/admin/sso/group-mappings'
          ? { providers: [{ slug: 'example', displayName: 'Example IdP' }] }
          : { enabled: false },
  }));
  apiClient.put.mockResolvedValue({
    data: {
      sso: { ...sso, strict_membership_sync: { value: true, locked: false } },
    },
  });

  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter
          initialEntries={[
            '/system-settings?section=sso-group-mappings&provider=example&keep=1',
          ]}
        >
          <SystemSettings session={{ email: 'admin@example.test' }} />
          <LocationSearch />
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );

  const card = await screen.findByRole('button', {
    name: /Single Sign-On/,
  });
  expect(card).toHaveAttribute('aria-expanded', 'true');
  expect(await screen.findByText(/Example IdP is enabled/)).toBeInTheDocument();
  await waitFor(() =>
    expect(screen.getByLabelText('Location query')).toHaveTextContent('?keep=1')
  );
  expect(screen.getByLabelText('Allow auto-link by email')).toBeDisabled();

  fireEvent.click(screen.getByLabelText('Strict membership sync'));
  fireEvent.click(screen.getByRole('button', { name: 'Save SSO policy' }));
  await waitFor(() =>
    expect(apiClient.put).toHaveBeenCalledWith('/api/admin/system-settings', {
      sso: {
        strict_membership_sync: true,
        config_sync_interval_ms: 45000,
        idp_http_timeout_ms: 20000,
        allow_private_idp_urls: false,
        allowed_idp_cidrs: '',
      },
    })
  );
});
