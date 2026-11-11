import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import SystemSettings from '../../src/pages/SystemSettings.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import apiClient from '../../src/utils/apiClient';
vi.mock('../../src/utils/apiClient', () => ({
  default: { get: vi.fn(), post: vi.fn() },
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
describe('SMTP test destination', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiClient.post.mockResolvedValue({ data: { success: true } });
  });
  for (const enforced of [true, false])
    it(
      enforced
        ? 'shows and submits the locked administrator destination'
        : 'preserves custom recipients when confirmation is off',
      async () => {
        apiClient.get.mockImplementation(async url => ({
          data: url.includes('system-settings')
            ? {
                smtp: {
                  configured: true,
                  test_recipient: enforced ? 'admin@example.test' : null,
                },
                whatsapp: {},
              }
            : { enabled: false },
        }));
        render(
          <ChakraProvider>
            <DashboardThemeProvider>
              <MemoryRouter>
                <SystemSettings session={{ email: 'admin@example.test' }} />
              </MemoryRouter>
            </DashboardThemeProvider>
          </ChakraProvider>
        );
        const smtpCard = await screen.findByRole('button', {
          name: /Email \(SMTP\)/,
        });
        if (smtpCard.getAttribute('aria-expanded') === 'false')
          fireEvent.click(smtpCard);
        const recipient = await screen.findByRole('textbox', {
          name: 'Test recipient',
          exact: true,
        });
        if (enforced) {
          expect(recipient).toBeDisabled();
          expect(recipient).toHaveValue('admin@example.test');
          expect(
            screen.getByText(/signed-in administrator/)
          ).toBeInTheDocument();
          expect(recipient).toHaveAccessibleDescription(
            /Recipient confirmation is enforced.*signed-in administrator/
          );
        } else {
          expect(recipient).toBeEnabled();
          fireEvent.change(recipient, {
            target: { value: 'custom@example.test' },
          });
        }
        fireEvent.click(
          screen.getByRole('button', { name: 'Send test email' })
        );
        await waitFor(() =>
          expect(apiClient.post).toHaveBeenCalledWith('/api/admin/test-smtp', {
            email: enforced ? 'admin@example.test' : 'custom@example.test',
          })
        );
      }
    );
});
