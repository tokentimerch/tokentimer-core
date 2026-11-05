import { ChakraProvider } from '@chakra-ui/react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import WebhookForm from '../../src/components/onboarding/alertWebhookForm.jsx';

const api = vi.hoisted(() => ({ test: vi.fn(), get: vi.fn(), put: vi.fn() }));
vi.mock('../../src/utils/apiClient', () => ({
  alertAPI: { testWebhook: api.test },
}));
vi.mock('../../src/utils/onboardingActions.js', () => ({
  onboardingActions: { getAlertSettings: api.get, putAlertSettings: api.put },
}));

describe('onboarding webhook save recovery', () => {
  it('keeps the tested draft and retries saving without sending another test', async () => {
    api.test.mockReset().mockResolvedValue({});
    api.get
      .mockReset()
      .mockResolvedValueOnce({ webhook_urls: [] })
      .mockResolvedValueOnce({ webhook_urls: [] })
      .mockResolvedValueOnce({ webhook_urls: [{ name: 'Ops' }] });
    api.put
      .mockReset()
      .mockRejectedValueOnce(new Error('Connection lost'))
      .mockResolvedValueOnce({});
    const onSaved = vi.fn();
    render(
      <ChakraProvider>
        <DashboardThemeProvider>
          <WebhookForm
            workspaceId='ws'
            existing={[]}
            onSaved={onSaved}
            onCancel={() => {}}
          />
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    fireEvent.change(screen.getByPlaceholderText('Ops channel'), {
      target: { value: 'Ops' },
    });
    fireEvent.change(screen.getByPlaceholderText('https://'), {
      target: { value: 'https://example.test/hook' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Send test and save' }));
    await screen.findByText(/Test passed, but saving was not confirmed/);
    fireEvent.click(screen.getByRole('button', { name: 'Retry save' }));
    await waitFor(() => expect(onSaved).toHaveBeenCalledWith('Ops'));
    expect(api.test).toHaveBeenCalledTimes(1);
    expect(api.put).toHaveBeenCalledTimes(2);
  });

  it('does not repeat a possibly successful save if readback failed', async () => {
    api.test.mockReset().mockResolvedValue({});
    api.get
      .mockReset()
      .mockResolvedValueOnce({ webhook_urls: [] })
      .mockRejectedValueOnce(new Error('Readback unavailable'))
      .mockResolvedValueOnce({ webhook_urls: [{ name: 'Ops' }] });
    api.put.mockReset().mockResolvedValue({});
    const onSaved = vi.fn();
    render(
      <ChakraProvider>
        <DashboardThemeProvider>
          <WebhookForm
            workspaceId='ws'
            existing={[]}
            onSaved={onSaved}
            onCancel={() => {}}
          />
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    fireEvent.change(screen.getByPlaceholderText('Ops channel'), {
      target: { value: 'Ops' },
    });
    fireEvent.change(screen.getByPlaceholderText('https://'), {
      target: { value: 'https://example.test/hook' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Send test and save' }));
    await screen.findByText(/Test passed, but saving was not confirmed/);
    fireEvent.click(screen.getByRole('button', { name: 'Retry save' }));
    await screen.findByText(/already exists. Check Alert Preferences/);
    expect(api.test).toHaveBeenCalledTimes(1);
    expect(api.put).toHaveBeenCalledTimes(1);
    expect(onSaved).not.toHaveBeenCalled();
  });
});
