import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import { logger } from '../../src/utils/logger.js';

const { showErrorMock } = vi.hoisted(() => ({
  showErrorMock: vi.fn(),
}));

vi.mock('../../src/utils/toast.js', () => ({
  showError: showErrorMock,
  showSuccess: vi.fn(),
  showWarning: vi.fn(),
  showInfo: vi.fn(),
  showToast: vi.fn(),
}));

vi.mock('../../src/utils/analytics.js', () => ({
  resetIdentity: vi.fn(),
}));

// Regression test: alertAPI.testWebhook() failures used to be reported to the
// user twice - once by the axios response interceptor's auto-toast inside
// handleApiError(), and once by the explicit showError() call at the
// AlertPreferences.jsx call site (handleTestWebhook / handleTestWebhookDraft).
// handleApiError() must suppress its own toast for the test-webhook endpoint
// so only the call site's contextual toast is shown.
describe('handleApiError - webhook test endpoint toast suppression', () => {
  beforeEach(() => {
    showErrorMock.mockClear();
  });

  it('does not auto-toast for a blocked-private-IP /api/test-webhook failure', async () => {
    const { handleApiError } = await import('../../src/utils/apiClient.js');

    const error = {
      config: { url: '/api/test-webhook' },
      response: {
        status: 400,
        data: {
          error:
            'Webhook blocked: 10.11.1.96 resolves to a private/reserved IP. Self-hosted deployments can set WEBHOOK_ALLOW_PRIVATE_IPS=true to allow private webhook destinations.',
          code: 'WEBHOOK_PRIVATE_IP_BLOCKED',
        },
      },
    };

    const message = handleApiError(error);

    expect(message).toMatch(/private\/reserved IP/);
    expect(showErrorMock).not.toHaveBeenCalled();
  });

  it('still auto-toasts for other endpoints (e.g. a generic 400)', async () => {
    const { handleApiError } = await import('../../src/utils/apiClient.js');

    const error = {
      config: { url: '/api/v1/workspaces/123/members' },
      response: {
        status: 400,
        data: { error: 'Something went wrong.' },
      },
    };

    handleApiError(error);

    expect(showErrorMock).toHaveBeenCalledTimes(1);
  });

  it('does not auto-toast for integration scan endpoints (existing behavior)', async () => {
    const { handleApiError } = await import('../../src/utils/apiClient.js');

    const error = {
      config: { url: '/api/v1/integrations/aws/scan?workspace_id=abc' },
      response: {
        status: 400,
        data: { error: 'Invalid credentials.' },
      },
    };

    handleApiError(error);

    expect(showErrorMock).not.toHaveBeenCalled();
  });
});

describe('API request cancellation', () => {
  beforeEach(() => {
    showErrorMock.mockClear();
  });

  it('keeps workspace-switch cancellation quiet and rejects it to the caller', async () => {
    const { default: apiClient, handleApiError } =
      await import('../../src/utils/apiClient.js');
    const log = vi.spyOn(logger, 'error').mockImplementation(() => {});
    const controller = new AbortController();
    const request = apiClient.get(
      '/api/v1/workspaces/old/certops/certificates',
      {
        signal: controller.signal,
        adapter: config =>
          new Promise((resolve, reject) => {
            config.signal.addEventListener('abort', () => {
              reject(new axios.CanceledError('canceled', config));
            });
          }),
      }
    );
    controller.abort();
    const error = await request.catch(caught => caught);
    expect(error.code).toBe('ERR_CANCELED');
    expect(handleApiError(error)).toBeNull();
    expect(log).not.toHaveBeenCalled();
    expect(showErrorMock).not.toHaveBeenCalled();
    log.mockRestore();
  });

  it('still logs and propagates a real API failure', async () => {
    const { default: apiClient, handleApiError } =
      await import('../../src/utils/apiClient.js');
    const log = vi.spyOn(logger, 'error').mockImplementation(() => {});
    const request = apiClient.get(
      '/api/v1/workspaces/new/certops/certificates',
      {
        adapter: config =>
          Promise.reject(
            new axios.AxiosError(
              'Server failed',
              'ERR_BAD_RESPONSE',
              config,
              null,
              { status: 500, data: { error: 'Server failed' }, config }
            )
          ),
      }
    );
    const error = await request.catch(caught => caught);
    expect(error.response.status).toBe(500);
    expect(log).toHaveBeenCalledTimes(1);
    expect(handleApiError(error)).toBe('Server failed');
    expect(showErrorMock).toHaveBeenCalledTimes(1);
    log.mockRestore();
  });
});
