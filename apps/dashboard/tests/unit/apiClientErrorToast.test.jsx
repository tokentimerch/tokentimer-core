import { describe, it, expect, vi, beforeEach } from 'vitest';

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
