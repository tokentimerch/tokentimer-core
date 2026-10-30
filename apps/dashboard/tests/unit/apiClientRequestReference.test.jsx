import { beforeEach, describe, expect, it, vi } from 'vitest';
import axios from 'axios';

const { showErrorMock } = vi.hoisted(() => ({ showErrorMock: vi.fn() }));
vi.mock('../../src/utils/toast.js', () => ({
  showError: showErrorMock,
  showSuccess: vi.fn(),
}));
vi.mock('../../src/utils/analytics.js', () => ({
  resetIdentity: vi.fn(),
  trackEvent: vi.fn(),
}));
const id = 'a2bcde12-3456-4789-abcd-0123456789ab';
const otherId = 'a2bcde12-3456-4789-abcd-0123456789ac';
const failure = (headers = {}, message = 'Unable to save') => ({
  config: { url: '/api/tokens' },
  response: { status: 500, data: { error: message }, headers },
});

beforeEach(() => {
  vi.resetModules();
  showErrorMock.mockClear();
});

describe('API error request references', () => {
  it.each([
    { 'x-request-id': id },
    { 'X-Request-Id': id },
    new axios.AxiosHeaders({ 'X-Request-Id': id }),
  ])(
    'shows a valid reference in the toast and returned message',
    async headers => {
      const { handleApiError } = await import('../../src/utils/apiClient.js');
      expect(handleApiError(failure(headers))).toBe(
        `Unable to save Reference: ${id}`
      );
      expect(showErrorMock).toHaveBeenCalledWith(
        `Unable to save. Reference: ${id}`
      );
    }
  );

  it.each([
    undefined,
    `${id}\n`,
    'secret-value',
    `${id}\nsecret-value`,
    `${id}x`,
    [id],
    123,
  ])('omits absent or invalid header text: %s', async value => {
    const { handleApiError } = await import('../../src/utils/apiClient.js');
    expect(handleApiError(failure({ 'x-request-id': value }))).toBe(
      'Unable to save'
    );
    expect(showErrorMock).toHaveBeenCalledWith('Unable to save.');
  });

  it('deduplicates identical errors even when request references differ', async () => {
    const { handleApiError } = await import('../../src/utils/apiClient.js');
    handleApiError(failure({ 'x-request-id': id }));
    expect(handleApiError(failure({ 'x-request-id': otherId }))).toContain(
      otherId
    );
    expect(showErrorMock).toHaveBeenCalledTimes(1);
    expect(showErrorMock.mock.calls[0][0]).toContain(id);
  });

  it('keeps integration errors in their modal while returning the reference', async () => {
    const { handleApiError } = await import('../../src/utils/apiClient.js');
    const error = failure({ 'x-request-id': id });
    error.config.url = '/api/v1/integrations/github/scan';
    expect(handleApiError(error)).toContain(`Reference: ${id}`);
    expect(showErrorMock).not.toHaveBeenCalled();
  });

  it('keeps canceled requests quiet even if they have a response header', async () => {
    const { handleApiError } = await import('../../src/utils/apiClient.js');
    const error = { ...failure({ 'x-request-id': id }), code: 'ERR_CANCELED' };
    expect(handleApiError(error)).toBeNull();
    expect(showErrorMock).not.toHaveBeenCalled();
  });

  it('preserves a reference when long error guidance is shortened for a toast', async () => {
    const { handleApiError } = await import('../../src/utils/apiClient.js');
    const message = 'Unable to save. If this persists, contact your operator.';
    expect(handleApiError(failure({ 'x-request-id': id }, message))).toContain(
      message
    );
    expect(showErrorMock).toHaveBeenCalledWith(
      `Unable to save. Reference: ${id}`
    );
  });

  it('does not invent a reference for a network failure', async () => {
    const { handleApiError } = await import('../../src/utils/apiClient.js');
    const message = handleApiError({ request: {}, message: 'Network Error' });
    expect(message).not.toContain('Reference:');
    expect(showErrorMock).toHaveBeenCalledTimes(1);
  });
});
