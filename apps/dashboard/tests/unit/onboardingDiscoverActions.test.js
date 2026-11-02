import { beforeEach, describe, expect, it, vi } from 'vitest';

const { api } = vi.hoisted(() => ({
  api: { post: vi.fn(), get: vi.fn() },
}));

vi.mock('../../src/utils/apiClient', () => ({
  default: api,
  handleApiError: vi.fn(e => e?.response?.data?.error || 'generic failure'),
}));

import { onboardingActions } from '../../src/utils/onboardingActions.js';
import { handleApiError } from '../../src/utils/apiClient';

const apiError = (status, data, headers = {}) =>
  Object.assign(new Error('Request failed'), {
    response: { status, data, headers },
  });

beforeEach(() => {
  api.post.mockReset();
  handleApiError.mockClear();
});

describe('onboardingActions.discoverHostnames', () => {
  it('sends subfinder_all only when asked, with the abort signal', async () => {
    api.post.mockResolvedValue({ data: { items: [] } });
    const controller = new AbortController();
    await onboardingActions.discoverHostnames('ws', 'example.com');
    expect(api.post.mock.calls[0][1]).toEqual({ domain: 'example.com' });
    await onboardingActions.discoverHostnames('ws', 'example.com', {
      includeAllSources: true,
      signal: controller.signal,
    });
    expect(api.post.mock.calls[1][1]).toEqual({
      domain: 'example.com',
      subfinder_all: true,
    });
    expect(api.post.mock.calls[1][2].signal).toBe(controller.signal);
  });

  it('returns the cap and only the codes of failed sources', async () => {
    api.post.mockResolvedValue({
      data: {
        items: [{ name: 'a.example.com' }],
        partial: true,
        meta: { truncated: true, maxResults: 500 },
        toolErrors: [
          {
            tool: 'subfinder',
            code: 'DOMAIN_CHECKER_TOOL_TIMEOUT',
            message: 'x',
            bin: '/usr/bin/subfinder',
          },
        ],
      },
    });
    const r = await onboardingActions.discoverHostnames('ws', 'example.com');
    expect(r).toMatchObject({
      partial: true,
      truncated: true,
      cap: 500,
      failedCodes: ['DOMAIN_CHECKER_TOOL_TIMEOUT'],
    });
    expect(JSON.stringify(r)).not.toMatch(/subfinder|usr\/bin/);
  });

  it('keeps the error code on a missing tool without a generic toast', async () => {
    api.post.mockRejectedValue(
      apiError(503, {
        error: 'Domain discovery tools are not available in this deployment.',
        code: 'DOMAIN_CHECKER_TOOL_MISSING',
      })
    );
    await expect(
      onboardingActions.discoverHostnames('ws', 'example.com')
    ).rejects.toMatchObject({
      code: 'DOMAIN_CHECKER_TOOL_MISSING',
      status: 503,
    });
    expect(api.post).toHaveBeenCalledTimes(1);
    expect(handleApiError).not.toHaveBeenCalled();
  });

  it('keeps the retry hint from the body, then from the header', async () => {
    api.post.mockRejectedValueOnce(
      apiError(409, {
        error: 'busy',
        code: 'DOMAIN_CHECKER_BUSY',
        retry_after_seconds: 60,
      })
    );
    await expect(
      onboardingActions.discoverHostnames('ws', 'example.com')
    ).rejects.toMatchObject({
      code: 'DOMAIN_CHECKER_BUSY',
      retryAfterSeconds: 60,
    });
    api.post.mockRejectedValueOnce(
      apiError(
        429,
        { error: 'slow down', code: 'DOMAIN_CHECKER_RATE_LIMITED' },
        { 'retry-after': '45' }
      )
    );
    await expect(
      onboardingActions.discoverHostnames('ws', 'example.com')
    ).rejects.toMatchObject({ retryAfterSeconds: 45, status: 429 });
  });

  it('does not retry a timeout, and marks a cancelled search', async () => {
    api.post.mockRejectedValueOnce(
      apiError(504, { error: 'late', code: 'DOMAIN_CHECKER_TIMEOUT' })
    );
    await expect(
      onboardingActions.discoverHostnames('ws', 'example.com')
    ).rejects.toMatchObject({ code: 'DOMAIN_CHECKER_TIMEOUT', status: 504 });
    expect(api.post).toHaveBeenCalledTimes(1);

    api.post.mockReset();
    api.post.mockRejectedValue(
      Object.assign(new Error('canceled'), { code: 'ERR_CANCELED' })
    );
    await expect(
      onboardingActions.discoverHostnames('ws', 'example.com')
    ).rejects.toMatchObject({ code: 'ERR_CANCELED' });
    expect(api.post).toHaveBeenCalledTimes(1);
  });

  it('uses the shared error handler for failures it does not word itself', async () => {
    api.post.mockRejectedValue(apiError(403, { error: 'Access denied.' }));
    await expect(
      onboardingActions.discoverHostnames('ws', 'example.com')
    ).rejects.toMatchObject({ message: 'Access denied.', status: 403 });
    expect(handleApiError).toHaveBeenCalled();
  });
});

describe('onboardingActions.createMonitor sections', () => {
  it('sends sections only when present', async () => {
    api.post.mockResolvedValue({ data: { id: 'm' } });
    await onboardingActions.createMonitor('ws', {
      url: 'https://a.example.com',
    });
    expect(api.post.mock.calls[0][1].section).toBeUndefined();
    await onboardingActions.createMonitor('ws', {
      url: 'https://a.example.com',
      section: ['prod'],
    });
    expect(api.post.mock.calls[1][1].section).toEqual(['prod']);
  });
});
