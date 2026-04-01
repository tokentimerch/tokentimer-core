import { describe, it, expect, vi, beforeEach } from 'vitest';

const loggerErrorMock = vi.fn();

vi.mock('../../src/utils/logger.js', () => ({
  logger: {
    error: loggerErrorMock,
  },
}));

describe('globalErrors', () => {
  beforeEach(() => {
    vi.resetModules();
    loggerErrorMock.mockReset();
  });

  it('installs handlers and logs unhandled error/rejection', async () => {
    await import('../../src/utils/globalErrors.js');

    const errorEvent = new Event('error', { cancelable: true });
    errorEvent.error = new Error('boom');
    window.dispatchEvent(errorEvent);
    expect(errorEvent.defaultPrevented).toBe(true);

    const rejectionEvent = new Event('unhandledrejection', {
      cancelable: true,
    });
    rejectionEvent.reason = 'bad';
    window.dispatchEvent(rejectionEvent);
    expect(rejectionEvent.defaultPrevented).toBe(true);

    expect(loggerErrorMock).toHaveBeenCalled();
  });
});
