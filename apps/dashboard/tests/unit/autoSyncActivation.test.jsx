import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import {
  AUTO_SYNC_MULTI_CONFIG_HREF,
  showAutoSyncEnableError,
} from '../../src/utils/autoSyncActivation.jsx';

const { showToastMock, showWarningMock } = vi.hoisted(() => ({
  showToastMock: vi.fn(),
  showWarningMock: vi.fn(),
}));

vi.mock('../../src/utils/toast.js', () => ({
  showToast: showToastMock,
  showWarning: showWarningMock,
}));

describe('showAutoSyncEnableError', () => {
  it('links system settings for the activation gate', () => {
    showAutoSyncEnableError({
      response: {
        data: {
          code: 'MULTI_CONFIG_DISABLED',
          error: 'Multiple configurations require operator activation',
          href: AUTO_SYNC_MULTI_CONFIG_HREF,
        },
      },
    });
    expect(showToastMock).toHaveBeenCalledWith(
      expect.objectContaining({
        title: 'Multiple configurations require operator activation',
      })
    );
    const description = showToastMock.mock.calls[0][0].description;
    render(<MemoryRouter>{description}</MemoryRouter>);
    const link = screen.getByRole('link', {
      name: 'Activate in System settings',
    });
    expect(link).toHaveAttribute('href', AUTO_SYNC_MULTI_CONFIG_HREF);
  });

  it('keeps ordinary enable failures as a warning toast', () => {
    showAutoSyncEnableError({
      response: { data: { error: 'Failed to encrypt credentials' } },
    });
    expect(showWarningMock).toHaveBeenCalledWith(
      'Failed to encrypt credentials'
    );
  });
});
