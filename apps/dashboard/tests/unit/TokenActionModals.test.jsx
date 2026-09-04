import { fireEvent, render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { describe, expect, it, vi } from 'vitest';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import {
  TokenDeletionModal,
  TokenRenewModal,
} from '../../src/components/TokenActionModals.jsx';

const token = {
  id: 'token-1',
  name: 'Production API token',
  category: 'general',
  type: 'other',
  expiresAt: '2027-09-01',
  monitor_url: 'https://status.example.com/health',
};

function renderWithProviders(ui) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>{ui}</DashboardThemeProvider>
    </ChakraProvider>
  );
}

describe('TokenDeletionModal', () => {
  it('shows the complete deletion impact and preserves cancel/confirm actions', () => {
    const onClose = vi.fn();
    const onConfirm = vi.fn();

    renderWithProviders(
      <TokenDeletionModal
        isOpen
        onClose={onClose}
        tokenToDelete={token}
        onConfirm={onConfirm}
      />
    );

    expect(
      screen.getByText(/Production API token · General · Other/)
    ).toBeInTheDocument();
    expect(screen.getByText('Asset summary')).toBeInTheDocument();
    expect(screen.getByText('Expiration date')).toBeInTheDocument();
    expect(
      screen.getByText(/Deleting this token will also remove the monitor/)
    ).toBeInTheDocument();
    expect(
      document.querySelectorAll('[data-dashboard-detail-row]')
    ).toHaveLength(4);

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    fireEvent.click(screen.getByRole('button', { name: 'Delete Token' }));

    expect(onClose).toHaveBeenCalledTimes(1);
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});

describe('TokenRenewModal', () => {
  it('preserves the controlled date, validation message, loading state, and actions', () => {
    const onClose = vi.fn();
    const onConfirm = vi.fn();
    const onRenewDateChange = vi.fn();

    renderWithProviders(
      <TokenRenewModal
        isOpen
        onClose={onClose}
        tokenToRenew={token}
        renewDate='2028-09-01'
        renewErrors={{ renewDate: 'Expiration date must be in the future' }}
        isRenewSubmitting={false}
        onRenewDateChange={onRenewDateChange}
        onConfirm={onConfirm}
      />
    );

    expect(screen.getByText('Asset summary')).toBeInTheDocument();
    expect(screen.getByText('Current expiration')).toBeInTheDocument();
    expect(
      screen.getByText('Expiration date must be in the future')
    ).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('New expiration date'), {
      target: { value: '2029-10-02' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));

    expect(onRenewDateChange).toHaveBeenCalledWith('2029-10-02');
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it('keeps the confirm button in its loading state while renewal submits', () => {
    renderWithProviders(
      <TokenRenewModal
        isOpen
        onClose={vi.fn()}
        tokenToRenew={token}
        renewDate='2028-09-01'
        renewErrors={{}}
        isRenewSubmitting
        onRenewDateChange={vi.fn()}
        onConfirm={vi.fn()}
      />
    );

    expect(screen.getByRole('button', { name: /Loading/ })).toBeDisabled();
  });
});
