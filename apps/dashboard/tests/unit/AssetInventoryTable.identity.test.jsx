import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import AssetInventoryTable from '../../src/components/AssetInventoryTable.jsx';

function show(token) {
  const handlers = {
    onOpenTokenModal: vi.fn(),
    onOpenRenew: vi.fn(),
    onDeleteToken: vi.fn(),
  };
  render(
    <ChakraProvider>
      <AssetInventoryTable
        tokens={[token]}
        allTokensCount={1}
        sortedVisibleCount={1}
        visibleCount={1}
        inventoryMode='mixed'
        {...handlers}
        getAssetTypeLabel={() => 'Certificate'}
        getTokenLocation={() => '-'}
        getTokenOwner={() => '-'}
        getStatusMeta={() => ({
          key: 'healthy',
          label: 'Healthy',
          color: 'green',
          bg: 'transparent',
        })}
      />
    </ChakraProvider>
  );
  return handlers;
}

describe('ambiguous certificate inventory actions', () => {
  const token = {
    id: 1,
    name: 'Shared certificate asset',
    category: 'cert',
    type: 'ssl_cert',
    expiresAt: '2027-01-01',
    __certificateLinkAmbiguous: true,
  };

  it('keeps desktop and mobile lifecycle actions disabled, without offering hard deletion', () => {
    const handlers = show(token);
    for (const button of [
      ...screen.getAllByRole('button', { name: /Renew/, hidden: true }),
      ...screen.getAllByRole('button', { name: /Retire/, hidden: true }),
    ]) {
      expect(button).toBeDisabled();
      fireEvent.click(button);
    }
    expect(
      screen.queryByRole('button', { name: /Delete/, hidden: true })
    ).not.toBeInTheDocument();
    expect(handlers.onOpenRenew).not.toHaveBeenCalled();
    expect(handlers.onDeleteToken).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Details' }));
    expect(handlers.onOpenTokenModal).toHaveBeenCalledWith(token);
  });

  it('shows aggregate retirement rather than expiry health when every linked identity is retired', () => {
    show({ ...token, __managedCertificatesRetired: true });
    expect(screen.getAllByText('Retired').length).toBeGreaterThan(0);
    expect(screen.queryByText('Healthy')).not.toBeInTheDocument();
  });
});
