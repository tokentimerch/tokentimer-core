import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import AssetInventoryTable from '../../src/components/AssetInventoryTable.jsx';

const { distributionGet } = vi.hoisted(() => ({ distributionGet: vi.fn() }));
vi.mock('../../src/utils/apiClient', async () => {
  const actual = await vi.importActual('../../src/utils/apiClient');
  return { ...actual, default: { ...actual.default, get: distributionGet } };
});

function show(token, workspaceId) {
  const handlers = {
    onOpenTokenModal: vi.fn(),
    onOpenRenew: vi.fn(),
    onDeleteToken: vi.fn(),
  };
  render(
    <ChakraProvider>
      <AssetInventoryTable
        tokens={[token]}
        workspaceId={workspaceId}
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

  it('allows desktop and mobile retirement to choose a certificate while keeping renewal gated', () => {
    const handlers = show(token);
    for (const button of [
      ...screen.getAllByRole('button', { name: /Renew/, hidden: true }),
    ]) {
      expect(button).toBeDisabled();
      fireEvent.click(button);
    }
    expect(
      screen.queryByRole('button', { name: /Delete/, hidden: true })
    ).not.toBeInTheDocument();
    expect(handlers.onOpenRenew).not.toHaveBeenCalled();
    const retireButtons = screen.getAllByRole('button', {
      name: /Retire/,
      hidden: true,
    });
    for (const button of retireButtons) {
      expect(button).not.toBeDisabled();
      fireEvent.click(button);
    }
    expect(handlers.onDeleteToken).toHaveBeenCalledTimes(retireButtons.length);
    expect(handlers.onDeleteToken).toHaveBeenCalledWith(token.id);
    fireEvent.click(screen.getByRole('button', { name: 'Details' }));
    expect(handlers.onOpenTokenModal).toHaveBeenCalledWith(token);
  });

  it('shows expiry and aggregate retirement separately on desktop and mobile', () => {
    show({ ...token, __managedCertificatesRetired: true });
    expect(screen.getAllByText('Retired')).toHaveLength(2);
    expect(screen.getAllByText('Within validity')).toHaveLength(2);
    expect(screen.queryAllByText('Healthy')).toHaveLength(0);
  });

  it.each([
    ['revoked', 'Revoked', 'Within validity'],
    ['decommissioned', 'Decommissioned', 'Within validity'],
    ['renewing', 'Renewing', 'Healthy'],
  ])(
    'shows expiry and the lifecycle of a single linked certificate in %s state',
    (status, lifecycleLabel, expiryLabel) => {
      show({
        ...token,
        __certificateLinkAmbiguous: false,
        cert_lifecycle_status: status,
        __managedCert: {
          id: 'managed-1',
          lifecycleStatus: status,
          observedRevocation: { status: 'revoked' },
        },
      });
      expect(screen.getAllByText(expiryLabel)).toHaveLength(2);
      expect(screen.getAllByText(lifecycleLabel)).toHaveLength(2);
    }
  );
});

it('keeps rollout markers off the asset inventory', () => {
  const managed = {
    id: 'managed-a',
    identityId: 'identity-shared',
    status: 'active',
    lifecycleStatus: 'active',
  };
  const asset = {
    id: 7,
    name: 'Shared TLS',
    category: 'cert',
    type: 'ssl_cert',
    expiresAt: '2027-01-01',
    __managedCert: managed,
  };
  show(asset, 'workspace-a');
  expect(screen.queryByText('Active')).not.toBeInTheDocument();
  expect(screen.queryByText('3 of 5 live')).not.toBeInTheDocument();
  expect(
    screen.queryByRole('button', { name: /Open certificate deployments/ })
  ).not.toBeInTheDocument();
  expect(distributionGet).not.toHaveBeenCalled();
});

it('does not fetch or display deployment for unrelated assets with the same domain', () => {
  distributionGet.mockClear();
  show(
    {
      id: 8,
      name: 'Unrelated secret',
      category: 'key_secret',
      type: 'api_key',
      domains: ['same.example'],
      __managedCert: { id: 'managed-a' },
    },
    'workspace-a'
  );
  expect(distributionGet).not.toHaveBeenCalled();
  expect(screen.queryByText(/verified/)).not.toBeInTheDocument();
});
