import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
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

  it('shows aggregate retirement rather than expiry health when every linked identity is retired', () => {
    show({ ...token, __managedCertificatesRetired: true });
    expect(screen.getAllByText('Retired').length).toBeGreaterThan(0);
    expect(screen.queryAllByText('Healthy')).toHaveLength(0);
  });

  it.each(['revoked', 'decommissioned'])(
    'uses persisted %s lifecycle when CertOps enrichment is unavailable',
    status => {
      show({
        ...token,
        __certificateLinkAmbiguous: false,
        cert_lifecycle_status: status,
      });
      expect(screen.queryAllByText('Healthy')).toHaveLength(0);
      expect(
        screen.getAllByText(status === 'revoked' ? 'Revoked' : 'Decommissioned')
          .length
      ).toBeGreaterThan(0);
    }
  );
});

it('adds a compact deployment indicator only for an authoritatively linked certificate token', async () => {
  distributionGet.mockResolvedValue({
    data: {
      groups: [
        {
          id: 'group',
          managed_certificate_id: 'managed-a',
          current_identity_id: 'identity-shared',
          summary: { total: 5, verified: 3, pending: 2 },
        },
      ],
    },
  });
  const managed = {
    id: 'managed-a',
    identityId: 'identity-shared',
    status: 'active',
  };
  const asset = {
    id: 7,
    name: 'Shared TLS',
    category: 'cert',
    type: 'ssl_cert',
    expiresAt: '2027-01-01',
    __managedCert: managed,
  };
  const handlers = show(asset, 'workspace-a');
  await waitFor(() =>
    expect(screen.getAllByText('3/5').length).toBeGreaterThan(0)
  );
  expect(
    screen.queryByRole('columnheader', { name: 'Deployment' })
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Details' }));
  expect(handlers.onOpenTokenModal).toHaveBeenCalledWith(
    expect.objectContaining({ id: 7, __managedCert: managed })
  );
  const deployment = screen.getAllByRole('button', {
    name: /Open certificate deployments: 3\/5 verified/,
  })[0];
  fireEvent.click(deployment);
  expect(handlers.onOpenTokenModal).toHaveBeenLastCalledWith(
    expect.objectContaining({ id: 7, __focusDeployments: true })
  );
  expect(distributionGet).toHaveBeenCalledTimes(1);
  expect(distributionGet.mock.calls[0][1].params).toMatchObject({
    managedCertificateIds: 'managed-a',
    identityIds: undefined,
  });
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
