import { ChakraProvider } from '@chakra-ui/react';
import { render, screen } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import CertificateIdentityDetailModal from '../../src/components/certops/CertificateIdentityDetailModal.jsx';

const {
  getIdentityMock,
  getManagedMock,
  listProfilesMock,
  getTokenMock,
  getAlertSettingsMock,
  getContactsMock,
  detailsModalMock,
} = vi.hoisted(() => ({
  getIdentityMock: vi.fn(),
  getManagedMock: vi.fn(),
  listProfilesMock: vi.fn(),
  getTokenMock: vi.fn(),
  getAlertSettingsMock: vi.fn(),
  getContactsMock: vi.fn(),
  detailsModalMock: vi.fn(),
}));

vi.mock('../../src/components/certops/certopsApi.js', () => ({
  getCertificateIdentity: getIdentityMock,
  getManagedCertificatesForToken: getManagedMock,
  listCertOpsRenewalProfiles: listProfilesMock,
  readdManagingSource: vi.fn(),
  stopManagingSource: vi.fn(),
}));

vi.mock('../../src/utils/apiClient', () => ({
  default: { get: getContactsMock },
  tokenAPI: { getToken: getTokenMock },
  workspaceAPI: { getAlertSettings: getAlertSettingsMock },
}));

vi.mock('../../src/components/certops/CertificateDetailsModal.jsx', () => ({
  default: props => {
    detailsModalMock(props);
    return (
      <div data-testid='unified-certificate-detail'>
        <span>{props.token.name}</span>
        {props.identityPanel}
      </div>
    );
  },
}));

beforeEach(() => {
  getIdentityMock.mockReset();
  getManagedMock.mockReset();
  getManagedMock.mockResolvedValue([]);
  listProfilesMock.mockReset();
  getTokenMock.mockReset();
  getAlertSettingsMock.mockReset();
  getContactsMock.mockReset();
  detailsModalMock.mockReset();
  listProfilesMock.mockResolvedValue([]);
  getAlertSettingsMock.mockResolvedValue({ contact_groups: [] });
  getContactsMock.mockResolvedValue({ data: { items: [] } });
});

it('shows one linked token together with all certificate sources and locations', async () => {
  const identity = {
    identityId: 'identity-1',
    tokenId: 7,
    commonName: 'shared.example.test',
    fingerprintSha256: 'a'.repeat(64),
    lifecycleStatus: 'active',
    status: 'discovered',
    locationCount: 2,
    sourceCount: 2,
    activeSourceCount: 2,
    locations: [
      {
        id: 'loc-1',
        sourceRef: 'file:///a.pem',
        presenceState: 'confirmed_present',
      },
      {
        id: 'loc-2',
        sourceRef: 'file:///b.pem',
        presenceState: 'confirmed_present',
      },
    ],
    sources: [
      {
        periodId: 'period-1',
        managedCertificateId: 'cert-1',
        source: 'api',
        startedAt: '2026-01-01T00:00:00Z',
        currentIdentityId: 'identity-1',
      },
      {
        periodId: 'period-2',
        managedCertificateId: 'cert-2',
        source: 'agent_filesystem',
        startedAt: '2026-02-01T00:00:00Z',
        currentIdentityId: 'identity-1',
      },
    ],
  };
  getIdentityMock.mockResolvedValue(identity);
  getManagedMock.mockResolvedValue([
    {
      id: 'cert-1',
      fingerprintSha256: 'a'.repeat(64),
      notBefore: '2026-10-02T00:00:00Z',
      keyMode: 'external-unknown',
      renewal: { state: 'not-eligible' },
    },
    {
      id: 'rotated',
      fingerprintSha256: 'b'.repeat(64),
      notBefore: '2026-11-01T00:00:00Z',
      renewal: { state: 'auto' },
    },
  ]);
  getTokenMock.mockResolvedValue({
    id: 7,
    name: 'Shared token asset',
    category: 'cert',
    type: 'ssl_cert',
  });

  render(
    <ChakraProvider>
      <CertificateIdentityDetailModal
        workspaceId='workspace-1'
        certificate={identity}
        isOpen
        onClose={vi.fn()}
        canManage
      />
    </ChakraProvider>
  );

  expect(await screen.findByText('Shared token asset')).toBeInTheDocument();
  expect(screen.getByText('file:///a.pem')).toBeInTheDocument();
  expect(screen.getByText('file:///b.pem')).toBeInTheDocument();
  expect(
    screen.getByRole('heading', { name: 'Management sources' })
  ).toBeInTheDocument();
  expect(
    screen.queryByRole('button', { name: 'View token details' })
  ).not.toBeInTheDocument();
  expect(detailsModalMock).toHaveBeenLastCalledWith(
    expect.objectContaining({
      token: expect.objectContaining({ id: 7 }),
      titleOverride: 'shared.example.test',
      certOps: expect.objectContaining({
        certificate: expect.objectContaining({
          fingerprintSha256: 'a'.repeat(64),
          notBefore: '2026-10-02T00:00:00Z',
          keyMode: 'external-unknown',
          renewal: { state: 'not-eligible' },
        }),
      }),
    })
  );
});
