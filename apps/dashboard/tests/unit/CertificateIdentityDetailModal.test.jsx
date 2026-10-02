import { ChakraProvider } from '@chakra-ui/react';
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
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
  stopMock,
  readdMock,
} = vi.hoisted(() => ({
  getIdentityMock: vi.fn(),
  getManagedMock: vi.fn(),
  listProfilesMock: vi.fn(),
  getTokenMock: vi.fn(),
  getAlertSettingsMock: vi.fn(),
  getContactsMock: vi.fn(),
  detailsModalMock: vi.fn(),
  stopMock: vi.fn(),
  readdMock: vi.fn(),
}));

vi.mock('../../src/components/certops/certopsApi.js', () => ({
  getCertificateIdentity: getIdentityMock,
  getManagedCertificatesForToken: getManagedMock,
  listCertOpsRenewalProfiles: listProfilesMock,
  readdManagingSource: readdMock,
  stopManagingSource: stopMock,
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
  stopMock.mockReset();
  readdMock.mockReset();
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
    locationCount: 3,
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
      {
        id: 'loc-tls',
        source: 'endpoint_monitor',
        locationKind: 'tls_endpoint',
        sourceRef: 'https://shared.example.test:443',
        evidenceKind: 'service_binding',
        capturedAt: '2026-10-02T12:00:00Z',
        presenceState: 'unknown',
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
  const locations = screen.getByRole('table', { name: 'Observed locations' });
  expect(
    within(locations).getByRole('columnheader', { name: 'Last observed' })
  ).toBeInTheDocument();
  expect(within(locations).getAllByRole('row')).toHaveLength(4);
  expect(within(locations).getByText('TLS endpoint')).toBeInTheDocument();
  expect(within(locations).getByText('Service use')).toBeInTheDocument();
  expect(
    within(
      within(locations)
        .getByText('https://shared.example.test:443')
        .closest('tr')
    ).getByText('Unknown')
  ).toBeInTheDocument();
  const sources = screen.getByRole('table', { name: 'Certificate management' });
  expect(
    within(sources).getByRole('columnheader', { name: 'Management period' })
  ).toBeInTheDocument();
  expect(within(sources).getAllByRole('row')).toHaveLength(3);
  expect(
    screen.getByRole('heading', { name: 'Certificate management' })
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

it('keeps one registration visible after stop/restart and reveals ended periods on request', async () => {
  const source = {
    periodId: 'current',
    managedCertificateId: 'cert-1',
    source: 'manual',
    sourceRef: 'manual://shared',
    startedAt: '2026-10-01T00:00:00Z',
    currentIdentityId: 'identity-1',
  };
  let identity = {
    identityId: 'identity-1',
    commonName: 'shared.example.test',
    fingerprintSha256: 'a'.repeat(64),
    locations: [],
    sources: [source],
  };
  getIdentityMock.mockImplementation(async () => identity);
  stopMock.mockImplementation(async () => {
    identity = {
      ...identity,
      sources: [
        {
          ...source,
          periodEndedAt: '2026-10-02T00:00:00Z',
          endedReason: 'stopped_by_operator',
        },
      ],
    };
    return { runningJobs: 0 };
  });
  readdMock.mockImplementation(async () => {
    identity = {
      ...identity,
      sources: [
        { ...source, periodId: 'restarted', startedAt: '2026-10-02T01:00:00Z' },
        ...identity.sources,
      ],
    };
    return {};
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
  fireEvent.click(await screen.findByRole('button', { name: 'Stop managing' }));
  const restart = await screen.findByRole('button', {
    name: 'Start managing again',
  });
  expect(stopMock).toHaveBeenCalledWith('workspace-1', 'current');
  expect(screen.getByText('Stopped')).toBeInTheDocument();
  fireEvent.click(restart);
  await waitFor(() =>
    expect(readdMock).toHaveBeenCalledWith('workspace-1', 'cert-1', {
      renewalProfileId: null,
      automationEnabled: false,
    })
  );
  await screen.findByRole('button', { name: 'Stop managing' });
  const table = screen.getByRole('table', { name: 'Certificate management' });
  expect(within(table).getAllByRole('row')).toHaveLength(2);
  expect(screen.queryByText('Ended')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('checkbox', { name: 'Show ended periods' }));
  expect(within(table).getAllByRole('row')).toHaveLength(3);
  expect(screen.getByText('Ended')).toBeInTheDocument();
  expect(
    screen.queryByRole('button', { name: 'Start managing again' })
  ).not.toBeInTheDocument();
});

it('does not offer to restart deleted endpoints or a registration now associated with a different certificate', async () => {
  const identity = {
    identityId: 'identity-1',
    sources: [
      {
        periodId: 'deleted',
        managedCertificateId: 'cert-1',
        periodEndedAt: '2026-10-01',
        startedAt: '2026-09-01',
        currentIdentityId: 'identity-1',
        endedReason: 'endpoint_monitor_deleted',
      },
      {
        periodId: 'rotated',
        managedCertificateId: 'cert-2',
        periodEndedAt: '2026-10-01',
        startedAt: '2026-09-01',
        currentIdentityId: 'identity-2',
      },
    ],
  };
  getIdentityMock.mockResolvedValue(identity);
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
  fireEvent.click(
    await screen.findByRole('checkbox', { name: 'Show ended periods' })
  );
  expect(
    screen.queryByRole('button', { name: 'Start managing again' })
  ).not.toBeInTheDocument();
  expect(screen.getAllByText('Ended')).toHaveLength(2);
});

it('keeps restart renewal choices independent for each registration', async () => {
  const identity = {
    identityId: 'identity-1',
    sources: ['one', 'two'].map(id => ({
      periodId: `period-${id}`,
      managedCertificateId: `cert-${id}`,
      source: 'manual',
      sourceRef: `manual://${id}`,
      startedAt: '2026-09-01',
      periodEndedAt: '2026-10-01',
      currentIdentityId: 'identity-1',
    })),
  };
  getIdentityMock.mockResolvedValue(identity);
  listProfilesMock.mockResolvedValue([
    { id: 'profile-1', name: 'Automatic renewal' },
  ]);
  readdMock.mockResolvedValue({});
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
  await screen.findAllByRole('option', { name: 'Automatic renewal' });
  fireEvent.change(
    screen.getByRole('combobox', { name: 'Renewal settings for manual://one' }),
    { target: { value: 'profile-1' } }
  );
  const rowTwo = screen.getByText('manual://two').closest('tr');
  fireEvent.click(
    within(rowTwo).getByRole('button', { name: 'Start managing again' })
  );
  await waitFor(() =>
    expect(readdMock).toHaveBeenCalledWith('workspace-1', 'cert-two', {
      renewalProfileId: null,
      automationEnabled: false,
    })
  );
});
