import { ChakraProvider } from '@chakra-ui/react';
import {
  fireEvent,
  render,
  screen,
  waitFor,
  cleanup,
} from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import CertificateIdentityDetailModal from '../../src/components/certops/CertificateIdentityDetailModal.jsx';

const { getIdentity, getManaged, getSettings, getToken, updateToken } =
  vi.hoisted(() => ({
    getIdentity: vi.fn(),
    getManaged: vi.fn(),
    getSettings: vi.fn(),
    getToken: vi.fn(),
    updateToken: vi.fn(),
  }));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'ws-1' }),
}));

vi.mock('../../src/components/certops/certopsApi.js', async importOriginal => ({
  ...(await importOriginal()),
  getCertificateIdentity: getIdentity,
  getManagedCertificatesForToken: getManaged,
  listCertOpsRenewalProfiles: vi.fn().mockResolvedValue([]),
}));

vi.mock('../../src/utils/apiClient', () => ({
  default: {
    get: vi
      .fn()
      .mockResolvedValue({
        data: { items: [], managed: false, configurations: [] },
      }),
  },
  tokenAPI: { getToken, updateToken },
  workspaceAPI: {
    getAlertSettings: getSettings,
    get: vi.fn().mockResolvedValue({ id: 'ws-1' }),
  },
}));

const groups = [
  { id: 'platform', name: 'Platform On-Call' },
  { id: 'security', name: 'Security On-Call' },
];

function openIdentity(managed = false) {
  const identity = {
    identityId: 'identity-1',
    tokenId: 7,
    commonName: 'api.example.test',
    fingerprintSha256: 'a'.repeat(64),
    managed,
    lifecycleStatus: 'active',
    activeSourceCount: managed ? 1 : 0,
    sourceCount: 1,
    locationCount: 0,
    locations: [],
    tokenSnapshot: {
      id: 7,
      name: 'Linked certificate asset',
      category: 'cert',
      type: 'ssl_cert',
      contact_group_ids: ['platform'],
    },
    certificateSnapshot: {
      commonName: 'api.example.test',
      fingerprintSha256: 'a'.repeat(64),
      notAfter: '2027-06-01T00:00:00Z',
    },
    sources: [
      {
        periodId: 'period-1',
        managedCertificateId: 'managed-1',
        source: 'api',
        startedAt: '2026-01-01T00:00:00Z',
        ...(managed ? {} : { endedAt: '2026-10-01T00:00:00Z' }),
      },
    ],
  };
  getIdentity.mockResolvedValue(identity);
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>
          <CertificateIdentityDetailModal
            workspaceId='ws-1'
            certificate={identity}
            isOpen
            onClose={vi.fn()}
            canManage
          />
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  getManaged.mockResolvedValue([]);
  getSettings.mockResolvedValue({ contact_groups: groups });
});
afterEach(cleanup);

it('loads readable contact-group names for an actively managed linked identity', async () => {
  openIdentity(true);
  expect(await screen.findByText('Platform On-Call')).toBeInTheDocument();
});

it('keeps readable asset group names after the last managing source stops', async () => {
  openIdentity();
  expect(await screen.findByText('Platform On-Call')).toBeInTheDocument();
  expect(getToken).not.toHaveBeenCalled();
  expect(getManaged).not.toHaveBeenCalled();
});

it('keeps existing workspace group choices editable for a stopped but linked identity', async () => {
  openIdentity();
  fireEvent.click(
    await screen.findByRole('button', { name: 'Edit', exact: true })
  );
  fireEvent.click(
    screen.getByRole('button', { name: 'Contact groups', exact: true })
  );
  expect(
    await screen.findByRole('option', { name: 'Platform On-Call', exact: true })
  ).toHaveAttribute('aria-selected', 'true');
  expect(
    screen.getByRole('option', { name: 'Security On-Call', exact: true })
  ).toBeInTheDocument();
  await waitFor(() => expect(getToken).not.toHaveBeenCalled());
});

it('loads group definitions even when live management enrichment fails', async () => {
  getManaged.mockRejectedValue(new Error('Management enrichment unavailable'));
  openIdentity(true);
  expect(await screen.findByText('Platform On-Call')).toBeInTheDocument();
});
