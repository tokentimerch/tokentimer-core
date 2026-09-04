import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  render,
  screen,
  fireEvent,
  waitFor,
  within,
} from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import CertOpsCertificates from '../../src/pages/certops/CertOpsCertificates.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const {
  useCertOpsCertificatesMock,
  useCertOpsCanManageMock,
  retireCertificateMock,
  setUpCertificateRenewalMock,
  detachCertificateRenewalProfileMock,
  retryRenewalSetupIntentMock,
  listCertificatesMock,
  listRenewalProfilesMock,
} = vi.hoisted(() => ({
  useCertOpsCertificatesMock: vi.fn(),
  useCertOpsCanManageMock: vi.fn(),
  retireCertificateMock: vi.fn(),
  setUpCertificateRenewalMock: vi.fn(),
  detachCertificateRenewalProfileMock: vi.fn(),
  retryRenewalSetupIntentMock: vi.fn(),
  listCertificatesMock: vi.fn(),
  listRenewalProfilesMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'ws-1', selectWorkspace: vi.fn() }),
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsCanManage: useCertOpsCanManageMock,
}));

vi.mock('../../src/components/certops/useCertOpsCertificates.js', () => ({
  useCertOpsCertificates: useCertOpsCertificatesMock,
}));

vi.mock('../../src/components/certops/certopsApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsApi.js'
  );
  return {
    ...actual,
    retireCertificate: retireCertificateMock,
    setUpCertificateRenewal: setUpCertificateRenewalMock,
    detachCertificateRenewalProfile: detachCertificateRenewalProfileMock,
    retryRenewalSetupIntent: retryRenewalSetupIntentMock,
    listCertificates: listCertificatesMock,
  };
});

vi.mock('../../src/components/certops/certopsRenewalApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsRenewalApi.js'
  );
  return {
    ...actual,
    listRenewalProfiles: listRenewalProfilesMock,
  };
});

function renderPage(initialEntries = ['/']) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter initialEntries={initialEntries}>
          <CertOpsCertificates />
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

function certState(overrides = {}) {
  return {
    enabled: true,
    certificates: [],
    pagination: null,
    loading: false,
    error: '',
    refresh: vi.fn(),
    ...overrides,
  };
}

function certificate(overrides = {}) {
  return {
    id: 'cert-11111111-1111-1111-1111-111111111111',
    commonName: 'example.test',
    subjectAltNames: [],
    status: 'active',
    source: 'manual',
    notAfter: '2099-01-01T00:00:00.000Z',
    keyMode: null,
    renewal: { state: 'not-configured' },
    ...overrides,
  };
}

beforeEach(() => {
  useCertOpsCertificatesMock.mockReset();
  useCertOpsCanManageMock.mockReset();
  retireCertificateMock.mockReset();
  setUpCertificateRenewalMock.mockReset();
  detachCertificateRenewalProfileMock.mockReset();
  retryRenewalSetupIntentMock.mockReset();
  listCertificatesMock.mockReset();
  listRenewalProfilesMock.mockReset();
  useCertOpsCanManageMock.mockReturnValue(true);
  useCertOpsCertificatesMock.mockReturnValue(certState());
  // Default: the retired-count probe (two limit:1 list calls) sees no
  // retired certificates, so most tests can ignore it entirely.
  listCertificatesMock.mockResolvedValue({
    items: [],
    pagination: { limit: 1, offset: 0, total: 0 },
  });
  // Default: no existing renewal profiles, so the setup modal falls back to
  // manual entry without an extra click in tests that don't care about the
  // preset picker.
  listRenewalProfilesMock.mockResolvedValue({ items: [], total: 0 });
});

describe('CertOpsCertificates list states', () => {
  it('shows a loading state distinct from the empty state', () => {
    useCertOpsCertificatesMock.mockReturnValue(certState({ loading: true }));

    renderPage();

    expect(
      screen.getByText('Loading managed certificates...')
    ).toBeInTheDocument();
    expect(
      screen.queryByText('No managed certificates yet')
    ).not.toBeInTheDocument();
  });

  it('shows an empty state when there are no certificates', () => {
    renderPage();

    expect(screen.getByText('No managed certificates yet')).toBeInTheDocument();
  });

  it('renders a certificate row with its status, expiry and renewal badges', () => {
    useCertOpsCertificatesMock.mockReturnValue(
      certState({ certificates: [certificate()] })
    );

    renderPage();

    const row = screen.getByText('example.test').closest('tr');
    expect(row).not.toBeNull();
    expect(row).toHaveAttribute('data-certificate-mobile-card');
    expect(screen.getByText('example.test')).toBeInTheDocument();
    expect(
      screen.getByRole('cell', { name: 'Status Active' })
    ).toBeInTheDocument();
    expect(screen.getByText('No auto-renewal')).toBeInTheDocument();
  });

  it('preserves the server page order and leaves derived renewal state non-sortable', () => {
    useCertOpsCertificatesMock.mockReturnValue(
      certState({
        certificates: [
          certificate({
            id: 'cert-zulu',
            commonName: 'zulu.example.test',
            notAfter: '2099-12-31T00:00:00.000Z',
          }),
          certificate({
            id: 'cert-alpha',
            commonName: 'alpha.example.test',
            notAfter: '2027-01-01T00:00:00.000Z',
          }),
        ],
        pagination: { limit: 20, offset: 20, total: 100 },
      })
    );

    renderPage();

    const first = screen.getByText('zulu.example.test');
    const second = screen.getByText('alpha.example.test');
    expect(
      first.compareDocumentPosition(second) & Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();
    expect(screen.getByLabelText('Sort by Expiry')).toBeInTheDocument();
    expect(screen.queryByLabelText('Sort by Renewal')).not.toBeInTheDocument();
  });

  it('requests ascending and descending server sorts and resets the offset', async () => {
    useCertOpsCertificatesMock.mockReturnValue(
      certState({
        certificates: [certificate()],
        pagination: { limit: 20, offset: 20, total: 100 },
      })
    );

    renderPage(['/?offset=20']);

    fireEvent.click(screen.getByLabelText('Sort by Certificate'));
    await waitFor(() => {
      expect(useCertOpsCertificatesMock).toHaveBeenLastCalledWith(
        expect.objectContaining({
          offset: 0,
          sort: 'certificate',
          direction: 'asc',
        })
      );
    });

    fireEvent.click(screen.getByLabelText('Sort by Certificate'));
    await waitFor(() => {
      expect(useCertOpsCertificatesMock).toHaveBeenLastCalledWith(
        expect.objectContaining({
          offset: 0,
          sort: 'certificate',
          direction: 'desc',
        })
      );
    });
  });

  it('places dashboard-style pagination above the table and uses icon actions', () => {
    useCertOpsCertificatesMock.mockReturnValue(
      certState({
        certificates: [certificate({ tokenId: 'token-1' })],
        pagination: { limit: 20, offset: 0, total: 1 },
      })
    );

    renderPage();

    const pagination = screen.getByRole('navigation', {
      name: 'certificates pagination',
    });
    const table = screen.getByRole('table');
    expect(
      pagination.compareDocumentPosition(table) &
        Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();

    ['Details', 'Set up renewal', 'Retire'].forEach(name => {
      expect(
        screen.getByRole('button', { name }).querySelector('svg')
      ).not.toBeNull();
    });
  });

  it('shows an error message distinct from the loading and empty states', () => {
    useCertOpsCertificatesMock.mockReturnValue(
      certState({ error: 'Could not load the managed certificate inventory.' })
    );

    renderPage();

    expect(
      screen.getByText('Could not load the managed certificate inventory.')
    ).toBeInTheDocument();
    expect(
      screen.queryByText('No managed certificates yet')
    ).not.toBeInTheDocument();
  });
});

describe('CertOpsCertificates filters', () => {
  it('excludes retired certificates by default', () => {
    renderPage();

    expect(useCertOpsCertificatesMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ excludeRetired: true })
    );
  });

  it('includes retired certificates once the Retired toggle is pressed', () => {
    renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Retired' }));

    expect(useCertOpsCertificatesMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ excludeRetired: undefined })
    );
  });

  it('does not force excludeRetired once an explicit status filter is chosen', () => {
    renderPage();

    fireEvent.change(screen.getByDisplayValue('All statuses'), {
      target: { value: 'revoked' },
    });

    expect(useCertOpsCertificatesMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ status: 'revoked', excludeRetired: undefined })
    );
  });

  it('filters by source', () => {
    renderPage();

    fireEvent.change(screen.getByDisplayValue('All sources'), {
      target: { value: 'agent_filesystem' },
    });

    expect(useCertOpsCertificatesMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ source: 'agent_filesystem' })
    );
  });
});

describe('CertOpsCertificates retire action', () => {
  it('does not show the retire action for a non-manager viewer', () => {
    useCertOpsCanManageMock.mockReturnValue(false);
    useCertOpsCertificatesMock.mockReturnValue(
      certState({ certificates: [certificate()] })
    );

    renderPage();

    expect(
      screen.queryByRole('button', { name: 'Retire' })
    ).not.toBeInTheDocument();
  });

  it('hides the retire action for an already-retired certificate', () => {
    useCertOpsCertificatesMock.mockReturnValue(
      certState({ certificates: [certificate({ status: 'revoked' })] })
    );

    renderPage();

    expect(
      screen.queryByRole('button', { name: 'Retire' })
    ).not.toBeInTheDocument();
  });

  it('opens the retire modal, submits it, and refreshes the list', async () => {
    const refresh = vi.fn();
    useCertOpsCertificatesMock.mockReturnValue(
      certState({ certificates: [certificate()], refresh })
    );
    retireCertificateMock.mockResolvedValue({ certificate: {} });

    renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Retire' }));
    const dialog = await screen.findByRole('dialog', {
      name: /Retire certificate/,
    });
    expect(dialog).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Decommission' }));

    await vi.waitFor(() => {
      expect(retireCertificateMock).toHaveBeenCalledWith(
        'ws-1',
        certificate().id,
        expect.objectContaining({ status: 'decommissioned' })
      );
      expect(refresh).toHaveBeenCalledTimes(1);
    });
  });
});

describe('CertOpsCertificates renewal setup and detach', () => {
  it('offers "Set up renewal" only for a manager-viewable, unprofiled, not-configured certificate', () => {
    useCertOpsCertificatesMock.mockReturnValue(
      certState({
        certificates: [
          certificate({
            renewal: { state: 'not-configured', profileId: null },
          }),
        ],
      })
    );

    renderPage();

    expect(
      screen.getByRole('button', { name: 'Set up renewal' })
    ).toBeInTheDocument();
  });

  it('does not offer "Set up renewal" for a non-manager viewer', () => {
    useCertOpsCanManageMock.mockReturnValue(false);
    useCertOpsCertificatesMock.mockReturnValue(
      certState({
        certificates: [
          certificate({
            renewal: { state: 'not-configured', profileId: null },
          }),
        ],
      })
    );

    renderPage();

    expect(
      screen.queryByRole('button', { name: 'Set up renewal' })
    ).not.toBeInTheDocument();
  });

  it('does not offer "Set up renewal" while a setup intent is already waiting', () => {
    useCertOpsCertificatesMock.mockReturnValue(
      certState({
        certificates: [
          certificate({
            renewal: { state: 'not-configured', profileId: null },
            renewalSetup: { state: 'waiting' },
          }),
        ],
      })
    );

    renderPage();

    expect(
      screen.queryByRole('button', { name: 'Set up renewal' })
    ).not.toBeInTheDocument();
    expect(
      screen.getByText('Setting up automatic renewal')
    ).toBeInTheDocument();
  });

  it('shows "Detach" instead of "Set up renewal" for a profiled certificate', () => {
    useCertOpsCertificatesMock.mockReturnValue(
      certState({
        certificates: [
          certificate({ renewal: { state: 'auto', profileId: 'profile-1' } }),
        ],
      })
    );

    renderPage();

    expect(screen.getByRole('button', { name: 'Detach' })).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Set up renewal' })
    ).not.toBeInTheDocument();
  });

  it('submits the setup modal and refreshes the list', async () => {
    const refresh = vi.fn();
    useCertOpsCertificatesMock.mockReturnValue(
      certState({
        certificates: [
          certificate({
            renewal: { state: 'not-configured', profileId: null },
          }),
        ],
        refresh,
      })
    );
    setUpCertificateRenewalMock.mockResolvedValue({ job: { id: 'job-1' } });

    renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Set up renewal' }));
    const dialog = await screen.findByRole('dialog', {
      name: /Set up automatic renewal/,
    });
    expect(dialog).toBeInTheDocument();

    // No existing renewal profiles (see beforeEach), so the modal falls back
    // to manual entry directly; wait for that async check to settle before
    // looking for the manual inputs.
    fireEvent.change(await screen.findByPlaceholderText('e.g. certbot-csr'), {
      target: { value: 'certbot-csr' },
    });
    fireEvent.change(screen.getByPlaceholderText('e.g. cloudflare'), {
      target: { value: 'cloudflare' },
    });
    fireEvent.change(
      screen.getByPlaceholderText(
        'e.g. https://acme-v02.api.letsencrypt.org/directory'
      ),
      { target: { value: 'https://acme-v02.api.letsencrypt.org/directory' } }
    );
    fireEvent.change(screen.getByPlaceholderText('e.g. example.com'), {
      target: { value: 'example.com' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Renew and set up' }));

    await vi.waitFor(() => {
      expect(setUpCertificateRenewalMock).toHaveBeenCalledWith(
        'ws-1',
        certificate().id,
        expect.objectContaining({
          payload: expect.objectContaining({
            commandRef: 'certbot-csr',
            dnsProvider: 'cloudflare',
            caEndpoint: 'https://acme-v02.api.letsencrypt.org/directory',
            dnsZone: 'example.com',
          }),
        })
      );
      expect(refresh).toHaveBeenCalledTimes(1);
    });
  });

  it('defaults to an existing profile as a preset and submits its values', async () => {
    const refresh = vi.fn();
    useCertOpsCertificatesMock.mockReturnValue(
      certState({
        certificates: [
          certificate({
            renewal: { state: 'not-configured', profileId: null },
          }),
        ],
        refresh,
      })
    );
    setUpCertificateRenewalMock.mockResolvedValue({ job: { id: 'job-1' } });
    listRenewalProfilesMock.mockResolvedValue({
      items: [
        {
          id: 'profile-existing',
          name: 'Derived: example.test (cert-1)',
          renewalProfile: {
            acme: { commandRef: 'certbot-csr' },
            ca: { endpoint: 'https://acme-v02.api.letsencrypt.org/directory' },
            dns: { provider: 'cloudflare', zone: 'example.com' },
          },
        },
      ],
      total: 1,
    });

    renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Set up renewal' }));
    await screen.findByRole('dialog', { name: /Set up automatic renewal/ });

    // The preset card renders once the profile list resolves (its name
    // appears both in the picker card and in the summary sentence above it);
    // no manual inputs are needed or shown by default.
    await screen.findAllByText('Derived: example.test (cert-1)');
    expect(screen.queryByPlaceholderText('e.g. certbot-csr')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Renew and set up' }));

    await vi.waitFor(() => {
      expect(setUpCertificateRenewalMock).toHaveBeenCalledWith(
        'ws-1',
        certificate().id,
        expect.objectContaining({
          payload: {
            commandRef: 'certbot-csr',
            dnsProvider: 'cloudflare',
            caEndpoint: 'https://acme-v02.api.letsencrypt.org/directory',
            dnsZone: 'example.com',
          },
        })
      );
      expect(refresh).toHaveBeenCalledTimes(1);
    });
  });

  it('switches an existing-profile default to manual entry', async () => {
    useCertOpsCertificatesMock.mockReturnValue(
      certState({
        certificates: [
          certificate({
            renewal: { state: 'not-configured', profileId: null },
          }),
        ],
      })
    );
    listRenewalProfilesMock.mockResolvedValue({
      items: [
        {
          id: 'profile-existing',
          name: 'Derived: example.test (cert-1)',
          renewalProfile: {
            acme: { commandRef: 'certbot-csr' },
            ca: { endpoint: 'https://acme-v02.api.letsencrypt.org/directory' },
            dns: { provider: 'cloudflare', zone: 'example.com' },
          },
        },
      ],
      total: 1,
    });

    renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Set up renewal' }));
    await screen.findByRole('dialog', { name: /Set up automatic renewal/ });
    await screen.findAllByText('Derived: example.test (cert-1)');

    fireEvent.click(
      screen.getByRole('checkbox', { name: 'Enter renewal details manually' })
    );

    expect(
      await screen.findByPlaceholderText('e.g. certbot-csr')
    ).toBeInTheDocument();
    expect(
      screen.queryByText('Derived: example.test (cert-1)')
    ).not.toBeInTheDocument();
  });

  it("prefills manual entry with the selected preset's values when switching", async () => {
    useCertOpsCertificatesMock.mockReturnValue(
      certState({
        certificates: [
          certificate({
            renewal: { state: 'not-configured', profileId: null },
          }),
        ],
      })
    );
    listRenewalProfilesMock.mockResolvedValue({
      items: [
        {
          id: 'profile-existing',
          name: 'Derived: example.test (cert-1)',
          renewalProfile: {
            acme: { commandRef: 'certbot-csr' },
            ca: { endpoint: 'https://acme-v02.api.letsencrypt.org/directory' },
            dns: { provider: 'cloudflare', zone: 'example.com' },
          },
        },
      ],
      total: 1,
    });

    renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Set up renewal' }));
    await screen.findByRole('dialog', { name: /Set up automatic renewal/ });
    await screen.findAllByText('Derived: example.test (cert-1)');

    fireEvent.click(
      screen.getByRole('checkbox', { name: 'Enter renewal details manually' })
    );

    // The manual fields are not blank: they carry the values copied from
    // the profile that was selected before switching, so tweaking one field
    // does not require retyping the rest.
    expect(await screen.findByDisplayValue('certbot-csr')).toBeInTheDocument();
    expect(
      screen.getByDisplayValue('https://acme-v02.api.letsencrypt.org/directory')
    ).toBeInTheDocument();
    expect(screen.getByDisplayValue('cloudflare')).toBeInTheDocument();
    expect(screen.getByDisplayValue('example.com')).toBeInTheDocument();
  });

  it("shows the certificate's own deployment path and warns when a preset's path does not match it", async () => {
    useCertOpsCertificatesMock.mockReturnValue(
      certState({
        certificates: [
          certificate({
            renewal: { state: 'not-configured', profileId: null },
            deployedCertPath: '/etc/ssl/certs/example.test.pem',
          }),
        ],
      })
    );
    listRenewalProfilesMock.mockResolvedValue({
      items: [
        {
          id: 'profile-other',
          name: 'Derived: other.test (cert-other)',
          renewalProfile: {
            acme: { commandRef: 'certbot-csr' },
            ca: { endpoint: 'https://acme-v02.api.letsencrypt.org/directory' },
            dns: { provider: 'cloudflare', zone: 'example.com' },
            deploymentTargets: [{ certPath: '/etc/ssl/certs/other.test.pem' }],
          },
        },
      ],
      total: 1,
    });

    renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Set up renewal' }));
    const dialog = await screen.findByRole('dialog', {
      name: /Set up automatic renewal/,
    });

    // The certificate's own discovered path is shown in the header.
    expect(
      within(dialog).getAllByText('/etc/ssl/certs/example.test.pem').length
    ).toBeGreaterThan(0);

    // The switch defaults to off (matching-only), and the only profile
    // available does not match this certificate's path, so it starts
    // hidden behind the empty-state prompt rather than being offered.
    expect(
      screen.getByText(/No profile matches this certificate's own path/)
    ).toBeInTheDocument();
    expect(
      screen.queryByText('Derived: other.test (cert-other)')
    ).not.toBeInTheDocument();

    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'Show all profiles, including ones that do not match this certificate',
      })
    );

    // The mismatched preset's own path renders in its card, and confirming
    // is still possible (the warning is advisory, not a hard block), but the
    // mismatch warning must be visible so the operator can catch it.
    await screen.findAllByText('/etc/ssl/certs/other.test.pem');
    expect(
      screen.getByText(/It looks like it belongs to a different/)
    ).toBeInTheDocument();
  });

  it('filters the preset picker to path-matching profiles by default, with a switch to reveal the rest', async () => {
    useCertOpsCertificatesMock.mockReturnValue(
      certState({
        certificates: [
          certificate({
            renewal: { state: 'not-configured', profileId: null },
            deployedCertPath: '/etc/ssl/certs/example.test.pem',
          }),
        ],
      })
    );
    listRenewalProfilesMock.mockResolvedValue({
      items: [
        {
          id: 'profile-match',
          name: 'Derived: example.test (cert-1)',
          renewalProfile: {
            acme: { commandRef: 'certbot-csr' },
            ca: { endpoint: 'https://acme-v02.api.letsencrypt.org/directory' },
            dns: { provider: 'cloudflare', zone: 'example.com' },
            deploymentTargets: [
              { certPath: '/etc/ssl/certs/example.test.pem' },
            ],
          },
        },
        {
          id: 'profile-other',
          name: 'Derived: other.test (cert-other)',
          renewalProfile: {
            acme: { commandRef: 'certbot-csr' },
            ca: { endpoint: 'https://acme-v02.api.letsencrypt.org/directory' },
            dns: { provider: 'cloudflare', zone: 'example.com' },
            deploymentTargets: [{ certPath: '/etc/ssl/certs/other.test.pem' }],
          },
        },
      ],
      total: 2,
    });

    renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Set up renewal' }));
    await screen.findByRole('dialog', { name: /Set up automatic renewal/ });
    await screen.findAllByText('Derived: example.test (cert-1)');

    // Only the path-matching profile is offered by default; the mismatched
    // one is hidden rather than risking a wrong pick.
    expect(
      screen.queryByText('Derived: other.test (cert-other)')
    ).not.toBeInTheDocument();
    expect(screen.getByText(/Showing 1 matching profile/)).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'Show all profiles, including ones that do not match this certificate',
      })
    );

    expect(
      await screen.findByText('Derived: other.test (cert-other)')
    ).toBeInTheDocument();
  });

  it('detaches a profiled certificate and refreshes the list', async () => {
    const refresh = vi.fn();
    useCertOpsCertificatesMock.mockReturnValue(
      certState({
        certificates: [
          certificate({ renewal: { state: 'auto', profileId: 'profile-1' } }),
        ],
        refresh,
      })
    );
    detachCertificateRenewalProfileMock.mockResolvedValue({
      certificateId: certificate().id,
      detachedProfileId: 'profile-1',
      invalidatedIntents: 0,
    });

    renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Detach' }));
    const dialog = await screen.findByRole('dialog', {
      name: /Detach renewal profile/,
    });
    expect(dialog).toBeInTheDocument();

    fireEvent.click(within(dialog).getByRole('button', { name: 'Detach' }));

    await vi.waitFor(() => {
      expect(detachCertificateRenewalProfileMock).toHaveBeenCalledWith(
        'ws-1',
        certificate().id
      );
      expect(refresh).toHaveBeenCalledTimes(1);
    });
  });

  it('retries a failed setup intent', async () => {
    const refresh = vi.fn();
    useCertOpsCertificatesMock.mockReturnValue(
      certState({
        certificates: [
          certificate({
            renewal: { state: 'not-configured', profileId: null },
            renewalSetup: {
              state: 'failed',
              intentId: 'outbox-1',
              message: 'Something failed.',
            },
          }),
        ],
        refresh,
      })
    );
    retryRenewalSetupIntentMock.mockResolvedValue({ status: 'pending' });

    renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));

    await vi.waitFor(() => {
      expect(retryRenewalSetupIntentMock).toHaveBeenCalledWith(
        'ws-1',
        'outbox-1'
      );
      expect(refresh).toHaveBeenCalledTimes(1);
    });
  });
});

describe('CertOpsCertificates retired count badge', () => {
  it('shows a retired count on the toggle once the probe resolves', async () => {
    listCertificatesMock.mockImplementation((_workspaceId, params) =>
      Promise.resolve({
        items: [],
        pagination: {
          limit: 1,
          offset: 0,
          total: params?.excludeRetired === false ? 7 : 4,
        },
      })
    );

    renderPage();

    const button = await screen.findByRole('button', { name: /Retired/ });
    await vi.waitFor(() => {
      expect(within(button).getByText('3')).toBeInTheDocument();
    });
  });

  it('does not show a badge while the retired-count probe is still loading', () => {
    listCertificatesMock.mockImplementation(() => new Promise(() => {}));

    renderPage();

    const button = screen.getByRole('button', { name: 'Retired' });
    expect(within(button).queryByText(/^\d+$/)).not.toBeInTheDocument();
  });

  it('re-probes the retired count after a certificate is retired', async () => {
    const refresh = vi.fn();
    useCertOpsCertificatesMock.mockReturnValue(
      certState({ certificates: [certificate()], refresh })
    );
    listCertificatesMock.mockImplementation((_workspaceId, params) =>
      Promise.resolve({
        items: [],
        pagination: {
          limit: 1,
          offset: 0,
          total: params?.excludeRetired === false ? 4 : 4,
        },
      })
    );
    retireCertificateMock.mockResolvedValue({ certificate: {} });

    renderPage();

    await screen.findByRole('button', { name: /Retired/ });
    const callsBeforeRetire = listCertificatesMock.mock.calls.length;

    fireEvent.click(screen.getByRole('button', { name: 'Retire' }));
    const dialog = await screen.findByRole('dialog', {
      name: /Retire certificate/,
    });
    expect(dialog).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Decommission' }));

    await vi.waitFor(() => {
      expect(retireCertificateMock).toHaveBeenCalled();
      expect(listCertificatesMock.mock.calls.length).toBeGreaterThan(
        callsBeforeRetire
      );
    });
  });
});
