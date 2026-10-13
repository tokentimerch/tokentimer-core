import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  render,
  screen,
  fireEvent,
  waitFor,
  within,
} from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import CertOpsLayout from '../../src/pages/certops/CertOpsLayout.jsx';
import CertOpsRenewals from '../../src/pages/certops/CertOpsRenewals.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const {
  useCertOpsAvailabilityMock,
  useCertOpsIsWorkspaceAdminMock,
  listRenewalProfilesMock,
  updateRenewalProfileMock,
  createAdcsRenewalProfileMock,
  listIssuersMock,
  listAgentsMock,
  listCertificatesMock,
  readdManagingSourceMock,
  stopManagingSourceMock,
  replaceManagingSourceMock,
  showSuccessMock,
} = vi.hoisted(() => ({
  useCertOpsAvailabilityMock: vi.fn(),
  useCertOpsIsWorkspaceAdminMock: vi.fn(),
  listRenewalProfilesMock: vi.fn(),
  updateRenewalProfileMock: vi.fn(),
  createAdcsRenewalProfileMock: vi.fn(),
  listIssuersMock: vi.fn(),
  listAgentsMock: vi.fn(),
  listCertificatesMock: vi.fn(),
  readdManagingSourceMock: vi.fn(),
  stopManagingSourceMock: vi.fn(),
  replaceManagingSourceMock: vi.fn(),
  showSuccessMock: vi.fn(),
}));

vi.mock('../../src/hooks/useDashboardShellProps.js', () => ({
  useDashboardShellProps: ({ pageTitle = '' } = {}) => ({
    dashboardColors: {},
    currentPath: '/certops/renewals',
    sessionName: 'Test User',
    isViewer: false,
    dashboardCanSeeManagerNav: true,
    isSystemAdmin: false,
    pageTitle,
  }),
}));

vi.mock('../../src/components/DashboardShell', () => ({
  default: ({ children, pageTitle }) => (
    <div>
      {pageTitle ? <h1>{pageTitle}</h1> : null}
      {children}
    </div>
  ),
}));

vi.mock('../../src/components/SEO.jsx', () => ({ default: () => null }));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'ws-1', selectWorkspace: vi.fn() }),
}));

vi.mock('../../src/utils/toast.js', () => ({
  showSuccess: showSuccessMock,
  showError: vi.fn(),
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsAvailability: useCertOpsAvailabilityMock,
  useCertOpsEnabled: () => true,
  useCertOpsIsWorkspaceAdmin: useCertOpsIsWorkspaceAdminMock,
  useCertOpsWorkspaceKillSwitch: () => ({
    certOpsPaused: false,
    certOpsEnabled: true,
    certOpsActive: true,
    loading: false,
    error: '',
    saving: false,
    setPaused: vi.fn(),
  }),
}));

vi.mock('../../src/components/certops/certopsEnrollmentsApi.js', () => ({
  listIssuers: listIssuersMock,
}));

vi.mock('../../src/components/certops/certopsAgentsApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsAgentsApi.js'
  );
  return {
    ...actual,
    listAgents: listAgentsMock,
  };
});

vi.mock('../../src/components/certops/certopsApi.js', async () => {
  const actual = await vi.importActual('../../src/components/certops/certopsApi.js');
  return {
    ...actual,
    listCertificates: listCertificatesMock,
    readdManagingSource: readdManagingSourceMock,
    stopManagingSource: stopManagingSourceMock,
    replaceManagingSource: replaceManagingSourceMock,
  };
});

vi.mock('../../src/pages/certops/CertOpsAdcs.jsx', () => ({
  default: () => <div>AD CS issuers</div>,
}));

vi.mock('../../src/components/certops/certopsRenewalApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsRenewalApi.js'
  );
  return {
    ...actual,
    listRenewalProfiles: listRenewalProfilesMock,
    updateRenewalProfile: updateRenewalProfileMock,
    createAdcsRenewalProfile: createAdcsRenewalProfileMock,
  };
});

async function openRenewalProfiles() {
  const header = await screen.findByRole('button', { name: /Renewal profiles/ });
  if (header.getAttribute('aria-expanded') !== 'true') {
    fireEvent.click(header);
  }
}

function renderPage(initialEntries = ['/certops/renewals']) {
  // The renewals tab renders inside the CertOps layout, which owns the
  // availability gate and the kill-switch banner, so the tests exercise it
  // through that layout rather than in isolation.
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <ChakraProvider>
        <DashboardThemeProvider>
          <Routes>
            <Route
              path='/certops'
              element={
                <CertOpsLayout session={{ user: { name: 'Test User' } }} />
              }
            >
              <Route path='renewals' element={<CertOpsRenewals />} />
            </Route>
          </Routes>
        </DashboardThemeProvider>
      </ChakraProvider>
    </MemoryRouter>
  );
}

function profile(overrides = {}) {
  return {
    id: 'profile-1',
    name: 'Derived: app.example.com',
    description: null,
    status: 'active',
    source: 'agent_issuance',
    autoRenewEnabled: true,
    renewBeforeDays: 30,
    keyMode: 'agent-local',
    renewalProfile: {
      keyAlgorithm: 'ecdsa',
      keySize: 256,
      dns: { provider: 'cloudflare', zone: 'example.com' },
      target: { certPath: '/etc/ssl/app.pem' },
    },
    derived: true,
    derivedFrom: { certificateId: 'cert-1' },
    certificateCount: 2,
    editableFields: [
      'sanPolicy',
      'keyAlgorithm',
      'keySize',
      'keyRotationPolicy',
      'verification',
      'preferredChain',
    ],
    createdAt: null,
    updatedAt: null,
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  useCertOpsAvailabilityMock.mockReturnValue({
    ready: true,
    enabled: true,
    error: '',
    retry: vi.fn(),
  });
  useCertOpsIsWorkspaceAdminMock.mockReturnValue(true);
  listRenewalProfilesMock.mockResolvedValue({
    items: [profile()],
    total: 1,
    limit: 50,
    offset: 0,
  });
  listIssuersMock.mockResolvedValue({ items: [] });
  listAgentsMock.mockResolvedValue({ items: [] });
  listCertificatesMock.mockResolvedValue({ items: [] });
  createAdcsRenewalProfileMock.mockResolvedValue({
    id: 'profile-new',
    agentDeclaresName: true,
  });
  readdManagingSourceMock.mockResolvedValue({ periodId: 'period-new' });
  stopManagingSourceMock.mockResolvedValue({});
  replaceManagingSourceMock.mockResolvedValue({ periodId: 'period-new' });
});

describe('CertOpsRenewals page', () => {
  it('starts with renewal profiles closed', async () => {
    renderPage();
    const header = await screen.findByRole('button', { name: /Renewal profiles/ });
    expect(header).toHaveAttribute('aria-expanded', 'false');
  });

  it('shows the renewal profiles', async () => {
    renderPage();
    await openRenewalProfiles();

    expect(await screen.findByText('Renewal profiles')).toBeInTheDocument();
    expect(screen.queryByText('Upcoming renewals')).not.toBeInTheDocument();
    expect(screen.queryByText(/Step 2/)).not.toBeInTheDocument();
    expect(screen.getByText(/ACME profiles appear after issuance/)).toBeInTheDocument();
    expect(screen.getByText('Derived: app.example.com')).toBeInTheDocument();
    const profiles = screen.getByRole('button', { name: /Renewal profiles/ });
    const issuers = screen.getByText('AD CS issuers');
    expect(
      profiles.compareDocumentPosition(issuers) & Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();
  });

  it('sorts renewal profiles on the server and resets the page', async () => {
    renderPage(['/certops/renewals?profileOffset=20']);
    await openRenewalProfiles();

    const profilesTable = await screen.findByRole('table');
    expect(
      within(profilesTable).getByRole('button', { name: 'Sort by Auto-renew' })
    ).toBeInTheDocument();
    fireEvent.click(
      within(profilesTable).getByRole('button', { name: 'Sort by Profile' })
    );
    await waitFor(() => {
      expect(listRenewalProfilesMock).toHaveBeenLastCalledWith(
        'ws-1',
        expect.objectContaining({
          offset: 0,
          sort: 'profile',
          direction: 'asc',
        })
      );
    });
  });

  it('requires confirmation before switching automatic renewal off', async () => {
    renderPage();
    await openRenewalProfiles();

    fireEvent.click(await screen.findByRole('button', { name: 'Switch off' }));

    expect(
      await screen.findByText('Switch automatic renewal off?')
    ).toBeInTheDocument();
    // The blast radius is stated, because one profile can cover many certs.
    expect(
      screen.getByText(
        '2 certificates using this profile will stop renewing automatically.'
      )
    ).toBeInTheDocument();
    expect(updateRenewalProfileMock).not.toHaveBeenCalled();
  });

  it('switches renewal off only after the operator confirms', async () => {
    updateRenewalProfileMock.mockResolvedValue(
      profile({ status: 'disabled', autoRenewEnabled: false })
    );

    renderPage();
    await openRenewalProfiles();

    fireEvent.click(await screen.findByRole('button', { name: 'Switch off' }));
    fireEvent.click(
      await screen.findByRole('button', { name: 'Switch renewal off' })
    );

    await waitFor(() => {
      expect(updateRenewalProfileMock).toHaveBeenCalledWith(
        'ws-1',
        'profile-1',
        {
          autoRenewEnabled: false,
        }
      );
    });
    expect(showSuccessMock).toHaveBeenCalledWith(
      'Automatic renewal switched off'
    );
  });

  it('switches renewal back on without a confirmation step', async () => {
    // Re-enabling is the safe direction, so it should not carry friction.
    listRenewalProfilesMock.mockResolvedValue({
      items: [profile({ status: 'disabled', autoRenewEnabled: false })],
      total: 1,
      limit: 50,
      offset: 0,
    });
    updateRenewalProfileMock.mockResolvedValue(profile());

    renderPage();
    await openRenewalProfiles();

    fireEvent.click(await screen.findByRole('button', { name: 'Switch on' }));

    await waitFor(() => {
      expect(updateRenewalProfileMock).toHaveBeenCalledWith(
        'ws-1',
        'profile-1',
        {
          autoRenewEnabled: true,
        }
      );
    });
  });

  it('hides every renewal control from a non-admin', async () => {
    // The API is admin-only, so showing the control to a manager would just
    // produce a 403 after they clicked it.
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(false);

    renderPage();
    await openRenewalProfiles();

    expect(await screen.findByText('Renewal profiles')).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Switch off' })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Change' })
    ).not.toBeInTheDocument();
    expect(
      screen.getByText('Only workspace admins can change renewal settings.')
    ).toBeInTheDocument();
  });

  it('saves a new renewal lead time', async () => {
    updateRenewalProfileMock.mockResolvedValue(
      profile({ renewBeforeDays: 45 })
    );

    renderPage();
    await openRenewalProfiles();

    fireEvent.click(await screen.findByRole('button', { name: 'Change' }));
    fireEvent.change(screen.getByLabelText('Renewal lead time in days'), {
      target: { value: '45' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(updateRenewalProfileMock).toHaveBeenCalledWith(
        'ws-1',
        'profile-1',
        {
          renewBeforeDays: 45,
        }
      );
    });
  });

  it('refuses to save a lead time the server would reject', async () => {
    renderPage();
    await openRenewalProfiles();

    fireEvent.click(await screen.findByRole('button', { name: 'Change' }));
    fireEvent.change(screen.getByLabelText('Renewal lead time in days'), {
      target: { value: '0' },
    });

    expect(
      screen.getByText('Enter a whole number of days between 1 and 365.')
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    expect(updateRenewalProfileMock).not.toHaveBeenCalled();
  });

  it('surfaces the immutable-field refusal with the field names the server named', async () => {
    // This is the one write failure an operator can act on, so it must not be
    // flattened into a generic error.
    updateRenewalProfileMock.mockRejectedValue({
      response: {
        data: {
          error:
            'These renewal-profile fields cannot be changed after issuance.',
          code: 'CERTOPS_PROFILE_FIELD_IMMUTABLE',
          fields: ['target'],
        },
      },
    });

    renderPage();
    await openRenewalProfiles();

    fireEvent.click(await screen.findByRole('button', { name: 'Switch off' }));
    fireEvent.click(
      await screen.findByRole('button', { name: 'Switch renewal off' })
    );

    expect(
      await screen.findByText(
        'These renewal-profile fields cannot be changed after issuance. (target)'
      )
    ).toBeInTheDocument();
    expect(showSuccessMock).not.toHaveBeenCalled();
  });

  it('does not offer renewal controls for an archived profile', async () => {
    listRenewalProfilesMock.mockResolvedValue({
      items: [profile({ status: 'archived', autoRenewEnabled: false })],
      total: 1,
      limit: 50,
      offset: 0,
    });

    renderPage();
    await openRenewalProfiles();

    // 'Archived' shows in both the status badge and the actions cell; what
    // matters is that no control is offered.
    expect(await screen.findAllByText('Archived')).not.toHaveLength(0);
    expect(
      screen.queryByRole('button', { name: 'Switch on' })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Change' })
    ).not.toBeInTheDocument();
  });

  it('explains an empty profile list instead of rendering a bare table', async () => {
    listRenewalProfilesMock.mockResolvedValue({
      items: [],
      total: 0,
      limit: 50,
      offset: 0,
    });

    renderPage();
    await openRenewalProfiles();

    expect(
      await screen.findByText('No renewal profiles yet.')
    ).toBeInTheDocument();
    expect(screen.queryByText('Upcoming renewals')).not.toBeInTheDocument();
  });

  it('surfaces a profile load failure rather than looking like an empty workspace', async () => {
    listRenewalProfilesMock.mockRejectedValue({
      response: { data: { error: 'Failed to list renewal profiles' } },
    });

    renderPage();
    await openRenewalProfiles();

    expect(
      await screen.findByText('Failed to list renewal profiles')
    ).toBeInTheDocument();
    expect(
      screen.queryByText('No renewal profiles yet.')
    ).not.toBeInTheDocument();
  });

  it('says a refused profile read was refused instead of showing an empty list', async () => {
    listRenewalProfilesMock.mockRejectedValue({ response: { status: 403 } });

    renderPage();
    await openRenewalProfiles();

    expect(
      await screen.findByText(
        'You do not have permission to view renewal automation for this workspace.'
      )
    ).toBeInTheDocument();
    expect(
      screen.queryByText('No renewal profiles yet.')
    ).not.toBeInTheDocument();
  });

  it('shows loading rather than an all-clear while a profile read is still in flight', async () => {
    listRenewalProfilesMock.mockReturnValue(new Promise(() => {}));

    renderPage();
    await openRenewalProfiles();

    expect(
      await screen.findByText('Loading renewal profiles...')
    ).toBeInTheDocument();
    expect(
      screen.queryByText('No renewal profiles yet.')
    ).not.toBeInTheDocument();
  });

  it('reads renewal profiles for a non-admin, leaving the write refusal to the server', async () => {
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(false);

    renderPage();
    await openRenewalProfiles();

    expect(
      await screen.findByText('Derived: app.example.com')
    ).toBeInTheDocument();
    expect(listRenewalProfilesMock).toHaveBeenCalled();
  });

  it('does not render renewal data when CertOps is disabled for the workspace', async () => {
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: false,
      error: '',
      retry: vi.fn(),
    });

    renderPage();

    expect(
      await screen.findByText('Certificate operations are not enabled')
    ).toBeInTheDocument();
    expect(screen.queryByText('Renewal profiles')).not.toBeInTheDocument();
  });

  it('gives the profile list a page control when more rows exist', async () => {
    listRenewalProfilesMock.mockResolvedValue({
      items: [profile()],
      total: 42,
      limit: 20,
      offset: 0,
    });

    renderPage();
    await openRenewalProfiles();

    expect(
      await screen.findByRole('navigation', {
        name: 'renewal profiles pagination',
      })
    ).toBeInTheDocument();
    expect(
      screen.getByText('Showing 1 to 20 of 42 renewal profiles')
    ).toBeInTheDocument();
    expect(
      screen.queryByRole('navigation', { name: 'certificates pagination' })
    ).not.toBeInTheDocument();
  });

  it('restores the profile page position from the URL on load', async () => {
    listRenewalProfilesMock.mockResolvedValue({
      items: [profile()],
      total: 42,
      limit: 20,
      offset: 20,
    });

    renderPage(['/certops/renewals?profileOffset=20']);
    await openRenewalProfiles();

    await waitFor(() => {
      expect(listRenewalProfilesMock).toHaveBeenLastCalledWith(
        'ws-1',
        expect.objectContaining({ limit: 20, offset: 20 })
      );
    });
  });

  it('offers a way back rather than an empty state when a shared link points past the end', async () => {
    listRenewalProfilesMock.mockResolvedValue({
      items: [],
      total: 3,
      limit: 20,
      offset: 200,
    });

    renderPage(['/certops/renewals?profileOffset=200']);
    await openRenewalProfiles();

    expect(
      await screen.findByText('This page is past the end of the list.')
    ).toBeInTheDocument();
    expect(
      screen.queryByText('No renewal profiles yet.')
    ).not.toBeInTheDocument();
  });

  it('lists certificate names from the profile when inventory does not', async () => {
    listRenewalProfilesMock.mockResolvedValue({
      items: [
        profile({
          certificateCount: 2,
          certificates: [
            {
              id: '11111111-1111-4111-8111-111111111111',
              commonName: 'one.example.com',
            },
            {
              id: '22222222-2222-4222-8222-222222222222',
              commonName: 'two.example.com',
            },
          ],
        }),
      ],
      total: 1,
      limit: 50,
      offset: 0,
    });
    renderPage();
    await openRenewalProfiles();
    fireEvent.click(await screen.findByRole('button', { name: 'Details' }));
    expect(await screen.findByRole('link', { name: 'one.example.com' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'two.example.com' })).toBeInTheDocument();
  });

  async function walkToAttach(dnsName = 'www.example.com') {
    listIssuersMock.mockResolvedValue({
      items: [
        {
          id: 'issuer-1',
          kind: 'adcs',
          name: 'TTLab Issuing CA',
          currentVersion: 1,
          revalidationRequired: false,
        },
      ],
    });
    renderPage();
    await openRenewalProfiles();
    fireEvent.click(await screen.findByRole('button', { name: 'New AD CS profile' }));
    expect(await screen.findByRole('option', { name: 'TTLab Issuing CA' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Profile name'), {
      target: { value: 'Web profile' },
    });
    fireEvent.change(screen.getByLabelText('AD CS issuer'), {
      target: { value: 'issuer-1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    fireEvent.change(screen.getByLabelText('Certificate name'), {
      target: { value: dnsName },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Review' }));
    fireEvent.click(screen.getByRole('button', { name: 'Create profile' }));
    expect(await screen.findByText('4. Attach')).toBeInTheDocument();
  }

  it('says where to attach later when no certificate uses the DNS name', async () => {
    listCertificatesMock.mockResolvedValue({
      items: [{ id: 'other', commonName: 'mail.example.com', name: 'mail.example.com' }],
    });

    await walkToAttach();

    expect(
      await screen.findByText(/No certificate in inventory uses www.example.com/)
    ).toBeInTheDocument();
    expect(screen.getByText(/Open Certificates later/)).toBeInTheDocument();
    expect(screen.getByText(/inside the 30 day lead time/)).toBeInTheDocument();
    expect(readdManagingSourceMock).not.toHaveBeenCalled();
    expect(stopManagingSourceMock).not.toHaveBeenCalled();
  });

  it('attaches a stopped certificate with automation enabled', async () => {
    listCertificatesMock.mockResolvedValue({
      items: [
        {
          id: 'identity-1',
          identityId: 'identity-1',
          commonName: 'www.example.com',
          name: 'www.example.com',
          managed: false,
          sources: [
            {
              periodId: 'period-1',
              managedCertificateId: 'mc-1',
              source: 'agent_windows',
              startedAt: '2026-01-01T00:00:00Z',
              periodEndedAt: '2026-02-01T00:00:00Z',
              endedReason: null,
            },
          ],
        },
      ],
    });

    await walkToAttach();
    fireEvent.click(
      await screen.findByRole('button', { name: 'Attach and enable automation' })
    );

    await waitFor(() => {
      expect(replaceManagingSourceMock).toHaveBeenCalledWith('ws-1', 'mc-1', {
        periodId: null,
        renewalProfileId: 'profile-new',
        automationEnabled: true,
      });
    });
    expect(readdManagingSourceMock).not.toHaveBeenCalled();
    expect(stopManagingSourceMock).not.toHaveBeenCalled();
    expect(
      await screen.findByText(/Automatic renewal is on/)
    ).toBeInTheDocument();
    expect(
      screen.getByText(/declares www.example.com has passed the CA check/)
    ).toBeInTheDocument();
  });

  it('stops an open period before attaching the profile', async () => {
    listCertificatesMock.mockResolvedValue({
      items: [
        {
          id: 'mc-1',
          identityId: 'identity-1',
          commonName: 'www.example.com',
          name: 'www.example.com',
          managed: true,
          managedCertificateId: 'mc-1',
          sources: [
            {
              periodId: 'period-open',
              managedCertificateId: 'mc-1',
              source: 'agent_windows',
              startedAt: '2026-01-01T00:00:00Z',
              periodEndedAt: null,
              endedReason: null,
            },
          ],
        },
      ],
    });

    await walkToAttach();
    expect(
      await screen.findByText(/stops that period and starts a new one/)
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Attach and enable automation' }));

    await waitFor(() => {
      expect(replaceManagingSourceMock).toHaveBeenCalledWith('ws-1', 'mc-1', {
        periodId: 'period-open',
        renewalProfileId: 'profile-new',
        automationEnabled: true,
      });
    });
    expect(stopManagingSourceMock).not.toHaveBeenCalled();
    expect(readdManagingSourceMock).not.toHaveBeenCalled();
  });
});
