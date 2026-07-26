import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import CertOpsRenewals from '../../src/pages/certops/CertOpsRenewals.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const {
  useCertOpsAvailabilityMock,
  useCertOpsIsWorkspaceAdminMock,
  listRenewalProfilesMock,
  listUpcomingRenewalsMock,
  updateRenewalProfileMock,
  showSuccessMock,
} = vi.hoisted(() => ({
  useCertOpsAvailabilityMock: vi.fn(),
  useCertOpsIsWorkspaceAdminMock: vi.fn(),
  listRenewalProfilesMock: vi.fn(),
  listUpcomingRenewalsMock: vi.fn(),
  updateRenewalProfileMock: vi.fn(),
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
}));

vi.mock('../../src/components/certops/certopsRenewalApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsRenewalApi.js'
  );
  return {
    ...actual,
    listRenewalProfiles: listRenewalProfilesMock,
    listUpcomingRenewals: listUpcomingRenewalsMock,
    updateRenewalProfile: updateRenewalProfileMock,
  };
});

function renderPage() {
  return render(
    <MemoryRouter>
      <ChakraProvider>
        <DashboardThemeProvider>
          <CertOpsRenewals session={{ user: { name: 'Test User' } }} />
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

function upcoming(overrides = {}) {
  return {
    certificateId: 'cert-1',
    commonName: 'app.example.com',
    notAfter: new Date(Date.now() + 20 * 86400000).toISOString(),
    renewsFrom: new Date(Date.now() - 2 * 86400000).toISOString(),
    profileId: 'profile-1',
    profileName: 'Derived: app.example.com',
    autoRenewEnabled: true,
    renewBeforeDays: 30,
    lastRenewJobStatus: 'succeeded',
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
  listUpcomingRenewalsMock.mockResolvedValue({
    items: [upcoming()],
    total: 1,
    limit: 50,
    offset: 0,
  });
});

describe('CertOpsRenewals page', () => {
  it('shows the renewal schedule and the profiles that drive it', async () => {
    renderPage();

    expect(await screen.findByText('Upcoming renewals')).toBeInTheDocument();
    expect(await screen.findByText('Renewal profiles')).toBeInTheDocument();
    // The profile name appears in both panels by design (schedule row subtitle
    // and profile row title), so assert on the count rather than uniqueness.
    expect(
      await screen.findAllByText('Derived: app.example.com')
    ).toHaveLength(2);
    expect(await screen.findByText('app.example.com')).toBeInTheDocument();
  });

  it('says a certificate is already in its renewal window rather than showing a past date', async () => {
    // A renewsFrom in the past means the scheduler is acting on it now. Showing
    // a stale date would read as "nothing happening until then".
    renderPage();

    expect(await screen.findByText('Due now')).toBeInTheDocument();
  });

  it('warns when a listed certificate will not renew automatically', async () => {
    // The failure this page exists to prevent: a certificate counting down to
    // expiry with renewal quietly switched off.
    listUpcomingRenewalsMock.mockResolvedValue({
      items: [upcoming({ autoRenewEnabled: false })],
      total: 1,
      limit: 50,
      offset: 0,
    });

    renderPage();

    expect(
      await screen.findByText(
        '1 certificate below will not renew automatically and will expire unless it is renewed by hand.'
      )
    ).toBeInTheDocument();
  });

  it('reports a certificate that has never been renewed instead of leaving the cell blank', async () => {
    listUpcomingRenewalsMock.mockResolvedValue({
      items: [upcoming({ lastRenewJobStatus: null })],
      total: 1,
      limit: 50,
      offset: 0,
    });

    renderPage();

    expect(await screen.findByText('Never renewed')).toBeInTheDocument();
  });

  it('requires confirmation before switching automatic renewal off', async () => {
    renderPage();

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

    fireEvent.click(await screen.findByRole('button', { name: 'Switch off' }));
    fireEvent.click(
      await screen.findByRole('button', { name: 'Switch renewal off' })
    );

    await waitFor(() => {
      expect(updateRenewalProfileMock).toHaveBeenCalledWith('ws-1', 'profile-1', {
        autoRenewEnabled: false,
      });
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

    fireEvent.click(await screen.findByRole('button', { name: 'Switch on' }));

    await waitFor(() => {
      expect(updateRenewalProfileMock).toHaveBeenCalledWith('ws-1', 'profile-1', {
        autoRenewEnabled: true,
      });
    });
  });

  it('hides every renewal control from a non-admin', async () => {
    // The API is admin-only, so showing the control to a manager would just
    // produce a 403 after they clicked it.
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(false);

    renderPage();

    expect(await screen.findByText('Renewal profiles')).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Switch off' })
    ).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Change' })).not.toBeInTheDocument();
    expect(
      screen.getByText('Only workspace admins can change renewal settings.')
    ).toBeInTheDocument();
  });

  it('saves a new renewal lead time', async () => {
    updateRenewalProfileMock.mockResolvedValue(profile({ renewBeforeDays: 45 }));

    renderPage();

    fireEvent.click(await screen.findByRole('button', { name: 'Change' }));
    fireEvent.change(
      screen.getByLabelText('Renewal lead time in days'),
      { target: { value: '45' } }
    );
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(updateRenewalProfileMock).toHaveBeenCalledWith('ws-1', 'profile-1', {
        renewBeforeDays: 45,
      });
    });
  });

  it("refuses to save a lead time the server would reject", async () => {
    renderPage();

    fireEvent.click(await screen.findByRole('button', { name: 'Change' }));
    fireEvent.change(
      screen.getByLabelText('Renewal lead time in days'),
      { target: { value: '0' } }
    );

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
          error: 'These renewal-profile fields cannot be changed after issuance.',
          code: 'CERTOPS_PROFILE_FIELD_IMMUTABLE',
          fields: ['target'],
        },
      },
    });

    renderPage();

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
      items: [
        profile({ status: 'archived', autoRenewEnabled: false }),
      ],
      total: 1,
      limit: 50,
      offset: 0,
    });

    renderPage();

    // 'Archived' shows in both the status badge and the actions cell; what
    // matters is that no control is offered.
    expect(await screen.findAllByText('Archived')).not.toHaveLength(0);
    expect(
      screen.queryByRole('button', { name: 'Switch on' })
    ).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Change' })).not.toBeInTheDocument();
  });

  it('explains an empty schedule instead of rendering a bare table', async () => {
    listRenewalProfilesMock.mockResolvedValue({
      items: [],
      total: 0,
      limit: 50,
      offset: 0,
    });
    listUpcomingRenewalsMock.mockResolvedValue({
      items: [],
      total: 0,
      limit: 50,
      offset: 0,
    });

    renderPage();

    expect(
      await screen.findByText('Nothing scheduled to renew.')
    ).toBeInTheDocument();
    expect(
      await screen.findByText('No renewal profiles yet.')
    ).toBeInTheDocument();
  });

  it('surfaces a load failure rather than looking like an empty workspace', async () => {
    listUpcomingRenewalsMock.mockRejectedValue({
      response: { data: { error: 'Failed to list upcoming renewals' } },
    });

    renderPage();

    expect(
      await screen.findByText('Failed to list upcoming renewals')
    ).toBeInTheDocument();
    // The all-clear message must not accompany a failed read.
    expect(
      screen.queryByText('Nothing scheduled to renew.')
    ).not.toBeInTheDocument();
  });

  it('says a refused read was refused instead of showing an empty schedule', async () => {
    // A 403 carries no body worth showing, so without special handling it would
    // degrade into "nothing scheduled to renew" and read as all-clear.
    listUpcomingRenewalsMock.mockRejectedValue({ response: { status: 403 } });
    listRenewalProfilesMock.mockRejectedValue({ response: { status: 403 } });

    renderPage();

    expect(
      await screen.findAllByText(
        'You do not have permission to view renewal automation for this workspace.'
      )
    ).toHaveLength(2);
    expect(
      screen.queryByText('Nothing scheduled to renew.')
    ).not.toBeInTheDocument();
    expect(screen.queryByText('No renewal profiles yet.')).not.toBeInTheDocument();
  });

  it('shows loading rather than an all-clear while a read is still in flight', async () => {
    // The regression this guards: an unresolved read rendering the empty state
    // makes a workspace full of expiring certificates look safe.
    listUpcomingRenewalsMock.mockReturnValue(new Promise(() => {}));
    listRenewalProfilesMock.mockReturnValue(new Promise(() => {}));

    renderPage();

    expect(
      await screen.findByText('Loading renewal schedule...')
    ).toBeInTheDocument();
    expect(
      screen.queryByText('Nothing scheduled to renew.')
    ).not.toBeInTheDocument();
    expect(screen.queryByText('No renewal profiles yet.')).not.toBeInTheDocument();
  });

  it('reads the schedule for a manager, leaving the write refusal to the server', async () => {
    // Reads are not gated client-side: a role lookup that has not resolved or
    // has failed must not be able to hide an expiring certificate.
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(false);

    renderPage();

    expect(await screen.findByText('app.example.com')).toBeInTheDocument();
    expect(listUpcomingRenewalsMock).toHaveBeenCalled();
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
      await screen.findByText('Certificate operations is not enabled')
    ).toBeInTheDocument();
    expect(screen.queryByText('Renewal profiles')).not.toBeInTheDocument();
  });
});
