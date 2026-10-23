import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({
  admin: { status: 'ready', isAdmin: true, retry: () => {} },
  outlet: { killSwitchResolved: true, certOpsPaused: false },
  wizardProps: null,
}));

vi.mock('react-router', async importOriginal => ({
  ...(await importOriginal()),
  useOutletContext: () => h.outlet,
}));
vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsWorkspaceAdminState: () => h.admin,
}));
vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'ws-1' }),
}));
vi.mock('../../src/utils/toast.js', () => ({
  showError: vi.fn(),
  showSuccess: vi.fn(),
}));
vi.mock('../../src/components/certops/certopsAgentsApi', () => ({
  listAgents: async () => ({ items: [{ id: 'agent-row', name: 'win-01' }] }),
}));
vi.mock('../../src/components/certops/certopsEnrollmentsApi', () => ({
  abandonEnrollment: vi.fn(),
  cancelEnrollment: vi.fn(),
  confirmIssuerKey: vi.fn(),
  dispatchIssuerPreflight: vi.fn(),
  enrollmentStateLabel: s => s,
  listEnrollments: async () => ({ items: [], pagination: { total: 0 } }),
  listIssuers: async () => ({ items: [], pagination: { total: 0 } }),
  proposeEnrollmentRequestId: vi.fn(),
}));
vi.mock('../../src/components/certops/AdcsIssuerWizard.jsx', () => ({
  default: props => {
    h.wizardProps = props;
    return props.isOpen ? <div role='dialog'>New AD CS issuer</div> : null;
  },
}));

import CertOpsAdcs from '../../src/pages/certops/CertOpsAdcs.jsx';
import CertOpsRenewals from '../../src/pages/certops/CertOpsRenewals.jsx';

vi.mock('../../src/components/certops/RenewalProfilesPanel.jsx', () => ({
  default: () => null,
}));

const AGENT = '3f2b9c1e-5d4a-4b7e-8c21-0a9d8e7f6b5c';

function Where() {
  const { search } = useLocation();
  return <div data-testid='search'>{search}</div>;
}

function renderRenewals(url) {
  return render(
    <MemoryRouter initialEntries={[url]}>
      <ChakraProvider>
        <DashboardThemeProvider>
          <Routes>
            <Route
              path='/certops/renewals'
              element={
                <>
                  <CertOpsRenewals />
                  <Where />
                </>
              }
            />
          </Routes>
        </DashboardThemeProvider>
      </ChakraProvider>
    </MemoryRouter>
  );
}

const search = () => screen.getByTestId('search').textContent;

beforeEach(() => {
  h.admin = { status: 'ready', isAdmin: true, retry: () => {} };
  h.outlet = { killSwitchResolved: true, certOpsPaused: false };
  h.wizardProps = null;
});

describe('New AD CS issuer deep link', () => {
  it('opens the section and the dialog, then clears the request', async () => {
    renderRenewals(
      `/certops/renewals?workspace=ws-1&action=new-adcs-issuer&agentId=${AGENT}&template=WebServer`
    );
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    expect(h.wizardProps).toMatchObject({
      isOpen: true,
      initialAgentId: AGENT,
      initialTemplate: 'WebServer',
    });
    await waitFor(() => expect(search()).toBe('?workspace=ws-1'));
  });

  it('opens the section for a re-check link without the new issuer dialog, then clears it', async () => {
    renderRenewals(
      `/certops/renewals?workspace=ws-1&action=check-adcs-issuer&issuerId=${AGENT}`
    );
    expect(await screen.findByText('No issuers yet.')).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).toBeNull();
    await waitFor(() => expect(search()).toBe('?workspace=ws-1'));
  });

  it('does nothing without the action', async () => {
    renderRenewals('/certops/renewals?workspace=ws-1');
    await screen.findByRole('button', { name: /AD CS issuers/ });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(search()).toBe('?workspace=ws-1');
  });

  it('shows the admin-only state instead of the dialog for a non-admin', async () => {
    h.admin = { status: 'ready', isAdmin: false, retry: () => {} };
    renderRenewals('/certops/renewals?workspace=ws-1&action=new-adcs-issuer');
    expect(
      await screen.findByText(/limited to workspace admins/)
    ).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).toBeNull();
    await waitFor(() => expect(search()).toBe('?workspace=ws-1'));
  });

  it('does not open the dialog while certificate operations are paused', async () => {
    h.outlet = { killSwitchResolved: true, certOpsPaused: true };
    renderRenewals('/certops/renewals?workspace=ws-1&action=new-adcs-issuer');
    await waitFor(() => expect(search()).toBe('?workspace=ws-1'));
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('waits for the pause state before deciding', async () => {
    h.outlet = { killSwitchResolved: false, certOpsPaused: false };
    renderRenewals('/certops/renewals?workspace=ws-1&action=new-adcs-issuer');
    await screen.findByRole('button', { name: /AD CS issuers/ });
    expect(search()).toContain('action=new-adcs-issuer');
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('opens again when the page is already showing and a new link arrives', async () => {
    h.outlet = { killSwitchResolved: true, certOpsPaused: false };
    const { rerender } = render(
      <MemoryRouter initialEntries={['/x']}>
        <ChakraProvider>
          <DashboardThemeProvider>
            <CertOpsAdcs />
          </DashboardThemeProvider>
        </ChakraProvider>
      </MemoryRouter>
    );
    await waitFor(() => expect(h.wizardProps).not.toBeNull());
    expect(h.wizardProps.isOpen).toBe(false);
    const handled = vi.fn();
    rerender(
      <MemoryRouter initialEntries={['/x']}>
        <ChakraProvider>
          <DashboardThemeProvider>
            <CertOpsAdcs
              openRequest={{ agentId: '', caConfig: '', template: '' }}
              onRequestHandled={handled}
            />
          </DashboardThemeProvider>
        </ChakraProvider>
      </MemoryRouter>
    );
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    expect(handled).toHaveBeenCalled();
  });
});
