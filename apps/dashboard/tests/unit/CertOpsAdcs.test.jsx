import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import CertOpsAdcs from '../../src/pages/certops/CertOpsAdcs.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const {
  isAdminMock,
  listIssuersMock,
  listEnrollmentsMock,
  listAgentsMock,
  createIssuerMock,
  dispatchIssuerPreflightMock,
  discardIssuerMock,
  proposeEnrollmentRequestIdMock,
  confirmIssuerKeyMock,
  showSuccessMock,
} = vi.hoisted(() => ({
  isAdminMock: vi.fn(),
  listIssuersMock: vi.fn(),
  listEnrollmentsMock: vi.fn(),
  listAgentsMock: vi.fn(),
  createIssuerMock: vi.fn(),
  dispatchIssuerPreflightMock: vi.fn(),
  discardIssuerMock: vi.fn(),
  proposeEnrollmentRequestIdMock: vi.fn(),
  confirmIssuerKeyMock: vi.fn(),
  showSuccessMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'ws-1', selectWorkspace: vi.fn() }),
}));

vi.mock('../../src/utils/toast.js', () => ({
  showSuccess: showSuccessMock,
  showError: vi.fn(),
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsIsWorkspaceAdmin: isAdminMock,
  useCertOpsWorkspaceAdminState: () => ({
    status: 'ready',
    isAdmin: isAdminMock(),
    retry: vi.fn(),
  }),
}));

vi.mock('../../src/components/certops/certopsAgentsApi.js', () => ({
  listAgents: listAgentsMock,
}));

vi.mock('../../src/components/certops/certopsEnrollmentsApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsEnrollmentsApi.js'
  );
  return {
    ...actual,
    listIssuers: listIssuersMock,
    listEnrollments: listEnrollmentsMock,
    listAgents: listAgentsMock,
    createIssuer: createIssuerMock,
    discardIssuer: discardIssuerMock,
    dispatchIssuerPreflight: dispatchIssuerPreflightMock,
    proposeEnrollmentRequestId: proposeEnrollmentRequestIdMock,
    confirmIssuerKey: confirmIssuerKeyMock,
  };
});

const KEY = 'ab'.repeat(32);

function renderPage() {
  return render(
    <MemoryRouter>
      <ChakraProvider>
        <DashboardThemeProvider>
          <CertOpsAdcs />
        </DashboardThemeProvider>
      </ChakraProvider>
    </MemoryRouter>
  );
}

function issuer(overrides = {}) {
  return {
    id: 'issuer-1',
    kind: 'adcs',
    name: 'Issuing CA',
    currentVersion: 2,
    revalidationRequired: true,
    lastPreflight: {
      caConfig: 'ca01.corp.example.com\\Corp Issuing CA 01',
      template: 'TokenTimerWebServer',
      templateCheck: { verdict: 'safe' },
      caCheck: { verdict: 'unsafe' },
      caCertificates: [
        {
          keySha256: KEY,
          thumbprintSha1: 'AABBCCDDEEFF00112233445566778899AABBCCDD',
        },
      ],
    },
    ...overrides,
  };
}

beforeEach(() => {
  isAdminMock.mockReset();
  listIssuersMock.mockReset();
  listEnrollmentsMock.mockReset();
  listAgentsMock.mockReset();
  createIssuerMock.mockReset();
  dispatchIssuerPreflightMock.mockReset();
  discardIssuerMock.mockReset();
  proposeEnrollmentRequestIdMock.mockReset();
  confirmIssuerKeyMock.mockReset();
  confirmIssuerKeyMock.mockResolvedValue({});
  showSuccessMock.mockReset();
  listAgentsMock.mockResolvedValue({ items: [] });
  listIssuersMock.mockResolvedValue({ items: [] });
  listEnrollmentsMock.mockResolvedValue({ items: [] });
});

describe('CertOpsAdcs', () => {
  it('hides issuer management from a non-admin', () => {
    isAdminMock.mockReturnValue(false);

    renderPage();

    expect(
      screen.getByText('AD CS issuer management is limited to workspace admins')
    ).toBeInTheDocument();
    expect(listIssuersMock).not.toHaveBeenCalled();
  });

  it('shows approval, an uncertain RequestId, and a stale CA-key notice', async () => {
    isAdminMock.mockReturnValue(true);
    listIssuersMock.mockResolvedValue({ items: [issuer()] });
    listEnrollmentsMock.mockResolvedValue({
      items: [
        {
          id: 'enr-1',
          state: 'pending_issuance',
          caConfig: 'ca01.corp.example.com\\Corp Issuing CA 01',
          template: 'TokenTimerWebServer',
          requestId: 42,
          caKeySha256: KEY,
          snapshotStale: true,
          issuerVersion: 1,
          issuerCurrentVersion: 2,
          revalidationRequired: true,
          lastErrorCode: 'ADCS_CA_KEY_CHANGED',
        },
        {
          id: 'enr-requested',
          state: 'requested',
          caConfig: 'ca01.corp.example.com\\Corp Issuing CA 01',
          template: 'TokenTimerWebServer',
          jobStatus: 'failed',
          jobErrorMessage: 'helper binary is not installed',
        },
        {
          id: 'enr-cancelled',
          state: 'cancelled',
          caConfig: 'ca01.corp.example.com\\Corp Issuing CA 01',
          template: 'TokenTimerWebServer',
        },
        {
          id: 'enr-2',
          state: 'submission_uncertain',
          caConfig: 'ca01.corp.example.com\\Corp Issuing CA 01',
          template: 'TokenTimerWebServer',
          requestId: null,
          caKeySha256: KEY,
          snapshotStale: false,
          revalidationRequired: false,
        },
      ],
    });

    renderPage();

    expect(await screen.findByText('Awaiting CA approval')).toBeInTheDocument();
    expect(screen.getByText(/RequestId\s+42/)).toBeInTheDocument();
    expect(
      screen.getByText(/^CA ca01\.corp\.example\.com\\Corp Issuing CA 01 · RequestId\s+42/),
    ).toBeInTheDocument();
    expect(screen.getAllByText(/key prefix abababababab/)).toHaveLength(2);
    expect(screen.getByText(/stays on issuer version 1/)).toBeInTheDocument();
    expect(screen.queryByText(/Cancel and re-enroll/)).not.toBeInTheDocument();
    expect(screen.getAllByText(/CA key changed/).length).toBeGreaterThan(0);
    expect(screen.getByText('Submission uncertain')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /Reconcile/ })
    ).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /Use this certificate/ })
    ).not.toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /Abandon/ })).toHaveLength(1);
    // Not started and install-failed rows are visible by default.
    expect(screen.getByText(/14-day limit has not started/)).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /Cancel enrollment/ })
    ).toBeInTheDocument();
    expect(screen.getByText(/helper binary is not installed/)).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: /Show not started or install failed \(1\)/,
      })
    );
    expect(screen.queryByText(/14-day limit has not started/)).not.toBeInTheDocument();
    expect(screen.queryByText('Cancelled')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('checkbox', { name: /Show finished \(1\)/ }));
    expect(screen.getByText('Cancelled')).toBeInTheDocument();
    expect(screen.queryByText(/MIIB/)).not.toBeInTheDocument();
  });

  it('offers key confirmation only after a safe preflight', async () => {
    isAdminMock.mockReturnValue(true);
    listIssuersMock.mockResolvedValue({
      items: [
        issuer({
          lastPreflight: {
            ...issuer().lastPreflight,
            caCheck: { verdict: 'safe' },
          },
        }),
      ],
    });

    renderPage();

    expect(
      await screen.findByRole('button', {
        name: /Use this certificate abababababab/,
      })
    ).toBeInTheDocument();
  });

  it('does not create an issuer until the CA check starts', async () => {
    isAdminMock.mockReturnValue(true);
    createIssuerMock.mockResolvedValue({ issuer: { id: 'issuer-2' } });

    renderPage();
    await screen.findByText(/No enrollments yet/);
    fireEvent.click(screen.getByRole('button', { name: 'New issuer' }));
    fireEvent.change(screen.getByLabelText('Issuer name'), {
      target: { value: 'Corp CA' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));

    expect(createIssuerMock).not.toHaveBeenCalled();
    expect(discardIssuerMock).not.toHaveBeenCalled();
    expect(screen.getByLabelText('CA config')).toBeInTheDocument();
    expect(screen.getByText(/Template name, not the display name/)).toBeInTheDocument();
    expect(
      screen.getByRole('link', { name: 'Where the template name comes from' })
    ).toHaveAttribute('href', expect.stringContaining('#certificate-template'));
  });

  it('discards the draft when the wizard closes before confirm', async () => {
    isAdminMock.mockReturnValue(true);
    listAgentsMock.mockResolvedValue({
      items: [{ id: 'agent-1', name: 'member-1' }],
    });
    createIssuerMock.mockResolvedValue({ issuer: { id: 'issuer-draft' } });
    dispatchIssuerPreflightMock.mockResolvedValue({ job: { id: 'job-1' } });
    discardIssuerMock.mockResolvedValue(undefined);

    renderPage();
    await screen.findByText(/No enrollments yet/);
    fireEvent.click(screen.getByRole('button', { name: 'New issuer' }));
    fireEvent.change(screen.getByLabelText('Issuer name'), {
      target: { value: 'Corp CA' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    fireEvent.change(screen.getByLabelText('Preflight agent'), {
      target: { value: 'agent-1' },
    });
    fireEvent.change(screen.getByLabelText('CA config'), {
      target: { value: 'ca01.example.com\\Corp CA' },
    });
    fireEvent.change(screen.getByLabelText('Template'), {
      target: { value: 'WebServer' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Run check' }));
    await waitFor(() => expect(createIssuerMock).toHaveBeenCalled());
    const closeButtons = screen.getAllByRole('button', { name: 'Close' });
    fireEvent.click(closeButtons.find((button) => button.textContent === 'Close'));
    await waitFor(() =>
      expect(discardIssuerMock).toHaveBeenCalledWith('ws-1', 'issuer-draft')
    );
  });

  it('hides an AD CS issuer that has no chosen certificate', async () => {
    isAdminMock.mockReturnValue(true);
    listIssuersMock.mockResolvedValue({
      items: [issuer({ currentVersion: 0, name: 'Draft CA' }), issuer()],
    });

    renderPage();

    expect(await screen.findByText('Issuing CA')).toBeInTheDocument();
    expect(screen.queryByText('Draft CA')).not.toBeInTheDocument();
  });

  it('keeps asking for a preflight verdict after dispatch', async () => {
    isAdminMock.mockReturnValue(true);
    listAgentsMock.mockResolvedValue({
      items: [{ id: 'agent-1', name: 'member-1' }],
    });
    listIssuersMock.mockResolvedValue({ items: [issuer()] });
    dispatchIssuerPreflightMock.mockResolvedValue({ job: { id: 'job-1' } });

    renderPage();
    await screen.findByRole('button', { name: /Run check for Issuing CA/ });
    expect(screen.queryByLabelText('CA config for Issuing CA')).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Agent for Issuing CA'), {
      target: { value: 'agent-1' },
    });
    fireEvent.submit(
      screen.getByRole('button', { name: /Run check for Issuing CA/ }).closest('form')
    );

    await waitFor(() => expect(dispatchIssuerPreflightMock).toHaveBeenCalled());
    expect(dispatchIssuerPreflightMock).toHaveBeenCalledWith(
      'ws-1',
      'issuer-1',
      expect.objectContaining({
        agentId: 'agent-1',
        caConfig: 'ca01.corp.example.com\\Corp Issuing CA 01',
        template: 'TokenTimerWebServer',
      })
    );
    expect(
      await screen.findByText(
        /Waiting for Issuing CA to report the preflight verdict/
      )
    ).toBeInTheDocument();
  });

  it('does not offer a new CA or template on a confirmed issuer', async () => {
    isAdminMock.mockReturnValue(true);
    listIssuersMock.mockResolvedValue({
      items: [
        issuer({
          revalidationRequired: false,
          caConfig: 'ca01.corp.example.com\\Corp Issuing CA 01',
          template: 'TokenTimerWebServer',
        }),
      ],
    });

    renderPage();

    expect(await screen.findByText(/A different pair is a new issuer/)).toBeInTheDocument();
    expect(screen.queryByLabelText('Agent for Issuing CA')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Check again' }));
    expect(screen.getByLabelText('Agent for Issuing CA')).toBeInTheDocument();
    expect(screen.queryByLabelText('CA config for Issuing CA')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Use this certificate/ })).not.toBeInTheDocument();
  });

  it('points at New AD CS profile after the CA certificate is pinned', async () => {
    isAdminMock.mockReturnValue(true);
    listAgentsMock.mockResolvedValue({
      items: [{ id: 'agent-1', name: 'member-1' }],
    });
    createIssuerMock.mockResolvedValue({ issuer: { id: 'issuer-new' } });
    dispatchIssuerPreflightMock.mockResolvedValue({ job: { id: 'job-1' } });
    listIssuersMock.mockResolvedValue({
      items: [
        issuer({
          id: 'issuer-new',
          name: 'Corp CA',
          currentVersion: 0,
          lastPreflight: {
            ...issuer().lastPreflight,
            caCheck: { verdict: 'safe' },
            templateCheck: { verdict: 'safe' },
          },
        }),
      ],
    });

    renderPage();
    await screen.findByText(/No enrollments yet/);
    fireEvent.click(screen.getByRole('button', { name: 'New issuer' }));
    fireEvent.change(screen.getByLabelText('Issuer name'), {
      target: { value: 'Corp CA' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    fireEvent.change(screen.getByLabelText('Preflight agent'), {
      target: { value: 'agent-1' },
    });
    fireEvent.change(screen.getByLabelText('CA config'), {
      target: { value: 'ca01.corp.example.com\\Corp Issuing CA' },
    });
    fireEvent.change(screen.getByLabelText('Template'), {
      target: { value: 'WebServer' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Run check' }));

    fireEvent.click(
      await screen.findByRole(
        'button',
        { name: 'Use this certificate' },
        { timeout: 5000 }
      )
    );

    expect(confirmIssuerKeyMock).toHaveBeenCalledWith(
      'ws-1',
      'issuer-new',
      expect.objectContaining({ caKeySha256: KEY })
    );
    expect(await screen.findByText(/New AD CS profile/)).toBeInTheDocument();
    expect(
      screen.getByText(/attaches the profile to a certificate already in inventory/)
    ).toBeInTheDocument();
  });

  it('loads the next page of issuers past the first 100', async () => {
    isAdminMock.mockReturnValue(true);
    const firstPage = Array.from({ length: 100 }, (_, index) =>
      issuer({ id: `issuer-${index}`, name: `CA ${index}` })
    );
    listIssuersMock
      .mockResolvedValueOnce({ items: firstPage, pagination: { total: 101 } })
      .mockResolvedValueOnce({
        items: [issuer({ id: 'issuer-100', name: 'CA 100' })],
        pagination: { total: 101 },
      });

    renderPage();

    expect(
      await screen.findByText('Showing 100 of 101 issuers.')
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Load more issuers' }));

    await waitFor(() => {
      expect(listIssuersMock).toHaveBeenLastCalledWith('ws-1', {
        limit: 100,
        offset: 100,
        includeUnconfigured: true,
      });
    });
    expect(await screen.findByText('CA 100')).toBeInTheDocument();
    expect(screen.queryByText(/Showing \d+ of \d+ issuers/)).not.toBeInTheDocument();
  });
});
