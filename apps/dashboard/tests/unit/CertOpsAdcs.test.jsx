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
  proposeEnrollmentRequestIdMock,
  showSuccessMock,
} = vi.hoisted(() => ({
  isAdminMock: vi.fn(),
  listIssuersMock: vi.fn(),
  listEnrollmentsMock: vi.fn(),
  listAgentsMock: vi.fn(),
  createIssuerMock: vi.fn(),
  dispatchIssuerPreflightMock: vi.fn(),
  proposeEnrollmentRequestIdMock: vi.fn(),
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
    dispatchIssuerPreflight: dispatchIssuerPreflightMock,
    proposeEnrollmentRequestId: proposeEnrollmentRequestIdMock,
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
  proposeEnrollmentRequestIdMock.mockReset();
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

    expect(
      await screen.findByText(
        (_, node) =>
          node?.tagName === 'P' &&
          node.textContent.startsWith('Awaiting CA approval ·')
      )
    ).toBeInTheDocument();
    expect(screen.getByText(/RequestId\s+42/)).toBeInTheDocument();
    expect(screen.getAllByText(/key abababababab/)).toHaveLength(2);
    expect(screen.getByText(/stays on issuer version 1/)).toBeInTheDocument();
    expect(screen.queryByText(/Cancel and re-enroll/)).not.toBeInTheDocument();
    expect(screen.getAllByText(/CA key changed/).length).toBeGreaterThan(0);
    expect(
      screen.getByText(
        (_, node) =>
          node?.tagName === 'P' &&
          node.textContent.startsWith('Submission uncertain ·')
      )
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Reconcile' })
    ).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /Confirm key/ })
    ).not.toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Abandon' })).toHaveLength(1);
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
      await screen.findByRole('button', { name: 'Confirm key abababababab' })
    ).toBeInTheDocument();
  });

  it('creates an issuer without claiming enrollment is enabled', async () => {
    isAdminMock.mockReturnValue(true);
    createIssuerMock.mockResolvedValue({ issuer: { id: 'issuer-2' } });

    renderPage();
    await screen.findByText(/No enrollments yet/);
    fireEvent.change(screen.getByLabelText('Issuer name'), {
      target: { value: 'Corp CA' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create issuer' }));

    await waitFor(() => {
      expect(createIssuerMock).toHaveBeenCalledWith('ws-1', {
        kind: 'adcs',
        name: 'Corp CA',
      });
    });
    expect(showSuccessMock).toHaveBeenCalledWith(
      expect.stringContaining('stays disabled until the release gate passes')
    );
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    await waitFor(() => {
      expect(listIssuersMock.mock.calls.length).toBeGreaterThan(1);
    });
  });

  it('keeps asking for a preflight verdict after dispatch', async () => {
    isAdminMock.mockReturnValue(true);
    listIssuersMock.mockResolvedValue({ items: [issuer()] });
    dispatchIssuerPreflightMock.mockResolvedValue({ job: { id: 'job-1' } });

    renderPage();
    await screen.findByRole('button', { name: 'Run preflight' });
    fireEvent.change(screen.getByLabelText('CA config'), {
      target: { value: 'ca01\\Corp CA' },
    });
    fireEvent.change(screen.getByLabelText('Template'), {
      target: { value: 'TokenTimerWebServer' },
    });
    fireEvent.submit(
      screen.getByRole('button', { name: 'Run preflight' }).closest('form')
    );

    expect(
      await screen.findByText(
        'Waiting for the agent to report the preflight verdict.'
      )
    ).toBeInTheDocument();
  });
});
