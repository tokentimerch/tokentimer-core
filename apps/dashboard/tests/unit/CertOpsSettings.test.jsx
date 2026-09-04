import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import CertOpsSettings from '../../src/pages/certops/CertOpsSettings.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const {
  useCertOpsCanManageMock,
  useCertOpsIsWorkspaceAdminMock,
  useCertOpsWorkspaceKillSwitchMock,
} = vi.hoisted(() => ({
  useCertOpsCanManageMock: vi.fn(),
  useCertOpsIsWorkspaceAdminMock: vi.fn(),
  useCertOpsWorkspaceKillSwitchMock: vi.fn(),
}));

vi.mock('react-router', async () => {
  const actual = await vi.importActual('react-router');
  return {
    ...actual,
    useOutletContext: () => ({ certOpsPaused: false }),
  };
});

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsCanManage: useCertOpsCanManageMock,
  useCertOpsIsWorkspaceAdmin: useCertOpsIsWorkspaceAdminMock,
  useCertOpsWorkspaceKillSwitch: useCertOpsWorkspaceKillSwitchMock,
}));

vi.mock('../../src/components/certops/ApiTokenList.jsx', () => ({
  default: () => <div>Machine token inventory</div>,
}));

vi.mock('../../src/components/certops/ApiTokenModal.jsx', () => ({
  default: () => null,
}));

function renderPage() {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>
          <CertOpsSettings />
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

beforeEach(() => {
  useCertOpsCanManageMock.mockReset();
  useCertOpsIsWorkspaceAdminMock.mockReset();
  useCertOpsWorkspaceKillSwitchMock.mockReset();
  useCertOpsCanManageMock.mockReturnValue(true);
  useCertOpsIsWorkspaceAdminMock.mockReturnValue(true);
  useCertOpsWorkspaceKillSwitchMock.mockReturnValue({
    certOpsRequireApprovalAlways: false,
    loading: false,
    error: '',
    saving: false,
    setRequireApprovalAlways: vi.fn(),
  });
});

describe('CertOpsSettings job approval policy', () => {
  it('shows the always-require-approval control and explains every creation path', () => {
    renderPage();

    expect(screen.getByText('Job approval')).toBeInTheDocument();
    expect(
      screen.getByText(/Require approval before every new job can run/)
    ).toBeInTheDocument();
    expect(
      screen.getByText(/machine API token calls, bulk renew, scheduled renewal/)
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText('Require approval for every new job')
    ).toBeInTheDocument();
  });

  it('lets an admin turn the policy on', async () => {
    const setRequireApprovalAlways = vi.fn().mockResolvedValue({});
    useCertOpsWorkspaceKillSwitchMock.mockReturnValue({
      certOpsRequireApprovalAlways: false,
      loading: false,
      error: '',
      saving: false,
      setRequireApprovalAlways,
    });

    renderPage();
    fireEvent.click(screen.getByLabelText('Require approval for every new job'));

    await waitFor(() => {
      expect(setRequireApprovalAlways).toHaveBeenCalledWith(true);
    });
  });
});
