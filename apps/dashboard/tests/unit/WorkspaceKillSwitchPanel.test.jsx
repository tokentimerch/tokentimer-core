import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import WorkspaceKillSwitchPanel from '../../src/components/certops/WorkspaceKillSwitchPanel.jsx';

const { useCertOpsIsWorkspaceAdminMock, useCertOpsWorkspaceKillSwitchMock } =
  vi.hoisted(() => ({
    useCertOpsIsWorkspaceAdminMock: vi.fn(),
    useCertOpsWorkspaceKillSwitchMock: vi.fn(),
  }));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsIsWorkspaceAdmin: useCertOpsIsWorkspaceAdminMock,
  useCertOpsWorkspaceKillSwitch: useCertOpsWorkspaceKillSwitchMock,
}));

function renderWithProviders(ui) {
  return render(
    <ChakraProvider>
      <MemoryRouter>{ui}</MemoryRouter>
    </ChakraProvider>
  );
}

function killSwitchState(overrides = {}) {
  return {
    certOpsPaused: false,
    certOpsEnabled: true,
    certOpsActive: true,
    loading: false,
    error: '',
    saving: false,
    setPaused: vi.fn(),
    ...overrides,
  };
}

describe('WorkspaceKillSwitchPanel', () => {
  beforeEach(() => {
    useCertOpsIsWorkspaceAdminMock.mockReset();
    useCertOpsWorkspaceKillSwitchMock.mockReset();
  });

  it('shows an Active badge and a Pause action for an admin', () => {
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(true);
    useCertOpsWorkspaceKillSwitchMock.mockReturnValue(killSwitchState());

    renderWithProviders(<WorkspaceKillSwitchPanel />);

    expect(screen.getByText('Active')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Pause certificate operations' })
    ).toBeInTheDocument();
  });

  it('shows a Paused badge and a Resume action once paused', () => {
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(true);
    useCertOpsWorkspaceKillSwitchMock.mockReturnValue(
      killSwitchState({ certOpsPaused: true, certOpsActive: false })
    );

    renderWithProviders(<WorkspaceKillSwitchPanel />);

    expect(screen.getByText('Paused')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Resume certificate operations' })
    ).toBeInTheDocument();
  });

  it('hides the action and explains admin-only control for a non-admin', () => {
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(false);
    useCertOpsWorkspaceKillSwitchMock.mockReturnValue(killSwitchState());

    renderWithProviders(<WorkspaceKillSwitchPanel />);

    expect(
      screen.queryByRole('button', { name: /certificate operations/ })
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/Only workspace admins can pause or resume/)
    ).toBeInTheDocument();
  });

  it('pauses through the confirm modal with a reason', async () => {
    const setPaused = vi.fn().mockResolvedValue({});
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(true);
    useCertOpsWorkspaceKillSwitchMock.mockReturnValue(
      killSwitchState({ setPaused })
    );

    renderWithProviders(<WorkspaceKillSwitchPanel />);

    fireEvent.click(
      screen.getByRole('button', { name: 'Pause certificate operations' })
    );
    expect(
      await screen.findByText(/New provisioning intent and command delivery/)
    ).toBeInTheDocument();

    fireEvent.change(
      screen.getByPlaceholderText('e.g. investigating a misissued certificate'),
      { target: { value: 'rotating a compromised key' } }
    );
    fireEvent.click(screen.getByRole('button', { name: 'Pause' }));

    await waitFor(() => {
      expect(setPaused).toHaveBeenCalledWith(true, 'rotating a compromised key');
    });
  });

  it('resumes through the confirm modal when already paused', async () => {
    const setPaused = vi.fn().mockResolvedValue({});
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(true);
    useCertOpsWorkspaceKillSwitchMock.mockReturnValue(
      killSwitchState({ certOpsPaused: true, certOpsActive: false, setPaused })
    );

    renderWithProviders(<WorkspaceKillSwitchPanel />);

    fireEvent.click(
      screen.getByRole('button', { name: 'Resume certificate operations' })
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Resume' }));

    await waitFor(() => {
      expect(setPaused).toHaveBeenCalledWith(false, undefined);
    });
  });

  it('surfaces a load error', () => {
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(true);
    useCertOpsWorkspaceKillSwitchMock.mockReturnValue(
      killSwitchState({ error: 'Internal error' })
    );

    renderWithProviders(<WorkspaceKillSwitchPanel />);

    expect(screen.getByText('Internal error')).toBeInTheDocument();
  });

  it('notes when the deployment-wide rollout flag is also off', () => {
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(true);
    useCertOpsWorkspaceKillSwitchMock.mockReturnValue(
      killSwitchState({ certOpsEnabled: false, certOpsActive: false })
    );

    renderWithProviders(<WorkspaceKillSwitchPanel />);

    expect(
      screen.getByText(/also off deployment-wide right now/)
    ).toBeInTheDocument();
  });
});
