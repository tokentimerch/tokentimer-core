import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ChakraProvider } from '@chakra-ui/react';

import AgentFleetPanel from '../../src/components/certops/AgentFleetPanel.jsx';

const {
  useWorkspaceMock,
  useCertOpsCanManageMock,
  useCertOpsAgentsMock,
  retireAgentMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  useCertOpsCanManageMock: vi.fn(),
  useCertOpsAgentsMock: vi.fn(),
  retireAgentMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: useWorkspaceMock,
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsCanManage: useCertOpsCanManageMock,
}));

vi.mock('../../src/components/certops/useCertOpsAgents.js', () => ({
  useCertOpsAgents: useCertOpsAgentsMock,
}));

vi.mock('../../src/components/certops/certopsAgentsApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsAgentsApi.js'
  );
  return {
    ...actual,
    retireAgent: retireAgentMock,
  };
});

function renderWithProviders(ui) {
  return render(
    <ChakraProvider>
      <MemoryRouter>{ui}</MemoryRouter>
    </ChakraProvider>
  );
}

function agentsState(overrides = {}) {
  return {
    enabled: true,
    agents: [],
    loading: false,
    error: '',
    refresh: vi.fn(),
    ...overrides,
  };
}

function sampleAgents() {
  return [
    {
      id: 'row-1',
      agentId: 'agent-active-1',
      name: 'dc1-edge',
      hostname: 'edge01',
      status: 'active',
      agentVersion: '1.2.3',
      lastSeenAt: new Date(Date.now() - 60000).toISOString(),
    },
    {
      id: 'row-2',
      agentId: 'agent-offline-1',
      name: 'dc2-core',
      hostname: 'core01',
      status: 'offline',
      agentVersion: '1.2.0',
      lastSeenAt: new Date(Date.now() - 3600000).toISOString(),
    },
    {
      id: 'row-3',
      agentId: 'agent-retired-1',
      name: 'old-agent',
      hostname: 'old01',
      status: 'retired',
      agentVersion: '1.0.0',
      lastSeenAt: null,
      retiredAt: new Date().toISOString(),
    },
  ];
}

describe('AgentFleetPanel', () => {
  beforeEach(() => {
    useWorkspaceMock.mockReset();
    useCertOpsCanManageMock.mockReset();
    useCertOpsAgentsMock.mockReset();
    retireAgentMock.mockReset();
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
  });

  it('renders nothing while CertOps availability is unresolved or disabled', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(agentsState({ enabled: false }));

    const { container } = renderWithProviders(<AgentFleetPanel />);

    expect(container.textContent).toBe('');
  });

  it('shows an empty state pointing to the Deploy an agent panel', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(agentsState());

    renderWithProviders(<AgentFleetPanel />);

    expect(screen.getByText('No agents yet.')).toBeInTheDocument();
    expect(
      screen.getByText(/Use the Deploy an agent panel on this page/)
    ).toBeInTheDocument();
  });

  it('renders agents with status badges, version and heartbeat, retire only on non-retired rows', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({ agents: sampleAgents() })
    );

    renderWithProviders(<AgentFleetPanel />);

    expect(screen.getByText('dc1-edge')).toBeInTheDocument();
    expect(screen.getByText('Active')).toBeInTheDocument();
    expect(screen.getByText('Offline')).toBeInTheDocument();
    expect(screen.getByText('Retired')).toBeInTheDocument();
    expect(screen.getByText('1.2.3')).toBeInTheDocument();
    // Active + offline are retirable, the retired agent is not.
    expect(screen.getAllByRole('button', { name: 'Retire' })).toHaveLength(2);
  });

  it('hides the actions column for a non-manager viewer', () => {
    useCertOpsCanManageMock.mockReturnValue(false);
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({ agents: sampleAgents() })
    );

    renderWithProviders(<AgentFleetPanel />);

    expect(
      screen.queryByRole('button', { name: 'Retire' })
    ).not.toBeInTheDocument();
  });

  it('retires an agent through the confirm modal and refreshes', async () => {
    const refresh = vi.fn();
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({ agents: sampleAgents(), refresh })
    );
    retireAgentMock.mockResolvedValue({
      agent: { id: 'row-1', status: 'retired' },
    });

    renderWithProviders(<AgentFleetPanel />);

    fireEvent.click(screen.getAllByRole('button', { name: 'Retire' })[0]);
    expect(
      await screen.findByText(/can no longer connect or lease jobs/)
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retire agent' }));

    await waitFor(() => {
      expect(retireAgentMock).toHaveBeenCalledWith('ws-1', 'row-1', {
        force: false,
        reason: undefined,
      });
      expect(refresh).toHaveBeenCalled();
    });
  });

  it('surfaces the force option when the retire is blocked by leased jobs', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({ agents: sampleAgents() })
    );
    retireAgentMock
      .mockRejectedValueOnce({
        response: {
          status: 409,
          data: { code: 'CERTOPS_AGENT_RETIRE_BLOCKED' },
        },
      })
      .mockResolvedValue({ agent: { id: 'row-1', status: 'retired' } });

    renderWithProviders(<AgentFleetPanel />);

    fireEvent.click(screen.getAllByRole('button', { name: 'Retire' })[0]);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Retire agent' })
    );

    expect(
      await screen.findByText(/still holds active job leases/)
    ).toBeInTheDocument();

    // Force requires a reason before the confirm button enables again.
    fireEvent.click(screen.getByRole('checkbox'));
    const forceButton = screen.getByRole('button', { name: 'Force retire' });
    expect(forceButton).toBeDisabled();

    fireEvent.change(screen.getByPlaceholderText('e.g. host decommissioned'), {
      target: { value: 'host is gone' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Force retire' }));

    await waitFor(() => {
      expect(retireAgentMock).toHaveBeenLastCalledWith('ws-1', 'row-1', {
        force: true,
        reason: 'host is gone',
      });
    });
  });
});
