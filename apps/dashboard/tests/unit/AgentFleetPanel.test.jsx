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

function renderWithProviders(ui, initialEntries = ['/']) {
  return render(
    <ChakraProvider>
      <MemoryRouter initialEntries={initialEntries}>{ui}</MemoryRouter>
    </ChakraProvider>
  );
}

function agentsState(overrides = {}) {
  const { pagination, ...rest } = overrides;
  const state = {
    enabled: true,
    agents: [],
    loading: false,
    error: '',
    refresh: vi.fn(),
    ...rest,
  };
  return {
    ...state,
    // Mirrors the list envelope: a null limit is the server's signal that the
    // whole fleet is present, so total matches the rows handed to the panel.
    pagination:
      pagination === undefined
        ? { limit: null, offset: 0, total: state.agents.length }
        : pagination,
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
      protocolVersion: 2,
      clockOffsetMs: 120,
      ntpSynced: true,
      pinnedSigningKeyId: 'ttsk_0123456789abcdef',
      lastSeenAt: new Date(Date.now() - 60000).toISOString(),
    },
    {
      id: 'row-2',
      agentId: 'agent-offline-1',
      name: 'dc2-core',
      hostname: 'core01',
      status: 'offline',
      agentVersion: '1.2.0',
      protocolVersion: 1,
      clockOffsetMs: -8200,
      ntpSynced: false,
      pinnedSigningKeyId: null,
      lastSeenAt: new Date(Date.now() - 3600000).toISOString(),
    },
    {
      id: 'row-3',
      agentId: 'agent-retired-1',
      name: 'old-agent',
      hostname: 'old01',
      status: 'retired',
      agentVersion: '1.0.0',
      protocolVersion: null,
      clockOffsetMs: null,
      ntpSynced: null,
      pinnedSigningKeyId: null,
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

  it('shows a Stale badge instead of Active when livenessState says the heartbeat is overdue (sweep has not yet caught up)', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    const agents = sampleAgents();
    // Row 1 is status='active' in the raw column, but the server-computed
    // livenessState flags it stale because last_seen_at is past the
    // offline threshold and the periodic sweep has not yet demoted it.
    agents[0].livenessState = 'stale';
    useCertOpsAgentsMock.mockReturnValue(agentsState({ agents }));

    renderWithProviders(<AgentFleetPanel />);

    expect(screen.getByText('Stale')).toBeInTheDocument();
    expect(screen.queryByText('Active')).not.toBeInTheDocument();
    // The raw offline row is unaffected and still reads "Offline".
    expect(screen.getByText('Offline')).toBeInTheDocument();
  });

  it('renders protocol version and clock drift columns, flagging large offsets', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({ agents: sampleAgents() })
    );

    renderWithProviders(<AgentFleetPanel />);

    expect(
      screen.getByRole('columnheader', { name: 'Protocol' })
    ).toBeInTheDocument();
    expect(
      screen.getByRole('columnheader', { name: 'Clock drift' })
    ).toBeInTheDocument();

    // Protocol versions per row; the retired agent has none. Scoped to the
    // table because the page control also renders a bare number.
    const rows = screen.getByRole('table');
    expect(within(rows).getByText('2')).toBeInTheDocument();
    expect(within(rows).getByText('1')).toBeInTheDocument();

    // Signed offsets; only the |offset| > 5000ms row is flagged.
    expect(screen.getByText('+120 ms')).toBeInTheDocument();
    expect(screen.getByText('-8200 ms')).toBeInTheDocument();
    expect(screen.getAllByText('Drift')).toHaveLength(1);

    // Unknown protocol/offset render as placeholders on the retired row.
    expect(screen.getAllByText('--').length).toBeGreaterThanOrEqual(2);
  });

  it('renders NTP sync state and pinned signing key columns', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({ agents: sampleAgents() })
    );

    renderWithProviders(<AgentFleetPanel />);

    expect(
      screen.getByRole('columnheader', { name: 'NTP' })
    ).toBeInTheDocument();
    expect(
      screen.getByRole('columnheader', { name: 'Signing key' })
    ).toBeInTheDocument();

    // One synced, one unsynced, and the retired row's unknown placeholder.
    expect(screen.getByText('Synced')).toBeInTheDocument();
    expect(screen.getByText('Not synced')).toBeInTheDocument();

    // Signing key ids are shortened for display.
    expect(screen.getByText('ttsk_0123456...')).toBeInTheDocument();
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

  it('pages the fleet through the URL and sends the page position to the hook', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({
        agents: sampleAgents(),
        pagination: { limit: 20, offset: 0, total: 57 },
      })
    );

    renderWithProviders(<AgentFleetPanel />);

    expect(
      screen.getByRole('navigation', { name: 'agents pagination' })
    ).toBeInTheDocument();
    expect(
      screen.getByText('Showing 1 to 20 of 57 agents')
    ).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole('button', { name: 'Next page of agents' })
    );
    expect(useCertOpsAgentsMock).toHaveBeenLastCalledWith(undefined, {
      limit: 20,
      offset: 20,
    });
  });

  it('reads a non-default page size from the URL', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({
        agents: sampleAgents(),
        pagination: { limit: 50, offset: 50, total: 300 },
      })
    );

    renderWithProviders(<AgentFleetPanel />, [
      '/?agentLimit=50&agentOffset=50',
    ]);

    expect(useCertOpsAgentsMock).toHaveBeenLastCalledWith(undefined, {
      limit: 50,
      offset: 50,
    });
  });

  it('offers a way back rather than an empty fleet when the URL page is past the end', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({
        agents: [],
        pagination: { limit: 20, offset: 200, total: 3 },
      })
    );

    renderWithProviders(<AgentFleetPanel />, ['/?agentOffset=200']);

    expect(
      screen.getByText('This page is past the end of the fleet.')
    ).toBeInTheDocument();
    expect(screen.queryByText('No agents yet.')).not.toBeInTheDocument();
  });

  it('forwards refreshSignal to useCertOpsAgents so a freshly registered agent refetches immediately', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(agentsState());

    const { rerender } = renderWithProviders(
      <AgentFleetPanel refreshSignal={0} />
    );
    expect(useCertOpsAgentsMock).toHaveBeenLastCalledWith(0, {
      limit: 20,
      offset: 0,
    });

    rerender(
      <ChakraProvider>
        <MemoryRouter>
          <AgentFleetPanel refreshSignal={1} />
        </MemoryRouter>
      </ChakraProvider>
    );
    expect(useCertOpsAgentsMock).toHaveBeenLastCalledWith(1, {
      limit: 20,
      offset: 0,
    });
  });
});
