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
  updateAgentAlertSettingsMock,
  getAlertSettingsMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  useCertOpsCanManageMock: vi.fn(),
  useCertOpsAgentsMock: vi.fn(),
  retireAgentMock: vi.fn(),
  updateAgentAlertSettingsMock: vi.fn(),
  getAlertSettingsMock: vi.fn(),
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
    updateAgentAlertSettings: updateAgentAlertSettingsMock,
  };
});

vi.mock('../../src/utils/apiClient', async () => {
  const actual = await vi.importActual('../../src/utils/apiClient');
  return {
    ...actual,
    workspaceAPI: {
      ...actual.workspaceAPI,
      getAlertSettings: getAlertSettingsMock,
    },
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
      platform: 'win32',
      status: 'active',
      agentVersion: '1.2.3',
      protocolVersion: 2,
      clockOffsetMs: 120,
      ntpSynced: true,
      pinnedSigningKeyId: 'ttsk_0123456789abcdef',
      lastSeenAt: new Date(Date.now() - 60000).toISOString(),
      downtimeAlertsEnabled: true,
      contactGroupId: null,
    },
    {
      id: 'row-2',
      agentId: 'agent-offline-1',
      name: 'dc2-core',
      hostname: 'core01',
      platform: 'linux',
      status: 'offline',
      agentVersion: '1.2.0',
      protocolVersion: 1,
      clockOffsetMs: -8200,
      ntpSynced: false,
      pinnedSigningKeyId: null,
      lastSeenAt: new Date(Date.now() - 3600000).toISOString(),
      downtimeAlertsEnabled: true,
      contactGroupId: 'g1',
      dependentAutoRenewCertificateCount: 3,
    },
    {
      id: 'row-3',
      agentId: 'agent-retired-1',
      name: 'old-agent',
      hostname: 'old01',
      platform: null,
      status: 'retired',
      agentVersion: '1.0.0',
      protocolVersion: null,
      clockOffsetMs: null,
      ntpSynced: null,
      pinnedSigningKeyId: null,
      lastSeenAt: null,
      retiredAt: new Date().toISOString(),
      downtimeAlertsEnabled: true,
      contactGroupId: null,
    },
  ];
}

describe('AgentFleetPanel', () => {
  beforeEach(() => {
    useWorkspaceMock.mockReset();
    useCertOpsCanManageMock.mockReset();
    useCertOpsAgentsMock.mockReset();
    retireAgentMock.mockReset();
    updateAgentAlertSettingsMock.mockReset();
    getAlertSettingsMock.mockReset();
    getAlertSettingsMock.mockResolvedValue({
      contact_groups: [{ id: 'g1', name: 'On-call' }],
      default_contact_group_id: 'g1',
    });
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
  });

  it('renders nothing while CertOps availability is unresolved or disabled', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(agentsState({ enabled: false }));

    const { container } = renderWithProviders(<AgentFleetPanel />);

    expect(container.textContent).toBe('');
  });

  it('shows an empty state pointing to the Deploy an agent button', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(agentsState());

    renderWithProviders(<AgentFleetPanel />);

    expect(screen.getByText('No agents yet.')).toBeInTheDocument();
    expect(
      screen.getByText(/Use the Deploy an agent button on this page/)
    ).toBeInTheDocument();
  });

  it('renders the caller-supplied header action next to the panel title', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(agentsState());

    renderWithProviders(
      <AgentFleetPanel headerAction={<button>Deploy an agent</button>} />
    );

    expect(
      screen.getByRole('button', { name: 'Deploy an agent' })
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

  it('preserves server order, sorts through the hook, and leaves derived status static', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    const agents = sampleAgents().slice(0, 2);
    agents[0].name = 'zulu-agent';
    agents[1].name = 'alpha-agent';
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({
        agents,
        pagination: { limit: 20, offset: 20, total: 100 },
      })
    );

    renderWithProviders(<AgentFleetPanel />, ['/?agentOffset=20']);

    const first = screen.getByText('zulu-agent');
    const second = screen.getByText('alpha-agent');
    expect(
      first.compareDocumentPosition(second) & Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();
    expect(
      screen.queryByRole('button', { name: 'Sort by Status' })
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Sort by Agent' }));
    await waitFor(() => {
      expect(useCertOpsAgentsMock).toHaveBeenLastCalledWith(undefined, {
        limit: 20,
        offset: 0,
        sort: 'agent',
        direction: 'asc',
      });
    });

    fireEvent.click(screen.getByRole('button', { name: 'Sort by Agent' }));
    await waitFor(() => {
      expect(useCertOpsAgentsMock).toHaveBeenLastCalledWith(undefined, {
        limit: 20,
        offset: 0,
        sort: 'agent',
        direction: 'desc',
      });
    });
  });

  it('renders a friendly OS label from the raw platform, and unknown/missing values safely', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({ agents: sampleAgents() })
    );

    renderWithProviders(<AgentFleetPanel />);

    expect(
      screen.getByRole('columnheader', { name: 'OS' })
    ).toBeInTheDocument();
    expect(screen.getByText('Windows')).toBeInTheDocument();
    expect(screen.getByText('Linux')).toBeInTheDocument();
    // The retired row has platform: null; renders the placeholder, not a crash.
    expect(screen.getAllByText('--').length).toBeGreaterThanOrEqual(1);
  });

  it('renders an unrecognized platform value raw rather than hiding it', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    const agents = sampleAgents();
    agents[0].platform = 'freebsd';
    useCertOpsAgentsMock.mockReturnValue(agentsState({ agents }));

    renderWithProviders(<AgentFleetPanel />);

    expect(screen.getByText('freebsd')).toBeInTheDocument();
  });

  it('shows the dependent auto-renew certificate count for an offline agent', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({ agents: sampleAgents() })
    );

    renderWithProviders(<AgentFleetPanel />);

    expect(
      screen.getByText(/3 auto-renew certificates affected/)
    ).toBeInTheDocument();
  });

  it('hides the affected-certificates hint for an active agent or a zero count', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    const agents = sampleAgents();
    agents[1].dependentAutoRenewCertificateCount = 0;
    useCertOpsAgentsMock.mockReturnValue(agentsState({ agents }));

    renderWithProviders(<AgentFleetPanel />);

    expect(
      screen.queryByText(/auto-renew certificate/)
    ).not.toBeInTheDocument();
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

  it('renders an Execution column badging declared-capability agents "Enabled" and others "No capability declared"', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    const agents = sampleAgents();
    agents[0].supportedOperations = ['renew', 'distribute-trust'];
    agents[1].supportedOperations = [];
    useCertOpsAgentsMock.mockReturnValue(agentsState({ agents }));

    renderWithProviders(<AgentFleetPanel />);

    expect(
      screen.getByRole('columnheader', { name: 'Execution' })
    ).toBeInTheDocument();
    expect(screen.getAllByText('Enabled')).toHaveLength(1);
    // Row 2 (no declared operations) and row 3 (retired, no operations key
    // at all) both fall back to the same warning badge.
    expect(screen.getAllByText('No capability declared')).toHaveLength(2);
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
    expect(
      screen.queryByRole('button', { name: 'Edit alerting' })
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

  it('opens Edit alerting, loads contact groups, and saves settings', async () => {
    const refresh = vi.fn();
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({ agents: sampleAgents(), refresh })
    );
    updateAgentAlertSettingsMock.mockResolvedValue({
      agent: {
        id: 'row-1',
        downtimeAlertsEnabled: false,
        contactGroupId: 'g1',
      },
    });

    renderWithProviders(<AgentFleetPanel />);

    fireEvent.click(
      screen.getAllByRole('button', { name: 'Edit alerting' })[0]
    );
    expect(
      await screen.findByText(/Downtime alert settings for/)
    ).toBeInTheDocument();

    await waitFor(() => {
      expect(getAlertSettingsMock).toHaveBeenCalledWith('ws-1');
    });
    expect(
      await screen.findByRole('option', { name: 'On-call (default)' })
    ).toBeInTheDocument();

    fireEvent.click(
      screen.getByText('Alert when this agent has not been seen for 10 minutes')
    );
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(updateAgentAlertSettingsMock).toHaveBeenCalledWith(
        'ws-1',
        'row-1',
        { downtimeAlertsEnabled: false, contactGroupId: null }
      );
      expect(refresh).toHaveBeenCalled();
    });
  });

  it('surfaces an error when the selected contact group no longer exists', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({ agents: sampleAgents() })
    );
    updateAgentAlertSettingsMock.mockRejectedValue({
      response: {
        status: 400,
        data: { code: 'CERTOPS_AGENT_CONTACT_GROUP_INVALID' },
      },
    });

    renderWithProviders(<AgentFleetPanel />);

    fireEvent.click(
      screen.getAllByRole('button', { name: 'Edit alerting' })[0]
    );
    await screen.findByText(/Downtime alert settings for/);
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    expect(
      await screen.findByText(/no longer exists in this workspace/)
    ).toBeInTheDocument();
  });
});
