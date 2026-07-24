import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ChakraProvider } from '@chakra-ui/react';

import DeployAgentPanel from '../../src/components/certops/DeployAgentPanel.jsx';

const {
  useWorkspaceMock,
  useCertOpsCanManageMock,
  useCertOpsBootstrapTokensMock,
  useCertOpsAgentsMock,
  createBootstrapTokenMock,
  revokeBootstrapTokenMock,
  listAgentsMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  useCertOpsCanManageMock: vi.fn(),
  useCertOpsBootstrapTokensMock: vi.fn(),
  useCertOpsAgentsMock: vi.fn(),
  createBootstrapTokenMock: vi.fn(),
  revokeBootstrapTokenMock: vi.fn(),
  listAgentsMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: useWorkspaceMock,
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsCanManage: useCertOpsCanManageMock,
}));

vi.mock('../../src/components/certops/useCertOpsAgents.js', () => ({
  useCertOpsBootstrapTokens: useCertOpsBootstrapTokensMock,
  useCertOpsAgents: useCertOpsAgentsMock,
}));

vi.mock('../../src/components/certops/certopsAgentsApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsAgentsApi.js'
  );
  return {
    ...actual,
    createBootstrapToken: createBootstrapTokenMock,
    revokeBootstrapToken: revokeBootstrapTokenMock,
    listAgents: listAgentsMock,
  };
});

function renderWithProviders(ui) {
  return render(
    <ChakraProvider>
      <MemoryRouter>{ui}</MemoryRouter>
    </ChakraProvider>
  );
}

function tokensState(overrides = {}) {
  return {
    enabled: true,
    tokens: [],
    loading: false,
    error: '',
    refresh: vi.fn(),
    ...overrides,
  };
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

/** Runs the step-1 flow: fill the name, create the token, close the modal. */
async function createTokenAndCloseModal() {
  fireEvent.change(screen.getByLabelText(/^Name/), {
    target: { value: 'dc1-edge' },
  });
  fireEvent.click(
    screen.getByRole('button', { name: 'Create bootstrap token' })
  );
  await screen.findByText(/shown only once and registers exactly one agent/);
  fireEvent.click(screen.getByRole('button', { name: 'Continue to install' }));
}

describe('DeployAgentPanel', () => {
  beforeEach(() => {
    useWorkspaceMock.mockReset();
    useCertOpsCanManageMock.mockReset();
    useCertOpsBootstrapTokensMock.mockReset();
    useCertOpsAgentsMock.mockReset();
    createBootstrapTokenMock.mockReset();
    revokeBootstrapTokenMock.mockReset();
    listAgentsMock.mockReset();
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
    useCertOpsAgentsMock.mockReturnValue(agentsState());
    listAgentsMock.mockResolvedValue({ items: [] });
  });

  it('renders nothing while CertOps availability is unresolved or disabled', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsBootstrapTokensMock.mockReturnValue(
      tokensState({ enabled: false })
    );

    const { container } = renderWithProviders(<DeployAgentPanel />);

    expect(container.textContent).toBe('');
  });

  it('shows a read-only explainer without the deploy steps for a viewer', () => {
    useCertOpsCanManageMock.mockReturnValue(false);
    useCertOpsBootstrapTokensMock.mockReturnValue(tokensState());

    renderWithProviders(<DeployAgentPanel />);

    expect(
      screen.getByText(/requires workspace manager permission/)
    ).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Create bootstrap token' })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText('Step 2: Run the installer on the target host')
    ).not.toBeInTheDocument();
  });

  it('shows the guided steps with accessible labels for a manager', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsBootstrapTokensMock.mockReturnValue(tokensState());

    renderWithProviders(<DeployAgentPanel />);

    expect(
      screen.getByText('Step 1: Create a bootstrap token')
    ).toBeInTheDocument();
    expect(screen.getByLabelText(/^Name/)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Expires/)).toBeInTheDocument();
    expect(
      screen.getByText('Step 2: Run the installer on the target host')
    ).toBeInTheDocument();
    expect(screen.getByText(/install-agent\.sh/)).toBeInTheDocument();
  });

  it('creates a token, shows the one-time secret, and keeps it out of the install command', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsBootstrapTokensMock.mockReturnValue(tokensState());
    createBootstrapTokenMock.mockResolvedValue({
      token: { id: 'bt-1', name: 'dc1-edge' },
      plaintextToken: 'ttboot_secret_value',
    });

    renderWithProviders(<DeployAgentPanel />);

    fireEvent.change(screen.getByLabelText(/^Name/), {
      target: { value: 'dc1-edge' },
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Create bootstrap token' })
    );

    await waitFor(() => {
      expect(createBootstrapTokenMock).toHaveBeenCalledTimes(1);
    });
    const [wsArg, payload] = createBootstrapTokenMock.mock.calls[0];
    expect(wsArg).toBe('ws-1');
    expect(payload.name).toBe('dc1-edge');
    expect(typeof payload.expiresAt).toBe('string');

    expect(
      await screen.findByText(/shown only once and registers exactly one agent/)
    ).toBeInTheDocument();
    // Secret appears only in the show-once display, never in the command.
    expect(screen.getAllByText(/ttboot_secret_value/)).toHaveLength(1);

    const commandBlock = screen.getByText(/install-agent\.sh/);
    expect(commandBlock.textContent).toContain('--api-url');
    expect(commandBlock.textContent).toContain("--workspace-id 'ws-1'");
    expect(commandBlock.textContent).not.toContain('ttboot_secret_value');
    expect(commandBlock.textContent).not.toContain('--bootstrap-token');
    expect(commandBlock.textContent).not.toContain(
      'TOKENTIMER_AGENT_BOOTSTRAP_TOKEN='
    );

    // Helper text explains the installer's hidden token prompt.
    expect(
      screen.getByText(/installer will prompt for it \(hidden input\)/)
    ).toBeInTheDocument();
  });

  it('detects an agent that registered before the first poll via the token-creation baseline', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsBootstrapTokensMock.mockReturnValue(tokensState());
    // Fleet already loaded in the panel when the token is created.
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({
        agents: [{ id: 'row-existing', agentId: 'agent-existing' }],
      })
    );
    createBootstrapTokenMock.mockResolvedValue({
      token: { id: 'bt-1', name: 'dc1-edge' },
      plaintextToken: 'ttboot_secret_value',
    });
    // The new agent registered between token creation and the first poll:
    // it must be reported on the very first tick, not treated as baseline.
    listAgentsMock.mockResolvedValue({
      items: [
        {
          id: 'row-existing',
          agentId: 'agent-existing',
          name: 'old-agent',
          status: 'active',
          createdAt: new Date(Date.now() - 3600000).toISOString(),
        },
        {
          id: 'row-new',
          agentId: 'agent-new',
          name: 'dc1-edge',
          status: 'active',
          createdAt: new Date().toISOString(),
        },
      ],
    });

    renderWithProviders(<DeployAgentPanel />);

    await createTokenAndCloseModal();
    fireEvent.click(screen.getByRole('button', { name: 'I ran the installer' }));

    expect(await screen.findByText(/is now connected/)).toBeInTheDocument();
    expect(listAgentsMock).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/dc1-edge/)).toBeInTheDocument();
  });

  it('detects a new agent by registration timestamp even when its id is in a stale baseline', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsBootstrapTokensMock.mockReturnValue(tokensState());
    // Baseline (stale) already contains the row id of the agent that will
    // register; detection must fall through to the timestamp comparison.
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({ agents: [{ id: 'row-1', agentId: 'agent-1' }] })
    );
    createBootstrapTokenMock.mockResolvedValue({
      token: { id: 'bt-1', name: 'dc1-edge' },
      plaintextToken: 'ttboot_secret_value',
    });
    listAgentsMock.mockResolvedValue({
      items: [
        {
          id: 'row-1',
          agentId: 'agent-1',
          name: 'dc1-edge',
          status: 'active',
          // Registered after token creation (clock-safe margin).
          createdAt: new Date(Date.now() + 60000).toISOString(),
        },
      ],
    });

    renderWithProviders(<DeployAgentPanel />);

    await createTokenAndCloseModal();
    fireEvent.click(screen.getByRole('button', { name: 'I ran the installer' }));

    expect(await screen.findByText(/is now connected/)).toBeInTheDocument();
    expect(screen.getByText(/dc1-edge/)).toBeInTheDocument();
  });

  it('falls back to a first-tick snapshot when waiting starts without a token created', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsBootstrapTokensMock.mockReturnValue(tokensState());
    // First poll snapshots the fleet; second poll returns the new agent.
    listAgentsMock.mockResolvedValueOnce({ items: [] }).mockResolvedValue({
      items: [
        {
          id: 'row-1',
          agentId: 'agent-1',
          name: 'dc1-edge',
          status: 'active',
        },
      ],
    });
    vi.useFakeTimers();

    try {
      renderWithProviders(<DeployAgentPanel />);

      fireEvent.click(
        screen.getByRole('button', { name: 'I ran the installer' })
      );

      expect(
        screen.getByText('Step 3: Waiting for the agent to register')
      ).toBeInTheDocument();

      // Snapshot poll, then the tick that finds the new agent.
      await vi.advanceTimersByTimeAsync(0);
      await vi.advanceTimersByTimeAsync(10000);

      expect(screen.getByText(/is now connected/)).toBeInTheDocument();
      expect(screen.getByText(/dc1-edge/)).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it('lists bootstrap tokens and revokes an active one', async () => {
    const refresh = vi.fn();
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsBootstrapTokensMock.mockReturnValue(
      tokensState({
        refresh,
        tokens: [
          {
            id: 'bt-1',
            name: 'active-token',
            tokenPrefix: 'ttboot_abc',
            status: 'active',
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
            createdAt: new Date().toISOString(),
          },
          {
            id: 'bt-2',
            name: 'used-token',
            tokenPrefix: 'ttboot_def',
            status: 'used',
            usedAt: new Date().toISOString(),
            createdAt: new Date().toISOString(),
          },
        ],
      })
    );
    revokeBootstrapTokenMock.mockResolvedValue({ token: { id: 'bt-1' } });

    renderWithProviders(<DeployAgentPanel />);

    expect(screen.getByText('active-token')).toBeInTheDocument();
    expect(screen.getByText('used-token')).toBeInTheDocument();
    // Only the active token can be revoked.
    const revokeButtons = screen.getAllByRole('button', { name: 'Revoke' });
    expect(revokeButtons).toHaveLength(1);

    fireEvent.click(revokeButtons[0]);
    expect(
      await screen.findByText('Revoke bootstrap token')
    ).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole('button', { name: 'Revoke' }).at(-1));

    await waitFor(() => {
      expect(revokeBootstrapTokenMock).toHaveBeenCalledWith('ws-1', 'bt-1');
      expect(refresh).toHaveBeenCalled();
    });
  });
});
