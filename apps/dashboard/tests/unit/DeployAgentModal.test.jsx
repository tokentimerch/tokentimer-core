import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import DeployAgentModal from '../../src/components/certops/DeployAgentModal.jsx';

const {
  useWorkspaceMock,
  useCertOpsCanManageMock,
  useCertOpsAgentsMock,
  createBootstrapTokenMock,
  listAgentsMock,
  getAlertSettingsMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  useCertOpsCanManageMock: vi.fn(),
  useCertOpsAgentsMock: vi.fn(),
  createBootstrapTokenMock: vi.fn(),
  listAgentsMock: vi.fn(),
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
    createBootstrapToken: createBootstrapTokenMock,
    listAgents: listAgentsMock,
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

function renderModal(props = {}) {
  return render(
    <ChakraProvider>
      <MemoryRouter>
        <DeployAgentModal isOpen onClose={vi.fn()} {...props} />
      </MemoryRouter>
    </ChakraProvider>
  );
}

function agentsState(overrides = {}) {
  return {
    enabled: true,
    agents: [],
    pagination: { limit: null, offset: 0, total: 0 },
    loading: false,
    error: '',
    refresh: vi.fn(),
    ...overrides,
  };
}

/** Agent-list envelope as the server sends it when no page was requested. */
function agentListResponse(items = []) {
  return {
    items,
    pagination: { limit: null, offset: 0, total: items.length },
  };
}

/** Runs the step-2 flow: fill the name, create the token, acknowledge it. */
async function createTokenAndAcknowledge() {
  fireEvent.change(screen.getByLabelText(/^Name/), {
    target: { value: 'dc1-edge' },
  });
  fireEvent.click(
    screen.getByRole('button', { name: 'Create bootstrap token' })
  );
  await screen.findByText(/shown only once and registers exactly one agent/);
  fireEvent.click(screen.getByRole('button', { name: 'I have saved this token' }));
}

describe('DeployAgentModal', () => {
  beforeEach(() => {
    useWorkspaceMock.mockReset();
    useCertOpsCanManageMock.mockReset();
    useCertOpsAgentsMock.mockReset();
    createBootstrapTokenMock.mockReset();
    listAgentsMock.mockReset();
    getAlertSettingsMock.mockReset();
    getAlertSettingsMock.mockResolvedValue({
      contact_groups: [{ id: 'g1', name: 'On-call' }],
      default_contact_group_id: 'g1',
    });
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
    useCertOpsAgentsMock.mockReturnValue(agentsState());
    listAgentsMock.mockResolvedValue(agentListResponse([]));
  });

  it('renders nothing for a viewer without manager permission', () => {
    useCertOpsCanManageMock.mockReturnValue(false);

    const { container } = renderModal();

    expect(container.textContent).toBe('');
  });

  it('shows the guided steps with accessible labels for a manager', () => {
    useCertOpsCanManageMock.mockReturnValue(true);

    renderModal();

    expect(
      screen.getByText('Step 1: Run the installer on the target host')
    ).toBeInTheDocument();
    expect(screen.getByText(/install-agent\.sh/)).toBeInTheDocument();
    expect(
      screen.getByText('Step 2: Create a bootstrap token')
    ).toBeInTheDocument();
    expect(screen.getByLabelText(/^Name/)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Expires/)).toBeInTheDocument();
  });

  it('creates a token, shows the one-time secret, and keeps it out of the install command', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    createBootstrapTokenMock.mockResolvedValue({
      token: { id: 'bt-1', name: 'dc1-edge' },
      plaintextToken: 'ttboot_secret_value',
    });

    renderModal();

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
    // Downtime alerts default to enabled with the workspace default group.
    expect(payload.downtimeAlertsEnabled).toBe(true);
    expect(payload.contactGroupId).toBe(null);

    expect(
      await screen.findByText(/shown only once and registers exactly one agent/)
    ).toBeInTheDocument();
    expect(screen.getAllByText(/ttboot_secret_value/)).toHaveLength(1);

    const commandBlock = screen.getByText(/install-agent\.sh/);
    expect(commandBlock.textContent).toContain('--api-url');
    expect(commandBlock.textContent).toContain("--workspace-id 'ws-1'");
    expect(commandBlock.textContent).not.toContain('ttboot_secret_value');
    expect(commandBlock.textContent).not.toContain('--bootstrap-token');
  });

  it('refuses to close while the secret is unacknowledged, via the footer button and the Modal itself', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    createBootstrapTokenMock.mockResolvedValue({
      token: { id: 'bt-1', name: 'dc1-edge' },
      plaintextToken: 'ttboot_secret_value',
    });
    const onClose = vi.fn();

    renderModal({ onClose });

    fireEvent.change(screen.getByLabelText(/^Name/), {
      target: { value: 'dc1-edge' },
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Create bootstrap token' })
    );
    await screen.findByText(/shown only once and registers exactly one agent/);

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onClose).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: 'I have saved this token' }));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('detects an agent that registered before the first poll via the token-creation baseline', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAgentsMock.mockReturnValue(
      agentsState({
        agents: [{ id: 'row-existing', agentId: 'agent-existing' }],
      })
    );
    createBootstrapTokenMock.mockResolvedValue({
      token: { id: 'bt-1', name: 'dc1-edge' },
      plaintextToken: 'ttboot_secret_value',
    });
    listAgentsMock.mockResolvedValue(
      agentListResponse([
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
      ])
    );

    renderModal();

    await createTokenAndAcknowledge();
    fireEvent.click(
      screen.getByRole('button', { name: 'I pasted the token, start watching' })
    );

    expect(await screen.findByText(/is now connected/)).toBeInTheDocument();
    expect(listAgentsMock).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/dc1-edge/)).toBeInTheDocument();
  });

  it('calls onAgentRegistered once the fresh agent is detected, so the fleet panel can refetch immediately', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    createBootstrapTokenMock.mockResolvedValue({
      token: { id: 'bt-1', name: 'dc1-edge' },
      plaintextToken: 'ttboot_secret_value',
    });
    listAgentsMock.mockResolvedValue(
      agentListResponse([
        {
          id: 'row-1',
          agentId: 'agent-1',
          name: 'dc1-edge',
          status: 'active',
          createdAt: new Date(Date.now() + 60000).toISOString(),
        },
      ])
    );
    const onAgentRegistered = vi.fn();

    renderModal({ onAgentRegistered });

    await createTokenAndAcknowledge();
    fireEvent.click(
      screen.getByRole('button', { name: 'I pasted the token, start watching' })
    );

    await screen.findByText(/is now connected/);
    expect(onAgentRegistered).toHaveBeenCalledTimes(1);
  });

  it('resets the wizard for a second deployment via "Deploy another agent"', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    createBootstrapTokenMock.mockResolvedValue({
      token: { id: 'bt-1', name: 'dc1-edge' },
      plaintextToken: 'ttboot_secret_value',
    });
    listAgentsMock.mockResolvedValue(
      agentListResponse([
        {
          id: 'row-1',
          agentId: 'agent-1',
          name: 'dc1-edge',
          status: 'active',
          createdAt: new Date(Date.now() + 60000).toISOString(),
        },
      ])
    );

    renderModal();

    await createTokenAndAcknowledge();
    fireEvent.click(
      screen.getByRole('button', { name: 'I pasted the token, start watching' })
    );
    await screen.findByText(/is now connected/);

    fireEvent.click(screen.getByRole('button', { name: 'Deploy another agent' }));

    expect(screen.queryByText(/is now connected/)).not.toBeInTheDocument();
    expect(screen.getByLabelText(/^Name/)).toHaveValue('');
  });

  it('cancels the registration poll on unmount', async () => {
    const clearIntervalSpy = vi.spyOn(window, 'clearInterval');
    useCertOpsCanManageMock.mockReturnValue(true);
    createBootstrapTokenMock.mockResolvedValue({
      token: { id: 'bt-1', name: 'dc1-edge' },
      plaintextToken: 'ttboot_secret_value',
    });
    listAgentsMock.mockResolvedValue(agentListResponse([]));

    const { unmount } = renderModal();

    await createTokenAndAcknowledge();
    fireEvent.click(
      screen.getByRole('button', { name: 'I pasted the token, start watching' })
    );

    await waitFor(() => expect(listAgentsMock).toHaveBeenCalledTimes(1));
    const callsBeforeUnmount = listAgentsMock.mock.calls.length;

    unmount();
    expect(clearIntervalSpy).toHaveBeenCalled();

    // Any poll already in flight must not schedule further work once
    // unmounted; a stray tick here would mean the interval outlived the
    // component.
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(listAgentsMock).toHaveBeenCalledTimes(callsBeforeUnmount);

    clearIntervalSpy.mockRestore();
  });

  it('switches step 1 to the Windows install command when the Windows toggle is selected', () => {
    useCertOpsCanManageMock.mockReturnValue(true);

    renderModal();

    expect(screen.getByText(/install-agent\.sh/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Windows' }));

    const commandBlock = screen.getByText(/install-agent\.ps1/);
    expect(commandBlock.textContent).toContain('--api-url');
    expect(commandBlock.textContent).toContain("--workspace-id 'ws-1'");
    expect(commandBlock.textContent).not.toContain('install-agent.sh');
    expect(
      screen.getByText(/elevated \(Administrator\) PowerShell prompt/)
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Linux' }));
    expect(screen.getByText(/install-agent\.sh/)).toBeInTheDocument();
  });

  it('disables new-token creation while paused but keeps the flow otherwise visible', () => {
    useCertOpsCanManageMock.mockReturnValue(true);

    renderModal({ certOpsPaused: true });

    expect(
      screen.getByText(/Certificate operations are paused for this workspace/)
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Create bootstrap token' })
    ).toBeDisabled();
  });

  it('shows the downtime alert checkbox checked by default with a contact group selector', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);

    renderModal();

    const checkbox = screen.getByRole('checkbox', {
      name: 'Agent downtime alerts',
    });
    expect(checkbox).toBeChecked();
    await waitFor(() => {
      expect(getAlertSettingsMock).toHaveBeenCalledWith('ws-1');
    });
    expect(
      await screen.findByRole('option', { name: 'On-call (default)' })
    ).toBeInTheDocument();
  });

  it('hides the contact group selector once downtime alerts are unchecked, and sends the unchecked state', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    createBootstrapTokenMock.mockResolvedValue({
      token: { id: 'bt-1', name: 'dc1-edge' },
      plaintextToken: 'ttboot_secret_value',
    });

    renderModal();

    fireEvent.click(
      screen.getByRole('checkbox', { name: 'Agent downtime alerts' })
    );
    expect(screen.queryByLabelText('Contact group')).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/^Name/), {
      target: { value: 'dc1-edge' },
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Create bootstrap token' })
    );

    await waitFor(() => {
      expect(createBootstrapTokenMock).toHaveBeenCalledTimes(1);
    });
    const [, payload] = createBootstrapTokenMock.mock.calls[0];
    expect(payload.downtimeAlertsEnabled).toBe(false);
  });

  it('sends the explicitly selected contact group id', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    createBootstrapTokenMock.mockResolvedValue({
      token: { id: 'bt-1', name: 'dc1-edge' },
      plaintextToken: 'ttboot_secret_value',
    });

    renderModal();

    await screen.findByRole('option', { name: 'On-call (default)' });
    fireEvent.change(screen.getByLabelText('Contact group'), {
      target: { value: 'g1' },
    });
    fireEvent.change(screen.getByLabelText(/^Name/), {
      target: { value: 'dc1-edge' },
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Create bootstrap token' })
    );

    await waitFor(() => {
      expect(createBootstrapTokenMock).toHaveBeenCalledTimes(1);
    });
    const [, payload] = createBootstrapTokenMock.mock.calls[0];
    expect(payload.contactGroupId).toBe('g1');
  });
});
