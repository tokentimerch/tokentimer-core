import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import AssistantConnectionsPanel from '../../src/components/certops/AssistantConnectionsPanel.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const mocks = vi.hoisted(() => ({
  workspace: 'workspace-a',
  manage: true,
  admin: true,
  load: vi.fn(),
  create: vi.fn(),
  revoke: vi.fn(),
  writes: vi.fn(),
}));
vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: mocks.workspace }),
}));
vi.mock('../../src/utils/apiClient.js', () => ({
  API_BASE_URL: 'https://api.example.test/prefix',
}));
vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsCanManage: () => mocks.manage,
  useCertOpsIsWorkspaceAdmin: () => mocks.admin,
}));
vi.mock('../../src/components/certops/assistantConnectionsApi.js', () => ({
  loadAssistantConnections: mocks.load,
  createAssistantSetup: mocks.create,
  revokeAssistantAccess: mocks.revoke,
  setAssistantWrites: mocks.writes,
}));

const empty = () => ({
  writesEnabled: false,
  connections: [],
  enrollments: [],
});
const grant = () => ({
  grant: 'SYNTHETIC_ONE_TIME_CODE',
  enrollment: {
    id: 'setup-a',
    name: 'My local assistant',
    status: 'pending',
    expiresAt: new Date(Date.now() + 600000).toISOString(),
  },
});
function ui() {
  return (
    <ChakraProvider>
      <DashboardThemeProvider>
        <AssistantConnectionsPanel userId={42} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}
async function openSetup() {
  fireEvent.click(
    await screen.findByRole('button', { name: 'Connect an MCP assistant' })
  );
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
}
async function createCode() {
  await openSetup();
  fireEvent.click(screen.getByRole('button', { name: 'Create setup code' }));
  await screen.findByLabelText('One-time setup code');
}
beforeEach(() => {
  localStorage.clear();
  mocks.workspace = 'workspace-a';
  mocks.manage = true;
  mocks.admin = true;
  vi.clearAllMocks();
  mocks.load.mockResolvedValue(empty());
  mocks.create.mockResolvedValue(grant());
  mocks.writes.mockResolvedValue(true);
  mocks.revoke.mockResolvedValue();
});

describe('MCP assistant setup', () => {
  it('grants issuance only when explicitly selected', async () => {
    render(ui());
    await openSetup();
    const issue = screen.getByLabelText('Allow certificate issuance requests');
    expect(issue).not.toBeChecked();
    fireEvent.click(issue);
    expect(
      screen.getByText(/Renewal and issuance requests include agent health/)
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /create setup code/i }));
    await screen.findByLabelText('One-time setup code');
    const scopes = mocks.create.mock.calls[0][1].scopes;
    expect(scopes).toContain('mcp:issue:request');
    expect(scopes).toContain('mcp:agents:read');
    expect(scopes).not.toContain('mcp:renew:request');
  });
  it('grants viewer invitations only when explicitly selected', async () => {
    render(ui());
    await openSetup();
    const invite = screen.getByLabelText('Review and invite viewers by email');
    expect(invite).not.toBeChecked();
    fireEvent.click(invite);
    fireEvent.click(screen.getByRole('button', { name: 'Create setup code' }));
    await screen.findByLabelText('One-time setup code');
    const scopes = mocks.create.mock.calls[0][1].scopes;
    expect(scopes).toContain('mcp:members:invite');
    expect(scopes).not.toContain('mcp:groups:create');
  });
  it('grants contact group access only when explicitly selected', async () => {
    render(ui());
    await openSetup();
    const group = screen.getByLabelText(
      'Create contact groups and list recipient names'
    );
    expect(group).not.toBeChecked();
    fireEvent.click(group);
    fireEvent.click(screen.getByRole('button', { name: 'Create setup code' }));
    await screen.findByLabelText('One-time setup code');
    const scopes = mocks.create.mock.calls[0][1].scopes;
    expect(scopes).toContain('mcp:groups:create');
    expect(scopes).not.toContain('mcp:contacts:create');
  });
  it('grants webhook creation only when explicitly selected', async () => {
    render(ui());
    await openSetup();
    const webhook = screen.getByLabelText('Allow reviewed webhook creation');
    expect(webhook).not.toBeChecked();
    fireEvent.click(webhook);
    fireEvent.click(screen.getByRole('button', { name: 'Create setup code' }));
    await screen.findByLabelText('One-time setup code');
    const scopes = mocks.create.mock.calls[0][1].scopes;
    expect(scopes).toContain('mcp:webhooks:create');
    expect(scopes).not.toContain('mcp:contacts:create');
  });
  it('compares methods in one dialog before offering connection details', async () => {
    mocks.load.mockResolvedValue({
      ...empty(),
      remote: {
        enabled: true,
        serverUrl: 'https://api.example.test/api/v1/operator/mcp',
      },
    });
    render(ui());
    fireEvent.click(
      await screen.findByRole('button', { name: 'Connect an MCP assistant' })
    );
    expect(screen.getByRole('radio', { name: /Remote HTTP/ })).toBeChecked();
    expect(
      screen.getByRole('radio', { name: 'Local adapter (stdio)' })
    ).not.toBeChecked();
    expect(
      screen.getByText(/Requires a client supporting Streamable HTTP and OAuth/)
    ).toBeInTheDocument();
    expect(
      screen.getByRole('link', {
        name: /MCP setup guide and client requirements/,
      })
    ).toHaveAttribute('href', expect.stringContaining('/docs/api/mcp-setup'));
    expect(screen.queryByLabelText('MCP server URL')).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole('radio', { name: 'Local adapter (stdio)' })
    );
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(screen.getByLabelText('Allow certificate renewal requests')).not.toBeChecked();
    expect(screen.getByLabelText('Access level')).toHaveValue('read-only');
    expect(
      screen.getByRole('button', { name: 'Create setup code' })
    ).toBeInTheDocument();
    expect(mocks.create).not.toHaveBeenCalled();
  });
  it('copies a remote URL without creating a setup code or requiring Node', async () => {
    const writeText = vi.fn().mockResolvedValue();
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    mocks.load.mockResolvedValue({
      ...empty(),
      remote: {
        enabled: true,
        serverUrl: 'https://api.example.test/api/v1/operator/mcp',
      },
    });
    render(ui());
    await openSetup();
    expect(await screen.findByLabelText('MCP server URL')).toHaveValue(
      'https://api.example.test/api/v1/operator/mcp'
    );
    fireEvent.click(screen.getByRole('button', { name: 'Copy server URL' }));
    await screen.findByText(/Server URL copied/);
    expect(writeText).toHaveBeenCalledWith(
      'https://api.example.test/api/v1/operator/mcp'
    );
    expect(mocks.create).not.toHaveBeenCalled();
  });
  it('can include manager-only agent reads without granting renewal permission', async () => {
    render(ui());
    await openSetup();
    fireEvent.click(screen.getByLabelText('View CertOps agent health'));
    fireEvent.click(screen.getByRole('button', { name: 'Create setup code' }));
    await screen.findByLabelText('One-time setup code');
    const input = mocks.create.mock.calls[0][1];
    expect(input.roleCeiling).toBe('workspace_manager');
    expect(input.scopes).toContain('mcp:agents:read');
    expect(input.scopes).not.toContain('mcp:renew:request');
    expect(input.scopes).not.toContain('mcp:requests:read');
  });
  it('does not load anything without an active workspace', () => {
    mocks.workspace = null;
    render(ui());
    expect(mocks.load).not.toHaveBeenCalled();
  });
  it('shows server unavailability without offering creation', async () => {
    mocks.load.mockRejectedValue({ response: { status: 404 } });
    render(ui());
    await screen.findByText(/MCP interface is not enabled/);
    expect(
      screen.queryByRole('button', { name: 'Connect an MCP assistant' })
    ).not.toBeInTheDocument();
  });
  it('distinguishes plan or role refusal and can retry an outage', async () => {
    mocks.load
      .mockRejectedValueOnce({ response: { status: 403 } })
      .mockResolvedValue(empty());
    render(ui());
    await screen.findByText(/Check your role and plan/);
    fireEvent.click(screen.getByRole('button', { name: 'Retry connections' }));
    await screen.findByRole('button', { name: 'Connect an MCP assistant' });
  });
  it('creates read-only access by default and masks the one-time secret', async () => {
    render(ui());
    await createCode();
    expect(mocks.create).toHaveBeenCalledWith('workspace-a', {
      name: 'My local assistant',
      scopes: [
        'mcp:identity:read',
        'mcp:certs:read',
        'mcp:jobs:read',
        'mcp:tokens:read',
      ],
      roleCeiling: 'viewer',
      connectionLifetimeDays: 30,
    });
    expect(screen.getByLabelText('One-time setup code')).toHaveAttribute(
      'type',
      'password'
    );
    expect(
      screen.queryByText('SYNTHETIC_ONE_TIME_CODE')
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/node packages\/mcp\/bin\/tokentimer-mcp.js enroll/)
        .textContent
    ).toContain('https://api.example.test/prefix');
  });
  it('uses explicit renewal consent, bounded role and selected lifetime', async () => {
    render(ui());
    await openSetup();
    fireEvent.change(screen.getByLabelText('Connection name'), {
      target: { value: ' My laptop ' },
    });
    fireEvent.change(screen.getByLabelText('Connection expires after'), {
      target: { value: '7' },
    });
    fireEvent.click(screen.getByLabelText('Allow certificate renewal requests'));
    fireEvent.click(screen.getByRole('button', { name: 'Create setup code' }));
    await screen.findByLabelText('One-time setup code');
    expect(mocks.create).toHaveBeenCalledWith(
      'workspace-a',
      expect.objectContaining({
        name: 'My laptop',
        roleCeiling: 'workspace_manager',
        connectionLifetimeDays: 7,
        scopes: expect.arrayContaining(['mcp:renew:request']),
      })
    );
  });
  it('does not show renewal consent or the workspace switch to a viewer', async () => {
    mocks.manage = false;
    mocks.admin = false;
    render(ui());
    await openSetup();
    expect(
      screen.queryByLabelText('Allow certificate renewal requests')
    ).not.toBeInTheDocument();
    expect(
      screen.queryByLabelText('Allow MCP renewal requests')
    ).not.toBeInTheDocument();
  });
  it('requires an explicit acknowledgement before creating a non-expiring local connection', async () => {
    render(ui());
    await openSetup();
    fireEvent.change(screen.getByLabelText('Connection expires after'), {
      target: { value: 'never' },
    });
    expect(
      screen.getByRole('button', { name: 'Create setup code' })
    ).toBeDisabled();
    fireEvent.click(
      screen.getByLabelText('Keep this connection active until I revoke it.')
    );
    fireEvent.click(screen.getByRole('button', { name: 'Create setup code' }));
    await screen.findByLabelText('One-time setup code');
    expect(mocks.create.mock.calls[0][1]).toMatchObject({ noExpiry: true });
    expect(mocks.create.mock.calls[0][1]).not.toHaveProperty(
      'connectionLifetimeDays'
    );
  });
  it('lets a manager return to read-only without write permission', async () => {
    render(ui());
    await openSetup();
    fireEvent.change(screen.getByLabelText('Access level'), {
      target: { value: 'read-write' },
    });
    fireEvent.click(
      screen.getByRole('checkbox', { name: /Allow certificate renewal requests/ })
    );
    fireEvent.change(screen.getByLabelText('Access level'), {
      target: { value: 'read-only' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create setup code' }));
    await screen.findByLabelText('One-time setup code');
    expect(mocks.create.mock.calls[0][1].scopes).not.toContain(
      'mcp:inventory:import'
    );
    expect(mocks.create.mock.calls[0][1].scopes).not.toContain(
      'mcp:renew:request'
    );
  });
  it('allows inventory import without renewal or agent-health permission', async () => {
    render(ui());
    await openSetup();
    fireEvent.change(screen.getByLabelText('Access level'), {
      target: { value: 'read-write' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create setup code' }));
    await screen.findByLabelText('One-time setup code');
    expect(mocks.create.mock.calls[0][1]).toMatchObject({
      roleCeiling: 'workspace_manager',
      scopes: expect.arrayContaining(['mcp:inventory:import']),
    });
    expect(mocks.create.mock.calls[0][1].scopes).not.toContain(
      'mcp:renew:request'
    );
    expect(mocks.create.mock.calls[0][1].scopes).not.toContain(
      'mcp:agents:read'
    );
  });
  it('grants inventory updates only after the separate checkbox is selected', async () => {
    render(ui());
    await openSetup();
    fireEvent.change(screen.getByLabelText('Access level'), {
      target: { value: 'read-write' },
    });
    const update = screen.getByLabelText('Allow reviewed inventory updates');
    expect(update).not.toBeChecked();
    fireEvent.click(update);
    fireEvent.click(screen.getByRole('button', { name: 'Create setup code' }));
    await screen.findByLabelText('One-time setup code');
    expect(mocks.create.mock.calls[0][1].scopes).toContain(
      'mcp:inventory:update'
    );
  });
  it('allows inventory updates without import or renewal permission', async () => {
    render(ui());
    await openSetup();
    fireEvent.click(screen.getByLabelText('Allow reviewed inventory updates'));
    fireEvent.click(screen.getByRole('button', { name: 'Create setup code' }));
    await screen.findByLabelText('One-time setup code');
    const scopes = mocks.create.mock.calls[0][1].scopes;
    expect(scopes).toContain('mcp:inventory:update');
    expect(scopes).not.toContain('mcp:inventory:import');
    expect(scopes).not.toContain('mcp:renew:request');
  });
  it('grants contact creation only when explicitly selected', async () => {
    render(ui());
    await openSetup();
    const contact = screen.getByLabelText('Allow reviewed contact creation');
    expect(contact).not.toBeChecked();
    fireEvent.click(contact);
    fireEvent.click(screen.getByRole('button', { name: 'Create setup code' }));
    await screen.findByLabelText('One-time setup code');
    const scopes = mocks.create.mock.calls[0][1].scopes;
    expect(scopes).toContain('mcp:contacts:create');
    expect(scopes).not.toContain('mcp:inventory:import');
  });
  it('returns renewal-only access to read-only', async () => {
    render(ui());
    await openSetup();
    const access = screen.getByLabelText('Access level');
    expect(access).toHaveValue('read-only');
    fireEvent.click(screen.getByLabelText('Allow certificate renewal requests'));
    expect(access).toHaveValue('read-write');
    expect(
      screen.getByText(/Renewal and issuance requests include agent health/)
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/Read-write adds reviewed inventory metadata imports/)
    ).not.toBeInTheDocument();
    fireEvent.change(access, { target: { value: 'read-only' } });
    expect(screen.getByLabelText('Allow certificate renewal requests')).not.toBeChecked();
    expect(
      screen.queryByText(/Renewal and issuance requests include agent health/)
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Create setup code' }));
    await screen.findByLabelText('One-time setup code');
    expect(mocks.create.mock.calls[0][1].scopes).not.toContain(
      'mcp:inventory:import'
    );
    expect(mocks.create.mock.calls[0][1].scopes).not.toContain(
      'mcp:renew:request'
    );
  });
  it('clears the code on close and keeps the pending code revocable', async () => {
    render(ui());
    await createCode();
    fireEvent.click(screen.getByRole('button', { name: 'Close', exact: true }));
    await waitFor(() =>
      expect(
        screen.queryByLabelText('One-time setup code')
      ).not.toBeInTheDocument()
    );
    mocks.load.mockResolvedValue({
      ...empty(),
      enrollments: [grant().enrollment],
    });
    fireEvent.click(screen.getByRole('button', { name: 'Manage connections' }));
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Revoke setup code' })
      ).toBeEnabled()
    );
    fireEvent.click(screen.getByRole('button', { name: 'Revoke setup code' }));
    await waitFor(() =>
      expect(mocks.revoke).toHaveBeenCalledWith(
        'workspace-a',
        'enrollments',
        'setup-a'
      )
    );
  });
  it('confirms redemption using fresh server state and removes the secret', async () => {
    render(ui());
    await createCode();
    mocks.load.mockResolvedValue({
      ...empty(),
      enrollments: [{ ...grant().enrollment, status: 'redeemed' }],
    });
    fireEvent.click(screen.getByRole('button', { name: 'Check connection' }));
    await screen.findByText(/Connection created\. Add the configuration/);
    await waitFor(() =>
      expect(
        screen.queryByLabelText('One-time setup code')
      ).not.toBeInTheDocument()
    );
  });
  it('does not claim success or retry automatically after an uncertain create', async () => {
    mocks.create.mockRejectedValue(new Error('lost response'));
    render(ui());
    await openSetup();
    fireEvent.click(screen.getByRole('button', { name: 'Create setup code' }));
    await screen.findByText(/Setup could not be confirmed/);
    expect(mocks.create).toHaveBeenCalledTimes(1);
    expect(
      screen.getByRole('button', { name: 'Create setup code' })
    ).toBeDisabled();
  });
  it('requires a name before creation', async () => {
    render(ui());
    await openSetup();
    fireEvent.change(screen.getByLabelText('Connection name'), {
      target: { value: '   ' },
    });
    expect(
      screen.getByRole('button', { name: 'Create setup code' })
    ).toBeDisabled();
  });
  it('removes expired setup codes from the dialog', async () => {
    mocks.create.mockResolvedValue({
      ...grant(),
      enrollment: {
        ...grant().enrollment,
        expiresAt: new Date(Date.now() - 1).toISOString(),
      },
    });
    render(ui());
    await openSetup();
    fireEvent.click(screen.getByRole('button', { name: 'Create setup code' }));
    await screen.findByText(/The setup code expired/);
    expect(
      screen.queryByLabelText('One-time setup code')
    ).not.toBeInTheDocument();
  });
  it('does not show old workspace state when an earlier request resolves late', async () => {
    let resolveOld;
    mocks.load.mockImplementationOnce(
      () =>
        new Promise(resolve => {
          resolveOld = resolve;
        })
    );
    const view = render(ui());
    mocks.workspace = 'workspace-b';
    view.rerender(ui());
    await screen.findByRole('button', { name: 'Connect an MCP assistant' });
    await act(async () =>
      resolveOld({
        ...empty(),
        connections: [
          {
            id: 'old',
            name: 'PRIVATE OLD WORKSPACE',
            scopes: [],
            status: 'active',
          },
        ],
      })
    );
    expect(screen.queryByText('PRIVATE OLD WORKSPACE')).not.toBeInTheDocument();
  });
  it('clears secret-bearing dialog state immediately on workspace switch', async () => {
    const view = render(ui());
    await createCode();
    mocks.workspace = 'workspace-b';
    view.rerender(ui());
    expect(
      screen.queryByLabelText('One-time setup code')
    ).not.toBeInTheDocument();
    await screen.findByRole('button', { name: 'Connect an MCP assistant' });
  });
  it('shows agent health in the connection permission summary', async () => {
    mocks.load.mockResolvedValue({
      ...empty(),
      connections: [
        {
          id: 'agent-only',
          name: 'Agent reader',
          status: 'active',
          scopes: ['mcp:agents:read'],
          expiresAt: null,
          lastUsedAt: null,
        },
      ],
    });
    render(ui());
    fireEvent.click(
      await screen.findByRole('button', { name: 'Manage connections' })
    );
    expect(screen.getByText(/Read \+ agent health/)).toBeInTheDocument();
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Revoke connection' })
      ).toBeEnabled()
    );
  });
  it('shows last use and revocation for an active connection', async () => {
    mocks.load.mockResolvedValue({
      ...empty(),
      connections: [
        {
          id: 'connection-a',
          name: 'My laptop',
          status: 'active',
          scopes: [],
          expiresAt: new Date(Date.now() + 86400000).toISOString(),
          lastUsedAt: null,
        },
      ],
    });
    render(ui());
    fireEvent.click(
      await screen.findByRole('button', { name: 'Manage connections' })
    );
    expect(screen.getByText('Last used: Not used yet')).toBeInTheDocument();
    expect(mocks.load).toHaveBeenCalledTimes(2);
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Revoke connection' })
      ).toBeEnabled()
    );
    fireEvent.click(
      await screen.findByRole('button', { name: 'Revoke connection' })
    );
    await waitFor(() =>
      expect(mocks.revoke).toHaveBeenCalledWith(
        'workspace-a',
        'connections',
        'connection-a'
      )
    );
  });
  it('disables new actions after a failed refresh instead of retaining authority', async () => {
    render(ui());
    await screen.findByRole('button', { name: 'Connect an MCP assistant' });
    mocks.load.mockRejectedValue(new Error('offline'));
    fireEvent.click(screen.getByRole('button', { name: 'Manage connections' }));
    await screen.findByText(/Could not load assistant access/);
    expect(
      screen.queryByRole('button', { name: 'Connect an MCP assistant' })
    ).not.toBeInTheDocument();
  });
  it('keeps an uncertain revocation unavailable until a fresh server read', async () => {
    const connection = {
      id: 'connection-a',
      name: 'My laptop',
      status: 'active',
      scopes: [],
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      lastUsedAt: null,
    };
    mocks.load.mockResolvedValue({ ...empty(), connections: [connection] });
    mocks.revoke.mockRejectedValue(new Error('lost response'));
    render(ui());
    expect(screen.queryByText('My laptop')).not.toBeInTheDocument();
    fireEvent.click(
      await screen.findByRole('button', { name: 'Manage connections' })
    );
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Revoke connection' })
      ).toBeEnabled()
    );
    fireEvent.click(screen.getByRole('button', { name: 'Revoke connection' }));
    await screen.findByText(/Could not confirm revocation/);
    expect(
      screen.queryByRole('button', { name: 'Revoke connection' })
    ).not.toBeInTheDocument();
    mocks.load.mockResolvedValue({
      ...empty(),
      connections: [{ ...connection, status: 'revoked' }],
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Refresh connections' })
    );
    await screen.findByText('revoked');
    expect(mocks.revoke).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: 'Done' }));
    await waitFor(() =>
      expect(
        screen.queryByRole('button', { name: 'Refresh connections' })
      ).not.toBeInTheDocument()
    );
  });
  it('keeps workspace renewal policy out of personal preferences', async () => {
    render(ui());
    await screen.findByRole('button', { name: 'Connect an MCP assistant' });
    expect(
      screen.queryByLabelText('Allow MCP renewal requests')
    ).not.toBeInTheDocument();
  });
});
