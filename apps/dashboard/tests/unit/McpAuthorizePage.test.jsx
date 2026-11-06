import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import McpAuthorizePage from '../../src/pages/McpAuthorizePage.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import { mcpAuthorizationReturnTo } from '../../src/utils/mcpAuthorization.js';
import { rememberMcpSetupPreference } from '../../src/utils/mcpSetupPreference.js';

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock('../../src/utils/apiClient.js', () => ({ default: mocks }));
vi.mock('../../src/components/SEO.jsx', () => ({ default: () => null }));
const requestId = 'a9f49469-0c47-4ac2-a1bc-a7dcbd7edab8';
const details = () => ({
  clientName: 'My assistant',
  clientId: 'ttmc_public',
  redirectOrigin: 'http://127.0.0.1:4790',
  identityVerified: false,
  expiresAt: new Date(Date.now() + 600000).toISOString(),
  workspaces: [
    { id: 'one', name: 'Certificates', canRequestRenewals: true },
    { id: 'two', name: 'Viewer workspace', canRequestRenewals: false },
  ],
});
const account = { id: 42, email: 'operator@example.test' };
function ui(session = account) {
  return (
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter initialEntries={['/mcp/authorize?request=' + requestId]}>
          <McpAuthorizePage session={session} />
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}
beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  mocks.get.mockResolvedValue({ data: details() });
  mocks.post.mockRejectedValue({
    response: { data: { error: 'plan_required' } },
  });
});
describe('remote MCP consent', () => {
  it('requires separate consent for issuance and clears it on workspace change', async () => {
    render(ui());
    await screen.findByText('My assistant');
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'one' },
    });
    const issue = screen.getByLabelText('Allow certificate issuance requests');
    expect(issue).not.toBeChecked();
    fireEvent.click(issue);
    expect(screen.getByLabelText('Include agent health')).toBeChecked();
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'two' },
    });
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'one' },
    });
    expect(
      screen.getByLabelText('Allow certificate issuance requests')
    ).not.toBeChecked();
  });
  it('requires separate consent for viewer invitations and clears it on workspace change', async () => {
    render(ui());
    await screen.findByText('My assistant');
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'one' },
    });
    const invite = screen.getByLabelText('Review and invite viewers by email');
    expect(invite).not.toBeChecked();
    fireEvent.click(invite);
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'two' },
    });
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'one' },
    });
    expect(
      screen.getByLabelText('Review and invite viewers by email')
    ).not.toBeChecked();
  });
  it('requires separate consent for contact groups and clears it on workspace change', async () => {
    render(ui());
    await screen.findByText('My assistant');
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'one' },
    });
    const group = screen.getByLabelText(
      'Create contact groups and list recipient names'
    );
    expect(group).not.toBeChecked();
    fireEvent.click(group);
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'two' },
    });
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'one' },
    });
    expect(
      screen.getByLabelText('Create contact groups and list recipient names')
    ).not.toBeChecked();
  });
  it('requires separate consent to create webhooks and clears it with read-only access', async () => {
    render(ui());
    await screen.findByText('My assistant');
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'one' },
    });
    const webhook = screen.getByLabelText('Allow reviewed webhook creation');
    expect(webhook).not.toBeChecked();
    fireEvent.click(webhook);
    fireEvent.change(screen.getByLabelText('Access level'), {
      target: { value: 'read-only' },
    });
    expect(webhook).not.toBeChecked();
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
    await waitFor(() =>
      expect(mocks.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ webhookCreate: false }),
        expect.any(Object)
      )
    );
  });
  it('requires separate consent to create contacts and clears it with read-only access', async () => {
    render(ui());
    await screen.findByText('My assistant');
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'one' },
    });
    const contact = screen.getByLabelText('Allow reviewed contact creation');
    expect(contact).not.toBeChecked();
    fireEvent.click(contact);
    fireEvent.change(screen.getByLabelText('Access level'), {
      target: { value: 'read-only' },
    });
    expect(contact).not.toBeChecked();
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
    await waitFor(() =>
      expect(mocks.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ contactCreate: false }),
        expect.any(Object)
      )
    );
  });
  it('can authorize inventory updates without granting import or renewal', async () => {
    render(ui());
    await screen.findByText('My assistant');
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'one' },
    });
    fireEvent.change(screen.getByLabelText('Access level'), {
      target: { value: 'read-write' },
    });
    fireEvent.click(screen.getByLabelText('Allow reviewed inventory updates'));
    fireEvent.click(screen.getByLabelText('Allow reviewed inventory imports'));
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
    await waitFor(() =>
      expect(mocks.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          inventoryUpdate: true,
          inventoryImport: false,
          renewals: false,
        }),
        expect.any(Object)
      )
    );
  });
  it('suggests setup choices but requires explicit consent and clears writes on a workspace change', async () => {
    rememberMcpSetupPreference({
      userId: account.id,
      workspaceId: 'one',
      renewals: true,
      agentHealth: true,
      lifetimeDays: 7,
    });
    render(ui());
    await screen.findByText('My assistant');
    expect(screen.getByRole('combobox', { name: /Workspace/ })).toHaveValue(
      'one'
    );
    expect(screen.getByLabelText('Allow renewal requests')).toBeChecked();
    expect(screen.getByLabelText('Access expires after')).toHaveValue('7');
    expect(mocks.post).not.toHaveBeenCalled();
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'two' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
    await waitFor(() =>
      expect(mocks.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          workspaceId: 'two',
          renewals: false,
          agentHealth: false,
        }),
        expect.any(Object)
      )
    );
  });
  it('preserves consent through sign-in when the workspace context adds a URL parameter', async () => {
    function ReturnDestination() {
      return (
        <span>{new URLSearchParams(useLocation().search).get('returnTo')}</span>
      );
    }
    render(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MemoryRouter
            initialEntries={[
              '/mcp/authorize?request=' +
                requestId +
                '&workspace=global-workspace',
            ]}
          >
            <Routes>
              <Route
                path='/mcp/authorize'
                element={<McpAuthorizePage session={null} />}
              />
              <Route path='/login' element={<ReturnDestination />} />
            </Routes>
          </MemoryRouter>
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    await screen.findByText('/mcp/authorize?request=' + requestId);
    expect(mocks.get).not.toHaveBeenCalled();
  });
  it('requires a workspace and starts with read-only, time-bounded access', async () => {
    render(ui());
    await screen.findByText('My assistant');
    expect(screen.getByRole('button', { name: 'Connect' })).toBeDisabled();
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'one' },
    });
    expect(screen.getByLabelText('Allow renewal requests')).not.toBeChecked();
    expect(screen.getByLabelText('Include agent health')).not.toBeChecked();
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
    await screen.findByText(/plan does not include MCP/);
    expect(mocks.post).toHaveBeenCalledWith(
      expect.stringContaining('/decision'),
      {
        decision: 'approve',
        workspaceId: 'one',
        lifetimeDays: 30,
        renewals: false,
        agentHealth: false,
        inventoryImport: false,
        inventoryUpdate: false,
        contactCreate: false,
        webhookCreate: false,
        groupCreate: false,
        memberInvite: false,
        issuance: false,
      },
      expect.any(Object)
    );
  });
  it('requires a separate choice for inventory updates and clears it on workspace change', async () => {
    render(ui());
    await screen.findByText('My assistant');
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'one' },
    });
    fireEvent.change(screen.getByLabelText('Access level'), {
      target: { value: 'read-write' },
    });
    const update = screen.getByLabelText('Allow reviewed inventory updates');
    expect(update).not.toBeChecked();
    fireEvent.click(update);
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'two' },
    });
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'one' },
    });
    expect(
      screen.getByLabelText('Allow reviewed inventory updates')
    ).not.toBeChecked();
  });
  it('shows agent health included in renewals and clears permissions on workspace change', async () => {
    render(ui());
    await screen.findByText('My assistant');
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'one' },
    });
    fireEvent.click(screen.getByLabelText('Allow renewal requests'));
    expect(screen.getByLabelText('Include agent health')).toBeChecked();
    expect(screen.getByLabelText('Include agent health')).toBeDisabled();
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'two' },
    });
    expect(
      screen.queryByLabelText('Allow renewal requests')
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
    await waitFor(() =>
      expect(mocks.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          workspaceId: 'two',
          renewals: false,
          agentHealth: false,
        }),
        expect.any(Object)
      )
    );
  });
  it('requires a fresh risk acknowledgement for non-expiring access, even when setup suggested it', async () => {
    rememberMcpSetupPreference({
      userId: account.id,
      workspaceId: 'one',
      lifetimeDays: null,
      noExpiry: true,
    });
    render(ui());
    await screen.findByText('My assistant');
    expect(screen.getByLabelText('Access expires after')).toHaveValue('never');
    expect(screen.getByRole('button', { name: 'Connect' })).toBeDisabled();
    fireEvent.click(
      screen.getByLabelText('Keep this connection active until I revoke it.')
    );
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
    await waitFor(() =>
      expect(mocks.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ noExpiry: true, lifetimeDays: null }),
        expect.any(Object)
      )
    );
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'two' },
    });
    expect(
      screen.getByLabelText('Keep this connection active until I revoke it.')
    ).not.toBeChecked();
    expect(screen.getByRole('button', { name: 'Connect' })).toBeDisabled();
  });
  it('lets a manager return to read-only without write permission', async () => {
    render(ui());
    await screen.findByText('My assistant');
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'one' },
    });
    fireEvent.change(screen.getByLabelText('Access level'), {
      target: { value: 'read-write' },
    });
    fireEvent.click(
      screen.getByRole('checkbox', { name: /Allow renewal requests/ })
    );
    fireEvent.change(screen.getByLabelText('Access level'), {
      target: { value: 'read-only' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
    await waitFor(() =>
      expect(mocks.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          inventoryImport: false,
          renewals: false,
          agentHealth: false,
        }),
        expect.any(Object)
      )
    );
  });
  it('returns renewal-only access to read-only', async () => {
    render(ui());
    await screen.findByText('My assistant');
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'one' },
    });
    const access = screen.getByLabelText('Access level');
    expect(access).toHaveValue('read-only');
    fireEvent.click(screen.getByLabelText('Allow renewal requests'));
    expect(access).toHaveValue('read-write');
    expect(
      screen.getByText(
        'Renewal requests are enabled; inventory imports are not enabled.'
      )
    ).toBeInTheDocument();
    fireEvent.change(access, { target: { value: 'read-only' } });
    expect(screen.getByLabelText('Allow renewal requests')).not.toBeChecked();
    expect(
      screen.getByText('Read-only cannot import inventory or request renewals.')
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
    await waitFor(() =>
      expect(mocks.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          inventoryImport: false,
          renewals: false,
          agentHealth: false,
        }),
        expect.any(Object)
      )
    );
  });
  it('keeps inventory import separate from renewal and agent-health permission', async () => {
    render(ui());
    await screen.findByText('My assistant');
    fireEvent.change(screen.getByRole('combobox', { name: /Workspace/ }), {
      target: { value: 'one' },
    });
    fireEvent.change(screen.getByLabelText('Access level'), {
      target: { value: 'read-write' },
    });
    fireEvent.change(screen.getByLabelText('Access expires after'), {
      target: { value: '365' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
    await waitFor(() =>
      expect(mocks.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          inventoryImport: true,
          renewals: false,
          agentHealth: false,
          lifetimeDays: 365,
        }),
        expect.any(Object)
      )
    );
  });
  it('offers cancellation without requiring workspace consent', async () => {
    render(ui());
    await screen.findByText('My assistant');
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() =>
      expect(mocks.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ decision: 'deny', workspaceId: '' }),
        expect.any(Object)
      )
    );
  });
  it('discards stale account responses after sign-in changes', async () => {
    let resolveOld;
    mocks.get.mockImplementationOnce(
      () =>
        new Promise(resolve => {
          resolveOld = resolve;
        })
    );
    const view = render(ui());
    view.rerender(ui({ id: 43, email: 'second@example.test' }));
    await screen.findByText(/second@example.test/);
    resolveOld({
      data: { ...details(), clientName: 'OLD ACCOUNT PRIVATE APP' },
    });
    await screen.findByText('My assistant');
    expect(
      screen.queryByText('OLD ACCOUNT PRIVATE APP')
    ).not.toBeInTheDocument();
  });
  it('refuses expired requests', async () => {
    mocks.get.mockResolvedValue({
      data: { ...details(), expiresAt: new Date(Date.now() - 1).toISOString() },
    });
    render(ui());
    await screen.findByText(/This request expired/);
    expect(screen.getByRole('button', { name: 'Connect' })).toBeDisabled();
  });
  it('only preserves the exact MCP consent return route through sign-in', () => {
    const safe = '/mcp/authorize?request=' + requestId;
    expect(mcpAuthorizationReturnTo(safe)).toBe(safe);
    for (const value of [
      '//evil.test',
      'https://evil.test' + safe,
      '/preferences',
      safe + '&extra=1',
      safe + '#other',
    ])
      expect(mcpAuthorizationReturnTo(value)).toBeNull();
  });
});
