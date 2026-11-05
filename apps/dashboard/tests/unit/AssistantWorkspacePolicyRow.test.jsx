import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import AssistantWorkspacePolicyRow from '../../src/components/certops/AssistantWorkspacePolicyRow.jsx';

const mocks = vi.hoisted(() => ({
  manage: true,
  workspace: 'one',
  load: vi.fn(),
  save: vi.fn(),
  loadIssuance: vi.fn(),
  saveIssuance: vi.fn(),
}));
vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: mocks.workspace }),
}));
vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsCanManage: () => mocks.manage,
}));
vi.mock('../../src/components/certops/assistantConnectionsApi.js', () => ({
  loadAssistantSettings: mocks.load,
  setAssistantWrites: mocks.save,
  loadAssistantIssuanceSettings: mocks.loadIssuance,
  setAssistantIssuance: mocks.saveIssuance,
}));
const ui = () => (
  <ChakraProvider>
    <DashboardThemeProvider>
      <MemoryRouter>
        <AssistantWorkspacePolicyRow />
      </MemoryRouter>
    </DashboardThemeProvider>
  </ChakraProvider>
);
beforeEach(() => {
  vi.clearAllMocks();
  mocks.manage = true;
  mocks.workspace = 'one';
  mocks.load.mockResolvedValue({ writesEnabled: false });
  mocks.save.mockResolvedValue(true);
  mocks.loadIssuance.mockResolvedValue({ issuanceEnabled: false });
  mocks.saveIssuance.mockResolvedValue(true);
});
describe('workspace MCP renewal control', () => {
  it('controls issuance independently from renewals', async () => {
    render(ui());
    fireEvent.click(
      await screen.findByLabelText('Allow MCP issuance requests')
    );
    await waitFor(() =>
      expect(mocks.saveIssuance).toHaveBeenCalledWith('one', true)
    );
    expect(mocks.save).not.toHaveBeenCalled();
  });
  it('allows an owner or manager to update the policy', async () => {
    render(ui());
    fireEvent.click(await screen.findByLabelText('Allow MCP renewal requests'));
    await waitFor(() => expect(mocks.save).toHaveBeenCalledWith('one', true));
    expect(screen.getByLabelText('Allow MCP renewal requests')).toBeChecked();
    expect(
      screen.getByRole('link', { name: 'Manage MCP assistants' })
    ).toHaveAttribute('href', '/preferences?workspace=one#mcp-assistants');
  });
  it('shows the policy to viewers without offering a write control', async () => {
    mocks.manage = false;
    render(ui());
    await waitFor(() => expect(screen.getAllByText('Off')).toHaveLength(2));
    expect(
      screen.queryByLabelText('Allow MCP renewal requests')
    ).not.toBeInTheDocument();
    expect(mocks.save).not.toHaveBeenCalled();
  });
  it('requires a fresh read after an uncertain update instead of displaying success', async () => {
    mocks.save.mockRejectedValue(new Error('lost response'));
    render(ui());
    fireEvent.click(await screen.findByLabelText('Allow MCP renewal requests'));
    await screen.findByText(/Retry to check its current value/);
    expect(
      screen.queryByLabelText('Allow MCP renewal requests')
    ).not.toBeInTheDocument();
    mocks.load.mockResolvedValue({ writesEnabled: true });
    fireEvent.click(screen.getByRole('button', { name: 'Retry MCP setting' }));
    await waitFor(() =>
      expect(screen.getByLabelText('Allow MCP renewal requests')).toBeChecked()
    );
  });
  it('does not carry the previous workspace policy across a switch', async () => {
    mocks.load.mockResolvedValueOnce({ writesEnabled: true });
    const view = render(ui());
    await waitFor(() =>
      expect(screen.getByLabelText('Allow MCP renewal requests')).toBeChecked()
    );
    mocks.workspace = 'two';
    view.rerender(ui());
    await waitFor(() =>
      expect(
        screen.getByLabelText('Allow MCP renewal requests')
      ).not.toBeChecked()
    );
  });
});
