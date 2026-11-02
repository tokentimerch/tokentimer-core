import { ChakraProvider } from '@chakra-ui/react';
import {
  fireEvent,
  render,
  screen,
  waitFor,
  cleanup,
} from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MaterialStoreStep } from '../../src/components/onboarding/materialStoreStep.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import {
  createJob,
  getJob,
} from '../../src/components/certops/certopsJobsApi.js';
import {
  materialContext,
  GROUP,
  ISSUER,
} from './materialOnboardingFixtures.js';
vi.mock('../../src/components/certops/certopsJobsApi.js', () => ({
  createJob: vi.fn(),
  getJob: vi.fn(),
}));
vi.mock('../../src/components/onboarding/JobActivity.jsx', () => ({
  default: ({ title }) => <div>{title}</div>,
}));
vi.mock(
  '../../src/components/onboarding/approvalPolicy.jsx',
  async original => ({
    ...(await original()),
    useJobApprovalPolicy: () => ({ required: true }),
  })
);
const show = ctx =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MaterialStoreStep ctx={ctx} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
beforeEach(() => {
  vi.clearAllMocks();
  getJob.mockResolvedValue({
    job: {
      id: 'noop',
      assignedAgentId: ISSUER,
      status: 'dry_run_complete',
      operation: 'noop',
      mode: 'dry_run',
    },
  });
});
afterEach(cleanup);
describe('Configure material store', () => {
  it('allows stopped-issuer preparation only after its observed signed check, retaining static requirements', async () => {
    const ctx = materialContext();
    Object.assign(ctx.summary.certops.agents.items[0], {
      livenessState: 'stale',
      claimEvidenceFresh: false,
    });
    const view = show(ctx);
    await screen.findByText(/This agent has passed its signed check/);
    expect(
      screen.getByRole('button', { name: 'Request real publication' })
    ).toBeDisabled();
    fireEvent.click(
      screen.getByLabelText(
        'The issuing agent is stopped while I prepare its group-specific configuration'
      )
    );
    expect(
      screen.getByRole('button', { name: 'Request real publication' })
    ).toBeEnabled();
    ctx.summary.certops.agents.items[0].declaredCapabilities = [];
    view.rerender(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MaterialStoreStep ctx={ctx} />
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    expect(
      screen.getByRole('button', { name: 'Request real publication' })
    ).toBeDisabled();
    expect(createJob).not.toHaveBeenCalled();
  });
  it('honors a blocked global distribution capability even when a provider is ready', async () => {
    const ctx = materialContext();
    Object.assign(
      ctx.capabilities.items.find(c => c.id === 'certops.vault_distribution'),
      { state: 'upgrade', entitled: false }
    );
    show(ctx);
    await screen.findByText(/This agent has passed its signed check/);
    fireEvent.click(
      screen.getByLabelText(
        'The issuing agent is stopped while I prepare its group-specific configuration'
      )
    );
    expect(
      screen.getByRole('button', { name: 'Request real publication' })
    ).toBeDisabled();
  });
  it.each(['vault-kv2', 'openbao-kv2'])(
    'uses persisted exact-version evidence for %s without claiming a continuous network check',
    provider => {
      show(materialContext(provider));
      expect(
        screen.getByText('Agent publication verified')
      ).toBeInTheDocument();
      expect(
        screen.getByText(/not a continuous connectivity probe/)
      ).toBeInTheDocument();
      expect(createJob).not.toHaveBeenCalled();
    }
  );
  it('cannot complete from a saved form or no-op when no publication receipt exists', () => {
    const ctx = materialContext();
    ctx.summary.certops.distribution.items[0].publication = null;
    show(ctx);
    expect(
      screen.getByText('Store connectivity not yet proven')
    ).toBeInTheDocument();
    expect(
      screen.queryByText('Agent publication verified')
    ).not.toBeInTheDocument();
  });
  it('keeps Azure gated even when an agent advertises Azure capability', () => {
    show(materialContext('azure-key-vault'));
    expect(
      screen.getByText('Implemented, production capability unavailable')
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Request real publication' })
    ).toBeDisabled();
    expect(screen.getByText(/VM managed identity/)).toBeInTheDocument();
  });
  it('requires workspace-manager RBAC even if capability facts are permissive', () => {
    const ctx = materialContext();
    ctx.capabilities.viewer.workspaceRole = 'viewer';
    show(ctx);
    expect(
      screen.getByRole('button', { name: 'Save public references' })
    ).toBeDisabled();
    expect(
      screen.getByRole('button', { name: 'Request real publication' })
    ).toBeDisabled();
    expect(createJob).not.toHaveBeenCalled();
  });
  it('shows unsupported providers and missing agents without submitting work', () => {
    const ctx = materialContext('unknown');
    ctx.summary.certops.agents.items = [];
    show(ctx);
    expect(
      screen.getByRole('option', { name: 'Unsupported provider' })
    ).toBeInTheDocument();
    expect(screen.getByText(/No agents are available/)).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Request real publication' })
    ).toBeDisabled();
  });
  it('does not save the host-local address when persisting public references', async () => {
    const ctx = materialContext();
    show(ctx);
    fireEvent.change(
      screen.getByLabelText('Customer-local store HTTPS address'),
      { target: { value: 'https://private-store.example.test' } }
    );
    fireEvent.click(
      screen.getByRole('button', { name: 'Save public references' })
    );
    await waitFor(() => expect(ctx.controller.update).toHaveBeenCalled());
    expect(JSON.stringify(ctx.session)).not.toContain('private-store');
    expect(ctx.session.progress.certops.materialSetup).toMatchObject({
      provider: 'vault-kv2',
      materialStoreRef: 'customer',
    });
  });
  it('labels publication as real and reuses the exact frozen request after a lost response and reload', async () => {
    const ctx = materialContext('openbao-kv2');
    ctx.session.progress.certops.materialSetup.groupId = '';
    createJob
      .mockRejectedValueOnce(new Error('lost response'))
      .mockResolvedValueOnce({
        job: {
          id: 'publish',
          status: 'pending_approval',
          payload: { publication: { groupId: GROUP } },
        },
      });
    const view = show(ctx);
    fireEvent.click(
      screen.getByLabelText(
        'The issuing agent is stopped while I prepare its group-specific configuration'
      )
    );
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Request real publication' })
      ).toBeEnabled()
    );
    fireEvent.click(
      screen.getByRole('button', { name: 'Request real publication' })
    );
    await waitFor(() => expect(createJob).toHaveBeenCalledTimes(1));
    await screen.findByText(/request could not be completed/);
    view.unmount();
    ctx.session.progress.certops.names = 'changed.example.test';
    show(ctx);
    fireEvent.click(
      screen.getByLabelText(
        'The issuing agent is stopped while I prepare its group-specific configuration'
      )
    );
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Request real publication' })
      ).toBeEnabled()
    );
    fireEvent.click(
      screen.getByRole('button', { name: 'Request real publication' })
    );
    await waitFor(() => expect(createJob).toHaveBeenCalledTimes(2));
    expect(createJob.mock.calls[1]).toEqual(createJob.mock.calls[0]);
    expect(createJob.mock.calls[0][1]).toMatchObject({
      operation: 'issue',
      mode: 'real',
      payload: {
        publicationDestination: { type: 'openbao-kv2' },
        sans: ['web.example.test'],
      },
    });
    await waitFor(() =>
      expect(ctx.session.progress.certops.vaultPublishJobId).toBe('publish')
    );
    expect(ctx.session.progress.certops.materialSetup.groupId).toBe(GROUP);
    fireEvent.change(
      screen.getByLabelText('Customer-local store HTTPS address'),
      { target: { value: 'https://store.example.test' } }
    );
    const localConfig = screen.getByRole('group', {
      name: /Issuer configuration to merge locally/,
      hidden: true,
    });
    expect(localConfig.textContent).toContain('web.example.test');
    expect(localConfig.textContent).not.toContain('changed.example.test');
  });
  it('fails closed on capability read failure and reports missing capabilities', () => {
    const ctx = materialContext();
    ctx.capabilities = null;
    ctx.summary.certops.agents.items[0].declaredCapabilities = [];
    show(ctx);
    expect(
      screen.getByText('Missing capability: certificate-publication-v1')
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Request real publication' })
    ).toBeDisabled();
  });
  it('clears unsaved host-local values when the workspace changes', () => {
    const first = materialContext(),
      next = materialContext();
    next.workspaceId = 'another-workspace';
    const view = show(first);
    fireEvent.change(
      screen.getByLabelText('Customer-local store HTTPS address'),
      { target: { value: 'https://first.example.test' } }
    );
    view.rerender(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MaterialStoreStep ctx={next} />
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    expect(
      screen.getByLabelText('Customer-local store HTTPS address')
    ).toHaveValue('');
  });
});
