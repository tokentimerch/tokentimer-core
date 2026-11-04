import { ChakraProvider } from '@chakra-ui/react';
import {
  fireEvent,
  render,
  screen,
  waitFor,
  cleanup,
} from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MaterialConsumerStep } from '../../src/components/onboarding/materialConsumerStep.jsx';
import { getJob } from '../../src/components/certops/certopsJobsApi.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import {
  requestRollout,
  assignConsumer,
  readDistribution,
} from '../../src/components/onboarding/vaultGuideApi.js';
import {
  materialContext,
  WS,
  GROUP,
  VERSION,
  CONSUMER,
} from './materialOnboardingFixtures.js';
vi.mock('../../src/components/onboarding/vaultGuideApi.js', () => ({
  readDistribution: vi.fn(),
  assignConsumer: vi.fn(),
  requestRollout: vi.fn(),
  retryDeployment: vi.fn(),
  resumeRollout: vi.fn(),
}));
vi.mock('../../src/components/certops/certopsJobsApi.js', () => ({
  createJob: vi.fn(),
  getJob: vi
    .fn()
    .mockResolvedValue({ job: { id: 'verify', status: 'pending_approval' } }),
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
        <MaterialConsumerStep ctx={ctx} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
beforeEach(() => {
  vi.clearAllMocks();
  getJob.mockResolvedValue({
    job: { id: 'verify', status: 'pending_approval' },
  });
  readDistribution.mockResolvedValue({
    versions: [
      {
        id: VERSION,
        state: 'published',
        valid_to: new Date(Date.now() + 86400000).toISOString(),
      },
    ],
    consumers: [],
  });
  requestRollout.mockResolvedValue({
    job: { id: 'verify', status: 'pending_approval' },
  });
});
afterEach(cleanup);
describe('Connect and validate consumers', () => {
  it('persists the exact consumer intent before authorization can take effect', async () => {
    const ctx = materialContext();
    let finish;
    assignConsumer.mockImplementation(
      () =>
        new Promise(resolve => {
          finish = resolve;
        })
    );
    const view = show(ctx);
    fireEvent.change(
      screen.getByLabelText('Customer-local store HTTPS address'),
      { target: { value: 'https://store.example.test' } }
    );
    fireEvent.click(
      await screen.findByRole('button', { name: 'Assign Consumer' })
    );
    await waitFor(() => expect(assignConsumer).toHaveBeenCalledOnce());
    const [, , bindingId, body] = assignConsumer.mock.calls[0];
    const saved = structuredClone(
      ctx.session.progress.certops.vaultConsumers || []
    );
    view.unmount();
    finish({
      binding: {
        id: bindingId,
        assigned_agent_id: body.agentId,
        deployment_profile_ref: body.deploymentProfileRef,
        profile_revision: 1,
        authorization_revision: 1,
      },
    });
    expect(saved).toEqual([
      expect.objectContaining({
        bindingId,
        agentId: CONSUMER,
        deploymentProfileRef: 'certificate-files',
      }),
    ]);
  });
  it('does not authorize a consumer when its intent cannot be saved', async () => {
    const ctx = materialContext();
    assignConsumer.mockImplementation(async (_ws, _group, id, body) => ({
      binding: {
        id,
        assigned_agent_id: body.agentId,
        deployment_profile_ref: body.deploymentProfileRef,
        profile_revision: 1,
        authorization_revision: 1,
      },
    }));
    ctx.controller.update.mockRejectedValueOnce(
      new Error('Guide progress unavailable')
    );
    show(ctx);
    fireEvent.change(
      screen.getByLabelText('Customer-local store HTTPS address'),
      { target: { value: 'https://store.example.test' } }
    );
    fireEvent.click(
      await screen.findByRole('button', { name: 'Assign Consumer' })
    );
    await screen.findByText('Guide progress unavailable');
    expect(assignConsumer).not.toHaveBeenCalled();
  });
  it('authorizes the chosen first consumer when another registered host sorts first', async () => {
    const ctx = materialContext();
    const consumer = ctx.summary.certops.agents.items[1];
    ctx.summary.certops.agents.items.splice(1, 0, {
      ...consumer,
      id: '66666666-6666-4666-8666-666666666666',
      wireAgentId: 'other-host',
      name: 'Other host',
    });
    assignConsumer.mockImplementation(async (_ws, groupId, id, body) => ({
      binding: {
        id,
        group_id: groupId,
        assigned_agent_id: body.agentId,
        deployment_profile_ref: body.deploymentProfileRef,
        profile_revision: 1,
        authorization_revision: 1,
        verification_policy: body.verificationPolicy,
        state: 'active',
      },
    }));
    show(ctx);
    fireEvent.change(
      screen.getByLabelText('Customer-local store HTTPS address'),
      {
        target: { value: 'https://store.example.test' },
      }
    );
    fireEvent.change(screen.getByLabelText('First consumer'), {
      target: { value: CONSUMER },
    });
    fireEvent.click(
      await screen.findByRole('button', { name: 'Assign Consumer' })
    );
    await waitFor(() => expect(assignConsumer).toHaveBeenCalledTimes(1));
    expect(assignConsumer.mock.calls[0][3].agentId).toBe(CONSUMER);
    await waitFor(() =>
      expect(ctx.session.progress.certops.vaultConsumers).toHaveLength(1)
    );
    cleanup();
    show(ctx);
    expect(screen.getByLabelText('First consumer')).toHaveValue(CONSUMER);
    expect(screen.getByLabelText('First consumer')).toBeDisabled();
  });
  it('lets a manager bootstrap the first consumer before any consumer has registered', () => {
    const ctx = materialContext('openbao-kv2');
    ctx.summary.certops.agents.items = ctx.summary.certops.agents.items.slice(
      0,
      1
    );
    const view = show(ctx);
    expect(
      screen.getByRole('button', { name: 'Create a consumer bootstrap token' })
    ).toBeEnabled();
    view.unmount();
    ctx.capabilities.viewer.workspaceRole = 'viewer';
    show(ctx);
    expect(
      screen.queryByRole('button', {
        name: 'Create a consumer bootstrap token',
      })
    ).not.toBeInTheDocument();
  });
  it('prepares a discovery-only consumer binding before enabling execution, while real deployment stays disabled', async () => {
    const ctx = materialContext();
    ctx.summary.certops.agents.items[1].supportedOperations = [];
    assignConsumer.mockImplementation(async (_ws, groupId, id, body) => ({
      binding: {
        id,
        group_id: groupId,
        assigned_agent_id: body.agentId,
        deployment_profile_ref: body.deploymentProfileRef,
        profile_revision: 1,
        authorization_revision: 3,
        verification_policy: body.verificationPolicy,
        state: 'active',
      },
    }));
    show(ctx);
    fireEvent.change(
      screen.getByLabelText('Customer-local store HTTPS address'),
      { target: { value: 'https://store.example.test' } }
    );
    const assign = screen.getByRole('button', { name: 'Assign Consumer' });
    expect(assign).toBeEnabled();
    fireEvent.click(assign);
    const configuration = await screen.findByRole('group', {
      name: /Consumer configuration/,
    });
    expect(configuration.textContent).toContain('"enabled": true');
    expect(configuration.textContent).toContain('"dryRun": true');
    fireEvent.click(
      screen.getByLabelText(
        'Configuration saved and agent restarted for Consumer'
      )
    );
    await waitFor(() =>
      expect(
        ctx.session.progress.certops.vaultConsumers[0].confirmedRevision
      ).toBe(3)
    );
    fireEvent.change(screen.getByLabelText('Published certificate version'), {
      target: { value: VERSION },
    });
    expect(
      screen.getByRole('button', { name: 'Deploy the selected version' })
    ).toBeDisabled();
    expect(requestRollout).not.toHaveBeenCalled();
  });
  it('uses a fresh request identity for an explicitly new verification after the previous one finishes', async () => {
    const ctx = materialContext();
    getJob.mockResolvedValue({ job: { id: 'verify', status: 'succeeded' } });
    const view = show(ctx);
    fireEvent.click(
      screen.getByRole('button', {
        name: 'Check installed material (no deployment)',
      })
    );
    const another = await screen.findByRole('button', {
      name: 'Prepare another verification',
    });
    await waitFor(() => expect(another).toBeEnabled());
    fireEvent.click(another);
    await waitFor(() =>
      expect(ctx.session.progress.certops.materialVerification).toBeNull()
    );
    view.rerender(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MaterialConsumerStep ctx={ctx} />
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    fireEvent.click(
      screen.getByRole('button', {
        name: 'Check installed material (no deployment)',
      })
    );
    await waitFor(() => expect(requestRollout).toHaveBeenCalledTimes(2));
    expect(requestRollout.mock.calls[1][3]).not.toBe(
      requestRollout.mock.calls[0][3]
    );
    expect(requestRollout.mock.calls[1][2].verificationOnly).toBe(true);
  });
  it('sends an explicit verification-only intent and preserves approval handling', async () => {
    const ctx = materialContext();
    show(ctx);
    fireEvent.click(
      screen.getByRole('button', {
        name: 'Check installed material (no deployment)',
      })
    );
    await waitFor(() => expect(requestRollout).toHaveBeenCalledTimes(1));
    expect(requestRollout).toHaveBeenCalledWith(
      WS,
      GROUP,
      { materialVersionId: VERSION, maxParallel: 1, verificationOnly: true },
      expect.any(String)
    );
    await screen.findByText('Waiting for approval');
    expect(ctx.session.progress.certops).not.toHaveProperty('verified');
    expect(assignConsumer).not.toHaveBeenCalled();
  });
  it('retries a lost verification request with the original version and key', async () => {
    const ctx = materialContext();
    requestRollout.mockRejectedValueOnce(new Error('lost'));
    const view = show(ctx);
    fireEvent.click(
      screen.getByRole('button', {
        name: 'Check installed material (no deployment)',
      })
    );
    await screen.findByText(/request could not be completed/);
    ctx.summary.certops.distribution.items[0].publication.materialVersionId =
      '66666666-6666-4666-8666-666666666666';
    view.unmount();
    show(ctx);
    fireEvent.click(
      screen.getByRole('button', {
        name: 'Check installed material (no deployment)',
      })
    );
    await waitFor(() => expect(requestRollout).toHaveBeenCalledTimes(2));
    expect(requestRollout.mock.calls[1]).toEqual(requestRollout.mock.calls[0]);
  });
  it('keeps read-only viewers and unqualified providers from creating verification requests', () => {
    const ctx = materialContext('azure-key-vault');
    ctx.capabilities.viewer.workspaceRole = 'viewer';
    show(ctx);
    expect(
      screen.getByRole('button', {
        name: 'Check installed material (no deployment)',
      })
    ).toBeDisabled();
    expect(requestRollout).not.toHaveBeenCalled();
  });
  it('reports missing consumer capabilities without submitting a deployment', () => {
    const ctx = materialContext();
    ctx.summary.certops.agents.items[1].declaredCapabilities = [];
    show(ctx);
    expect(
      screen.getByText(/Missing capability: deploy-from-store-v1/)
    ).toBeInTheDocument();
    expect(requestRollout).not.toHaveBeenCalled();
  });
  it('shows the missing-agent requirement and preserves the distinct assurance policies', () => {
    const ctx = materialContext();
    ctx.summary.certops.agents.items = ctx.summary.certops.agents.items.slice(
      0,
      1
    );
    show(ctx);
    expect(screen.getByText(/No Linux consumer agents/)).toBeInTheDocument();
    expect(
      screen.getByRole('option', { name: /Installed files only/ })
    ).toBeInTheDocument();
    expect(
      screen.getByRole('option', { name: /Served —/ })
    ).toBeInTheDocument();
    expect(screen.getByRole('option', { name: /Trust —/ })).toBeInTheDocument();
  });
  it('reuses the real binding API for OpenBao installed-only Linux destinations', async () => {
    const ctx = materialContext('openbao-kv2');
    assignConsumer.mockImplementation(async (_ws, groupId, id, body) => ({
      binding: {
        id,
        group_id: groupId,
        assigned_agent_id: body.agentId,
        deployment_profile_ref: body.deploymentProfileRef,
        profile_revision: 1,
        authorization_revision: 3,
        verification_policy: body.verificationPolicy,
        state: 'active',
      },
    }));
    show(ctx);
    fireEvent.change(
      screen.getByLabelText('Customer-local store HTTPS address'),
      { target: { value: 'https://bao.example.test' } }
    );
    fireEvent.click(
      await screen.findByRole('button', { name: 'Assign Consumer' })
    );
    await waitFor(() => expect(assignConsumer).toHaveBeenCalledTimes(1));
    expect(assignConsumer.mock.calls[0][3]).toMatchObject({
      agentId: CONSUMER,
      verificationPolicy: 'installed',
    });
    expect(
      screen.getByRole('group', { name: /Consumer configuration/ }).textContent
    ).toContain('openbao-kv2');
    expect(
      screen.getByRole('group', { name: /Consumer configuration/ }).textContent
    ).not.toContain('reloadService');
  });
  it('keeps Windows gated despite all advertised connector capabilities', () => {
    const ctx = materialContext();
    Object.assign(ctx.summary.certops.agents.items[1], {
      platform: 'win32',
      declaredCapabilities: [
        ...ctx.summary.certops.agents.items[1].declaredCapabilities,
        'windows-material-iis-v1',
        'windows-cert-store-v1',
        'iis-binding-v1',
      ],
    });
    show(ctx);
    fireEvent.change(screen.getByLabelText('Consumer destination'), {
      target: { value: 'win32' },
    });
    expect(
      screen.getByText(
        'Windows/IIS shared import is implemented but production-gated'
      )
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Authorize IIS binding' })
    ).toBeDisabled();
    expect(
      screen.getByRole('button', { name: 'Request real IIS deployment' })
    ).toBeDisabled();
    expect(
      screen.getByRole('button', {
        name: 'Check installed material (no deployment)',
      })
    ).toBeDisabled();
  });
  it('uses only trust assurance and the typed connector on a qualification-enabled IIS fixture', async () => {
    const ctx = materialContext();
    readDistribution.mockResolvedValue({
      versions: [],
      consumers: [
        {
          binding_id: 'existing-iis',
          agent_platform: 'win32',
          agent_name: 'IIS fixture',
          profile_revision: 1,
          authorization_revision: 4,
          latest_deployment: {
            stage: 'orphaned_unknown_effect',
            failureCode: 'material_windows_deployment_failed',
            jobId: 'original-deployment',
          },
        },
      ],
    });
    getJob.mockResolvedValue({ job: { id: 'verify', status: 'succeeded' } });
    ctx.capabilities.items.find(
      c => c.id === 'certops.windows_material_iis'
    ).qualified = true;
    ctx.capabilities.items.find(
      c => c.id === 'certops.windows_material_iis'
    ).state = 'ready';
    Object.assign(ctx.summary.certops.agents.items[1], {
      platform: 'win32',
      declaredCapabilities: [
        ...ctx.summary.certops.agents.items[1].declaredCapabilities,
        'windows-material-iis-v1',
        'windows-cert-store-v1',
        'iis-binding-v1',
      ],
    });
    assignConsumer.mockImplementation(async (_ws, groupId, id, body) => ({
      binding: {
        id,
        group_id: groupId,
        assigned_agent_id: body.agentId,
        deployment_profile_ref: body.deploymentProfileRef,
        profile_revision: 1,
        authorization_revision: 4,
        verification_policy: body.verificationPolicy,
      },
    }));
    show(ctx);
    fireEvent.change(screen.getByLabelText('Consumer destination'), {
      target: { value: 'win32' },
    });
    fireEvent.change(screen.getByLabelText('Windows consumer agent'), {
      target: { value: CONSUMER },
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Authorize IIS binding' })
    );
    const config = await screen.findByRole('group', {
      name: /Typed IIS binding/,
    });
    expect(config.textContent).toContain('windows-material-iis-v1');
    expect(config.textContent).toContain('windows-iis');
    const generated = JSON.parse(config.querySelector('pre').textContent);
    const bindingId = assignConsumer.mock.calls[0][2];
    expect(generated.declaredTargetSelectors).toEqual([
      bindingId,
      'iis-public',
    ]);
    expect(generated.materialBindings[bindingId].target.reference).toBe(
      'iis-public'
    );
    expect(assignConsumer.mock.calls[0][3].verificationPolicy).toBe('trust');
    expect(
      screen.getByRole('button', { name: 'Request real IIS deployment' })
    ).toBeDisabled();
    expect(requestRollout).not.toHaveBeenCalled();
    await screen.findByText('material_windows_deployment_failed');
    expect(screen.getByText('IIS consumer deployment')).toBeInTheDocument();
    fireEvent.click(
      screen.getByLabelText(
        'I applied the exact authorized binding configuration and enabled real execution on the consumer'
      )
    );
    fireEvent.click(
      screen.getByRole('button', { name: 'Request real IIS deployment' })
    );
    await waitFor(() => expect(requestRollout).toHaveBeenCalledTimes(1));
    expect(requestRollout.mock.calls[0][2]).toMatchObject({
      materialVersionId: VERSION,
      verificationOnly: false,
    });
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Prepare another IIS rollout' })
      ).toBeDisabled()
    );
  });
});
