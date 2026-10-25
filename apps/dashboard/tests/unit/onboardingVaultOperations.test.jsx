import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  VaultAgentTest,
  VaultRolloutGuide,
} from '../../src/components/onboarding/VaultGuidedOperations.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const api = vi.hoisted(() => ({
  createJob: vi.fn(),
  getJob: vi.fn(),
  readDistribution: vi.fn(),
  assignConsumer: vi.fn(),
  requestRollout: vi.fn(),
  retryDeployment: vi.fn(),
}));
vi.mock('../../src/components/certops/certopsJobsApi.js', () => api);
vi.mock('../../src/components/onboarding/vaultGuideApi.js', () => api);
vi.mock('../../src/components/onboarding/JobActivity.jsx', () => ({
  default: ({ jobId }) => <div>Timeline for {jobId}</div>,
}));
const WS = '11111111-1111-4111-8111-111111111111';
const GROUP = '22222222-2222-4222-8222-222222222222';
const BINDING = '33333333-3333-4333-8333-333333333333';
const first = {
  id: 'consumer-row-a',
  wireAgentId: 'consumer-wire-a',
  name: 'First web server',
  platform: 'linux',
};
const second = {
  id: 'consumer-row-b',
  wireAgentId: 'consumer-wire-b',
  name: 'Second web server',
  platform: 'linux',
};
const ctx = () => ({
  workspaceId: WS,
  docs: () => [],
  refresh: vi.fn().mockResolvedValue(undefined),
  controller: { update: vi.fn().mockResolvedValue(undefined) },
  session: {
    intent: { goal: 'certops_vault' },
    progress: {
      certops: {
        objective: 'vault',
        infrastructure: 'linux',
        names: 'www.example.com',
        zone: 'example.com',
        vaultAddress: 'https://vault.example.com',
        groupId: GROUP,
        vaultBindingId: BINDING,
      },
    },
  },
});
const wrap = element =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>{element}</DashboardThemeProvider>
    </ChakraProvider>
  );
const props = context => ({
  ctx: context,
  groupId: GROUP,
  firstAgentId: first.id,
  firstBindingId: BINDING,
  agents: [first, second],
  config: {
    vaultAddress: 'https://vault.example.com',
    workspaceId: WS,
    groupId: GROUP,
    names: ['www.example.com'],
    zone: 'example.com',
    dnsProvider: 'rfc2136',
  },
  approvalRequired: false,
});
beforeEach(() => {
  vi.clearAllMocks();
  api.readDistribution.mockResolvedValue({ versions: [], consumers: [] });
  api.getJob.mockResolvedValue({ job: { id: 'test-job', status: 'pending' } });
});

describe('Vault jobs stay in onboarding', () => {
  it('reuses a passed issuer check without offering the same send action again', async () => {
    const context = ctx();
    context.session.progress.certops.dryRunJobId = 'setup-check';
    api.getJob.mockResolvedValue({
      job: {
        id: 'setup-check',
        status: 'dry_run_complete',
        operation: 'noop',
        assignedAgentId: first.id,
      },
    });
    wrap(<VaultAgentTest ctx={context} agent={first} isIssuer />);
    await screen.findByText('Signed dry run completed');
    expect(
      screen.queryByRole('button', { name: /Send a test job/ })
    ).toBeNull();
    expect(api.createJob).not.toHaveBeenCalled();
  });

  it('keeps the completed setup check when retrying a failed Vault issuer check', async () => {
    const context = ctx();
    context.session.progress.certops.dryRunJobId = 'setup-check';
    context.session.progress.certops.vaultDryRunJobIds = {
      [first.id]: 'failed-vault-check',
    };
    api.getJob.mockResolvedValue({
      job: {
        id: 'failed-vault-check',
        status: 'failed',
        assignedAgentId: first.id,
      },
    });
    api.createJob.mockResolvedValue({
      job: { id: 'vault-retry', status: 'pending' },
    });
    wrap(<VaultAgentTest ctx={context} agent={first} isIssuer />);
    await screen.findByText('Test status: failed');
    fireEvent.click(
      screen.getByRole('button', {
        name: /(?:Send a test job to|Retry test for) First web server/,
      })
    );
    await waitFor(() => expect(context.controller.update).toHaveBeenCalled());
    const updated = context.controller.update.mock.calls[0][0](context.session);
    expect(updated.progress.certops.dryRunJobId).toBe('setup-check');
    expect(updated.progress.certops.vaultDryRunJobIds[first.id]).toBe(
      'vault-retry'
    );
  });

  it('sends an attributed signed dry run and shows its real result without a CLI', async () => {
    const context = ctx();
    api.createJob.mockResolvedValue({
      job: { id: 'test-job', status: 'pending' },
    });
    api.getJob.mockResolvedValue({
      job: {
        id: 'test-job',
        status: 'dry_run_complete',
        operation: 'noop',
        assignedAgentId: first.id,
      },
    });
    wrap(<VaultAgentTest ctx={context} agent={first} />);
    fireEvent.click(
      screen.getByRole('button', {
        name: 'Send a test job to First web server',
      })
    );
    await waitFor(() =>
      expect(screen.getByText('Signed dry run completed')).toBeTruthy()
    );
    expect(api.createJob).toHaveBeenCalledWith(
      WS,
      expect.objectContaining({
        operation: 'noop',
        mode: 'dry_run',
        assignedAgentId: first.id,
      })
    );
    expect(api.createJob.mock.calls[0][1]).not.toHaveProperty(
      'requiresApproval'
    );
    const updater = context.controller.update.mock.calls[0][0];
    expect(
      updater(context.session).progress.certops.vaultDryRunJobIds[first.id]
    ).toBe('test-job');
    expect(screen.getByText('Timeline for test-job')).toBeTruthy();
    expect(document.body.textContent).not.toMatch(
      /POST|GET|curl|Sign in for the API/
    );
  });

  it('does not treat a completed real-operation request as the signed noop check', async () => {
    const context = ctx();
    context.session.progress.certops.vaultDryRunJobIds = {
      [first.id]: 'wrong-job',
    };
    api.getJob.mockResolvedValue({
      job: {
        id: 'wrong-job',
        operation: 'issue',
        status: 'dry_run_complete',
        assignedAgentId: first.id,
        mode: 'real',
      },
    });
    wrap(<VaultAgentTest ctx={context} agent={first} />);
    await screen.findByText('Test status: dry_run_complete');
    expect(screen.queryByText('Signed dry run completed')).toBeNull();
  });

  it('does not call a pending or failed check completed', async () => {
    const context = ctx();
    context.session.progress.certops.vaultDryRunJobIds = {
      [first.id]: 'existing-test',
    };
    api.getJob.mockResolvedValue({
      job: { id: 'existing-test', status: 'failed' },
    });
    wrap(<VaultAgentTest ctx={context} agent={first} />);
    await waitFor(() =>
      expect(screen.getByText('Test status: failed')).toBeTruthy()
    );
    expect(screen.queryByText('Signed dry run completed')).toBeNull();
    expect(api.createJob).not.toHaveBeenCalled();
  });

  it('assigns the selected consumer and generates its actual returned authorization revision', async () => {
    const context = ctx();
    api.assignConsumer.mockResolvedValue({
      id: BINDING,
      assigned_agent_id: first.id,
      authorization_revision: 7,
      profile_revision: 1,
      deployment_profile_ref: 'nginx-public',
      state: 'active',
    });
    wrap(<VaultRolloutGuide {...props(context)} />);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Assign First web server' })
    );
    await waitFor(() =>
      expect(screen.getByText('Authorization revision 7')).toBeTruthy()
    );
    expect(api.assignConsumer).toHaveBeenCalledWith(
      WS,
      GROUP,
      BINDING,
      expect.objectContaining({
        agentId: first.id,
        required: true,
        verificationPolicy: 'trust',
      })
    );
    expect(document.body.textContent).toContain('"authorizationRevision": 7');
    expect(document.body.textContent).toContain('consumer-wire-a');
    expect(
      screen.getByRole('button', { name: 'Deploy the selected version' })
    ).toBeDisabled();
    expect(api.requestRollout).not.toHaveBeenCalled();
  });

  it('uses the selected local deployment profile consistently in assignment and copied configuration', async () => {
    const context = ctx();
    api.assignConsumer.mockResolvedValue({
      id: BINDING,
      assigned_agent_id: first.id,
      authorization_revision: 3,
      profile_revision: 1,
      deployment_profile_ref: 'nginx-shared',
      state: 'active',
    });
    wrap(<VaultRolloutGuide {...props(context)} />);
    fireEvent.change(
      screen.getByLabelText('Deployment profile for First web server'),
      {
        target: { value: 'nginx-shared' },
      }
    );
    fireEvent.click(
      screen.getByRole('button', { name: 'Assign First web server' })
    );
    await waitFor(() =>
      expect(screen.getByText('Authorization revision 3')).toBeTruthy()
    );
    expect(api.assignConsumer.mock.calls[0][3].deploymentProfileRef).toBe(
      'nginx-shared'
    );
    expect(document.body.textContent).toContain(
      '"deploymentProfileRef": "nginx-shared"'
    );
    expect(document.body.textContent).toContain('"reference": "nginx-shared"');
    expect(document.body.textContent).toContain('"authorizationRevision": 3');
  });

  it('does not accept a failed local confirmation save', async () => {
    const context = ctx();
    api.readDistribution.mockResolvedValue({
      versions: [],
      consumers: [
        {
          binding_id: BINDING,
          assigned_agent_id: first.id,
          binding_state: 'active',
          authorization_revision: 2,
          profile_revision: 1,
          deployment_profile_ref: 'nginx-public',
        },
      ],
    });
    context.controller.update.mockRejectedValue(
      new Error('Session save failed')
    );
    wrap(<VaultRolloutGuide {...props(context)} />);
    const confirmation = await screen.findByRole('checkbox', {
      name: 'Configuration saved and agent restarted for First web server',
    });
    fireEvent.click(confirmation);
    await screen.findByText('Session save failed');
    expect(confirmation).not.toBeChecked();
    expect(api.requestRollout).not.toHaveBeenCalled();
  });

  it.each(['rollout-job', 'consumer-job'])(
    'shows shared job evidence only once when consumer job is %s',
    async deploymentId => {
      const context = ctx();
      context.session.progress.certops.vaultRolloutJobId = 'rollout-job';
      context.session.progress.certops.vaultConsumers = [first, second].map(
        (agent, index) => ({
          agentId: agent.id,
          bindingId: `binding-${index}`,
          deploymentProfileRef: 'nginx-public',
        })
      );
      api.readDistribution.mockResolvedValue({
        versions: [],
        consumers: [first, second].map((agent, index) => ({
          binding_id: `binding-${index}`,
          assigned_agent_id: agent.id,
          binding_state: 'active',
          authorization_revision: 1,
          profile_revision: 1,
          deployment_profile_ref: 'nginx-public',
          verification_policy: 'trust',
          latest_deployment: { jobId: deploymentId, stage: 'trust_validated' },
        })),
      });
      wrap(<VaultRolloutGuide {...props(context)} />);
      await screen.findAllByText('Authorization revision 1');
      expect(screen.getAllByText(`Timeline for ${deploymentId}`)).toHaveLength(
        1
      );
      expect(screen.getAllByText('Timeline for rollout-job')).toHaveLength(1);
    }
  );

  it('pins the chosen published version and keeps rollout success separate from live consumer verification', async () => {
    const context = ctx();
    const version = {
      id: 'published-version',
      state: 'published',
      provider_version: '4',
      valid_to: '2099-01-01T00:00:00Z',
    };
    const binding = {
      binding_id: BINDING,
      assigned_agent_id: first.id,
      binding_state: 'active',
      authorization_revision: 2,
      profile_revision: 1,
      deployment_profile_ref: 'nginx-public',
      verification_policy: 'trust',
      wave: 0,
      converged: false,
    };
    api.readDistribution.mockResolvedValue({
      versions: [version, { id: 'unpublished-version', state: 'allocated' }],
      consumers: [binding],
    });
    api.requestRollout.mockResolvedValue({
      id: 'rollout-job',
      status: 'succeeded',
    });
    api.getJob.mockResolvedValue({
      job: { id: 'rollout-job', status: 'succeeded' },
    });
    const view = wrap(<VaultRolloutGuide {...props(context)} />);
    await waitFor(() =>
      expect(screen.getByText('Authorization revision 2')).toBeTruthy()
    );
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'Configuration saved and agent restarted for First web server',
      })
    );
    await waitFor(() =>
      expect(
        screen.getByRole('checkbox', {
          name: 'Configuration saved and agent restarted for First web server',
        })
      ).toBeChecked()
    );
    fireEvent.change(screen.getByLabelText('Published certificate version'), {
      target: { value: version.id },
    });
    expect(
      screen.queryByRole('option', { name: /unpublished-version/ })
    ).toBeNull();
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Deploy the selected version' })
      ).toBeEnabled()
    );
    fireEvent.click(
      screen.getByRole('button', { name: 'Deploy the selected version' })
    );
    await waitFor(() => expect(api.requestRollout).toHaveBeenCalledOnce());
    expect(api.requestRollout.mock.calls[0].slice(0, 3)).toEqual([
      WS,
      GROUP,
      { materialVersionId: version.id, maxParallel: 1 },
    ]);
    expect(api.requestRollout.mock.calls[0][3]).toMatch(
      /^wizard-vault-rollout-/
    );
    expect(screen.queryByText('All selected consumers verified')).toBeNull();
    api.readDistribution.mockResolvedValue({
      versions: [version],
      consumers: [
        {
          ...binding,
          converged: true,
          desired_material_version_id: version.id,
          latest_deployment: {
            jobId: 'deployment-job',
            stage: 'trust_validated',
          },
        },
      ],
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Refresh distribution status' })
    );
    await waitFor(() =>
      expect(screen.getByText('All selected consumers verified')).toBeTruthy()
    );
    expect(screen.getByText('Timeline for deployment-job')).toBeTruthy();
    view.unmount();
  });
});
