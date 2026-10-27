import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import { VaultRolloutGuide } from '../../src/components/onboarding/VaultGuidedOperations.jsx';

const api = vi.hoisted(() => ({
  getJob: vi.fn(),
  createJob: vi.fn(),
  readDistribution: vi.fn(),
  assignConsumer: vi.fn(),
  requestRollout: vi.fn(),
  retryDeployment: vi.fn(),
  resumeRollout: vi.fn(),
}));
vi.mock('../../src/components/certops/certopsJobsApi.js', () => api);
vi.mock('../../src/components/onboarding/vaultGuideApi.js', () => api);
vi.mock('../../src/components/onboarding/JobActivity.jsx', () => ({
  default: ({ jobId }) => <div>Job output for {jobId}</div>,
}));
const GROUP = '22222222-2222-4222-8222-222222222222';
const BINDING = '33333333-3333-4333-8333-333333333333';
const agent = {
  id: 'consumer',
  name: 'Certificate host',
  wireAgentId: 'consumer-wire',
  platform: 'linux',
};
const version = {
  id: 'version',
  provider_version: 1,
  state: 'published',
  valid_to: '2099-01-01',
};
const binding = (overrides = {}) => ({
  binding_id: BINDING,
  binding_state: 'active',
  assigned_agent_id: agent.id,
  authorization_revision: 1,
  profile_revision: 1,
  deployment_profile_ref: 'certificate-files',
  verification_policy: 'installed',
  desired_material_version_id: version.id,
  converged: false,
  ...overrides,
});
function context(saved = {}) {
  const session = {
    intent: { goal: 'certops_vault' },
    progress: {
      certops: {
        objective: 'vault',
        groupId: GROUP,
        vaultMaterialVersionId: version.id,
        vaultConsumers: [
          { agentId: agent.id, bindingId: BINDING, confirmedRevision: 1 },
        ],
        ...saved,
      },
    },
  };
  return {
    session,
    workspaceId: '11111111-1111-4111-8111-111111111111',
    summary: {
      certops: { distribution: { items: [{ id: GROUP, completed: false }] } },
    },
    refresh: vi.fn().mockResolvedValue(),
    controller: {
      update: vi.fn(change =>
        Promise.resolve(Object.assign(session, change(session)))
      ),
    },
  };
}
function element(ctx, groupId = GROUP) {
  return (
    <ChakraProvider>
      <DashboardThemeProvider>
        <VaultRolloutGuide
          ctx={ctx}
          groupId={groupId}
          firstAgentId={agent.id}
          firstBindingId={BINDING}
          agents={[agent]}
          config={{
            workspaceId: ctx.workspaceId,
            groupId,
            vaultAddress: 'https://vault.example.com',
            names: ['web.example.com'],
            zone: 'example.com',
            dnsProvider: 'rfc2136',
            consumerDeliveryMode: 'files',
            deployPath: '/srv/certificates',
          }}
          approvalRequired={false}
        />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}
const progress = () => within(screen.getByTestId('vault-rollout-progress'));
const refresh = () =>
  fireEvent.click(
    screen.getByRole('button', { name: 'Refresh distribution status' })
  );

beforeEach(() => {
  vi.clearAllMocks();
  api.readDistribution.mockResolvedValue({
    versions: [version],
    consumers: [binding()],
  });
  api.getJob.mockResolvedValue({ job: { id: 'rollout', status: 'succeeded' } });
});

describe('Vault distribution progress', () => {
  it('explains assignment and host preparation before asking the user to wait', async () => {
    api.readDistribution.mockResolvedValue({
      versions: [version],
      consumers: [],
    });
    const ctx = context();
    api.assignConsumer.mockResolvedValue({
      ...binding(),
      id: BINDING,
      state: 'active',
    });
    render(element(ctx));
    await screen.findByText('Assign the consumers');
    expect(
      progress().getByText(/Use Assign on each consumer card/)
    ).toBeVisible();
    expect(screen.getByText('Assignment needed')).toBeVisible();
    fireEvent.click(
      screen.getByRole('button', { name: 'Assign Certificate host' })
    );
    await screen.findByText('Prepare the consumer hosts');
    expect(screen.getByText('Configuration needed')).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Deploy the selected version' })
    ).toBeDisabled();
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: /Configuration saved and agent restarted/,
      })
    );
    await screen.findByText('Ready to deploy');
    expect(
      screen.getByRole('button', { name: 'Deploy the selected version' })
    ).toBeEnabled();
    expect(api.requestRollout).not.toHaveBeenCalled();
  });

  it('distinguishes an unpublished certificate from an available version waiting to be selected', async () => {
    const ctx = context({ vaultMaterialVersionId: '' });
    api.readDistribution.mockResolvedValue({
      versions: [],
      consumers: [binding()],
    });
    render(element(ctx));
    await screen.findByText('Waiting for certificate publication');
    expect(
      progress().getByText(/Complete the publish job above/)
    ).toBeVisible();
    api.readDistribution.mockResolvedValue({
      versions: [version],
      consumers: [binding()],
    });
    refresh();
    await screen.findByText('Choose a certificate version');
    fireEvent.change(screen.getByLabelText('Published certificate version'), {
      target: { value: version.id },
    });
    await screen.findByText('Ready to deploy');
  });

  it.each([
    ['pending_approval', undefined, 'Rollout approval is required'],
    [
      'succeeded',
      { stage: 'failed', jobId: 'deployment' },
      'A consumer deployment needs attention',
    ],
    [
      'succeeded',
      {
        stage: 'queued',
        jobId: 'deployment',
        rolloutState: 'paused',
        rolloutId: 'server-rollout',
        rolloutRequestJobId: 'rollout',
      },
      'Resume the paused rollout',
    ],
    ['failed', undefined, 'The rollout did not complete'],
    [
      'succeeded',
      { stage: 'files_installed', jobId: 'deployment' },
      'Waiting for confirmed file installations',
    ],
  ])(
    'explains %s with %j without treating the request as delivery',
    async (status, deployment, title) => {
      api.getJob.mockResolvedValue({ job: { id: 'rollout', status } });
      api.readDistribution.mockResolvedValue({
        versions: [version],
        consumers: [binding({ latest_deployment: deployment })],
      });
      const ctx = context({ vaultRolloutJobId: 'rollout' });
      render(element(ctx));
      await waitFor(() => expect(progress().getByText(title)).toBeVisible());
      expect(progress().getByText(/0 of 1 consumers confirmed/)).toBeVisible();
      expect(
        screen.queryByText(
          'Certificate files installed on all selected consumers'
        )
      ).toBeNull();
    }
  );

  it('counts other active consumers and waits for authoritative rollout completion', async () => {
    const ctx = context({ vaultRolloutJobId: 'rollout' });
    ctx.summary.certops.distribution.items[0].completed = true;
    const selected = binding({ converged: true });
    const other = binding({
      binding_id: 'external-binding',
      assigned_agent_id: 'external-agent',
      agent_name: 'Existing host',
      required: false,
    });
    api.readDistribution.mockResolvedValue({
      versions: [version],
      consumers: [selected, other],
    });
    render(element(ctx));
    await screen.findByText('Other consumers are still pending');
    expect(progress().getByText(/1 of 2 consumers confirmed/)).toBeVisible();
    expect(progress().getByText('Existing host')).toBeVisible();
    expect(
      screen.queryByText(
        'Certificate files installed on all selected consumers'
      )
    ).toBeNull();

    ctx.summary.certops.distribution.items[0].completed = false;
    api.readDistribution.mockResolvedValue({
      versions: [version],
      consumers: [selected, { ...other, converged: true }],
    });
    refresh();
    await screen.findByText('Confirming distribution completion');
    expect(progress().getByText(/2 of 2 consumers confirmed/)).toBeVisible();
    expect(
      screen.queryByText(
        'Certificate files installed on all selected consumers'
      )
    ).toBeNull();

    ctx.refresh.mockImplementation(() => {
      ctx.summary.certops.distribution.items[0].completed = true;
      return Promise.resolve();
    });
    refresh();
    await screen.findByText(
      'Certificate files installed on all selected consumers'
    );
    expect(ctx.refresh).toHaveBeenCalledTimes(2);
    expect(api.requestRollout).not.toHaveBeenCalled();
  });

  it.each([
    { converged: true, desired_material_version_id: 'older-version' },
    { converged: false, latest_deployment: { stage: 'files_installed' } },
    { converged: true, latest_deployment: { stage: 'failed' } },
    { converged: true, latest_deployment: { stage: 'blocked' } },
  ])(
    'keeps incomplete or mismatched current evidence out of the confirmation count: %j',
    async overrides => {
      const ctx = context({ vaultRolloutJobId: 'rollout' });
      ctx.summary.certops.distribution.items[0].completed = true;
      api.readDistribution.mockResolvedValue({
        versions: [version],
        consumers: [binding(overrides)],
      });
      render(element(ctx));
      await waitFor(() =>
        expect(progress().getByText(/0 of 1 consumers confirmed/)).toBeVisible()
      );
      expect(
        screen.queryByText(
          'Certificate files installed on all selected consumers'
        )
      ).toBeNull();
    }
  );

  it('clears completion when a status refresh fails and recovers with fresh evidence', async () => {
    const ctx = context({ vaultRolloutJobId: 'rollout' });
    ctx.summary.certops.distribution.items[0].completed = true;
    api.readDistribution.mockResolvedValue({
      versions: [version],
      consumers: [binding({ converged: true })],
    });
    render(element(ctx));
    await screen.findByText(
      'Certificate files installed on all selected consumers'
    );
    api.readDistribution.mockRejectedValueOnce(
      new Error('Status request failed')
    );
    refresh();
    await screen.findByText('Distribution status is unavailable');
    expect(
      screen.queryByText(
        'Certificate files installed on all selected consumers'
      )
    ).toBeNull();
    expect(progress().queryByRole('progressbar')).toBeNull();
    refresh();
    await screen.findByText(
      'Certificate files installed on all selected consumers'
    );
  });

  it('does not reuse successful evidence while another distribution is loading', async () => {
    const ctx = context({ vaultRolloutJobId: 'rollout' });
    ctx.summary.certops.distribution.items[0].completed = true;
    api.readDistribution.mockResolvedValue({
      versions: [version],
      consumers: [binding({ converged: true })],
    });
    const view = render(element(ctx));
    await screen.findByText(
      'Certificate files installed on all selected consumers'
    );
    api.readDistribution.mockImplementation(() => new Promise(() => {}));
    view.rerender(element(ctx, 'another-group'));
    expect(
      screen.queryByText(
        'Certificate files installed on all selected consumers'
      )
    ).toBeNull();
    expect(progress().getByText('Checking distribution status')).toBeVisible();
  });
  it('refreshes a terminal rollout job with the same ID after recovery', async () => {
    const ctx = context({ vaultRolloutJobId: 'rollout' });
    api.getJob.mockResolvedValue({ job: { id: 'rollout', status: 'failed' } });
    render(element(ctx));
    await screen.findByText('The rollout did not complete');
    expect(
      screen.getByRole('button', { name: 'Prepare another rollout' })
    ).toBeVisible();
    api.getJob.mockResolvedValue({ job: { id: 'rollout', status: 'pending' } });
    refresh();
    await screen.findByText('Waiting for confirmed file installations');
    expect(
      screen.queryByRole('button', { name: 'Prepare another rollout' })
    ).toBeNull();
    expect(api.getJob).toHaveBeenCalledTimes(2);
    expect(api.requestRollout).not.toHaveBeenCalled();
  });
});
