import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import { VaultRolloutGuide } from '../../src/components/onboarding/VaultGuidedOperations.jsx';

const api = vi.hoisted(() => ({
  getJob: vi.fn(),
  listJobLog: vi.fn(),
  listJobEvidence: vi.fn(),
  listAgentJobLog: vi.fn(),
  readDistribution: vi.fn(),
  resumeRollout: vi.fn(),
  retryDeployment: vi.fn(),
  requestRollout: vi.fn(),
  assignConsumer: vi.fn(),
  createJob: vi.fn(),
}));
vi.mock('../../src/components/certops/certopsJobsApi.js', () => api);
vi.mock('../../src/components/certops/certopsJobsApi', () => api);
vi.mock('../../src/components/onboarding/vaultGuideApi.js', () => api);
const bindingId = '33333333-3333-4333-8333-333333333333';
const agent = {
  id: 'consumer',
  wireAgentId: 'consumer-wire',
  name: 'Web server',
  platform: 'linux',
};
let retried;
const binding = () => ({
  binding_id: bindingId,
  assigned_agent_id: agent.id,
  binding_state: 'active',
  authorization_revision: 1,
  profile_revision: 1,
  verification_policy: 'trust',
  deployment_profile_ref: 'nginx-public',
  desired_material_version_id: 'version',
  latest_deployment: {
    jobId: 'deployment-job',
    stage: retried ? 'trust_validated' : 'orphaned_unknown_effect',
    rolloutId: 'real-rollout',
    rolloutState: 'paused',
    rolloutRequestJobId: 'request-job',
  },
});
function show() {
  const ctx = {
    workspaceId: 'workspace',
    refresh: vi.fn().mockResolvedValue(),
    controller: { update: vi.fn().mockResolvedValue() },
    session: {
      intent: { goal: 'certops_vault' },
      progress: {
        certops: {
          objective: 'vault',
          vaultRolloutJobId: 'request-job',
          vaultMaterialVersionId: 'version',
          vaultConsumers: [
            {
              agentId: agent.id,
              bindingId,
              confirmedRevision: 1,
              deploymentProfileRef: 'nginx-public',
            },
          ],
        },
      },
    },
  };
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <VaultRolloutGuide
          ctx={ctx}
          groupId='group'
          firstAgentId={agent.id}
          firstBindingId={bindingId}
          agents={[agent]}
          config={{
            names: ['web.example.com'],
            zone: 'example.com',
            dnsProvider: 'rfc2136',
            vaultAddress: 'https://vault.example.com',
          }}
          approvalRequired={false}
        />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}
beforeEach(() => {
  vi.clearAllMocks();
  retried = false;
  api.readDistribution.mockImplementation(async () => ({
    versions: [
      {
        id: 'version',
        state: 'published',
        valid_to: '2099-01-01',
        provider_version: 1,
      },
    ],
    consumers: [binding()],
  }));
  api.getJob.mockImplementation(async (_ws, id) => ({
    job: {
      id,
      status:
        id === 'request-job' || retried
          ? 'succeeded'
          : 'orphaned_unknown_effect',
    },
  }));
  api.listJobLog.mockResolvedValue({ items: [] });
  api.listJobEvidence.mockResolvedValue({ items: [] });
  api.listAgentJobLog.mockImplementation(async () => ({
    items: [
      {
        claimId: 'claim',
        attempt: retried ? 2 : 1,
        seq: 1,
        level: 'info',
        message: retried ? 'New attempt output' : 'Original attempt output',
        ts: '2026-10-26T12:00:00Z',
      },
    ],
    logsComplete: true,
    linesVisible: true,
    hasMore: false,
    jobStatus: retried ? 'succeeded' : 'orphaned_unknown_effect',
    streams: [{ claimId: 'claim', attempt: retried ? 2 : 1, status: 'final' }],
  }));
  api.retryDeployment.mockImplementation(async () => {
    retried = true;
    return { jobId: 'deployment-job' };
  });
  api.resumeRollout.mockResolvedValue({
    id: 'real-rollout',
    state: 'deploying',
  });
});
it('refreshes a terminal job and its output after retrying the same job ID', async () => {
  show();
  const title = await screen.findByRole('heading', {
    name: 'Deployment: Web server',
  });
  const panel = title.closest('[data-testid="job-activity"]');
  await waitFor(() =>
    expect(
      within(panel).getAllByText('Needs reconciliation').length
    ).toBeGreaterThan(0)
  );
  fireEvent.click(
    screen.getByRole('button', { name: 'Retry deployment to Web server' })
  );
  await screen.findByText('Deployment: Certificate and TLS trust validated');
  expect(
    (await screen.findAllByText(/New attempt output/)).length
  ).toBeGreaterThan(0);
  await waitFor(() =>
    expect(screen.queryAllByText('Needs reconciliation')).toHaveLength(0)
  );
  expect(api.retryDeployment).toHaveBeenCalledWith(
    'workspace',
    'deployment-job'
  );
});
it('resumes the server-reported rollout after reload without using the request job ID', async () => {
  retried = true;
  show();
  fireEvent.click(
    await screen.findByRole('button', { name: 'Resume rollout' })
  );
  await waitFor(() =>
    expect(api.resumeRollout).toHaveBeenCalledWith(
      'workspace',
      'group',
      'real-rollout'
    )
  );
  expect(api.requestRollout).not.toHaveBeenCalled();
  expect(screen.queryByText('All consumers verified')).toBeNull();
});

it('requires a retry of a failed or uncertain consumer before allowing resume', async () => {
  show();
  expect(
    await screen.findByRole('button', { name: 'Resume rollout' })
  ).toBeDisabled();
  expect(api.resumeRollout).not.toHaveBeenCalled();
});

it('does not resume another request that deployed the same version to the same consumer', async () => {
  retried = true;
  const original = api.readDistribution.getMockImplementation();
  api.readDistribution.mockImplementation(async () => {
    const result = await original();
    result.consumers[0].latest_deployment.rolloutRequestJobId =
      'another-request';
    return result;
  });
  show();
  await screen.findByText('Authorization revision 1');
  expect(screen.queryByRole('button', { name: 'Resume rollout' })).toBeNull();
});

it('shows a refused resume without claiming convergence or creating a replacement rollout', async () => {
  retried = true;
  api.resumeRollout.mockRejectedValue(new Error('Workspace is paused'));
  show();
  fireEvent.click(
    await screen.findByRole('button', { name: 'Resume rollout' })
  );
  await screen.findByText('Workspace is paused');
  expect(api.requestRollout).not.toHaveBeenCalled();
  expect(screen.queryByText('All consumers verified')).toBeNull();
});
