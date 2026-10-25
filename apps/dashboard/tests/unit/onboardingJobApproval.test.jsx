import { act, fireEvent, render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { VaultStep } from '../../src/components/onboarding/certopsFinalSteps.jsx';
import IssueStep from '../../src/components/onboarding/certopsIssueStep.jsx';
import { ExecutionStep } from '../../src/components/onboarding/certopsExecutionStep.jsx';
import {
  createJob,
  getJob,
} from '../../src/components/certops/certopsJobsApi.js';
import { getWorkspaceCertOpsPauseState } from '../../src/components/certops/certopsApi.js';

vi.mock('../../src/hooks/useDashboardTheme', async importOriginal => ({
  ...(await importOriginal()),
  useDashboardTheme: () => ({ muted: 'gray.500' }),
}));
vi.mock('../../src/components/certops/certopsJobsApi.js', () => ({
  createJob: vi.fn(),
  getJob: vi.fn(),
}));
vi.mock('../../src/components/certops/certopsApi.js', () => ({
  getWorkspaceCertOpsPauseState: vi.fn(),
}));
vi.mock('../../src/components/onboarding/JobActivity.jsx', () => ({
  default: () => null,
  JobTimelineList: () => null,
}));

const WS = '11111111-1111-4111-8111-111111111111';
const GROUP = '22222222-2222-4222-8222-222222222222';

const policy = required =>
  getWorkspaceCertOpsPauseState.mockResolvedValue({
    certOpsRequireApprovalAlways: required,
  });

const flush = () => act(async () => {});

const vaultCtx = (extra = {}) => ({
  docs: () => [],
  workspaceId: WS,
  apiUrl: 'http://localhost:4000',
  refresh: vi.fn().mockResolvedValue(undefined),
  controller: { update: vi.fn().mockResolvedValue(undefined) },
  session: {
    progress: {
      certops: {
        objective: 'vault',
        names: 'a.example.com',
        zone: 'example.com',
        groupId: GROUP,
        vaultAddress: 'https://vault.example.com:8200',
        ...extra,
      },
    },
  },
  summary: {
    certops: {
      agents: {
        items: [
          {
            id: 'issuer',
            wireAgentId: 'w-issuer',
            livenessState: 'live',
            platform: 'linux',
            commandProfiles: ['certbot'],
          },
          {
            id: 'consumer',
            wireAgentId: 'w-consumer',
            livenessState: 'live',
            platform: 'linux',
          },
        ],
      },
      distribution: { groups: 0 },
    },
  },
});

const showVault = async ctx => {
  render(
    <ChakraProvider>
      <VaultStep ctx={ctx} />
    </ChakraProvider>
  );
  await flush();
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe('Vault publish job approval', () => {
  it('shows no approval prompt and starts the job right away when the policy is off', async () => {
    policy(false);
    createJob.mockResolvedValue({
      job: { id: 'j1', status: 'pending', payload: {} },
    });
    await showVault(vaultCtx());
    const notes = screen.getAllByTestId('approval-policy-off');
    expect(notes).toHaveLength(2);
    for (const note of notes) {
      expect(note.textContent).toMatch(
        /Approval is off for this workspace, jobs start right away/
      );
    }
    const settingsLinks = screen.getAllByRole('link', {
      name: 'CertOps settings',
    });
    expect(settingsLinks).toHaveLength(2);
    for (const link of settingsLinks) {
      expect(link).toHaveAttribute('href', '/certops/settings');
    }
    expect(screen.queryByTestId('approval-policy-on')).toBeNull();
    expect(screen.queryByTestId('approval-wait')).toBeNull();
    expect(document.body.textContent).not.toMatch(/held for approval/);

    fireEvent.click(
      screen.getByRole('button', { name: 'Create the publish job' })
    );
    await flush();
    expect(createJob).toHaveBeenCalledTimes(1);
    expect(createJob.mock.calls[0][1]).not.toHaveProperty('requiresApproval');
  });

  it('explains approval before the job exists when the policy is on', async () => {
    policy(true);
    await showVault(vaultCtx());
    const notes = screen.getAllByTestId('approval-policy-on');
    expect(notes).toHaveLength(2);
    for (const note of notes) {
      expect(note.textContent).toMatch(
        /waits until a workspace manager other than the person who creates it approves/
      );
    }
    expect(notes.map(note => note.textContent).join(' ')).toMatch(
      /this job waits/
    );
    expect(notes.map(note => note.textContent).join(' ')).toMatch(
      /this rollout waits/
    );
    expect(screen.queryByTestId('approval-policy-off')).toBeNull();
    expect(screen.getByTestId('vault-dry-run-approval')).toBeTruthy();
  });

  it('says nothing about approval while the policy is unknown', async () => {
    getWorkspaceCertOpsPauseState.mockRejectedValue(new Error('offline'));
    await showVault(vaultCtx());
    expect(screen.queryByTestId('approval-policy-on')).toBeNull();
    expect(screen.queryByTestId('approval-policy-off')).toBeNull();
    expect(screen.queryByTestId('vault-dry-run-approval')).toBeNull();
  });

  describe('with a created job', () => {
    beforeEach(() => vi.useFakeTimers({ shouldAdvanceTime: true }));
    afterEach(() => vi.useRealTimers());

    it('shows the waiting panel only while the job is pending approval', async () => {
      policy(true);
      getJob.mockResolvedValue({
        job: { id: 'j1', status: 'pending_approval' },
      });
      await showVault(vaultCtx({ vaultPublishJobId: 'j1' }));
      expect(screen.getByTestId('approval-wait').textContent).toMatch(
        /cannot approve your own job/
      );
      // The created publication has its waiting panel; the later rollout still
      // describes its own workspace policy.
      expect(screen.getAllByTestId('approval-policy-on')).toHaveLength(1);
      expect(screen.getByTestId('approval-policy-on').textContent).toMatch(
        /this rollout waits/
      );

      getJob.mockResolvedValue({ job: { id: 'j1', status: 'running' } });
      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000);
      });
      expect(screen.queryByTestId('approval-wait')).toBeNull();
    });

    it('trusts the job status when the policy flag is stale', async () => {
      policy(false);
      getJob.mockResolvedValue({
        job: { id: 'j1', status: 'pending_approval' },
      });
      await showVault(vaultCtx({ vaultPublishJobId: 'j1' }));
      expect(screen.getByTestId('approval-wait')).toBeTruthy();
    });

    it('shows no prompt for a running job even though the policy is on', async () => {
      policy(true);
      getJob.mockResolvedValue({ job: { id: 'j1', status: 'running' } });
      await showVault(vaultCtx({ vaultPublishJobId: 'j1' }));
      expect(screen.queryByTestId('approval-wait')).toBeNull();
      expect(screen.getAllByTestId('approval-policy-on')).toHaveLength(1);
      expect(screen.getByTestId('approval-policy-on').textContent).toMatch(
        /this rollout waits/
      );
      expect(screen.queryByTestId('approval-policy-off')).toBeNull();
    });
  });
});

describe('First certificate request approval', () => {
  const issueCtx = issueJob => ({
    docs: () => [],
    workspaceId: WS,
    refresh: vi.fn().mockResolvedValue(undefined),
    controller: { update: vi.fn().mockResolvedValue(undefined) },
    session: {
      progress: {
        certops: {
          objective: 'automate',
          infrastructure: 'linux',
          names: 'app.example.com',
          zone: 'example.com',
          dnsProvider: 'rfc2136',
          certPath: '/etc/ssl/tt/app.pem',
        },
      },
    },
    summary: {
      certops: {
        agents: {
          live: 1,
          executionEnabled: true,
          items: [
            {
              id: 'i',
              livenessState: 'live',
              platform: 'linux',
              commandProfiles: ['certbot'],
            },
          ],
        },
        dryRun: { status: 'dry_run_complete' },
        issueJob,
      },
    },
  });
  const showIssue = async ctx => {
    render(
      <ChakraProvider>
        <IssueStep ctx={ctx} />
      </ChakraProvider>
    );
    await flush();
  };

  it('says approval is off, with a link, before the request', async () => {
    policy(false);
    await showIssue(issueCtx(undefined));
    expect(screen.getByTestId('approval-policy-off')).toBeTruthy();
    expect(screen.queryByTestId('approval-wait')).toBeNull();
  });

  it('shows the waiting panel only for a job pending approval', async () => {
    policy(true);
    await showIssue(issueCtx({ id: 'o1', status: 'pending_approval' }));
    expect(screen.getByTestId('approval-wait')).toBeTruthy();
    expect(screen.queryByTestId('approval-policy-on')).toBeNull();
  });

  it('shows no approval UI for a queued job when the policy is off', async () => {
    policy(false);
    getJob.mockResolvedValue({ job: { id: 'o1', status: 'pending' } });
    await showIssue(issueCtx({ id: 'o1', status: 'pending' }));
    expect(screen.queryByTestId('approval-wait')).toBeNull();
    expect(screen.queryByTestId('approval-policy-off')).toBeNull();
  });
});

describe('Dry run approval', () => {
  const execCtx = () => ({
    docs: () => [],
    workspaceId: WS,
    refresh: vi.fn().mockResolvedValue(undefined),
    controller: { update: vi.fn().mockResolvedValue(undefined) },
    session: {
      intent: { goal: 'certops_automate' },
      progress: {
        certops: {
          objective: 'automate',
          infrastructure: 'linux',
          dryRunJobId: 'd1',
        },
      },
    },
    summary: {
      certops: {
        agents: {
          live: 1,
          executionEnabled: true,
          items: [
            {
              id: 'i',
              livenessState: 'live',
              platform: 'linux',
              commandProfiles: ['certbot'],
            },
          ],
        },
      },
    },
  });
  const showExec = async () => {
    render(
      <ChakraProvider>
        <ExecutionStep ctx={execCtx()} />
      </ChakraProvider>
    );
    await flush();
  };

  it('guides the approval instead of calling a pending job a failed one', async () => {
    policy(true);
    getJob.mockResolvedValue({ job: { id: 'd1', status: 'pending_approval' } });
    await showExec();
    expect(screen.getByTestId('approval-wait')).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/has not passed/);
  });

  it('keeps the existing warning for other unfinished states', async () => {
    policy(false);
    getJob.mockResolvedValue({ job: { id: 'd1', status: 'pending' } });
    await showExec();
    expect(screen.queryByTestId('approval-wait')).toBeNull();
    expect(document.body.textContent).toMatch(/The test job has not passed/);
  });
});
