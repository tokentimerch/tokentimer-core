import { render, screen, waitFor, within } from '@testing-library/react';
import { ChakraProvider, ColorModeScript } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({
  createJob: vi.fn(),
  getJob: vi.fn(),
  listJobLog: vi.fn(),
  listJobEvidence: vi.fn(),
  listAgentJobLog: vi.fn(),
}));
vi.mock('../../src/components/certops/certopsJobsApi.js', () => api);
vi.mock('../../src/components/certops/certopsJobsApi', () => api);
vi.mock('../../src/components/certops/certopsAgentsApi.js', () => ({
  listAgents: vi.fn().mockResolvedValue({
    items: [{ id: 'a1', createdAt: '2026-10-21T20:49:33.353Z' }],
  }),
  createBootstrapToken: vi.fn(),
}));

import IssueStep from '../../src/components/onboarding/certopsIssueStep.jsx';
import { ExecutionStep } from '../../src/components/onboarding/certopsExecutionStep.jsx';
import { AgentStep } from '../../src/components/onboarding/certopsAgentStep.jsx';
import {
  FirstCertificateStep,
  VaultStep,
} from '../../src/components/onboarding/certopsFinalSteps.jsx';
import AdcsStep from '../../src/components/onboarding/certopsAdcsStep.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const WS = '31c99396-ba6a-43a3-b972-4d42482b4fd0';
const docs = (key, label) => [{ label, url: `https://docs.example/${key}` }];

const finishedJob = {
  id: 'job-1',
  status: 'succeeded',
  mode: 'real',
  createdAt: '2026-10-21T21:38:55.083Z',
  startedAt: '2026-10-21T21:39:06.529Z',
  completedAt: '2026-10-21T21:39:11.820Z',
};
const agentPage = {
  items: [
    {
      claimId: 'c',
      attempt: 1,
      seq: 1,
      level: 'info',
      message: 'ACME order succeeded',
      ts: '2026-10-21T21:39:11.104Z',
    },
    {
      claimId: 'c',
      attempt: 1,
      seq: 2,
      level: 'info',
      message: 'reload succeeded for service haproxy',
      ts: '2026-10-21T21:39:11.601Z',
    },
  ],
  hasMore: false,
  nextCursor: 'n',
  logsComplete: true,
  jobStatus: 'succeeded',
  linesVisible: true,
  streams: [{ claimId: 'c', attempt: 1, status: 'final' }],
};

const agent = {
  id: 'a1',
  wireAgentId: 'agent-1',
  hostname: 'web-01',
  platform: 'linux',
  agentVersion: '0.18.0',
  livenessState: 'live',
  lastSeenAt: '2026-10-22T07:18:47.670Z',
  commandProfiles: ['certbot'],
  declaredCapabilities: [],
};

function makeCtx(goal, certops, summaryCertops) {
  const session = { intent: { goal }, progress: { certops } };
  return {
    session,
    workspaceId: WS,
    apiUrl: 'https://tt.example.com',
    docs,
    refresh: vi.fn().mockResolvedValue(undefined),
    summary: { certops: summaryCertops },
    controller: {
      update: vi.fn(mutate => {
        Object.assign(session, mutate(session));
        return Promise.resolve();
      }),
    },
  };
}

const automate = {
  objective: 'automate',
  infrastructure: 'linux',
  names: 'www.example.com',
  zone: 'example.com',
  dnsProvider: 'cloudflare',
  certPath: '/etc/ssl/tokentimer/www.pem',
  reloadService: 'haproxy',
  configReviewed: true,
};

const mount = (Step, ctx, colorMode = 'light') => {
  localStorage.setItem('chakra-ui-color-mode', colorMode);
  return render(
    <ChakraProvider>
      <ColorModeScript initialColorMode={colorMode} />
      <DashboardThemeProvider>
        <Step ctx={ctx} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
};

beforeEach(() => {
  api.createJob.mockReset();
  api.getJob.mockReset().mockResolvedValue({ job: finishedJob });
  api.listJobLog.mockReset().mockResolvedValue({ items: [], pagination: {} });
  api.listJobEvidence
    .mockReset()
    .mockResolvedValue({ items: [], pagination: {} });
  api.listAgentJobLog.mockReset().mockResolvedValue(agentPage);
});

describe.each(['light', 'dark'])('first issuance (%s)', mode => {
  it('shows the facts, the real timeline and the terminal output', async () => {
    const ctx = makeCtx('certops_automate', automate, {
      agents: { live: 1, total: 1, executionEnabled: true, items: [agent] },
      dryRun: { status: 'dry_run_complete' },
      issueJob: { id: 'job-1', status: 'succeeded', mode: 'real' },
    });
    mount(IssueStep, ctx, mode);
    const facts = screen.getByTestId('issue-facts');
    expect(within(facts).getByText('www.example.com')).toBeVisible();
    expect(
      within(facts).getByText('/etc/ssl/tokentimer/www.pem')
    ).toBeVisible();
    expect(within(facts).getByText('Issued')).toBeVisible();
    expect(await screen.findByText('Request created')).toBeVisible();
    expect(await screen.findByText('Order validated')).toBeVisible();
    expect(await screen.findByText('Service reloaded')).toBeVisible();
    expect(screen.getByRole('list', { name: 'Job timeline' })).toBeVisible();
    expect(screen.getByRole('log', { name: 'Agent output' })).toBeVisible();
    expect(screen.getByTestId('issue-next')).toBeVisible();
    expect(screen.getByText('Certificate issued')).toBeVisible();
  });
});

describe('first issuance without a request yet', () => {
  it('asks for the dry-run acknowledgement and shows no timeline', () => {
    const ctx = makeCtx('certops_automate', automate, {
      agents: { live: 1, total: 1, executionEnabled: true, items: [agent] },
      dryRun: { status: 'dry_run_complete' },
    });
    mount(IssueStep, ctx);
    expect(screen.getByTestId('dryrun-ack-warning')).toBeVisible();
    expect(screen.queryByTestId('job-activity')).toBeNull();
    expect(api.getJob).not.toHaveBeenCalled();
  });

  it('explains a failed order as an error panel with the next action', async () => {
    api.getJob.mockResolvedValue({
      job: { ...finishedJob, status: 'failed', errorMessage: 'DNS timed out' },
    });
    const ctx = makeCtx('certops_automate', automate, {
      agents: { live: 1, total: 1, executionEnabled: true, items: [agent] },
      dryRun: { status: 'dry_run_complete' },
      issueJob: {
        id: 'job-1',
        status: 'failed',
        mode: 'real',
        errorMessage: 'DNS timed out',
      },
    });
    mount(IssueStep, ctx);
    expect(await screen.findByRole('alert')).toHaveTextContent(/DNS timed out/);
    expect(screen.getByText('What to do next')).toBeVisible();
    expect(await screen.findByText('Finished: Failed')).toBeVisible();
  });
});

describe('execution step', () => {
  it('lists the three stages as an ordered list and the dry-run timeline', async () => {
    api.getJob.mockResolvedValue({
      job: { ...finishedJob, status: 'dry_run_complete' },
    });
    const ctx = makeCtx(
      'certops_automate',
      { ...automate, dryRunJobId: 'job-1' },
      {
        agents: { live: 1, total: 1, executionEnabled: true, items: [agent] },
        dryRun: { status: 'dry_run_complete' },
      }
    );
    mount(ExecutionStep, ctx);
    const stages = screen.getByRole('list', { name: 'Execution stages' });
    expect(within(stages).getAllByRole('listitem')).toHaveLength(3);
    expect(await screen.findByText('Finished: Dry-run complete')).toBeVisible();
    expect(screen.getByText('The dry run passed')).toBeVisible();
  });

  it('shows the server edits as a prerequisite before execution is on', () => {
    const ctx = makeCtx('certops_automate', automate, {
      agents: { live: 1, total: 1, executionEnabled: false, items: [agent] },
    });
    mount(ExecutionStep, ctx);
    expect(screen.getAllByText('Waiting').length).toBeGreaterThan(0);
    expect(screen.getByText('Turn on execution on the server')).toBeVisible();
  });
});

describe('agent step', () => {
  it('shows when the agent registered and when it last checked in', async () => {
    const ctx = makeCtx('certops_automate', automate, {
      agents: { live: 1, total: 1, executionEnabled: false, items: [agent] },
    });
    mount(AgentStep, ctx);
    const box = await screen.findByTestId('agent-checkin');
    expect(screen.getByText(/web-01 \(linux, version/)).toBeVisible();
    expect(
      await within(box).findByText('Agent registered (first seen)')
    ).toBeVisible();
    expect(within(box).getByText('Last check-in')).toBeVisible();
    expect(
      within(box).getByRole('list', { name: 'Agent timeline' })
    ).toBeVisible();
  });

  it('shows the controller report for a Kubernetes cluster', () => {
    const ctx = makeCtx(
      'certops_observe',
      { objective: 'observe', infrastructure: 'kubernetes', clusterId: 'prod' },
      {
        agents: { live: 0, total: 0, items: [] },
        controllers: {
          clusters: [
            { clusterId: 'prod', lastReportedAt: '2026-10-22T07:00:00.000Z' },
          ],
        },
      }
    );
    mount(AgentStep, ctx);
    const status = screen.getByTestId('controller-status');
    expect(within(status).getByText('Reporting')).toBeVisible();
    expect(
      within(status).getByText('Last report from cluster prod')
    ).toBeVisible();
  });
});

describe('discovery step', () => {
  it('turns the count into a success panel with the agent check-in', () => {
    const ctx = makeCtx(
      'certops_observe',
      { objective: 'observe', infrastructure: 'linux' },
      {
        agents: { live: 1, total: 1, items: [agent] },
        certificates: { total: 2, observed: 2, active: 2 },
      }
    );
    mount(FirstCertificateStep, ctx);
    expect(screen.getByText(/certificates? in the inventory/)).toBeVisible();
    expect(screen.getByText(/Agent web-01 last seen/)).toBeVisible();
  });

  it('tells what to check when nothing was reported', () => {
    const ctx = makeCtx(
      'certops_observe',
      { objective: 'observe', infrastructure: 'linux' },
      { agents: { live: 0, total: 0, items: [] }, certificates: { total: 0 } }
    );
    mount(FirstCertificateStep, ctx);
    expect(screen.getByText('No certificates reported yet')).toBeVisible();
    expect(screen.getByText('If nothing shows up')).toBeVisible();
  });
});

describe('Microsoft CA step', () => {
  it('shows numbered checks and the agent check-in', () => {
    const ctx = makeCtx(
      'certops_adcs',
      { objective: 'adcs', infrastructure: 'windows' },
      {
        adcs: { issuers: [], profiles: 0 },
        agents: { items: [agent] },
      }
    );
    mount(AdcsStep, ctx);
    expect(
      screen.getByRole('region', {
        name: '1. Agent connected and able to enroll',
      })
    ).toBeVisible();
    expect(screen.getAllByText('To do').length).toBeGreaterThan(0);
    expect(screen.getByText(/Agent web-01 last seen/)).toBeVisible();
    expect(screen.getByText('Still to do on your side')).toBeVisible();
  });
});

describe('Vault step', () => {
  it('shows what happened to the publish job', async () => {
    api.getJob.mockResolvedValue({
      job: { ...finishedJob, status: 'pending_approval', startedAt: null },
    });
    const ctx = makeCtx(
      'certops_vault',
      {
        objective: 'vault',
        names: 'a.example.com',
        zone: 'example.com',
        vaultPublishJobId: 'job-1',
      },
      {
        agents: { items: [agent] },
        distribution: { groups: 0, bindings: 0 },
      }
    );
    mount(VaultStep, ctx);
    expect(
      await screen.findByText('What happened to the publish job')
    ).toBeVisible();
    await waitFor(() =>
      expect(
        screen.getAllByText('Waiting for approval').length
      ).toBeGreaterThan(1)
    );
  });
});
