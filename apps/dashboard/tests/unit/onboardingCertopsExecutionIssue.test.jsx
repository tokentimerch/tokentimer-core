import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/components/certops/certopsJobsApi.js', () => ({
  createJob: vi.fn(),
  getJob: vi.fn(),
}));

import {
  createJob,
  getJob,
} from '../../src/components/certops/certopsJobsApi.js';
import IssueStep, {
  issueWaitNotice,
} from '../../src/components/onboarding/certopsIssueStep.jsx';
import { ExecutionStep } from '../../src/components/onboarding/certopsExecutionStep.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const WS = '045d89e4-3c97-4029-ab18-fa6f200ebe96';
const docs = (key, label) => [{ label, url: `https://docs.example/${key}` }];

function makeCtx(goal, certops, summary) {
  const session = { intent: { goal }, progress: { certops } };
  return {
    session,
    workspaceId: WS,
    apiUrl: 'https://tt.example.com',
    docs,
    refresh: vi.fn().mockResolvedValue(undefined),
    summary,
    controller: {
      update: vi.fn(mutate => {
        Object.assign(session, mutate(session));
        return Promise.resolve();
      }),
    },
  };
}

const mount = (Step, ctx) =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <Step ctx={ctx} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );

const agent = {
  id: 'a1',
  wireAgentId: 'agent-1',
  livenessState: 'live',
  platform: 'linux',
  commandProfiles: ['certbot'],
};

const automate = {
  objective: 'automate',
  infrastructure: 'linux',
  names: 'www.example.com',
  zone: 'example.com',
  dnsProvider: 'cloudflare',
  certPath: '/etc/ssl/tokentimer/www.pem',
  configReviewed: true,
};

const ready = {
  certops: {
    agents: { live: 1, total: 1, executionEnabled: true, items: [agent] },
    dryRun: { status: 'dry_run_complete' },
  },
};

beforeEach(() => {
  createJob.mockReset();
  getJob.mockReset();
  getJob.mockResolvedValue({ job: { status: 'dry_run_complete' } });
  createJob.mockResolvedValue({ id: 'job-1', status: 'pending' });
});

describe('execution step', () => {
  const observing = {
    certops: {
      agents: { live: 1, total: 1, executionEnabled: false, items: [agent] },
    },
  };

  it('shows an execution block to merge, with the path and the restart command (Linux)', () => {
    mount(
      ExecutionStep,
      makeCtx('certops_automate', { ...automate }, observing)
    );
    const text = document.body.textContent;
    expect(text).toContain('/opt/tokentimer-agent/state/config.json');
    expect(text).toMatch(/Do not replace the file/);
    expect(text).toContain('sudo systemctl restart tokentimer-agent');
    const block = screen.getByLabelText(/Copy execution block/);
    expect(block).toBeInTheDocument();
    // A fragment to merge, never a whole document that would drop agentId.
    const pre = document.querySelector('pre[data-language="json"]');
    expect(pre.textContent.trim().startsWith('"execution"')).toBe(true);
    expect(() => JSON.parse(pre.textContent)).toThrow();
  });

  it('gives the Windows path and service restart', () => {
    mount(
      ExecutionStep,
      makeCtx(
        'certops_automate',
        { ...automate, infrastructure: 'windows' },
        observing
      )
    );
    expect(document.body.textContent).toContain(
      'C:\\ProgramData\\TokenTimerAgent\\state\\config.json'
    );
    expect(document.body.textContent).toContain(
      'Restart-Service TokenTimerAgent'
    );
  });

  it('explains why the test job button is disabled', () => {
    mount(
      ExecutionStep,
      makeCtx('certops_automate', { ...automate }, observing)
    );
    expect(
      screen.getByRole('button', { name: 'Send a test job' })
    ).toBeDisabled();
    expect(screen.getByTestId('send-test-hint').textContent).toMatch(
      /stays disabled until the agent checks in again/
    );
  });

  it('uses a fresh setup request and recovers the same key after a lost response', async () => {
    const context = makeCtx('certops_automate', { ...automate }, ready);
    createJob.mockRejectedValueOnce(new Error('Response lost'));
    mount(ExecutionStep, context);
    fireEvent.click(screen.getByRole('button', { name: 'Send a test job' }));
    await screen.findByText('Response lost');
    const key = createJob.mock.calls[0][1].idempotencyKey;
    expect(key).toMatch(/^wizard-dryrun-a1-[a-f0-9-]{36}$/);
    expect(context.session.progress.certops.dryRunRequestKey).toBe(key);
    expect(context.session.progress.certops.dryRunRequestAgentId).toBe(
      agent.id
    );
    fireEvent.click(screen.getByRole('button', { name: 'Send a test job' }));
    await waitFor(() => expect(createJob).toHaveBeenCalledTimes(2));
    expect(createJob.mock.calls[1][1].idempotencyKey).toBe(key);
    expect(createJob.mock.calls[1][1]).not.toHaveProperty('requiresApproval');
  });

  it("does not reuse another agent's persisted request key", async () => {
    const context = makeCtx(
      'certops_automate',
      {
        ...automate,
        dryRunRequestKey: 'another-agent-request',
        dryRunRequestAgentId: 'other-agent',
      },
      ready
    );
    mount(ExecutionStep, context);
    fireEvent.click(screen.getByRole('button', { name: 'Send a test job' }));
    await waitFor(() => expect(createJob).toHaveBeenCalledOnce());
    expect(createJob.mock.calls[0][1].idempotencyKey).not.toBe(
      'another-agent-request'
    );
  });

  it('tells the reader to set dryRun to false in the same block after a passing dry run', async () => {
    mount(
      ExecutionStep,
      makeCtx(
        'certops_automate',
        { ...automate, dryRunJobId: 'dry-1' },
        {
          certops: {
            agents: { live: 1, executionEnabled: true, items: [agent] },
            dryRun: { status: 'dry_run_complete' },
          },
        }
      )
    );
    await waitFor(() =>
      expect(document.body.textContent).toMatch(
        /set dryRun to false in the same execution block of \/opt\/tokentimer-agent\/state\/config\.json/
      )
    );
  });
});

describe('issue step', () => {
  it('keeps the request button disabled until dryRun false and the restart are acknowledged', async () => {
    mount(IssueStep, makeCtx('certops_automate', { ...automate }, ready));
    const button = screen.getByRole('button', {
      name: 'Request a staging certificate',
    });
    expect(button).toBeDisabled();
    expect(screen.getByTestId('ack-hint').textContent).toMatch(
      /stays disabled until you tick this box/
    );
    expect(screen.getByTestId('dryrun-ack-warning').textContent).toContain(
      '/opt/tokentimer-agent/state/config.json'
    );
    expect(document.body.textContent).toContain(
      'sudo systemctl restart tokentimer-agent'
    );
    fireEvent.click(screen.getByRole('checkbox'));
    expect(button).not.toBeDisabled();
    fireEvent.click(button);
    await waitFor(() => expect(createJob).toHaveBeenCalledTimes(1));
  });

  it('puts the warning before the button and still needs the other prerequisites', () => {
    mount(
      IssueStep,
      makeCtx(
        'certops_automate',
        { ...automate },
        {
          certops: {
            agents: { live: 1, executionEnabled: true, items: [agent] },
            dryRun: null,
          },
        }
      )
    );
    fireEvent.click(screen.getByRole('checkbox'));
    expect(
      screen.getByRole('button', { name: 'Request a staging certificate' })
    ).toBeDisabled();
    expect(document.body.textContent).toMatch(/Needs a passing dry run first/);
  });

  it('uses the Windows path and service restart on Windows', () => {
    mount(
      IssueStep,
      makeCtx(
        'certops_automate',
        { ...automate, infrastructure: 'windows', acmeClientPath: 'C:\\a.sh' },
        ready
      )
    );
    expect(screen.getByTestId('dryrun-ack-warning').textContent).toContain(
      'C:\\ProgramData\\TokenTimerAgent\\state\\config.json'
    );
    expect(document.body.textContent).toContain(
      'Restart-Service TokenTimerAgent'
    );
  });

  it('puts the human sentence before the error code', () => {
    mount(
      IssueStep,
      makeCtx(
        'certops_automate',
        { ...automate, issueJobId: 'job-1' },
        {
          certops: {
            ...ready.certops,
            issueJob: {
              id: 'job-1',
              status: 'failed',
              mode: 'real',
              errorCode: 'ACME_FAILED',
              errorMessage: 'The CA refused the order.',
            },
          },
        }
      )
    );
    const alert = screen.getByText(/The CA refused the order\./);
    expect(alert.textContent).toBe(
      'The CA refused the order. (code: ACME_FAILED)'
    );
    expect(document.body.textContent).toMatch(
      /can stay reserved by an earlier request/
    );
    expect(document.body.textContent).not.toMatch(/provisioning/);
  });

  it('says in plain words that the path stays locked while a request waits', () => {
    const since = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const text = issueWaitNotice({ status: 'pending', since });
    expect(text).toMatch(/stays locked/);
    expect(text).not.toMatch(/reserved|dnsProviders/);
  });
});
