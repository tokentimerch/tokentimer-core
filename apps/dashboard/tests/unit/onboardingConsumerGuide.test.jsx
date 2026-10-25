import { act, render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { VaultStep } from '../../src/components/onboarding/certopsFinalSteps.jsx';
import {
  NO_CLAIM_AFTER_MS,
  default as IssueStep,
  issueWaitNotice,
} from '../../src/components/onboarding/certopsIssueStep.jsx';
import { nextSteps } from '../../src/components/onboarding/OnboardingPage.jsx';
import {
  buildConsumerPlaceholderCommand,
  buildIssueJob,
  buildReconcileCommand,
  buildServerSnippet,
  buildVaultConfigs,
  keyPathFor,
} from '../../src/components/onboarding/certopsConfig.js';
import {
  SUMMARY_POLL_MS,
  vaultNeedsPolling,
  verifyNeedsPolling,
} from '../../src/components/onboarding/useSummaryPolling.js';
import { CHECK_STATUS } from '../../src/components/onboarding/verification.js';
import { pickGoalAgent } from '../../src/components/onboarding/certopsMatrix.js';

vi.mock('../../src/hooks/useDashboardTheme', async importOriginal => ({
  ...(await importOriginal()),
  useDashboardTheme: () => ({ muted: 'gray.500' }),
}));
vi.mock('../../src/components/certops/certopsJobsApi.js', () => ({
  createJob: vi.fn(),
  getJob: vi.fn(),
}));
vi.mock('../../src/components/onboarding/vaultGuideApi.js', () => ({
  readDistribution: vi.fn().mockResolvedValue({ versions: [], consumers: [] }),
  assignConsumer: vi.fn(),
  requestRollout: vi.fn(),
  retryDeployment: vi.fn(),
}));

const UUID_A = '11111111-1111-4111-8111-111111111111';
const UUID_B = '22222222-2222-4222-8222-222222222222';

describe('Linux key location', () => {
  it('picks the agent that can place orders, not the newest one', () => {
    const consumer = {
      id: 'c',
      livenessState: 'live',
      platform: 'linux',
      commandProfiles: [],
    };
    const issuer = {
      id: 'i',
      livenessState: 'live',
      platform: 'linux',
      commandProfiles: ['certbot'],
    };
    expect(pickGoalAgent([consumer, issuer], 'automate', 'linux').id).toBe('i');
    expect(pickGoalAgent([consumer, issuer], 'vault', 'linux').id).toBe('i');
    expect(pickGoalAgent([consumer], 'automate', 'linux').id).toBe('c');
    expect(pickGoalAgent([consumer, issuer], 'observe', 'linux').id).toBe('c');
    expect(pickGoalAgent([], 'automate', 'linux')).toBeUndefined();
  });

  it('derives the key next to the certificate', () => {
    expect(keyPathFor('/etc/ssl/tt/site.pem')).toBe('/etc/ssl/tt/site.pem.key');
    expect(keyPathFor('relative.pem')).toBe('');
  });

  it('puts keyPath in the issue job payload', () => {
    const job = buildIssueJob({
      os: 'linux',
      names: ['a.example.com'],
      zone: 'example.com',
      dnsProvider: 'rfc2136',
      certPath: '/etc/ssl/tt/site.pem',
      idempotencyKey: 'k',
    });
    expect(job.payload.keyPath).toBe('/etc/ssl/tt/site.pem.key');
  });

  it('prints nginx, Apache and HAProxy lines that name the key', () => {
    const certPath = '/etc/ssl/tt/site.pem';
    expect(buildServerSnippet({ reloadService: 'nginx', certPath })).toMatch(
      /ssl_certificate\s+\/etc\/ssl\/tt\/site\.pem;\nssl_certificate_key \/etc\/ssl\/tt\/site\.pem\.key;/
    );
    expect(buildServerSnippet({ reloadService: 'apache', certPath })).toMatch(
      /SSLCertificateKeyFile \/etc\/ssl\/tt\/site\.pem\.key/
    );
    expect(buildServerSnippet({ reloadService: 'haproxy', certPath })).toMatch(
      /crt \/etc\/ssl\/tt\/site\.pem/
    );
    expect(buildServerSnippet({ certPath: 'nope' })).toBe('');
  });
});

describe('Vault consumer folder', () => {
  it('creates the placeholder as the agent user, never as root', () => {
    const text = buildConsumerPlaceholderCommand({});
    expect(text).toMatch(/^sudo -u tokentimer-agent openssl req/);
    expect(text).toContain('/etc/nginx/tokentimer/privkey.pem');
    expect(text).toContain('/etc/nginx/tokentimer/fullchain.pem');
  });

  it('prints the real recovery command and nothing invented', () => {
    const text = buildReconcileCommand(UUID_A);
    expect(text).toContain(`reconcile-material-binding.js ${UUID_A}`);
    expect(text).toContain('TOKENTIMER_AGENT_CONFIG_DIR=');
  });

  it('allows the deploy folder and the key store in the consumer policy', () => {
    const out = buildVaultConfigs({
      vaultAddress: 'https://vault.example.com:8200',
      workspaceId: UUID_A,
      groupId: UUID_B,
      names: ['*.example.com'],
      zone: 'example.com',
      dnsProvider: 'rfc2136',
      consumerBindingId: UUID_A,
    });
    expect(out.consumer.policy.allowedPaths).toContain('/etc/nginx/tokentimer');
    const probe = out.consumer.materialBindings[UUID_A].probes[0];
    expect(probe.sni).toBe('www.example.com');
  });

  const showVault = ctx =>
    render(
      <ChakraProvider>
        <VaultStep ctx={ctx} />
      </ChakraProvider>
    );

  const ctxWith = (distribution, agents = []) => ({
    docs: () => [],
    workspaceId: UUID_A,
    apiUrl: 'http://localhost:4000',
    refresh: vi.fn().mockResolvedValue(undefined),
    session: {
      progress: {
        certops: {
          objective: 'vault',
          names: 'a.example.com',
          zone: 'example.com',
          groupId: UUID_B,
          vaultAddress: 'https://vault.example.com:8200',
        },
      },
    },
    summary: { certops: { agents: { items: agents }, distribution } },
  });

  it('passes --write-path for the deploy folder and explains the files', () => {
    showVault(ctxWith({ groups: 0, bindings: 0 }));
    expect(document.body.textContent).toMatch(
      /--write-path '\/etc\/tokentimer\/certificates'/
    );
    expect(document.body.textContent).toMatch(/material_install_failed/);
    expect(document.body.textContent).toMatch(
      /fullchain\.pem and privkey\.pem/
    );
  });

  it('explains material_binding_uncertain and the supported recovery', () => {
    showVault(ctxWith({ groups: 0, bindings: 0 }));
    const note = screen.getByTestId('vault-uncertain-note');
    expect(note.tagName).toBe('DETAILS');
    expect(note.textContent).toMatch(/material_binding_uncertain/);
    expect(note.textContent).toMatch(/reconcile-material-binding\.js/);
    expect(note.textContent).toMatch(/Do not delete/);
  });

  it('says a rollout has no dry run and offers the signed one', () => {
    showVault(ctxWith({ groups: 0, bindings: 0 }));
    expect(screen.getByTestId('vault-dry-run-note').textContent).toMatch(
      /A rollout itself has no dry run/
    );
    expect(document.body.textContent).toMatch(/Send a test job/);
    expect(document.body.textContent).not.toMatch(/POST.*certops\/jobs/);
  });
});

describe('Linux request step', () => {
  const ctx = (extra = {}) => ({
    docs: () => [],
    workspaceId: 'w1',
    refresh: vi.fn().mockResolvedValue(undefined),
    session: {
      progress: {
        certops: {
          objective: 'automate',
          infrastructure: 'linux',
          names: 'app.example.com',
          zone: 'example.com',
          dnsProvider: 'rfc2136',
          certPath: '/etc/ssl/tt/app.pem',
          reloadService: 'nginx',
          ...extra,
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
              id: 'c',
              livenessState: 'live',
              platform: 'linux',
              commandProfiles: [],
            },
            {
              id: 'i',
              livenessState: 'live',
              platform: 'linux',
              commandProfiles: ['certbot'],
            },
          ],
        },
        dryRun: { status: 'dry_run_complete' },
      },
    },
  });

  it('prints the key path, the server lines and the running-server note', () => {
    render(
      <ChakraProvider>
        <IssueStep ctx={ctx()} />
      </ChakraProvider>
    );
    expect(screen.getByTestId('key-note').textContent).toMatch(
      /\/etc\/ssl\/tt\/app\.pem\.key/
    );
    expect(document.body.textContent).toMatch(
      /ssl_certificate_key \/etc\/ssl\/tt\/app\.pem\.key;/
    );
    expect(screen.getByTestId('server-running-note').textContent).toMatch(
      /Start nginx before you request/
    );
  });
});

describe('issueWaitNotice', () => {
  const now = Date.parse('2026-10-21T12:00:00.000Z');
  const ago = ms => new Date(now - ms).toISOString();

  it('stays quiet before the wait is long enough', () => {
    expect(
      issueWaitNotice({ status: 'pending', since: ago(60000), now })
    ).toBeNull();
  });

  it('explains the wait and the missing cancel after three minutes', () => {
    const text = issueWaitNotice({
      status: 'pending',
      since: ago(NO_CLAIM_AFTER_MS + 1),
      now,
    });
    expect(text).toMatch(/^No agent has taken this request\./);
    expect(text).toMatch(/DNS provider you chose/);
    expect(text).not.toMatch(/dnsProviders/);
    expect(text).toMatch(/You cannot cancel this request from here/);
    expect(text).toMatch(/certificate file path stays locked/);
  });

  it('only applies to a request an agent could still take', () => {
    for (const status of [
      'running',
      'failed',
      'pending_approval',
      'succeeded',
    ]) {
      expect(
        issueWaitNotice({ status, since: ago(NO_CLAIM_AFTER_MS * 5), now })
      ).toBeNull();
    }
    expect(issueWaitNotice({ status: 'pending', since: null, now })).toBeNull();
  });
});

describe('summary polling', () => {
  it('polls while the backlog warning, a publish job or an open rollout matters', () => {
    expect(vaultNeedsPolling({ backlogMessage: 'x', distribution: {} })).toBe(
      true
    );
    expect(vaultNeedsPolling({ publishActive: true, distribution: {} })).toBe(
      true
    );
    expect(
      vaultNeedsPolling({ distribution: { groups: 1, verified: false } })
    ).toBe(true);
    expect(vaultNeedsPolling({ distribution: { groups: 0 } })).toBe(false);
    expect(
      vaultNeedsPolling({ distribution: { groups: 1, verified: true } })
    ).toBe(false);
  });

  it('keeps the final check refreshing only while something can clear', () => {
    expect(verifyNeedsPolling({ checks: [{ id: 'worker' }] })).toBe(true);
    expect(
      verifyNeedsPolling({
        checks: [{ id: 'distribution', status: CHECK_STATUS.WARN }],
      })
    ).toBe(true);
    expect(
      verifyNeedsPolling({
        checks: [{ id: 'distribution', status: CHECK_STATUS.PASS }],
      })
    ).toBe(false);
    expect(verifyNeedsPolling(undefined)).toBe(false);
  });

  describe('in the Vault step', () => {
    beforeEach(() => vi.useFakeTimers());
    afterEach(() => vi.useRealTimers());

    const ctxFor = distribution => ({
      docs: () => [],
      workspaceId: UUID_A,
      apiUrl: 'http://localhost:4000',
      refresh: vi.fn().mockResolvedValue(undefined),
      session: { progress: { certops: { objective: 'vault' } } },
      summary: { certops: { agents: { items: [] }, distribution } },
    });

    it('refreshes every 15 seconds while the warning shows and stops on unmount', () => {
      const ctx = ctxFor({ groups: 0, outboxBacklog: { count: 2 } });
      const { unmount } = render(
        <ChakraProvider>
          <VaultStep ctx={ctx} />
        </ChakraProvider>
      );
      act(() => {
        vi.advanceTimersByTime(SUMMARY_POLL_MS * 2);
      });
      expect(ctx.refresh).toHaveBeenCalledTimes(2);
      unmount();
      act(() => {
        vi.advanceTimersByTime(SUMMARY_POLL_MS * 2);
      });
      expect(ctx.refresh).toHaveBeenCalledTimes(2);
    });

    it('does not poll when nothing is waiting', () => {
      const ctx = ctxFor({ groups: 0, outboxBacklog: { count: 0 } });
      render(
        <ChakraProvider>
          <VaultStep ctx={ctx} />
        </ChakraProvider>
      );
      act(() => {
        vi.advanceTimersByTime(SUMMARY_POLL_MS * 3);
      });
      expect(ctx.refresh).not.toHaveBeenCalled();
    });
  });
});

describe('completion follow-ups', () => {
  const issued = { issueJob: { status: 'succeeded', mode: 'real' } };

  it('suggests the first staging order only until one was issued', () => {
    expect(nextSteps('certops_automate', {}).join(' ')).toMatch(
      /Issue your first certificate with the staging CA/
    );
    const after = nextSteps('certops_automate', issued).join(' ');
    expect(after).not.toMatch(/Issue your first certificate/);
    expect(after).toMatch(/real DNS provider/);
    expect(after).toMatch(/Check renewals in the Certificates page/);
  });

  it('does not count a dry run or a failed order as issued', () => {
    for (const issueJob of [
      { status: 'succeeded', mode: 'dry_run' },
      { status: 'failed', mode: 'real' },
    ]) {
      expect(nextSteps('certops_automate', { issueJob }).join(' ')).toMatch(
        /Issue your first certificate/
      );
    }
  });

  it('stops asking for a first rollout once one is verified', () => {
    expect(
      nextSteps('certops_vault', { distribution: { verified: true } }).join(' ')
    ).not.toMatch(/Run a verified rollout/);
    expect(nextSteps('certops_vault', {}).join(' ')).toMatch(
      /Run a verified rollout/
    );
  });
});
