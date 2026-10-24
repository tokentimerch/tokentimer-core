import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { describe, expect, it, vi } from 'vitest';
import AdcsStep from '../../src/components/onboarding/certopsAdcsStep.jsx';
import { VaultStep } from '../../src/components/onboarding/certopsFinalSteps.jsx';
import {
  WORKER_NOTE,
  outboxBacklogMessage,
  overdueEnrollmentsMessage,
} from '../../src/components/onboarding/certopsWorkerMessages.js';
import {
  CHECK_STATUS,
  evaluateVerification,
} from '../../src/components/onboarding/verification.js';

vi.mock('../../src/hooks/useDashboardTheme', async importOriginal => ({
  ...(await importOriginal()),
  useDashboardTheme: () => ({ muted: 'gray.500' }),
}));
vi.mock('../../src/components/certops/certopsJobsApi.js', () => ({
  createJob: vi.fn(),
  getJob: vi.fn(),
}));

const NOW = Date.parse('2026-10-21T12:00:00.000Z');
const minutesAgo = m => new Date(NOW - m * 60000).toISOString();

describe('overdueEnrollmentsMessage', () => {
  const certops = (overdue, extra) => ({
    adcs: { enrollments: { overdue }, ...extra },
  });

  it('is hidden at zero and when an older API omits the field', () => {
    expect(
      overdueEnrollmentsMessage(certops({ count: 0, oldestDueAt: null }), NOW)
    ).toBeNull();
    expect(overdueEnrollmentsMessage({ adcs: {} }, NOW)).toBeNull();
    expect(overdueEnrollmentsMessage(undefined, NOW)).toBeNull();
    expect(overdueEnrollmentsMessage('unknown', NOW)).toBeNull();
  });

  it('handles plural, singular and the age in minutes', () => {
    expect(
      overdueEnrollmentsMessage(
        certops({ count: 3, oldestDueAt: minutesAgo(42) }),
        NOW
      )
    ).toBe(
      '3 enrollments are overdue by 42 min. They will not progress without a running CertOps worker.'
    );
    expect(
      overdueEnrollmentsMessage(
        certops({ count: 1, oldestDueAt: minutesAgo(7) }),
        NOW
      )
    ).toBe(
      '1 enrollment is overdue by 7 min. It will not progress without a running CertOps worker.'
    );
  });

  it('omits the age when the date is missing', () => {
    expect(
      overdueEnrollmentsMessage(certops({ count: 2, oldestDueAt: null }), NOW)
    ).toBe(
      '2 enrollments are overdue. They will not progress without a running CertOps worker.'
    );
  });
});

describe('outboxBacklogMessage', () => {
  it('is hidden at zero or when the field is missing', () => {
    expect(
      outboxBacklogMessage({ distribution: { outboxBacklog: { count: 0 } } })
    ).toBeNull();
    expect(outboxBacklogMessage({ distribution: {} })).toBeNull();
    expect(outboxBacklogMessage(undefined)).toBeNull();
  });

  it('handles singular and plural', () => {
    const at = count => ({ distribution: { outboxBacklog: { count } } });
    expect(outboxBacklogMessage(at(1))).toBe(
      '1 CertOps notification or rollout request is waiting for the worker.'
    );
    expect(outboxBacklogMessage(at(4))).toBe(
      '4 CertOps notifications or rollout requests are waiting for the worker.'
    );
  });
});

function adcsCtx(certops) {
  return {
    docs: () => [],
    refresh: vi.fn().mockResolvedValue(undefined),
    session: {
      progress: {
        certops: {
          objective: 'adcs',
          infrastructure: 'windows',
          caHost: 'ca01.corp.example.com',
          caName: 'Corp Issuing CA',
        },
      },
    },
    summary: { certops: { agents: { items: [] }, ...certops } },
  };
}

const showAdcs = ctx =>
  render(
    <ChakraProvider>
      <AdcsStep ctx={ctx} />
    </ChakraProvider>
  );

describe('AdcsStep worker signals', () => {
  it('always names the CertOps worker as a requirement', () => {
    showAdcs(adcsCtx({ adcs: { issuers: [], profiles: 0 } }));
    expect(screen.getByTestId('adcs-worker-note').textContent).toBe(
      WORKER_NOTE
    );
    expect(WORKER_NOTE).toMatch(/worker-certops/);
    expect(WORKER_NOTE).toMatch(/certops cron job/);
  });

  it('warns when enrollments are overdue', () => {
    showAdcs(
      adcsCtx({
        adcs: {
          issuers: [],
          profiles: 0,
          enrollments: {
            overdue: {
              count: 2,
              oldestDueAt: new Date(Date.now() - 600000).toISOString(),
            },
          },
        },
      })
    );
    const warning = screen.getByTestId('adcs-overdue-warning');
    expect(warning.textContent).toMatch(
      /^2 enrollments are overdue by \d+ min/
    );
    expect(warning.getAttribute('role')).toBe('note');
  });

  it('shows no warning at zero or when an older API omits the field', () => {
    showAdcs(
      adcsCtx({
        adcs: {
          issuers: [],
          profiles: 0,
          enrollments: { overdue: { count: 0, oldestDueAt: null } },
        },
      })
    );
    expect(screen.queryByTestId('adcs-overdue-warning')).toBeNull();
  });

  it('shows no warning when the field is missing', () => {
    showAdcs(adcsCtx({ adcs: { issuers: [], profiles: 0 } }));
    expect(screen.queryByTestId('adcs-overdue-warning')).toBeNull();
  });
});

function vaultCtx(distribution) {
  return {
    docs: () => [],
    workspaceId: 'w1',
    apiUrl: 'http://localhost:4000',
    refresh: vi.fn().mockResolvedValue(undefined),
    session: { progress: { certops: { objective: 'vault' } } },
    summary: { certops: { agents: { items: [] }, distribution } },
  };
}

const showVault = ctx =>
  render(
    <ChakraProvider>
      <VaultStep ctx={ctx} />
    </ChakraProvider>
  );

describe('VaultStep worker signals', () => {
  it('warns when requests are waiting for the worker', () => {
    showVault(
      vaultCtx({ groups: 0, bindings: 0, outboxBacklog: { count: 2 } })
    );
    expect(screen.getByTestId('vault-backlog-warning').textContent).toBe(
      '2 CertOps notifications or rollout requests are waiting for the worker.'
    );
  });

  it('shows no warning at zero or when an older API omits the field', () => {
    showVault(vaultCtx({ groups: 0, bindings: 0 }));
    expect(screen.queryByTestId('vault-backlog-warning')).toBeNull();
  });
});

describe('final check', () => {
  const verify = certops =>
    evaluateVerification({
      goal: 'certops_vault',
      monitors: [],
      token: null,
      summary: {
        certops: {
          agents: { live: 1 },
          certificates: { total: 1 },
          ...certops,
        },
      },
    });

  it('adds a follow up when work is waiting on the worker', () => {
    const result = verify({
      distribution: { outboxBacklog: { count: 1 } },
      adcs: {
        enrollments: { overdue: { count: 2, oldestDueAt: minutesAgo(1) } },
      },
    });
    const worker = result.checks.find(c => c.id === 'worker');
    expect(worker.status).toBe(CHECK_STATUS.WARN);
    expect(worker.detail).toMatch(/2 enrollments are overdue/);
    expect(worker.detail).toMatch(/1 CertOps notification or rollout request/);
  });

  it('adds nothing at zero or when the fields are missing', () => {
    expect(
      verify({ distribution: { outboxBacklog: { count: 0 } } }).checks.some(
        c => c.id === 'worker'
      )
    ).toBe(false);
    expect(verify({}).checks.some(c => c.id === 'worker')).toBe(false);
  });

  it('always carries the static worker sentence once for CertOps goals', () => {
    expect(verify({}).notes).toEqual([WORKER_NOTE]);
    expect(
      verify({ distribution: { outboxBacklog: { count: 3 } } }).notes
    ).toEqual([WORKER_NOTE]);
    for (const goal of [
      'certops_observe',
      'certops_automate',
      'certops_adcs',
    ]) {
      expect(
        evaluateVerification({ goal, monitors: [], token: null, summary: {} })
          .notes
      ).toEqual([WORKER_NOTE]);
    }
  });

  it('keeps the sentence off goals that have nothing to do with the worker', () => {
    const result = evaluateVerification({
      goal: 'track_asset',
      monitors: [],
      token: null,
      summary: {},
    });
    expect(result.notes).toEqual([]);
  });
});
