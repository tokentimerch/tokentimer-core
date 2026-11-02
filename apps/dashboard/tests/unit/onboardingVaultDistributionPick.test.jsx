import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { describe, expect, it, vi } from 'vitest';
import { VaultStep } from '../../src/components/onboarding/certopsFinalSteps.jsx';
import {
  candidateDistributions,
  scopeDistribution,
} from '../../src/components/onboarding/distributionModel.js';
import {
  chooseDistribution,
  chooseInfrastructure,
  scopeCertops,
} from '../../src/components/onboarding/certopsScope.js';
import {
  isStepSatisfied,
  planJourney,
} from '../../src/components/onboarding/journeyPlanner.js';
import { finishesByItself } from '../../src/components/onboarding/heldSteps.js';
import { evaluateVerification } from '../../src/components/onboarding/verification.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const GROUP_A = '11111111-1111-4111-8111-111111111111';
const GROUP_B = '22222222-2222-4222-8222-222222222222';

const group = (id, over = {}) => ({
  id,
  materialStoreRef: 'secret',
  verified: true,
  existedBeforeSession: false,
  createdAt: '2026-10-22T11:00:00.000Z',
  lastVerifiedAt: '2026-10-22T11:30:00.000Z',
  ...over,
});
const old = over => group(GROUP_A, { existedBeforeSession: true, ...over });
const fresh = over => group(GROUP_B, over);

const reality = items => ({
  certops: {
    agents: { items: [], live: 0 },
    distribution: {
      groups: items.length,
      bindings: 0,
      verified: items.some(i => i.verified),
      items,
    },
  },
});
const saved = (over = {}) => ({
  objective: 'vault',
  infrastructure: 'linux',
  names: 'app.example.com',
  zone: 'example.com',
  ...over,
});
const done = (items, over) =>
  isStepSatisfied('certops_vault', {
    reality: reality(items),
    progress: { certops: saved(over) },
    objective: 'vault',
    goal: 'certops_vault',
  });

describe('distributions a session may use', () => {
  it('without an opt-in only groups with session work count', () => {
    expect(candidateDistributions([old(), fresh()]).map(i => i.id)).toEqual([
      GROUP_B,
    ]);
  });

  it('with an opt-in only the chosen group counts', () => {
    expect(
      candidateDistributions([old(), fresh()], GROUP_A).map(i => i.id)
    ).toEqual([GROUP_A]);
    expect(candidateDistributions([old(), fresh()], 'nope')).toEqual([]);
  });

  it('reads an API that does not say as all new', () => {
    const plain = { id: 'x', verified: true };
    expect(candidateDistributions([plain])).toHaveLength(1);
  });

  it('keeps workspace aggregates from a server that has no items', () => {
    const scoped = scopeDistribution({ groups: 2, verified: true }, '');
    expect(scoped.groups).toBe(2);
    expect(scoped.verified).toBe(true);
  });

  it('recomputes groups and verified from the usable items', () => {
    const scoped = scopeDistribution(
      {
        groups: 2,
        verified: true,
        items: [old(), fresh({ verified: false })],
      },
      ''
    );
    expect(scoped.groups).toBe(1);
    expect(scoped.verified).toBe(false);
  });
});

describe('Share a certificate through Vault in the planner', () => {
  it('finishes file-only delivery from fresh backend evidence without live TLS, never from an unrelated or earlier setup', () => {
    expect(done([fresh({ verified: false, completed: true })])).toBe(true);
    expect(done([old({ verified: false, completed: true })])).toBe(false);
    expect(
      done([fresh({ verified: false, completed: true })], { groupId: GROUP_A })
    ).toBe(false);
    expect(done([fresh({ verified: false, completed: false })])).toBe(false);
  });
  it('stays open when the only verified group was there before the session', () => {
    expect(done([old()])).toBe(false);
  });

  it('is satisfied by a group verified in this session', () => {
    expect(done([old(), fresh()])).toBe(true);
    expect(done([fresh({ verified: false })])).toBe(false);
  });

  it('is satisfied by a chosen group only after Continue confirms it', () => {
    expect(done([old()], { chosenDistributionId: GROUP_A })).toBe(false);
    expect(
      done([old()], {
        chosenDistributionId: GROUP_A,
        chosenDistributionConfirmed: GROUP_A,
      })
    ).toBe(true);
  });

  it('ignores a confirmation that was about another group', () => {
    expect(
      done([old(), fresh()], {
        chosenDistributionId: GROUP_A,
        chosenDistributionConfirmed: GROUP_B,
      })
    ).toBe(false);
  });

  it('needs the chosen group to be verified', () => {
    expect(
      done([old({ verified: false })], {
        chosenDistributionId: GROUP_A,
        chosenDistributionConfirmed: GROUP_A,
      })
    ).toBe(false);
  });

  it('keeps the step on Vault when the second distribution is still to do', () => {
    const plan = planJourney({
      intent: { goal: 'certops_vault' },
      progress: {
        certops: saved({ configReviewed: true }),
      },
      reality: reality([old()]),
    });
    expect(plan.steps.find(s => s.id === 'certops_vault').status).not.toBe(
      'done'
    );
  });
});

describe('the distribution choice', () => {
  it('is saved for the Vault goal and cleared on untick', () => {
    const a = chooseDistribution(saved(), 'vault', GROUP_A);
    expect(a.chosenDistributionId).toBe(GROUP_A);
    const none = chooseDistribution(a, 'vault', null);
    expect(none.chosenDistributionId).toBeUndefined();
  });

  it('drops the confirmation when another group is picked', () => {
    const a = chooseDistribution(saved(), 'vault', GROUP_A);
    const confirmed = { ...a, chosenDistributionConfirmed: GROUP_A };
    expect(
      chooseDistribution(confirmed, 'vault', GROUP_A)
        .chosenDistributionConfirmed
    ).toBe(GROUP_A);
    expect(
      chooseDistribution(confirmed, 'vault', GROUP_B)
        .chosenDistributionConfirmed
    ).toBeUndefined();
  });

  it('is reset when the pick changes', () => {
    const picked = {
      ...saved(),
      chosenDistributionId: GROUP_A,
      chosenDistributionConfirmed: GROUP_A,
    };
    const next = chooseInfrastructure(picked, 'vault', 'windows');
    expect(next.chosenDistributionId).toBeUndefined();
    expect(next.chosenDistributionConfirmed).toBeUndefined();
    expect(
      chooseInfrastructure(picked, 'vault', 'linux').chosenDistributionId
    ).toBe(GROUP_A);
  });

  it('does not leak into another goal', () => {
    const picked = { ...saved(), chosenDistributionId: GROUP_A };
    expect(
      scopeCertops(picked, 'observe').chosenDistributionId
    ).toBeUndefined();
  });

  it('waits for Continue only when a distribution was chosen', () => {
    const goal = 'certops_vault';
    expect(finishesByItself('certops_vault', { goal, progress: {} })).toBe(
      true
    );
    expect(
      finishesByItself('certops_vault', {
        goal,
        progress: { certops: saved({ chosenDistributionId: GROUP_A }) },
      })
    ).toBe(false);
  });
});

describe('verification of the Vault goal', () => {
  const run = (items, distributionId) =>
    evaluateVerification({
      goal: 'certops_vault',
      summary: reality(items),
      infrastructure: 'linux',
      distributionId,
    }).checks.find(c => c.id === 'distribution');

  it('does not call an older distribution the one the guide set up', () => {
    expect(run([old()]).label).toMatch(/not verified/);
    expect(run([old()], GROUP_A).label).toMatch(/verified by a rollout/);
    expect(run([fresh()]).label).toMatch(/verified by a rollout/);
  });
});

function ctxFor(items, savedOver = {}) {
  const session = {
    intent: { goal: 'certops_vault' },
    progress: { certops: saved(savedOver) },
  };
  return {
    session,
    workspaceId: 'ws-1',
    apiUrl: 'https://api.example.com',
    docs: () => [],
    refresh: vi.fn().mockResolvedValue(undefined),
    summary: reality(items),
    controller: {
      update: vi.fn(async mutate => {
        Object.assign(session, mutate(session));
      }),
    },
  };
}

const show = ctx =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <VaultStep ctx={ctx} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );

describe('Share a certificate through Vault with a distribution from before', () => {
  it('offers the guide and does not call the old distribution done', () => {
    show(ctxFor([old()]));
    expect(screen.getByTestId('existing-distributions-note')).toHaveTextContent(
      '1 completed distribution is already in this workspace'
    );
    expect(
      screen.queryByRole('combobox', { name: /distribution/i })
    ).toBeNull();
    expect(screen.queryByTestId('vault-use-distribution')).toBeNull();
  });

  it('lists the old group only after the box is ticked, then asks Continue', async () => {
    const ctx = ctxFor([old()]);
    const { rerender } = show(ctx);
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'My Vault distribution is already set up',
      })
    );
    const select = await screen.findByLabelText('Choose your distribution');
    fireEvent.change(select, { target: { value: GROUP_A } });
    await waitFor(() =>
      expect(
        scopeCertops(ctx.session.progress.certops, 'vault').chosenDistributionId
      ).toBe(GROUP_A)
    );
    rerender(
      <ChakraProvider>
        <DashboardThemeProvider>
          <VaultStep ctx={{ ...ctx }} />
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    const next = screen.getByTestId('vault-use-distribution');
    expect(next).toBeEnabled();
    fireEvent.click(next);
    await waitFor(() =>
      expect(
        scopeCertops(ctx.session.progress.certops, 'vault')
          .chosenDistributionConfirmed
      ).toBe(GROUP_A)
    );
  });

  it('holds Continue while the chosen group is not verified', () => {
    show(
      ctxFor([old({ verified: false })], {
        chosenDistributionId: GROUP_A,
      })
    );
    expect(screen.getByTestId('vault-use-distribution')).toBeDisabled();
  });
});
