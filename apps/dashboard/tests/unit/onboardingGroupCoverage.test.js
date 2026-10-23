import { describe, expect, it } from 'vitest';
import {
  GOALS,
  stepsForGoal,
} from '../../src/components/onboarding/journeyPlanner.js';
import {
  ITEMS_SHOWN,
  canContinueTicks,
  canTickGoal,
  confirmsDefault,
  describeItemsCovered,
  describeTicks,
  isDefaultOnlyGoal,
  observedForPick,
  planSessionItems,
  recipientsSatisfied,
  summarizeItems,
  tickIds,
} from '../../src/components/onboarding/groupAttachment.js';

const wired = (summary, ids) => ({
  ...summary,
  references: { ...summary.references, tokenGroups: ids },
});

// What a session of each goal holds once its own work has produced items.
// The fixture is one summary and one progress per pick.
const AGENT = { id: 'a1', platform: 'linux', existedBeforeSession: false };
const WIN_AGENT = { id: 'w1', platform: 'win32', existedBeforeSession: false };
function sessionFor(goal, pick = '') {
  const certops = {
    agents: { items: [AGENT, WIN_AGENT] },
    sessionCertificates: [
      { certificateId: 'c1', tokenId: 41, source: 'issue' },
      { certificateId: 'c2', tokenId: 42, source: 'publish' },
      { certificateId: 'c3', tokenId: 43, source: 'enrollment' },
    ],
    observedCertificates: {
      total: 2,
      items: [
        {
          certificateId: 'o1',
          tokenId: 51,
          source: 'agent_filesystem',
          agentId: 'a1',
        },
        {
          certificateId: 'o2',
          tokenId: 52,
          source: 'agent_windows',
          agentId: 'w1',
        },
        {
          certificateId: 'o3',
          tokenId: 53,
          source: 'cert_manager',
          clusterId: 'prod',
        },
      ],
    },
  };
  return {
    refs: {
      tokenIds: [11, 21],
      assetTokenIds: [21],
      monitorIds: ['m1'],
    },
    summary: {
      certops,
      monitors: { items: [{ id: 'm1', tokenId: 11 }] },
      references: {
        tokenIds: { existing: [11, 21] },
        assetTokenIds: { existing: [21] },
        monitorIds: { existing: ['m1'] },
      },
    },
    progress: {
      certops: {
        objective: GOALS[goal].certopsObjective,
        ...(pick ? { infrastructure: pick } : {}),
        ...(pick === 'kubernetes' ? { clusterId: 'prod' } : {}),
      },
    },
  };
}

// Every goal that shows the alerts step, with its picks.
const PICKS = {
  monitor_https: [''],
  track_asset: [''],
  certops_observe: ['linux', 'windows', 'kubernetes'],
  certops_automate: ['linux', 'windows'],
  certops_adcs: ['windows'],
  certops_vault: ['linux'],
};
// Goals that never carry an item of their own in this step.
const NO_ITEM_GOALS = ['alerting'];

describe('which goals show the alerts step', () => {
  it('covers every core goal that has a recipients step', () => {
    const withStep = Object.keys(GOALS).filter(g =>
      GOALS[g].steps.includes('recipients')
    );
    const covered = [...Object.keys(PICKS), ...NO_ITEM_GOALS].sort();
    // The import goals drop the step with the import dialog on (the default),
    // and keep it only on the parked guided path.
    const imports = ['import_file', 'import_integration'];
    expect(withStep.filter(g => !imports.includes(g)).sort()).toEqual(covered);
    for (const goal of imports) {
      expect(stepsForGoal(goal, false)).not.toContain('recipients');
      expect(stepsForGoal(goal, true)).toContain('recipients');
    }
  });
});

describe.each(Object.entries(PICKS))('%s', (goal, picks) => {
  it.each(picks)('ticks its own items with pick "%s"', pick => {
    const { refs, summary, progress } = sessionFor(goal, pick);
    expect(canTickGoal(goal)).toBe(true);
    expect(isDefaultOnlyGoal(goal)).toBe(false);
    const plan = planSessionItems({ goal, refs, summary, progress });
    const ids = tickIds(goal, plan);
    expect(ids.length).toBeGreaterThan(0);
    expect(plan.blocked).toBeNull();
    // With items the step never falls back to the default-only wording.
    const sentence = describeTicks({
      goal,
      items: ids.map(id => ({
        id,
        kind: plan.websites.includes(id)
          ? 'website'
          : plan.assets.includes(id)
            ? 'asset'
            : 'certificate',
        groupIds: [],
      })),
      defaultName: 'Ops',
    });
    expect(sentence).toMatch(/^Ticked groups receive alerts for /);
    expect(sentence).not.toMatch(/does not create items/);
    expect(confirmsDefault(goal, plan)).toBe(false);
  });

  it.each(picks)(
    'needs a ticked group per item to continue (pick "%s")',
    pick => {
      const { refs, summary, progress } = sessionFor(goal, pick);
      const plan = planSessionItems({ goal, refs, summary, progress });
      const ids = tickIds(goal, plan);
      const groupsOf = id => Object.fromEntries(ids.map(i => [i, id]));
      const none = wired(summary, groupsOf([]));
      const all = wired(summary, groupsOf(['ops']));
      expect(canContinueTicks({ goal, refs, reality: none, progress })).toBe(
        false
      );
      expect(canContinueTicks({ goal, refs, reality: all, progress })).toBe(
        true
      );
      // Ticks alone never finish the step: the operator's Continue does.
      expect(recipientsSatisfied({ goal, refs, progress, reality: all })).toBe(
        false
      );
      expect(
        recipientsSatisfied({
          goal,
          refs,
          progress: { ...progress, recipientsConfirmedFor: goal },
          reality: all,
        })
      ).toBe(true);
    }
  );
});

describe('goals with no item of their own', () => {
  it('only the alerting goal is default-only', () => {
    for (const goal of NO_ITEM_GOALS) {
      expect(canTickGoal(goal)).toBe(false);
      expect(isDefaultOnlyGoal(goal)).toBe(true);
    }
    for (const goal of Object.keys(GOALS)) {
      if (!NO_ITEM_GOALS.includes(goal)) {
        expect(isDefaultOnlyGoal(goal)).toBe(false);
      }
    }
  });
});

describe('observedForPick', () => {
  const certops = sessionFor('certops_observe').summary.certops;

  it('keeps the exact platform of the pick', () => {
    expect(
      observedForPick(certops, { infrastructure: 'linux' }).items.map(
        c => c.certificateId
      )
    ).toEqual(['o1']);
    expect(
      observedForPick(certops, { infrastructure: 'windows' }).items.map(
        c => c.certificateId
      )
    ).toEqual(['o2']);
  });

  it('defaults to Linux when no pick is saved yet, like the install step', () => {
    expect(
      observedForPick(certops, {}).items.map(c => c.certificateId)
    ).toEqual(['o1']);
  });

  it('uses the controller certificates for Kubernetes, narrowed to the cluster', () => {
    expect(
      observedForPick(certops, {
        infrastructure: 'kubernetes',
        clusterId: 'prod',
      }).items.map(c => c.certificateId)
    ).toEqual(['o3']);
    expect(
      observedForPick(certops, {
        infrastructure: 'kubernetes',
        clusterId: 'dev',
      }).items
    ).toEqual([]);
    expect(
      observedForPick(certops, { infrastructure: 'kubernetes' }).items
    ).toHaveLength(1);
  });

  it('never adopts an agent that was already in the workspace unless it was chosen', () => {
    const old = {
      agents: {
        items: [{ id: 'a1', platform: 'linux', existedBeforeSession: true }],
      },
      observedCertificates: certops.observedCertificates,
    };
    expect(observedForPick(old, { infrastructure: 'linux' }).items).toEqual([]);
    expect(
      observedForPick(old, { infrastructure: 'linux', chosenAgentId: 'a1' })
        .items
    ).toHaveLength(1);
    expect(
      observedForPick(old, { infrastructure: 'linux', chosenAgentId: 'zz' })
        .items
    ).toEqual([]);
  });

  it('reads an older server, or an unknown summary, as nothing found', () => {
    expect(observedForPick(undefined).items).toEqual([]);
    expect(observedForPick('unknown').items).toEqual([]);
    expect(observedForPick({ agents: { items: [AGENT] } }).items).toEqual([]);
  });

  it('flags a list the server cut short', () => {
    const cut = {
      ...certops,
      observedCertificates: { ...certops.observedCertificates, total: 99 },
    };
    expect(observedForPick(cut, {}).truncated).toBe(true);
    expect(observedForPick(certops, {}).truncated).toBe(false);
  });
});

describe('observe session items', () => {
  it('lists certificates without a token as waiting, and blocks past the cap', () => {
    const certops = {
      agents: { items: [AGENT] },
      observedCertificates: {
        total: 2,
        items: [
          {
            certificateId: 'a',
            tokenId: 7,
            source: 'agent_filesystem',
            agentId: 'a1',
          },
          {
            certificateId: 'b',
            tokenId: null,
            source: 'agent_filesystem',
            agentId: 'a1',
          },
        ],
      },
    };
    const progress = {
      certops: { objective: 'observe', infrastructure: 'linux' },
    };
    const plan = planSessionItems({
      goal: 'certops_observe',
      summary: { certops },
      progress,
    });
    expect(plan.certificates).toEqual(['7']);
    expect(plan.noToken).toBe(1);
    const cut = planSessionItems({
      goal: 'certops_observe',
      summary: {
        certops: {
          ...certops,
          observedCertificates: { ...certops.observedCertificates, total: 51 },
        },
      },
      progress,
    });
    expect(cut.blocked).toBe('capObserved');
  });

  it('falls back to confirming the default group while nothing is found', () => {
    const plan = planSessionItems({
      goal: 'certops_observe',
      summary: { certops: { agents: { items: [AGENT] } } },
      progress: { certops: { objective: 'observe' } },
    });
    expect(plan.certificates).toEqual([]);
    expect(confirmsDefault('certops_observe', plan)).toBe(true);
    expect(
      describeTicks({
        goal: 'certops_observe',
        items: [],
        defaultName: 'Ops',
      })
    ).toBe(
      'No certificates found yet. Certificates your agent finds later use the workspace default group "Ops".'
    );
  });

  it('judges a not-yet-grouped certificate by the default group that stays reachable', () => {
    const certops = {
      agents: { items: [AGENT] },
      observedCertificates: {
        total: 1,
        items: [
          {
            certificateId: 'a',
            tokenId: 7,
            source: 'agent_filesystem',
            agentId: 'a1',
          },
        ],
      },
    };
    const progress = {
      certops: { objective: 'observe', infrastructure: 'linux' },
      recipientsConfirmedFor: 'certops_observe',
    };
    const reality = {
      certops,
      references: { tokenGroups: { 7: [] } },
      alerts: { contactGroups: { defaultHasRecipient: true } },
    };
    expect(
      recipientsSatisfied({
        goal: 'certops_observe',
        refs: {},
        progress,
        reality,
      })
    ).toBe(false);
  });
});

describe('the list of items under the heading', () => {
  const certs = n =>
    Array.from({ length: n }, (_, i) => ({
      id: String(i),
      kind: 'certificate',
      name: `c${i}`,
      groupIds: [],
    }));

  it('names the first ten and counts the rest', () => {
    expect(ITEMS_SHOWN).toBe(10);
    const { shown, more } = summarizeItems(certs(14));
    expect(shown).toHaveLength(10);
    expect(more).toBe(4);
    expect(summarizeItems(certs(3))).toEqual({
      shown: ['c0', 'c1', 'c2'],
      more: 0,
    });
  });

  it('says what the ticks apply to', () => {
    expect(describeItemsCovered(certs(1), 'certops_observe')).toBe(
      '1 certificate your agent found'
    );
    expect(describeItemsCovered(certs(4), 'certops_observe')).toBe(
      '4 certificates your agent found'
    );
    expect(describeItemsCovered(certs(2), 'certops_vault')).toBe(
      '2 certificates from this setup'
    );
    expect(
      describeItemsCovered([{ kind: 'website' }, { kind: 'website' }], 'x')
    ).toBe('2 websites you added');
    expect(describeItemsCovered([{ kind: 'asset' }], 'x')).toBe(
      '1 asset you added'
    );
    expect(
      describeItemsCovered([{ kind: 'asset' }, { kind: 'website' }], 'x')
    ).toBe('2 items from this guide');
  });
});
