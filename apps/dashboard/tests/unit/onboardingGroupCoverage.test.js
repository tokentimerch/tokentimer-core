import { describe, expect, it } from 'vitest';
import {
  GOALS,
  stepsForGoal,
} from '../../src/components/onboarding/journeyPlanner.js';
import {
  DEFAULT_ONLY_NOTE,
  DEFAULT_ONLY_NOTE_WITH_ITEMS,
  ITEMS_SHOWN,
  adcsGap,
  canContinueTicks,
  canTickGoal,
  confirmsDefault,
  defaultOnlyNote,
  describeItemsCovered,
  describeTicks,
  isDefaultOnlyGoal,
  observedForPick,
  planSessionItems,
  recipientsNeedPolling,
  recipientsSatisfied,
  summarizeItems,
  tickIds,
  workspaceHasItems,
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

// Every certificate goal and pick, in each state a managed item can be in:
// the thing the guide manages exists (with or without a token) or does not
// yet. A pick that has something never gets the default-only wording.
describe('pick x state matrix for the certificate goals', () => {
  const SOURCES = {
    certops_observe: null,
    certops_automate: ['issue'],
    certops_vault: ['publish'],
    certops_adcs: ['profile', 'enrollment'],
  };
  const certGoals = Object.keys(SOURCES);
  const cases = certGoals.flatMap(goal =>
    PICKS[goal].map(pick => [goal, pick])
  );

  // One session where the goal's own item exists, optionally without a token.
  function withItem(goal, pick, { tokenId = 77, source } = {}) {
    const base = sessionFor(goal, pick);
    const certops =
      goal === 'certops_observe'
        ? {
            ...base.summary.certops,
            observedCertificates: {
              total: 1,
              items: [
                {
                  certificateId: 'o',
                  tokenId,
                  source:
                    pick === 'kubernetes'
                      ? 'cert_manager'
                      : pick === 'windows'
                        ? 'agent_windows'
                        : 'agent_filesystem',
                  agentId: pick === 'windows' ? 'w1' : 'a1',
                  clusterId: 'prod',
                },
              ],
            },
          }
        : {
            ...base.summary.certops,
            sessionCertificates: [
              {
                certificateId: 'x',
                tokenId,
                source: source || SOURCES[goal][0],
              },
            ],
          };
    return {
      ...base,
      summary: { ...base.summary, certops },
    };
  }
  function nothingYet(goal, pick) {
    const base = sessionFor(goal, pick);
    return {
      ...base,
      summary: {
        ...base.summary,
        certops: {
          ...base.summary.certops,
          sessionCertificates: [],
          observedCertificates: { total: 0, items: [] },
        },
      },
    };
  }
  const sentenceFor = (goal, plan, items = []) =>
    describeTicks({
      goal,
      items,
      defaultName: 'Ops',
      noToken: plan.noToken,
    });
  const DEFAULT_ONLY_WORDS = /does not create items|Nothing was created yet/;

  it.each(cases)('%s / %s: an item with a token is ticked', (goal, pick) => {
    const { refs, summary, progress } = withItem(goal, pick);
    const plan = planSessionItems({ goal, refs, summary, progress });
    expect(tickIds(goal, plan)).toEqual(['77']);
    expect(confirmsDefault(goal, plan)).toBe(false);
    expect(plan.noToken).toBe(0);
    expect(
      sentenceFor(goal, plan, [{ id: '77', kind: 'certificate', groupIds: [] }])
    ).not.toMatch(DEFAULT_ONLY_WORDS);
    expect(defaultOnlyNote({ goal, summary })).toBe('');
    expect(
      recipientsNeedPolling({ goal, plan, ready: true, itemCount: 1 })
    ).toBe(false);
  });

  it.each(cases)(
    '%s / %s: an item without a token is named, never default-only',
    (goal, pick) => {
      const { refs, summary, progress } = withItem(goal, pick, {
        tokenId: null,
      });
      const plan = planSessionItems({ goal, refs, summary, progress });
      expect(tickIds(goal, plan)).toEqual([]);
      expect(plan.noToken).toBe(1);
      const sentence = sentenceFor(goal, plan);
      expect(sentence).toMatch(/no inventory record yet/);
      expect(sentence).not.toMatch(DEFAULT_ONLY_WORDS);
      expect(defaultOnlyNote({ goal, summary })).toBe('');
      // The record appears on its own, so the page keeps reading.
      expect(
        recipientsNeedPolling({ goal, plan, ready: true, itemCount: 0 })
      ).toBe(true);
    }
  );

  it.each(cases)(
    '%s / %s: with nothing yet it confirms the default group and keeps reading',
    (goal, pick) => {
      const { refs, summary, progress } = nothingYet(goal, pick);
      const plan = planSessionItems({ goal, refs, summary, progress });
      expect(tickIds(goal, plan)).toEqual([]);
      expect(confirmsDefault(goal, plan)).toBe(true);
      expect(defaultOnlyNote({ goal, summary })).toBe('');
      expect(
        recipientsNeedPolling({ goal, plan, ready: true, itemCount: 0 })
      ).toBe(true);
      // Still reading the ticks: nothing to poll for yet.
      expect(
        recipientsNeedPolling({ goal, plan, ready: false, itemCount: 0 })
      ).toBe(false);
    }
  );

  it('AD CS names the missing attachment instead of the generic fallback', () => {
    const text = describeTicks({
      goal: 'certops_adcs',
      items: [],
      defaultName: 'Ops',
    });
    expect(text).toBe(
      'No certificate is attached to the renewal profile yet, so there is nothing to tick. Until then the workspace default group "Ops" is used.'
    );
    expect(text).not.toMatch(DEFAULT_ONLY_WORDS);
  });
});

describe('AD CS certificates before the first enrollment', () => {
  const progress = (extra = {}) => ({
    certops: { objective: 'adcs', infrastructure: 'windows', ...extra },
  });
  const adcsSummary = (sessionCertificates, adcs) => ({
    certops: { sessionCertificates, ...(adcs ? { adcs } : {}) },
  });

  it('plans the certificates a profile is attached to, no enrollment needed', () => {
    const plan = planSessionItems({
      goal: 'certops_adcs',
      summary: adcsSummary([
        { certificateId: 'a', tokenId: 5, source: 'profile' },
        { certificateId: 'b', tokenId: 6, source: 'profile' },
      ]),
      progress: progress(),
    });
    expect(plan.certificates).toEqual(['5', '6']);
    expect(plan.noToken).toBe(0);
  });

  it('merges enrollments once they exist and lists a token once', () => {
    const plan = planSessionItems({
      goal: 'certops_adcs',
      summary: adcsSummary([
        { certificateId: 'a', tokenId: 5, source: 'profile' },
        { certificateId: 'c', tokenId: 5, source: 'enrollment' },
        { certificateId: 'd', tokenId: 9, source: 'enrollment' },
      ]),
      progress: progress(),
    });
    expect(plan.certificates).toEqual(['5', '9']);
  });

  it('does not take issue or publish certificates for AD CS', () => {
    const plan = planSessionItems({
      goal: 'certops_adcs',
      summary: adcsSummary([
        { certificateId: 'a', tokenId: 5, source: 'issue' },
        { certificateId: 'b', tokenId: 6, source: 'publish' },
      ]),
      progress: progress(),
    });
    expect(plan.certificates).toEqual([]);
    expect(confirmsDefault('certops_adcs', plan)).toBe(true);
  });

  it('does not take profile certificates for the other goals', () => {
    for (const goal of ['certops_automate', 'certops_vault']) {
      const plan = planSessionItems({
        goal,
        summary: adcsSummary([
          { certificateId: 'a', tokenId: 5, source: 'profile' },
        ]),
        progress: { certops: { objective: GOALS[goal].certopsObjective } },
      });
      expect(plan.certificates).toEqual([]);
    }
  });

  it('blocks ticking past the cap', () => {
    const many = Array.from({ length: 51 }, (_, i) => ({
      certificateId: `c${i}`,
      tokenId: 100 + i,
      source: 'profile',
    }));
    const plan = planSessionItems({
      goal: 'certops_adcs',
      summary: adcsSummary(many),
      progress: progress(),
    });
    expect(plan.blocked).toBe('cap');
  });

  describe('adcsGap', () => {
    const issuer = (over = {}) => ({
      id: 'i1',
      confirmed: true,
      safe: true,
      profileCount: 1,
      attachedCertificates: 1,
      ...over,
    });
    const gap = (issuers, extra) =>
      adcsGap({
        summary: { certops: { adcs: { issuers, profiles: 0 } } },
        progress: progress(extra),
      });

    it('says a profile is missing, or not attached, or nothing', () => {
      expect(gap([issuer({ profileCount: 0, attachedCertificates: 0 })])).toBe(
        'profile'
      );
      expect(gap([issuer({ attachedCertificates: 0 })])).toBe('attach');
      expect(gap([issuer()])).toBeNull();
    });

    it('counts only the issuer of this session, or the one the operator chose', () => {
      const old = issuer({
        id: 'old',
        existedBeforeSession: true,
        attachedCertificates: 4,
      });
      const fresh = issuer({ attachedCertificates: 0 });
      expect(gap([old, fresh])).toBe('attach');
      expect(gap([old, fresh], { chosenIssuerId: 'old' })).toBeNull();
    });

    it('claims nothing when the server does not say', () => {
      expect(adcsGap({ summary: {}, progress: progress() })).toBeNull();
      expect(
        adcsGap({ summary: { certops: 'unknown' }, progress: progress() })
      ).toBeNull();
    });
  });
});

describe('recipientsNeedPolling', () => {
  const none = { noToken: 0 };
  it('reads for a website without a record, whatever else is going on', () => {
    expect(
      recipientsNeedPolling({ goal: 'monitor_https', plan: { noToken: 1 } })
    ).toBe(true);
    expect(recipientsNeedPolling({ goal: 'monitor_https', plan: none })).toBe(
      false
    );
  });

  it('never reads for goals whose items are in hand when they are added', () => {
    for (const goal of ['track_asset', 'alerting', 'import_file']) {
      expect(
        recipientsNeedPolling({
          goal,
          plan: none,
          ready: true,
          itemCount: 0,
        })
      ).toBe(false);
    }
  });
});

describe('the default-only note', () => {
  it('is only for the alerting goal and never claims "no items" in a workspace that has some', () => {
    for (const goal of Object.keys(PICKS)) {
      expect(defaultOnlyNote({ goal, summary: {} })).toBe('');
      expect(
        defaultOnlyNote({
          goal,
          summary: { certops: { certificates: { total: 3 } } },
        })
      ).toBe('');
    }
    expect(defaultOnlyNote({ goal: 'alerting', summary: {} })).toBe(
      DEFAULT_ONLY_NOTE
    );
    for (const summary of [
      { assets: { total: 2 } },
      { monitors: { items: [{ id: 'm' }] } },
      { certops: { certificates: { total: 1 } } },
    ]) {
      expect(workspaceHasItems(summary)).toBe(true);
      expect(defaultOnlyNote({ goal: 'alerting', summary })).toBe(
        DEFAULT_ONLY_NOTE_WITH_ITEMS
      );
    }
    expect(DEFAULT_ONLY_NOTE_WITH_ITEMS).not.toMatch(/does not create items/);
    expect(workspaceHasItems({ certops: 'unknown' })).toBe(false);
  });
});
