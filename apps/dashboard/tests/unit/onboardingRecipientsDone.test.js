import { describe, expect, it } from 'vitest';
import {
  isStepSatisfied,
  planJourney,
} from '../../src/components/onboarding/journeyPlanner.js';
import { recipientsSatisfied } from '../../src/components/onboarding/groupAttachment.js';
import {
  clearGoal,
  progressForGoalChange,
} from '../../src/components/onboarding/sessionTransitions.js';

// "Choose who gets alerted" is judged per goal on what THIS session created,
// not on whether the workspace has a default group.

const ready = id => ({ id, state: 'ready', blockers: [] });
const capabilities = {
  items: [
    ready('monitoring.endpoint'),
    ready('assets.manual'),
    ready('assets.file_import'),
    ready('alerts.contact_groups'),
    ready('certops.core'),
    ready('certops.adcs'),
    ready('certops.vault_distribution'),
  ],
};

// The workspace default group reaches someone in every case below, which is
// exactly the situation that used to mark the step done.
const defaultOk = {
  contactGroups: { defaultHasRecipient: true, defaultHasEmailRecipient: true },
  smtpConfigured: true,
};

function reality({
  monitors = [],
  tokens = [],
  assets = [],
  groups = {},
} = {}) {
  return {
    assets: { total: assets.length },
    monitors: { items: monitors },
    alerts: defaultOk,
    references: {
      tokenIds: { existing: tokens },
      assetTokenIds: { existing: assets },
      monitorIds: { existing: monitors.map(m => m.id) },
      tokenGroups: groups,
    },
  };
}

const site = { id: 'm1', url: 'https://example.com', tokenId: 7 };
const siteRefs = {
  monitorUrl: site.url,
  monitorIds: ['m1'],
  tokenIds: [7],
};
const assetRefs = { assetTokenIds: [5], tokenIds: [5] };

function recipients(goal, { refs = {}, progress = {}, reality: r }) {
  return recipientsSatisfied({ goal, refs, progress, reality: r });
}

describe('recipients step: website monitor goal', () => {
  it('is not done when nothing was created yet', () => {
    expect(recipients('monitor_https', { reality: reality() })).toBe(false);
  });

  it('is not done when the website has no group, even with a default group', () => {
    const r = reality({
      monitors: [site],
      tokens: [7],
      groups: { 7: [] },
    });
    expect(recipients('monitor_https', { refs: siteRefs, reality: r })).toBe(
      false
    );
  });

  it('is done once the website carries a reachable group', () => {
    const r = reality({
      monitors: [site],
      tokens: [7],
      groups: { 7: ['g1'] },
    });
    expect(recipients('monitor_https', { refs: siteRefs, reality: r })).toBe(
      true
    );
  });

  it('needs every website of this session to carry a group', () => {
    const second = { id: 'm2', url: 'https://two.example.com', tokenId: 8 };
    const refs = {
      ...siteRefs,
      monitorIds: ['m1', 'm2'],
      tokenIds: [7, 8],
    };
    const some = reality({
      monitors: [site, second],
      tokens: [7, 8],
      groups: { 7: ['g1'], 8: [] },
    });
    expect(recipients('monitor_https', { refs, reality: some })).toBe(false);
    const all = reality({
      monitors: [site, second],
      tokens: [7, 8],
      groups: { 7: ['g1'], 8: ['g1'] },
    });
    expect(recipients('monitor_https', { refs, reality: all })).toBe(true);
  });

  it('ignores a website that has no certificate record to carry a group', () => {
    const noToken = {
      id: 'm3',
      url: 'https://three.example.com',
      tokenId: null,
    };
    const refs = { ...siteRefs, monitorIds: ['m1', 'm3'] };
    const r = reality({
      monitors: [site, noToken],
      tokens: [7],
      groups: { 7: ['g1'] },
    });
    expect(recipients('monitor_https', { refs, reality: r })).toBe(true);
  });

  it('does not count a stored confirmation flag', () => {
    const r = reality({ monitors: [site], tokens: [7], groups: { 7: [] } });
    expect(
      recipients('monitor_https', {
        refs: siteRefs,
        progress: { recipientsConfirmedFor: 'monitor_https' },
        reality: r,
      })
    ).toBe(false);
  });

  it('reopens when the group stops reaching anyone', () => {
    // The server lists only groups that reach a recipient, so a group that
    // lost its recipients drops out of the map.
    const before = reality({
      monitors: [site],
      tokens: [7],
      groups: { 7: ['g1'] },
    });
    const after = reality({ monitors: [site], tokens: [7], groups: { 7: [] } });
    expect(
      recipients('monitor_https', { refs: siteRefs, reality: before })
    ).toBe(true);
    expect(
      recipients('monitor_https', { refs: siteRefs, reality: after })
    ).toBe(false);
  });

  it('is not done against a summary that cannot say which groups are attached', () => {
    const r = reality({ monitors: [site], tokens: [7] });
    delete r.references.tokenGroups;
    expect(recipients('monitor_https', { refs: siteRefs, reality: r })).toBe(
      false
    );
  });
});

describe('recipients step: asset goal', () => {
  it('is not done when nothing was created yet', () => {
    expect(recipients('track_asset', { reality: reality() })).toBe(false);
  });

  it('is not done when the asset carries no group', () => {
    const r = reality({ tokens: [5], assets: [5], groups: { 5: [] } });
    expect(recipients('track_asset', { refs: assetRefs, reality: r })).toBe(
      false
    );
  });

  it('is done once the asset carries a reachable group', () => {
    const r = reality({ tokens: [5], assets: [5], groups: { 5: ['g2'] } });
    expect(recipients('track_asset', { refs: assetRefs, reality: r })).toBe(
      true
    );
  });

  it('is not satisfied by a website from another goal in the same session', () => {
    const refs = { ...siteRefs, ...assetRefs, tokenIds: [7, 5] };
    const r = reality({
      monitors: [site],
      tokens: [7, 5],
      assets: [5],
      groups: { 7: ['g1'], 5: [] },
    });
    expect(recipients('track_asset', { refs, reality: r })).toBe(false);
  });

  it('is not satisfied by an asset when the goal is the website monitor', () => {
    const refs = { ...siteRefs, ...assetRefs, tokenIds: [7, 5] };
    const r = reality({
      monitors: [site],
      tokens: [7, 5],
      assets: [5],
      groups: { 7: [], 5: ['g1'] },
    });
    expect(recipients('monitor_https', { refs, reality: r })).toBe(false);
  });
});

describe.each([
  'import_file',
  'import_integration',
  'alerting',
  'certops_observe',
  'certops_automate',
  'certops_adcs',
  'certops_vault',
])('recipients step: %s', goal => {
  const base = reality();

  it('is not done by an existing default group alone', () => {
    expect(recipients(goal, { reality: base })).toBe(false);
  });

  it('is done after the operator confirms this goal', () => {
    expect(
      recipients(goal, {
        progress: { recipientsConfirmedFor: goal },
        reality: base,
      })
    ).toBe(true);
  });

  it('ignores a confirmation made for another goal', () => {
    expect(
      recipients(goal, {
        progress: { recipientsConfirmedFor: 'monitor_https' },
        reality: base,
      })
    ).toBe(false);
  });

  it('reopens when the default group no longer reaches anyone', () => {
    const gone = {
      ...base,
      alerts: {
        ...defaultOk,
        contactGroups: {
          defaultHasRecipient: false,
          defaultHasEmailRecipient: false,
        },
      },
    };
    expect(
      recipients(goal, {
        progress: { recipientsConfirmedFor: goal },
        reality: gone,
      })
    ).toBe(false);
  });
});

describe('recipients step in the planned journey', () => {
  const statusOf = (plan, id) => plan.steps.find(s => s.id === id).status;

  it('stays open for a website goal until a group is attached', () => {
    const base = {
      intent: { goal: 'monitor_https' },
      operationRefs: siteRefs,
      capabilities,
    };
    const open = planJourney({
      ...base,
      reality: reality({ monitors: [site], tokens: [7], groups: { 7: [] } }),
    });
    expect(statusOf(open, 'monitor')).toBe('done');
    expect(statusOf(open, 'recipients')).toBe('current');
    expect(statusOf(open, 'verify')).toBe('upcoming');

    const attached = planJourney({
      ...base,
      reality: reality({
        monitors: [site],
        tokens: [7],
        groups: { 7: ['g1'] },
      }),
    });
    expect(statusOf(attached, 'recipients')).toBe('done');
    expect(statusOf(attached, 'verify')).toBe('current');
  });

  it('lets the operator skip it explicitly', () => {
    const plan = planJourney({
      intent: { goal: 'monitor_https' },
      progress: { skipped: ['recipients'] },
      operationRefs: siteRefs,
      capabilities,
      reality: reality({ monitors: [site], tokens: [7], groups: { 7: [] } }),
    });
    expect(statusOf(plan, 'recipients')).toBe('skipped');
    expect(statusOf(plan, 'verify')).toBe('current');
  });

  it('does not let another goal done step complete it', () => {
    // Website goal finished earlier in the session; now on the asset goal.
    const plan = planJourney({
      intent: { goal: 'track_asset' },
      operationRefs: { ...siteRefs, ...assetRefs, tokenIds: [7, 5] },
      capabilities,
      reality: reality({
        monitors: [site],
        tokens: [7, 5],
        assets: [5],
        groups: { 7: ['g1'], 5: [] },
      }),
    });
    expect(statusOf(plan, 'asset')).toBe('done');
    expect(statusOf(plan, 'recipients')).toBe('current');
  });

  it('keeps a CertOps setup open until the recipients are confirmed', () => {
    const input = {
      intent: { goal: 'certops_observe' },
      capabilities,
      reality: reality(),
    };
    expect(statusOf(planJourney(input), 'recipients')).not.toBe('done');
    const confirmed = planJourney({
      ...input,
      progress: { recipientsConfirmedFor: 'certops_observe' },
    });
    expect(statusOf(confirmed, 'recipients')).toBe('done');
  });

  it('passes the goal through isStepSatisfied', () => {
    const r = reality({ monitors: [site], tokens: [7], groups: { 7: ['g1'] } });
    expect(
      isStepSatisfied('recipients', {
        reality: r,
        refs: siteRefs,
        goal: 'monitor_https',
      })
    ).toBe(true);
    // Without a goal nothing can be judged, so the step stays open.
    expect(isStepSatisfied('recipients', { reality: r, refs: siteRefs })).toBe(
      false
    );
  });
});

describe('recipients step when the goal changes mid-journey', () => {
  it('drops the confirmation when another goal is picked', () => {
    const next = progressForGoalChange(
      { recipientsConfirmedFor: 'certops_observe', skipped: ['recipients'] },
      'certops_automate'
    );
    expect(next.recipientsConfirmedFor).toBeUndefined();
    expect(next.skipped).toBeUndefined();
  });

  it('drops the confirmation when the goal is cleared', () => {
    const patch = clearGoal({
      intent: { goal: 'import_file' },
      progress: { recipientsConfirmedFor: 'import_file' },
    });
    expect(patch.progress.recipientsConfirmedFor).toBeUndefined();
  });

  it('does not carry a confirmation from one goal to the next', () => {
    const progress = { recipientsConfirmedFor: 'import_file' };
    expect(
      recipients('certops_observe', { progress, reality: reality() })
    ).toBe(false);
  });

  it('judges a returning website goal from the server again', () => {
    // Switching away and back must not remember anything but real state.
    const r = reality({ monitors: [site], tokens: [7], groups: { 7: [] } });
    expect(recipients('monitor_https', { refs: siteRefs, reality: r })).toBe(
      false
    );
  });
});

describe('recipients step stays open until the person continues', () => {
  const statusOf = (plan, id) => plan.steps.find(s => s.id === id)?.status;
  const input = {
    intent: { goal: 'monitor_https' },
    operationRefs: siteRefs,
    capabilities,
    reality: reality({ monitors: [site], tokens: [7], groups: { 7: ['g1'] } }),
  };

  it('moves on by itself when nothing holds it', () => {
    const plan = planJourney(input);
    expect(statusOf(plan, 'recipients')).toBe('done');
    expect(plan.currentStepId).toBe('verify');
  });

  it('keeps the finished step current, marked done, while it is held', () => {
    const plan = planJourney({ ...input, heldStepId: 'recipients' });
    expect(statusOf(plan, 'recipients')).toBe('done');
    expect(statusOf(plan, 'verify')).toBe('upcoming');
    expect(plan.currentStepId).toBe('recipients');
    expect(plan.complete).toBe(false);
  });

  it('ignores a hold on a step that is not done', () => {
    const plan = planJourney({
      ...input,
      heldStepId: 'recipients',
      reality: reality({ monitors: [site], tokens: [7], groups: { 7: [] } }),
    });
    expect(statusOf(plan, 'recipients')).toBe('current');
    expect(plan.currentStepId).toBe('recipients');
  });
});
