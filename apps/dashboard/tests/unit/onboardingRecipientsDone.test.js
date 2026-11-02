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

const confirmedFor = goal => ({ recipientsConfirmedFor: goal });

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

  it('is not done by the groups alone, even when they are attached already', () => {
    // The product attaches the workspace default group to a new certificate.
    const r = reality({
      monitors: [site],
      tokens: [7],
      groups: { 7: ['g1'] },
    });
    expect(recipients('monitor_https', { refs: siteRefs, reality: r })).toBe(
      false
    );
  });

  it('is done once the website carries a reachable group and it is confirmed', () => {
    const r = reality({
      monitors: [site],
      tokens: [7],
      groups: { 7: ['g1'] },
    });
    expect(
      recipients('monitor_https', {
        refs: siteRefs,
        progress: confirmedFor('monitor_https'),
        reality: r,
      })
    ).toBe(true);
  });

  it('ignores a confirmation made for another goal', () => {
    const r = reality({
      monitors: [site],
      tokens: [7],
      groups: { 7: ['g1'] },
    });
    expect(
      recipients('monitor_https', {
        refs: siteRefs,
        progress: confirmedFor('track_asset'),
        reality: r,
      })
    ).toBe(false);
  });

  it('needs every website of this session to carry a group', () => {
    const second = { id: 'm2', url: 'https://two.example.com', tokenId: 8 };
    const refs = {
      ...siteRefs,
      monitorIds: ['m1', 'm2'],
      tokenIds: [7, 8],
    };
    const progress = confirmedFor('monitor_https');
    const some = reality({
      monitors: [site, second],
      tokens: [7, 8],
      groups: { 7: ['g1'], 8: [] },
    });
    expect(recipients('monitor_https', { refs, progress, reality: some })).toBe(
      false
    );
    const all = reality({
      monitors: [site, second],
      tokens: [7, 8],
      groups: { 7: ['g1'], 8: ['g1'] },
    });
    expect(recipients('monitor_https', { refs, progress, reality: all })).toBe(
      true
    );
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
    expect(
      recipients('monitor_https', {
        refs,
        progress: confirmedFor('monitor_https'),
        reality: r,
      })
    ).toBe(true);
  });

  it('does not count a stored confirmation while no group is attached', () => {
    const r = reality({ monitors: [site], tokens: [7], groups: { 7: [] } });
    expect(
      recipients('monitor_https', {
        refs: siteRefs,
        progress: confirmedFor('monitor_https'),
        reality: r,
      })
    ).toBe(false);
  });

  it('reopens when the group stops reaching anyone', () => {
    // The server lists only groups that reach a recipient, so a group that
    // lost its recipients drops out of the map.
    const progress = confirmedFor('monitor_https');
    const before = reality({
      monitors: [site],
      tokens: [7],
      groups: { 7: ['g1'] },
    });
    const after = reality({ monitors: [site], tokens: [7], groups: { 7: [] } });
    expect(
      recipients('monitor_https', { refs: siteRefs, progress, reality: before })
    ).toBe(true);
    expect(
      recipients('monitor_https', { refs: siteRefs, progress, reality: after })
    ).toBe(false);
  });

  it('is not done against a summary that cannot say which groups are attached', () => {
    const r = reality({ monitors: [site], tokens: [7] });
    delete r.references.tokenGroups;
    expect(
      recipients('monitor_https', {
        refs: siteRefs,
        progress: confirmedFor('monitor_https'),
        reality: r,
      })
    ).toBe(false);
  });
});

describe('recipients step: asset goal', () => {
  it('is not done when nothing was created yet', () => {
    expect(recipients('track_asset', { reality: reality() })).toBe(false);
  });

  it('is not done when the asset carries no group', () => {
    const r = reality({ tokens: [5], assets: [5], groups: { 5: [] } });
    expect(
      recipients('track_asset', {
        refs: assetRefs,
        progress: confirmedFor('track_asset'),
        reality: r,
      })
    ).toBe(false);
  });

  it('is not done by a reachable group that was never confirmed', () => {
    const r = reality({ tokens: [5], assets: [5], groups: { 5: ['g2'] } });
    expect(recipients('track_asset', { refs: assetRefs, reality: r })).toBe(
      false
    );
    expect(
      recipients('track_asset', {
        refs: assetRefs,
        progress: confirmedFor('monitor_https'),
        reality: r,
      })
    ).toBe(false);
  });

  it('is done once the asset carries a reachable group and it is confirmed', () => {
    const r = reality({ tokens: [5], assets: [5], groups: { 5: ['g2'] } });
    expect(
      recipients('track_asset', {
        refs: assetRefs,
        progress: confirmedFor('track_asset'),
        reality: r,
      })
    ).toBe(true);
  });

  it('is not satisfied by a website from another goal in the same session', () => {
    const refs = { ...siteRefs, ...assetRefs, tokenIds: [7, 5] };
    const r = reality({
      monitors: [site],
      tokens: [7, 5],
      assets: [5],
      groups: { 7: ['g1'], 5: [] },
    });
    expect(
      recipients('track_asset', {
        refs,
        progress: confirmedFor('track_asset'),
        reality: r,
      })
    ).toBe(false);
  });

  it('is not satisfied by an asset when the goal is the website monitor', () => {
    const refs = { ...siteRefs, ...assetRefs, tokenIds: [7, 5] };
    const r = reality({
      monitors: [site],
      tokens: [7, 5],
      assets: [5],
      groups: { 7: [], 5: ['g1'] },
    });
    expect(
      recipients('monitor_https', {
        refs,
        progress: confirmedFor('monitor_https'),
        reality: r,
      })
    ).toBe(false);
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

describe('recipients step: website without a certificate record', () => {
  const noToken = { id: 'm9', url: 'https://down.example.com', tokenId: null };
  const refs = { monitorUrl: noToken.url, monitorIds: ['m9'], tokenIds: [] };

  it('waits for a confirmation when no website can carry a group', () => {
    const r = reality({ monitors: [noToken] });
    expect(recipients('monitor_https', { refs, reality: r })).toBe(false);
    expect(
      recipients('monitor_https', {
        refs,
        progress: { recipientsConfirmedFor: 'monitor_https' },
        reality: r,
      })
    ).toBe(true);
  });

  it('needs a default group that reaches someone to confirm', () => {
    const r = reality({ monitors: [noToken] });
    r.alerts = {
      ...defaultOk,
      contactGroups: { defaultHasRecipient: false },
    };
    expect(
      recipients('monitor_https', {
        refs,
        progress: { recipientsConfirmedFor: 'monitor_https' },
        reality: r,
      })
    ).toBe(false);
  });

  it('judges by the ticks again once a certificate record appears', () => {
    const r = reality({
      monitors: [{ ...noToken, tokenId: 12 }],
      tokens: [12],
      groups: { 12: [] },
    });
    expect(
      recipients('monitor_https', {
        refs,
        progress: { recipientsConfirmedFor: 'monitor_https' },
        reality: r,
      })
    ).toBe(false);
  });
});

describe.each([
  ['certops_automate', 'issue'],
  ['certops_vault', 'publish'],
  ['certops_adcs', 'enrollment'],
])('recipients step: %s certificates', (goal, source) => {
  const made = (tokenId, certificateId = 'c1', as = source) => ({
    certificateId,
    tokenId,
    source: as,
  });
  const withCerts = (list, groups = {}) => {
    const r = reality({ groups });
    r.certops = { sessionCertificates: list };
    return r;
  };

  it('is not done while the certificate carries no group', () => {
    const r = withCerts([made(41)], { 41: [] });
    expect(recipients(goal, { reality: r })).toBe(false);
    // A stored confirmation does not stand in for a reachable group.
    expect(
      recipients(goal, {
        progress: { recipientsConfirmedFor: goal },
        reality: r,
      })
    ).toBe(false);
  });

  it('is not done by groups that were never confirmed', () => {
    // The certificate token is born with the workspace default group.
    const r = withCerts([made(41)], { 41: ['g1'] });
    expect(recipients(goal, { reality: r })).toBe(false);
    expect(
      recipients(goal, {
        progress: { recipientsConfirmedFor: 'monitor_https' },
        reality: r,
      })
    ).toBe(false);
  });

  it('is done once every certificate of this session carries a group and it is confirmed', () => {
    const progress = { recipientsConfirmedFor: goal };
    const r = withCerts([made(41), made(42, 'c2')], {
      41: ['g1'],
      42: ['g1', 'g2'],
    });
    expect(recipients(goal, { progress, reality: r })).toBe(true);
    const partial = withCerts([made(41), made(42, 'c2')], {
      41: ['g1'],
      42: [],
    });
    expect(recipients(goal, { progress, reality: partial })).toBe(false);
  });

  it('reopens when the group stops reaching anyone', () => {
    const r = withCerts([made(41)], { 41: [] });
    expect(
      recipients(goal, {
        progress: { recipientsConfirmedFor: goal },
        reality: r,
      })
    ).toBe(false);
  });

  it('is not done against a summary that cannot say which groups are attached', () => {
    const r = withCerts([made(41)]);
    delete r.references.tokenGroups;
    expect(
      recipients(goal, {
        progress: { recipientsConfirmedFor: goal },
        reality: r,
      })
    ).toBe(false);
  });

  it('ignores certificates that belong to another pick', () => {
    const other = source === 'issue' ? 'enrollment' : 'issue';
    const r = withCerts([made(41, 'c1', other)], { 41: ['g1'] });
    expect(recipients(goal, { reality: r })).toBe(false);
    expect(
      recipients(goal, {
        progress: { recipientsConfirmedFor: goal },
        reality: r,
      })
    ).toBe(true);
  });

  it('falls back to the confirmation while nothing has a token yet', () => {
    const r = withCerts([made(null)]);
    expect(recipients(goal, { reality: r })).toBe(false);
    expect(
      recipients(goal, {
        progress: { recipientsConfirmedFor: goal },
        reality: r,
      })
    ).toBe(true);
  });
});

describe('recipients step in the planned journey', () => {
  const statusOf = (plan, id) => plan.steps.find(s => s.id === id).status;

  it('shows the step on arrival when the items already carry a group', () => {
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

    // The default group is attached by the product: still shown, never skipped.
    const withDefault = planJourney({
      ...base,
      reality: reality({
        monitors: [site],
        tokens: [7],
        groups: { 7: ['g1'] },
      }),
    });
    expect(statusOf(withDefault, 'recipients')).toBe('current');
    expect(withDefault.currentStepId).toBe('recipients');
    expect(statusOf(withDefault, 'verify')).toBe('upcoming');

    const continued = planJourney({
      ...base,
      progress: { recipientsConfirmedFor: 'monitor_https' },
      reality: reality({
        monitors: [site],
        tokens: [7],
        groups: { 7: ['g1'] },
      }),
    });
    expect(statusOf(continued, 'recipients')).toBe('done');
    expect(statusOf(continued, 'verify')).toBe('current');
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
    ).toBe(false);
    expect(
      isStepSatisfied('recipients', {
        reality: r,
        refs: siteRefs,
        progress: confirmedFor('monitor_https'),
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

  it.each([
    ['monitor_https', 'track_asset'],
    ['track_asset', 'certops_automate'],
    ['certops_automate', 'monitor_https'],
  ])('drops a %s confirmation when %s is picked', (from, to) => {
    const next = progressForGoalChange({ recipientsConfirmedFor: from }, to);
    expect(next.recipientsConfirmedFor).toBeUndefined();
  });

  it('judges a returning website goal from the server again', () => {
    // Switching away and back must not remember anything but real state.
    const r = reality({ monitors: [site], tokens: [7], groups: { 7: ['g1'] } });
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
    progress: confirmedFor('monitor_https'),
    reality: reality({ monitors: [site], tokens: [7], groups: { 7: ['g1'] } }),
  };

  it('moves on once the person has continued and nothing holds it', () => {
    const plan = planJourney(input);
    expect(statusOf(plan, 'recipients')).toBe('done');
    expect(plan.currentStepId).toBe('verify');
  });

  it('keeps a step that was never confirmed open on arrival', () => {
    const plan = planJourney({ ...input, progress: {} });
    expect(statusOf(plan, 'recipients')).toBe('current');
    expect(plan.currentStepId).toBe('recipients');
  });

  it('shows an already confirmed step as done when it is reviewed', () => {
    const plan = planJourney(input);
    expect(plan.steps.find(s => s.id === 'recipients').status).toBe('done');
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

describe('recipients step journeys with the default group attached already', () => {
  const statusOf = (plan, id) => plan.steps.find(s => s.id === id)?.status;

  it('shows the asset step, then moves on after Continue', () => {
    const input = {
      intent: { goal: 'track_asset' },
      operationRefs: assetRefs,
      capabilities,
      reality: reality({ tokens: [5], assets: [5], groups: { 5: ['g1'] } }),
    };
    const arrival = planJourney(input);
    expect(statusOf(arrival, 'asset')).toBe('done');
    expect(arrival.currentStepId).toBe('recipients');

    const continued = planJourney({
      ...input,
      progress: confirmedFor('track_asset'),
    });
    expect(statusOf(continued, 'recipients')).toBe('done');
    expect(continued.currentStepId).toBe('verify');
  });

  it('shows the website step again after switching goals and back', () => {
    const input = {
      intent: { goal: 'monitor_https' },
      operationRefs: siteRefs,
      capabilities,
      reality: reality({
        monitors: [site],
        tokens: [7],
        groups: { 7: ['g1'] },
      }),
    };
    const confirmed = planJourney({
      ...input,
      progress: confirmedFor('monitor_https'),
    });
    expect(confirmed.currentStepId).toBe('verify');

    const away = progressForGoalChange(
      confirmedFor('monitor_https'),
      'track_asset'
    );
    const back = progressForGoalChange(away, 'monitor_https');
    expect(planJourney({ ...input, progress: back }).currentStepId).toBe(
      'recipients'
    );
  });

  it.each([
    ['certops_automate', 'issue'],
    ['certops_vault', 'publish'],
    ['certops_adcs', 'enrollment'],
  ])('keeps %s on the step until it is confirmed', (goal, source) => {
    const r = reality({ groups: { 41: ['g1'] } });
    r.certops = {
      sessionCertificates: [{ certificateId: 'c1', tokenId: 41, source }],
    };
    const check = progress =>
      isStepSatisfied('recipients', { reality: r, progress, goal });
    expect(check({})).toBe(false);
    expect(check(confirmedFor(goal))).toBe(true);
    // A confirmation from another goal never carries over.
    expect(check(confirmedFor('monitor_https'))).toBe(false);
    expect(
      check(progressForGoalChange(confirmedFor(goal), 'monitor_https'))
    ).toBe(false);
  });
});
