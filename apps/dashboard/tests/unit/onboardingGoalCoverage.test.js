import { describe, expect, it } from 'vitest';
import { GOALS, STEP_DEFS } from '../../src/components/onboarding/modules.js';
import { evaluateVerification } from '../../src/components/onboarding/verification.js';
import { planJourney } from '../../src/components/onboarding/journeyPlanner.js';

const routed = {
  alert_state: { eligibility: { eligible_channels: ['email'] } },
};
const unrouted = { alert_state: { eligibility: { eligible_channels: [] } } };
const smtp = { alerts: { smtpConfigured: true } };

describe('goal registry is complete', () => {
  it('every step a goal uses has a definition and a unique title', () => {
    for (const [id, goal] of Object.entries(GOALS)) {
      expect(goal.steps.length, id).toBeGreaterThan(0);
      expect(goal.steps[goal.steps.length - 1], `${id} ends with verify`).toBe(
        'verify'
      );
      for (const step of goal.steps) {
        expect(
          STEP_DEFS[step],
          `${id} uses undefined step ${step}`
        ).toBeDefined();
      }
      expect(new Set(goal.steps).size, `${id} repeats a step`).toBe(
        goal.steps.length
      );
      expect(goal.requires.length, id).toBeGreaterThan(0);
    }
  });

  it('every goal can be planned from a blank state without throwing', () => {
    for (const id of Object.keys(GOALS)) {
      const plan = planJourney({ intent: { goal: id } });
      expect(plan.steps[0].id).toBe('goal');
      expect(plan.currentStepId, id).toBeTruthy();
    }
  });

  it('only candidate goals depend on a gated capability', () => {
    for (const [id, goal] of Object.entries(GOALS)) {
      if (goal.requires.includes('certops.vault_distribution')) {
        expect(goal.candidate, id).toBe(true);
      }
    }
  });
});

describe('evaluateVerification for every goal', () => {
  it('imports pass with assets and a routed sample', () => {
    for (const goal of ['import_file', 'import_integration']) {
      const r = evaluateVerification({
        goal,
        token: routed,
        summary: { ...smtp, assets: { total: 12 } },
      });
      expect(r.ok, goal).toBe(true);
      expect(r.checks.find(c => c.id === 'assets').detail).toBe('12 in total');
    }
  });

  it('imports fail when nothing arrived or alerts have nowhere to go', () => {
    expect(
      evaluateVerification({
        goal: 'import_file',
        token: null,
        summary: { ...smtp, assets: { total: 0 } },
      }).ok
    ).toBe(false);
    const noRoute = evaluateVerification({
      goal: 'import_integration',
      token: unrouted,
      summary: { ...smtp, assets: { total: 3 } },
    });
    expect(noRoute.ok).toBe(false);
    expect(noRoute.checks.find(c => c.id === 'routing').status).toBe('fail');
  });

  it('an alerting-only goal does not fail just because there are no assets', () => {
    const r = evaluateVerification({
      goal: 'alerting',
      token: null,
      summary: { ...smtp, assets: { total: 0 } },
    });
    expect(r.checks.find(c => c.id === 'assets').status).toBe('warn');
    expect(r.ok).toBe(true);
  });

  it('CertOps goals check the agent and report certificates as a follow-up', () => {
    const noAgent = evaluateVerification({
      goal: 'certops_observe',
      token: null,
      summary: {
        ...smtp,
        certops: { agents: { live: 0 }, certificates: { total: 0 } },
      },
    });
    expect(noAgent.ok).toBe(false);
    expect(noAgent.checks.find(c => c.id === 'agent').status).toBe('fail');

    const connected = evaluateVerification({
      goal: 'certops_observe',
      token: routed,
      summary: {
        ...smtp,
        certops: { agents: { live: 1 }, certificates: { total: 0 } },
      },
    });
    expect(connected.ok).toBe(true);
    expect(connected.checks.find(c => c.id === 'certificates').status).toBe(
      'warn'
    );
  });

  it('unreadable CertOps state is a warning, never a pass', () => {
    const r = evaluateVerification({
      goal: 'certops_observe',
      token: routed,
      summary: { ...smtp, certops: 'unknown' },
    });
    expect(r.checks.find(c => c.id === 'certops').status).toBe('warn');
    expect(r.checks.find(c => c.id === 'agent')).toBeUndefined();
  });

  it('a Vault goal is never reported as working without a verified rollout', () => {
    const base = {
      goal: 'certops_vault',
      token: routed,
      summary: {
        ...smtp,
        certops: { agents: { live: 2 }, certificates: { total: 1 } },
      },
    };
    const unverified = evaluateVerification({
      ...base,
      summary: {
        ...base.summary,
        certops: {
          ...base.summary.certops,
          distribution: { groups: 1, verified: false },
        },
      },
    });
    expect(unverified.checks.find(c => c.id === 'distribution').status).toBe(
      'warn'
    );
    const verified = evaluateVerification({
      ...base,
      summary: {
        ...base.summary,
        certops: {
          ...base.summary.certops,
          distribution: { groups: 1, verified: true },
        },
      },
    });
    expect(verified.checks.find(c => c.id === 'distribution').status).toBe(
      'pass'
    );
  });
});
