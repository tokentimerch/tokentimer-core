import { describe, expect, it } from 'vitest';
import {
  describeSetupUse,
  groupReaches,
  planGroupDelete,
  usesDefaultOnly,
} from '../../src/components/onboarding/alertGroupUsage.js';

const ops = { id: 'ops', name: 'Ops', email_contact_ids: ['c1'] };
const billing = { id: 'billing', name: 'Billing', email_contact_ids: ['c2'] };

describe('groupReaches', () => {
  it('counts an existing email contact or an existing webhook', () => {
    const emails = new Set(['c1']);
    const hooks = new Set(['Ops Slack']);
    expect(groupReaches(ops, hooks, emails)).toBe(true);
    expect(groupReaches(billing, hooks, emails)).toBe(false);
    expect(groupReaches({ webhook_names: ['Ops Slack'] }, hooks, emails)).toBe(
      true
    );
    expect(groupReaches({ webhook_names: ['Gone'] }, hooks, emails)).toBe(
      false
    );
  });
});

describe('planGroupDelete', () => {
  it('allows a group that is not the default and keeps the others', () => {
    const plan = planGroupDelete({
      group: billing,
      groups: [ops, billing],
      defaultId: 'ops',
    });
    expect(plan.allowed).toBe(true);
    expect(plan.remaining.map(g => g.id)).toEqual(['ops']);
  });

  it('blocks the default group and says to hand it over first', () => {
    const plan = planGroupDelete({
      group: ops,
      groups: [ops, billing],
      defaultId: 'ops',
    });
    expect(plan.allowed).toBe(false);
    expect(plan.reason).toMatch(/Make another group the default first/);
  });

  it('blocks the only group with its own reason', () => {
    const plan = planGroupDelete({
      group: ops,
      groups: [ops],
      defaultId: 'ops',
    });
    expect(plan.allowed).toBe(false);
    expect(plan.reason).toMatch(/only group/);
  });

  it('compares ids as text', () => {
    const plan = planGroupDelete({
      group: { id: 7, name: 'Seven' },
      groups: [{ id: 7, name: 'Seven' }, ops],
      defaultId: '7',
    });
    expect(plan.allowed).toBe(false);
  });
});

describe('describeSetupUse', () => {
  const base = {
    groups: [ops, billing],
    defaultId: 'ops',
    defaultReaches: true,
  };

  it('uses the default group for websites and marks only it as used', () => {
    const use = describeSetupUse({ ...base, goal: 'monitor_https' });
    expect(use.lines[0]).toMatch(
      /Websites you add here use the default group "Ops"/
    );
    expect(use.usedIds).toEqual(['ops']);
    expect(use.warning).toBe('');
  });

  it('describes the default group for the agent goals', () => {
    const use = describeSetupUse({ ...base, goal: 'certops_observe' });
    expect(use.lines[0]).toMatch(/agents and their certificates/);
    expect(use.usedIds).toEqual(['ops']);
  });

  it('never claims a per-asset rule that the wizard cannot see', () => {
    for (const goal of ['monitor_https', 'alerting', 'certops_observe']) {
      const text = describeSetupUse({ ...base, goal }).lines.join(' ');
      expect(text).not.toMatch(/ticked|chosen during the import|Each asset/);
    }
  });

  it('warns when there is no default or the default reaches nobody', () => {
    expect(
      describeSetupUse({ ...base, defaultId: '', goal: 'alerting' }).warning
    ).toMatch(/Make one of the groups below the default/);
    expect(
      describeSetupUse({ ...base, defaultReaches: false, goal: 'alerting' })
        .warning
    ).toMatch(/"Ops" reaches nobody yet/);
  });

  it('only calls the default the setup group where it governs everything', () => {
    expect(usesDefaultOnly('monitor_https')).toBe(true);
    expect(usesDefaultOnly('alerting')).toBe(true);
    expect(usesDefaultOnly('certops_observe')).toBe(true);
    expect(usesDefaultOnly('track_asset')).toBe(false);
    expect(usesDefaultOnly('import_file')).toBe(false);
    expect(usesDefaultOnly('import_integration')).toBe(false);
  });
});
