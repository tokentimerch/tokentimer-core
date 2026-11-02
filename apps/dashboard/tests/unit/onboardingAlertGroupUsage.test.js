import { describe, expect, it } from 'vitest';
import {
  groupReaches,
  planGroupDelete,
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

  it('blocks the default group and points to Alert Preferences', () => {
    const plan = planGroupDelete({
      group: ops,
      groups: [ops, billing],
      defaultId: 'ops',
    });
    expect(plan.allowed).toBe(false);
    expect(plan.reason).toBe(
      'It is the default group. Make another group the default in Alert Preferences first.'
    );
  });

  it('blocks the only group with its own reason', () => {
    const plan = planGroupDelete({
      group: ops,
      groups: [ops],
      defaultId: 'ops',
    });
    expect(plan.allowed).toBe(false);
    expect(plan.reason).toMatch(/only group/);
    expect(plan.reason).toMatch(/in Alert Preferences/);
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
